//! FortiAnalyzer XML report parser.
//!
//! Handles FortiAnalyzer "Daily Summary Report" (and other report
//! templates that share the same schema shape) — an XML document rooted
//! at `<FortiAnalyzer_Report name="…">` containing a mix of `<chart>`
//! and `<table>` sections, each with `<id value="N">` rows and
//! per-row fields.
//!
//! FortiAnalyzer reports are **aggregates, not logs**: each section is
//! a "top N" list (top users by traffic, top websites, top threats,
//! etc.) with no pair-wise flows between entities. We can't learn
//! "user X talked to domain Y" from the report. To produce a useful
//! graph anyway, the parser emits a **radial structure** anchored on a
//! synthetic `ReportContext` entity: every extracted entity gets a
//! `Connect` relation from the hub, and the hub carries the report's
//! macro-level metadata.
//!
//! Sections that naturally pair two entities (`Top Threat` has
//! `Threat` + `Category`, `Top Application by Severity` has
//! `Application` + `Category`) also emit a pair-wise secondary
//! relation so the graph has structure beyond pure spokes.
//!
//! ## Extensibility
//!
//! The parser is built on a [`ChartHandler`] trait + [`HandlerRegistry`]
//! pattern. Six default handlers ship for the Daily Summary Report
//! sections. Future report templates plug in by constructing a
//! registry via `HandlerRegistry::with_default_handlers()`, calling
//! `.register(new_handler)`, and passing it to
//! `FortiAnalyzerXmlParser::with_registry(...)`. A generic fallback
//! handler ([`GenericFortiHandler`]) uses field-name + content
//! heuristics to extract IPs, Hosts, and Domains from sections the
//! registry doesn't know about.
//!
//! ## XML parsing strategy
//!
//! Uses the `quick-xml` crate's event-based `Reader` API (no serde
//! feature needed). A small state machine walks
//! `FortiAnalyzer_Report → (chart|table) → id → field*` and emits
//! one `Vec<ParsedTriple>` per closed section via the registry.
//!
//! Row fields are stored as `HashMap<String, Vec<String>>` because
//! the `Top Website by Traffic` chart uses repeated `<Col>` tags
//! positionally (index 0 = domain, index 1 = bytes string). All
//! handlers access fields via helpers on [`Row`].
//!
//! ## Sections handled by default handlers
//!
//! - `Top User by Traffic` → `IP` entities with `bytes` + `percent`
//! - `Top Website by Traffic` → `Domain` entities (DNS relation) with
//!   `bytes` + `percent`
//! - `Top Threat` → `Other("Threat")` + pair-wise
//!   `Other("ThreatCategory")` with `threat_score` + `incidents`
//! - `Compromised Host` → `Host` entities with `severity: compromised`
//! - `Top Application by Severity` → `Other("Application")` +
//!   pair-wise `Other("AppCategory")` with `sessions` + `bytes`
//! - `Top Application Category` → `Other("AppCategory")` with `bytes`
//!
//! Sections with no entity-per-row data (`Daily Summary Top Traffic
//! Line`, `Incidents by Severity`, `<macro>` elements) are skipped.
//! The `Daily Summary Top Traffic Line` chart's first `Time_Stamp` is
//! extracted to anchor the `ReportContext` id on the report's actual
//! date.

use std::collections::HashMap;
use std::sync::Arc;

use quick_xml::Reader;
use quick_xml::events::Event;

use graph_hunter_core::entity::Entity;
use graph_hunter_core::ip_utils::{self, IpClass};
use graph_hunter_core::parser::{LogParser, ParsedTriple};
use graph_hunter_core::relation::Relation;
use graph_hunter_core::service_classifier;
use graph_hunter_core::types::{EntityType, RelationType};

/// Enriches an IP entity with classification metadata (private/public,
/// subnet) at parse time. Called by handlers that emit IP entities.
fn enrich_ip_entity(entity: &mut Entity) {
    if let Some(class) = ip_utils::classify_ip(&entity.id) {
        entity
            .metadata
            .insert("ip_class".into(), format!("{class:?}"));
        entity.metadata.insert(
            "is_internal".into(),
            matches!(class, IpClass::Private | IpClass::Loopback).to_string(),
        );
    }
    if let Some(subnet) = ip_utils::subnet_24(&entity.id) {
        entity.metadata.insert("subnet".into(), subnet);
    }
}

/// Enriches an Application entity and its radial relation with service
/// classification metadata (category, risk tag, description).
fn enrich_app_entity(entity: &mut Entity, radial: &mut Relation, app_name: &str) {
    let info = service_classifier::classify_application(app_name);
    let cat = format!("{:?}", info.category);
    entity
        .metadata
        .insert("service_category".into(), cat.clone());
    entity
        .metadata
        .insert("risk_tag".into(), info.risk_tag.into());
    entity
        .metadata
        .insert("service_description".into(), info.description.into());
    radial.metadata.insert("service_category".into(), cat);
}

// ---------------------------------------------------------------------------
// Row: one <id value="N"> inside a <chart> or <table>.
// ---------------------------------------------------------------------------

/// One parsed row from a FortiAnalyzer `<chart>` or `<table>` section.
/// Fields are stored as `Vec<String>` because some sections use
/// repeated tag names (e.g., `<Col>` appears twice in one row of
/// `Top Website by Traffic` — position 0 is the domain, position 1 is
/// the bytes string).
#[derive(Debug, Clone, Default)]
pub struct Row {
    fields: HashMap<String, Vec<String>>,
}

impl Row {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a value under `field_name`. A single field with the
    /// same name called twice ends up as `[value1, value2]`.
    pub fn push(&mut self, field_name: impl Into<String>, value: impl Into<String>) {
        self.fields
            .entry(field_name.into())
            .or_default()
            .push(value.into());
    }

    /// Returns the first value for a field, or `None` if absent.
    pub fn first(&self, field_name: &str) -> Option<&str> {
        self.fields
            .get(field_name)
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }

    /// Returns the i-th value for a field, or `None` if out of range.
    pub fn get(&self, field_name: &str, index: usize) -> Option<&str> {
        self.fields
            .get(field_name)
            .and_then(|v| v.get(index))
            .map(|s| s.as_str())
    }

    /// Returns every value under a field name in document order.
    pub fn all(&self, field_name: &str) -> &[String] {
        self.fields
            .get(field_name)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Iterator over all (field_name, &values) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[String])> {
        self.fields.iter().map(|(k, v)| (k.as_str(), v.as_slice()))
    }

    /// True if the row has no fields.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ChartHandler trait + HandlerRegistry
// ---------------------------------------------------------------------------

/// Context passed to every `ChartHandler::extract` call.
#[derive(Debug, Clone)]
pub struct ReportContext {
    /// Stable id of the synthetic anchor entity. Every handler emits
    /// relations from this id.
    pub id: String,
    /// Display label for the anchor entity.
    pub label: String,
    /// Epoch seconds at which the report's data period starts.
    pub timestamp: i64,
}

/// A handler for one or more FortiAnalyzer chart/table section names.
///
/// Implementations must be `Send + Sync` so a single `Arc<dyn
/// ChartHandler>` can be shared across parses from multiple threads.
pub trait ChartHandler: Send + Sync {
    /// Canonical names this handler claims. Case-sensitive; matched
    /// against the `name=` attribute of `<chart>` or `<table>`.
    fn names(&self) -> &[&'static str];

    /// Extract triples from one section's parsed rows. Returns an
    /// empty Vec when nothing matches (e.g., rows are malformed).
    fn extract(
        &self,
        section_name: &str,
        rows: &[Row],
        context: &ReportContext,
    ) -> Vec<ParsedTriple>;
}

/// Registry that maps section names to handlers. Construct via
/// [`HandlerRegistry::with_default_handlers`] to get the built-in
/// six handlers + generic fallback, then `.register(...)` any custom
/// ones. Pass to [`FortiAnalyzerXmlParser::with_registry`].
pub struct HandlerRegistry {
    by_name: HashMap<String, Arc<dyn ChartHandler>>,
    fallback: Arc<dyn ChartHandler>,
}

impl HandlerRegistry {
    /// Registry with the six built-in handlers for the Daily Summary
    /// Report plus `GenericFortiHandler` as the fallback.
    pub fn with_default_handlers() -> Self {
        let mut r = Self {
            by_name: HashMap::new(),
            fallback: Arc::new(GenericFortiHandler),
        };
        r.register(Arc::new(TopUserByTrafficHandler));
        r.register(Arc::new(TopWebsiteByTrafficHandler));
        r.register(Arc::new(TopThreatHandler));
        r.register(Arc::new(CompromisedHostHandler));
        r.register(Arc::new(TopApplicationBySeverityHandler));
        r.register(Arc::new(TopApplicationCategoryHandler));
        r
    }

    /// Registers a handler under each name it claims. Re-registering
    /// the same name replaces the previous handler.
    pub fn register(&mut self, handler: Arc<dyn ChartHandler>) {
        for name in handler.names() {
            self.by_name.insert((*name).to_string(), handler.clone());
        }
    }

    /// Overrides the generic fallback handler. The default is
    /// [`GenericFortiHandler`].
    pub fn set_fallback(&mut self, handler: Arc<dyn ChartHandler>) {
        self.fallback = handler;
    }

    /// Looks up a handler by section name. Returns the fallback if
    /// no name match.
    pub fn find(&self, section_name: &str) -> Arc<dyn ChartHandler> {
        self.by_name
            .get(section_name)
            .cloned()
            .unwrap_or_else(|| self.fallback.clone())
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::with_default_handlers()
    }
}

// ---------------------------------------------------------------------------
// Default handlers — six built-ins for the Daily Summary Report.
// ---------------------------------------------------------------------------

/// Handler for `Top User by Traffic`. The `User_Name` field literally
/// contains IPs in this report template (`10.3.10.66`), so we classify
/// as `EntityType::IP`.
pub struct TopUserByTrafficHandler;

impl ChartHandler for TopUserByTrafficHandler {
    fn names(&self) -> &[&'static str] {
        &["Top User by Traffic"]
    }

    fn extract(&self, section_name: &str, rows: &[Row], ctx: &ReportContext) -> Vec<ParsedTriple> {
        rows.iter()
            .filter_map(|row| {
                let id = row.first("User_Name")?;
                if id.is_empty() {
                    return None;
                }
                let bytes = row.first("Bytes").unwrap_or("").to_string();
                let percent = row.first("Percent_of_Total").unwrap_or("").to_string();
                let mut ip = Entity::new(id, EntityType::IP);
                enrich_ip_entity(&mut ip);
                let mut rel = Relation::new(&ctx.id, id, RelationType::Connect, ctx.timestamp);
                rel.metadata.insert("bytes".to_string(), bytes);
                rel.metadata.insert("percent_of_total".to_string(), percent);
                rel.metadata
                    .insert("source_chart".to_string(), section_name.to_string());
                Some((context_entity(ctx), rel, ip))
            })
            .collect()
    }
}

/// Handler for `Top Website by Traffic`. Uses the positional `<Col>`
/// convention: `Col[0]` is the domain name, `Col[1]` is the bytes
/// string. Emits a `DNS` relation (natural for web traffic).
pub struct TopWebsiteByTrafficHandler;

impl ChartHandler for TopWebsiteByTrafficHandler {
    fn names(&self) -> &[&'static str] {
        &["Top Website by Traffic"]
    }

    fn extract(&self, section_name: &str, rows: &[Row], ctx: &ReportContext) -> Vec<ParsedTriple> {
        rows.iter()
            .filter_map(|row| {
                let domain = row.get("Col", 0)?;
                if domain.is_empty() {
                    return None;
                }
                let bytes = row.get("Col", 1).unwrap_or("").to_string();
                let percent = row.first("Percent_of_Total").unwrap_or("").to_string();
                let dom = Entity::new(domain, EntityType::Domain);
                let mut rel = Relation::new(&ctx.id, domain, RelationType::DNS, ctx.timestamp);
                rel.metadata.insert("bytes".to_string(), bytes);
                rel.metadata.insert("percent_of_total".to_string(), percent);
                rel.metadata
                    .insert("source_chart".to_string(), section_name.to_string());
                Some((context_entity(ctx), rel, dom))
            })
            .collect()
    }
}

/// Handler for `Top Threat`. Emits both a radial relation
/// (ReportContext → Threat) and a pair-wise relation
/// (Threat → ThreatCategory).
pub struct TopThreatHandler;

impl ChartHandler for TopThreatHandler {
    fn names(&self) -> &[&'static str] {
        &["Top Threat"]
    }

    fn extract(&self, section_name: &str, rows: &[Row], ctx: &ReportContext) -> Vec<ParsedTriple> {
        let mut out = Vec::with_capacity(rows.len() * 2);
        for row in rows {
            let Some(threat_name) = row.first("Threat") else {
                continue;
            };
            if threat_name.is_empty() {
                continue;
            }
            let category = row
                .first("Category")
                .unwrap_or("Unknown")
                .trim()
                .to_string();
            let threat_score = row.first("Threat_Score").unwrap_or("").trim().to_string();
            let incidents = row.first("Incidents").unwrap_or("").trim().to_string();

            let threat_id = format!("threat:{}", threat_name);
            let threat_entity = Entity::new(&threat_id, EntityType::Other("Threat".to_string()));

            // Radial: ReportContext → Threat
            let mut radial =
                Relation::new(&ctx.id, &threat_id, RelationType::Connect, ctx.timestamp);
            radial
                .metadata
                .insert("threat_name".to_string(), threat_name.to_string());
            radial
                .metadata
                .insert("threat_score".to_string(), threat_score.clone());
            radial
                .metadata
                .insert("incidents".to_string(), incidents.clone());
            radial
                .metadata
                .insert("source_chart".to_string(), section_name.to_string());
            out.push((context_entity(ctx), radial, threat_entity.clone()));

            // Pair-wise: Threat → ThreatCategory
            if !category.is_empty() && category != "Unknown" {
                let cat_id = format!("threat-category:{}", category);
                let cat_entity =
                    Entity::new(&cat_id, EntityType::Other("ThreatCategory".to_string()));
                let mut pair =
                    Relation::new(&threat_id, &cat_id, RelationType::Connect, ctx.timestamp);
                pair.metadata
                    .insert("source_chart".to_string(), section_name.to_string());
                pair.metadata
                    .insert("threat_score".to_string(), threat_score);
                pair.metadata.insert("incidents".to_string(), incidents);
                out.push((threat_entity, pair, cat_entity));
            }
        }
        out
    }
}

/// Handler for `Compromised Host`. Flags each host with a
/// `severity: compromised` metadata entry.
pub struct CompromisedHostHandler;

impl ChartHandler for CompromisedHostHandler {
    fn names(&self) -> &[&'static str] {
        &["Compromised Host"]
    }

    fn extract(&self, section_name: &str, rows: &[Row], ctx: &ReportContext) -> Vec<ParsedTriple> {
        rows.iter()
            .filter_map(|row| {
                let name = row.first("Host_Name")?;
                if name.is_empty() {
                    return None;
                }
                // The field name is literally `__of_Threats` in the XML —
                // FortiAnalyzer's escaping of "# of Threats" loses the
                // leading `#` and replaces space with `_`.
                let threats = row
                    .first("__of_Threats")
                    .or_else(|| row.first("Threats"))
                    .unwrap_or("")
                    .to_string();
                let percent = row.first("Percent_of_Total").unwrap_or("").to_string();

                let host = Entity::new(name, EntityType::Host);
                let mut rel = Relation::new(&ctx.id, name, RelationType::Connect, ctx.timestamp);
                rel.metadata
                    .insert("severity".to_string(), "compromised".to_string());
                rel.metadata.insert("threat_count".to_string(), threats);
                rel.metadata.insert("percent_of_total".to_string(), percent);
                rel.metadata
                    .insert("source_chart".to_string(), section_name.to_string());
                Some((context_entity(ctx), rel, host))
            })
            .collect()
    }
}

/// Handler for `Top Application by Severity`. Emits both a radial
/// relation and a pair-wise `Application → AppCategory` relation.
pub struct TopApplicationBySeverityHandler;

impl ChartHandler for TopApplicationBySeverityHandler {
    fn names(&self) -> &[&'static str] {
        &["Top Application by Severity"]
    }

    fn extract(&self, section_name: &str, rows: &[Row], ctx: &ReportContext) -> Vec<ParsedTriple> {
        let mut out = Vec::with_capacity(rows.len() * 2);
        for row in rows {
            let Some(app_name) = row.first("Application") else {
                continue;
            };
            if app_name.is_empty() {
                continue;
            }
            let category = row
                .first("Category")
                .unwrap_or("Unknown")
                .trim()
                .to_string();
            let risk = row.first("Risk").unwrap_or("").trim().to_string();
            let sessions = row.first("Sessions").unwrap_or("").trim().to_string();
            let bytes = row.first("Bytes").unwrap_or("").trim().to_string();

            let app_id = format!("application:{}", app_name);
            let mut app_entity = Entity::new(&app_id, EntityType::Other("Application".to_string()));

            // Radial
            let mut radial = Relation::new(&ctx.id, &app_id, RelationType::Connect, ctx.timestamp);
            radial
                .metadata
                .insert("app_name".to_string(), app_name.to_string());
            radial
                .metadata
                .insert("sessions".to_string(), sessions.clone());
            radial.metadata.insert("bytes".to_string(), bytes.clone());
            radial.metadata.insert("risk".to_string(), risk.clone());
            radial
                .metadata
                .insert("source_chart".to_string(), section_name.to_string());
            enrich_app_entity(&mut app_entity, &mut radial, app_name);
            out.push((context_entity(ctx), radial, app_entity.clone()));

            // Pair-wise: Application → AppCategory
            if !category.is_empty() && category != "Unknown" {
                let cat_id = format!("app-category:{}", category);
                let cat_entity = Entity::new(&cat_id, EntityType::Other("AppCategory".to_string()));
                let mut pair =
                    Relation::new(&app_id, &cat_id, RelationType::Connect, ctx.timestamp);
                pair.metadata.insert("sessions".to_string(), sessions);
                pair.metadata.insert("bytes".to_string(), bytes);
                pair.metadata
                    .insert("source_chart".to_string(), section_name.to_string());
                out.push((app_entity, pair, cat_entity));
            }
        }
        out
    }
}

/// Handler for `Top Application Category`. This chart uses the
/// positional `<Col>` convention: `Col[0]` is the category name,
/// `Col[1]` is the bytes string.
pub struct TopApplicationCategoryHandler;

impl ChartHandler for TopApplicationCategoryHandler {
    fn names(&self) -> &[&'static str] {
        &["Top Application Category"]
    }

    fn extract(&self, section_name: &str, rows: &[Row], ctx: &ReportContext) -> Vec<ParsedTriple> {
        rows.iter()
            .filter_map(|row| {
                let cat = row.get("Col", 0)?;
                if cat.is_empty() {
                    return None;
                }
                let bytes = row.get("Col", 1).unwrap_or("").to_string();
                let percent = row.first("Percent_of_Total").unwrap_or("").to_string();

                let cat_id = format!("app-category:{}", cat);
                let cat_entity = Entity::new(&cat_id, EntityType::Other("AppCategory".to_string()));
                let mut rel = Relation::new(&ctx.id, &cat_id, RelationType::Connect, ctx.timestamp);
                rel.metadata.insert("bytes".to_string(), bytes);
                rel.metadata.insert("percent_of_total".to_string(), percent);
                rel.metadata
                    .insert("source_chart".to_string(), section_name.to_string());
                Some((context_entity(ctx), rel, cat_entity))
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// GenericFortiHandler — fallback for unknown chart/table names.
// ---------------------------------------------------------------------------

/// Best-effort handler for sections the registry doesn't know.
///
/// Walks every field in every row and applies name-first then
/// content-pattern heuristics to identify an entity. Emits one
/// `ReportContext → Connect → entity` triple per detected entity,
/// with all other fields stored as relation metadata.
///
/// Field-name heuristics:
/// - `User_Name`, `Account`, `Source_User` → `IP` if value parses as
///   IPv4/IPv6, else `User`
/// - `Host_Name`, `Device_Name`, `Hostname` → `Host`
/// - `Source_IP`, `Destination_IP`, `Src`, `Dst`, any value parseable
///   as IPv4/IPv6 → `IP`
/// - `URL`, `Website`, `Domain`, `Query` → `Domain`
/// - `Threat`, `Application`, `Category` → `Other(<FieldName>)`
pub struct GenericFortiHandler;

impl ChartHandler for GenericFortiHandler {
    fn names(&self) -> &[&'static str] {
        // The registry routes unknown sections to the fallback
        // regardless of this list.
        &[]
    }

    fn extract(&self, section_name: &str, rows: &[Row], ctx: &ReportContext) -> Vec<ParsedTriple> {
        let mut out = Vec::new();
        for row in rows {
            if let Some((mut entity, relation_type)) = detect_primary_entity(row) {
                // Enrich IP entities with classification metadata.
                if entity.entity_type == EntityType::IP {
                    enrich_ip_entity(&mut entity);
                }
                let target_id = entity.id.clone();
                let mut rel = Relation::new(&ctx.id, &target_id, relation_type, ctx.timestamp);
                // Stash every field of the row into relation metadata
                // for debugging / UI display.
                for (name, values) in row.iter() {
                    let joined = values.join("; ");
                    rel.metadata.insert(name.to_string(), joined);
                }
                rel.metadata
                    .insert("source_chart".to_string(), section_name.to_string());
                rel.metadata
                    .insert("handler".to_string(), "generic_forti".to_string());
                // Enrich Application entities with service classification.
                if let EntityType::Other(ref kind) = entity.entity_type {
                    if kind == "Application" {
                        let app_name = entity.id.strip_prefix("application:").unwrap_or(&entity.id);
                        let info = service_classifier::classify_application(app_name);
                        let cat = format!("{:?}", info.category);
                        entity
                            .metadata
                            .insert("service_category".into(), cat.clone());
                        entity
                            .metadata
                            .insert("risk_tag".into(), info.risk_tag.into());
                        entity
                            .metadata
                            .insert("service_description".into(), info.description.into());
                        rel.metadata.insert("service_category".into(), cat);
                    }
                }
                out.push((context_entity(ctx), rel, entity));
            }
        }
        out
    }
}

/// Inspects a row and returns the first entity it can identify, using
/// field-name heuristics first, then content patterns.
fn detect_primary_entity(row: &Row) -> Option<(Entity, RelationType)> {
    // 1. Try by field name.
    for (name, values) in row.iter() {
        let Some(value) = values.first() else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        let name_lc = name.to_ascii_lowercase();
        match name_lc.as_str() {
            "user_name" | "account" | "source_user" => {
                if looks_like_ip(value) {
                    return Some((Entity::new(value, EntityType::IP), RelationType::Connect));
                }
                return Some((Entity::new(value, EntityType::User), RelationType::Auth));
            }
            "host_name" | "device_name" | "hostname" => {
                return Some((Entity::new(value, EntityType::Host), RelationType::Connect));
            }
            "source_ip" | "destination_ip" | "src" | "dst" | "src_ip" | "dst_ip" => {
                return Some((Entity::new(value, EntityType::IP), RelationType::Connect));
            }
            "url" | "website" | "domain" | "query" | "host" => {
                return Some((Entity::new(value, EntityType::Domain), RelationType::DNS));
            }
            "threat" => {
                let id = format!("threat:{}", value);
                return Some((
                    Entity::new(id, EntityType::Other("Threat".to_string())),
                    RelationType::Connect,
                ));
            }
            "application" => {
                let id = format!("application:{}", value);
                return Some((
                    Entity::new(id, EntityType::Other("Application".to_string())),
                    RelationType::Connect,
                ));
            }
            _ => {}
        }
    }

    // 2. Content pattern: first value that parses as an IPv4/IPv6.
    for (_, values) in row.iter() {
        if let Some(value) = values.first() {
            if looks_like_ip(value) {
                return Some((Entity::new(value, EntityType::IP), RelationType::Connect));
            }
        }
    }

    // 3. Content pattern: first value that looks like a domain.
    for (_, values) in row.iter() {
        if let Some(value) = values.first() {
            if looks_like_domain(value) {
                return Some((Entity::new(value, EntityType::Domain), RelationType::DNS));
            }
        }
    }
    None
}

/// Returns true if `s` parses as an IPv4 or IPv6 address. Uses
/// `std::net::IpAddr` so it matches RFC validity exactly.
fn looks_like_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// Heuristic domain detector: has at least one dot, no whitespace,
/// at least one ASCII letter, length ≥ 4, and the last segment is
/// 2-24 chars of letters/digits (a plausible TLD).
fn looks_like_domain(s: &str) -> bool {
    if s.len() < 4 || s.contains(' ') || s.contains('\t') || s.contains('/') {
        return false;
    }
    let Some(last_dot) = s.rfind('.') else {
        return false;
    };
    let tld = &s[last_dot + 1..];
    if tld.is_empty() || tld.len() > 24 {
        return false;
    }
    if !tld.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    if !s.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    // Reject pure numeric (e.g. "1.2.3.4" is an IP, not a domain).
    if s.chars()
        .all(|c| c.is_ascii_digit() || c == '.' || c == ':')
    {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// ReportContext entity helper
// ---------------------------------------------------------------------------

/// Constructs (or re-constructs) the `ReportContext` anchor entity
/// handlers use as the left-hand side of every emitted triple.
fn context_entity(ctx: &ReportContext) -> Entity {
    let mut e = Entity::new(&ctx.id, EntityType::Other("ReportContext".to_string()));
    e.metadata.insert("label".to_string(), ctx.label.clone());
    e.metadata
        .insert("kind".to_string(), "FortiAnalyzer Report".to_string());
    e.metadata
        .insert("timestamp".to_string(), ctx.timestamp.to_string());
    e
}

// ---------------------------------------------------------------------------
// The parser itself
// ---------------------------------------------------------------------------

/// FortiAnalyzer XML report parser. Holds an extensible handler
/// registry; defaults to `HandlerRegistry::with_default_handlers()`.
pub struct FortiAnalyzerXmlParser {
    registry: HandlerRegistry,
}

impl Default for FortiAnalyzerXmlParser {
    fn default() -> Self {
        Self::new()
    }
}

impl FortiAnalyzerXmlParser {
    /// Parser with the six built-in handlers + generic fallback.
    pub fn new() -> Self {
        Self {
            registry: HandlerRegistry::with_default_handlers(),
        }
    }

    /// Parser with a custom registry. Use this to add handlers for
    /// new report templates without touching this module.
    pub fn with_registry(registry: HandlerRegistry) -> Self {
        Self { registry }
    }
}

/// Parser state machine. The XML shape is:
///   <FortiAnalyzer_Report name="X">
///     <chart name="Y"> | <table name="Y">
///       <id value="N">
///         <FieldA>text</FieldA>
///         <FieldB>text</FieldB>
///       </id>
///     </chart> | </table>
///     <macro name="Z"><value>…</value></macro>
///   </FortiAnalyzer_Report>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SectionKind {
    Chart,
    Table,
}

impl LogParser for FortiAnalyzerXmlParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        let mut reader = Reader::from_str(data);
        // quick-xml 0.38 dropped trim_text; we trim text manually in
        // the Text event handler instead.
        let mut out: Vec<ParsedTriple> = Vec::new();
        let mut buf = Vec::new();

        let mut current_section: Option<(String, SectionKind)> = None;
        let mut current_rows: Vec<Row> = Vec::new();
        let mut in_row = false;
        let mut current_row = Row::new();
        let mut current_field: Option<String> = None;
        let mut current_text = String::new();

        let mut report_name: Option<String> = None;
        let mut first_timestamp: Option<i64> = None;
        let mut report_context: Option<ReportContext> = None;
        let mut context_emitted = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    let tag_bytes = e.name().into_inner().to_vec();
                    let tag_name = String::from_utf8_lossy(&tag_bytes).into_owned();

                    match tag_name.as_str() {
                        "FortiAnalyzer_Report" => {
                            report_name = attr(&e, b"name");
                        }
                        "chart" | "table" => {
                            if let Some(name) = attr(&e, b"name") {
                                let kind = if tag_name == "chart" {
                                    SectionKind::Chart
                                } else {
                                    SectionKind::Table
                                };
                                current_section = Some((name, kind));
                                current_rows.clear();
                                in_row = false;
                                current_row = Row::new();
                                current_field = None;
                                current_text.clear();
                            }
                        }
                        "id" if current_section.is_some() => {
                            in_row = true;
                            current_row = Row::new();
                            current_field = None;
                            current_text.clear();
                        }
                        _ if in_row => {
                            // Field tag inside <id>.
                            current_field = Some(tag_name);
                            current_text.clear();
                        }
                        _ => {}
                    }
                }
                Ok(Event::Text(t)) => {
                    if current_field.is_some() {
                        if let Ok(text) = t.decode() {
                            current_text.push_str(text.as_ref());
                        }
                    }
                }
                Ok(Event::End(e)) => {
                    let tag_bytes = e.name().into_inner().to_vec();
                    let tag_name = String::from_utf8_lossy(&tag_bytes).into_owned();

                    if let Some(ref field) = current_field {
                        if &tag_name == field {
                            let trimmed = current_text.trim().to_string();
                            current_row.push(field.clone(), trimmed);
                            current_field = None;
                            current_text.clear();
                            continue;
                        }
                    }
                    match tag_name.as_str() {
                        "id" if in_row => {
                            if !current_row.is_empty() {
                                current_rows.push(std::mem::take(&mut current_row));
                            }
                            in_row = false;
                        }
                        "chart" | "table" => {
                            if let Some((name, _kind)) = current_section.take() {
                                // Special case: extract the first Time_Stamp
                                // from the Daily Summary time-series chart
                                // to anchor the report_context id, but emit
                                // no triples for that section.
                                if name == "Daily Summary Top Traffic Line" {
                                    if first_timestamp.is_none() {
                                        first_timestamp = current_rows
                                            .iter()
                                            .find_map(|r| r.first("Time_Stamp"))
                                            .and_then(|s| s.parse::<i64>().ok());
                                    }
                                } else {
                                    // Ensure the report context is built
                                    // before dispatching.
                                    if report_context.is_none() {
                                        report_context = Some(build_context(
                                            report_name.as_deref(),
                                            first_timestamp,
                                        ));
                                    }
                                    let ctx = report_context.as_ref().unwrap();

                                    // Emit the context entity itself once
                                    // so the graph has an explicit hub node
                                    // even if no section ever produces a
                                    // self-referential triple.
                                    if !context_emitted {
                                        out.push(self_loop_triple(ctx));
                                        context_emitted = true;
                                    }

                                    let handler = self.registry.find(&name);
                                    let triples = handler.extract(&name, &current_rows, ctx);
                                    out.extend(triples);
                                }
                                current_rows.clear();
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(_) => break, // Malformed XML: return whatever we got.
                _ => {}
            }
            buf.clear();
        }

        // Edge case: no sections produced triples AND the parser did
        // see a FortiAnalyzer_Report root. Still emit the context
        // entity so the ingestion success log isn't misleading.
        if !context_emitted && report_name.is_some() {
            let ctx = build_context(report_name.as_deref(), first_timestamp);
            out.push(self_loop_triple(&ctx));
        }

        out
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extracts an attribute value by name from an XML start tag.
fn attr(e: &quick_xml::events::BytesStart, key: &[u8]) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.into_inner() == key)
        .and_then(|a| std::str::from_utf8(&a.value).ok().map(|s| s.to_string()))
}

/// Builds the `ReportContext` anchor from the report name + first
/// Time_Stamp (if available).
fn build_context(report_name: Option<&str>, first_ts: Option<i64>) -> ReportContext {
    let name = report_name.unwrap_or("FortiAnalyzer Report");
    let slug = slugify(name);
    let ts = first_ts.unwrap_or(0);
    let id = format!("faz:{}:{}", slug, ts);
    let label = format!("{} — {}", name, human_date(ts));
    ReportContext {
        id,
        label,
        timestamp: ts,
    }
}

/// Lowercase + replace non-alphanumerics with dashes + collapse runs.
fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_was_dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            out.push('-');
            last_was_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

/// Minimal epoch-seconds → ISO-ish date. No chrono dep needed — we
/// just want a readable label.
fn human_date(epoch_s: i64) -> String {
    if epoch_s <= 0 {
        return "unknown".to_string();
    }
    // Stringify via epoch days → yyyy-mm-dd, approximate (drop TZ).
    // For the purpose of a label this is fine; the precise timestamp
    // stays in the metadata.
    let days = epoch_s / 86_400;
    let (y, m, d) = days_to_ymd(days);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// Converts days-since-unix-epoch to (year, month, day). Simple
/// gregorian arithmetic, no TZ handling. Good enough for labels.
fn days_to_ymd(mut days: i64) -> (i64, u32, u32) {
    // Shift so that day 0 = 1970-01-01 becomes "Mar 1 of year 0" in
    // the Howard Hinnant algorithm (more resilient for negatives).
    days += 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = (days - era * 146097) as u32; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// A self-referential triple on the report context: `ctx → Connect → ctx`
/// with a single "hub" metadata flag. Guarantees the context entity
/// is materialized in the graph even when no handler produces triples.
fn self_loop_triple(ctx: &ReportContext) -> ParsedTriple {
    let entity = context_entity(ctx);
    let mut rel = Relation::new(&ctx.id, &ctx.id, RelationType::Connect, ctx.timestamp);
    rel.metadata.insert("hub".to_string(), "true".to_string());
    rel.metadata.insert("label".to_string(), ctx.label.clone());
    (entity.clone(), rel, entity)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn run(xml: &str) -> Vec<ParsedTriple> {
        FortiAnalyzerXmlParser::new().parse(xml)
    }

    fn entity_ids(triples: &[ParsedTriple]) -> Vec<String> {
        let mut ids: Vec<String> = triples
            .iter()
            .flat_map(|(a, _, b)| [a.id.clone(), b.id.clone()])
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    #[test]
    fn empty_report_still_emits_context_entity() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
</FortiAnalyzer_Report>"#;
        let triples = run(xml);
        assert_eq!(triples.len(), 1, "context-only self-loop expected");
        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, dst.id);
        assert!(src.id.starts_with("faz:daily-summary-report"));
        assert_eq!(
            src.entity_type,
            EntityType::Other("ReportContext".to_string())
        );
        assert_eq!(rel.metadata.get("hub").map(String::as_str), Some("true"));
    }

    #[test]
    fn top_user_by_traffic_extracts_ips() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
    <chart name="Top User by Traffic">
        <id value="1">
            <User_Name>10.3.10.66</User_Name>
            <Bytes>5983237494</Bytes>
            <Percent_of_Total>29.18%</Percent_of_Total>
        </id>
        <id value="2">
            <User_Name>10.3.10.65</User_Name>
            <Bytes>3387957275</Bytes>
            <Percent_of_Total>16.52%</Percent_of_Total>
        </id>
    </chart>
</FortiAnalyzer_Report>"#;
        let triples = run(xml);
        // 1 self-loop (context hub) + 2 radial = 3
        assert_eq!(triples.len(), 3);
        let ips: Vec<_> = triples
            .iter()
            .filter(|(_, _, d)| d.entity_type == EntityType::IP)
            .map(|(_, _, d)| d.id.as_str())
            .collect();
        assert_eq!(ips, ["10.3.10.66", "10.3.10.65"]);
        // Metadata carried on the radial relations.
        let first_rel = triples
            .iter()
            .find(|(_, _, d)| d.id == "10.3.10.66")
            .unwrap();
        assert_eq!(first_rel.1.metadata.get("bytes").unwrap(), "5983237494");
        assert_eq!(
            first_rel.1.metadata.get("percent_of_total").unwrap(),
            "29.18%"
        );
        assert_eq!(
            first_rel.1.metadata.get("source_chart").unwrap(),
            "Top User by Traffic"
        );
    }

    #[test]
    fn top_website_handles_positional_col_tags() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
    <chart name="Top Website by Traffic">
        <id value="1">
            <Col>office.net</Col>
            <Col>31.10 GB</Col>
            <Percent_of_Total>33.36 </Percent_of_Total>
        </id>
        <id value="2">
            <Col>googleapis.com</Col>
            <Col>20.65 GB</Col>
            <Percent_of_Total>22.16 </Percent_of_Total>
        </id>
    </chart>
</FortiAnalyzer_Report>"#;
        let triples = run(xml);
        // 1 self-loop + 2 radial DNS = 3
        assert_eq!(triples.len(), 3);
        let domains: Vec<_> = triples
            .iter()
            .filter(|(_, _, d)| d.entity_type == EntityType::Domain)
            .map(|(_, _, d)| d.id.as_str())
            .collect();
        assert_eq!(domains, ["office.net", "googleapis.com"]);
        // Bytes come from Col[1].
        let first_rel = triples
            .iter()
            .find(|(_, _, d)| d.id == "office.net")
            .unwrap();
        assert_eq!(first_rel.1.metadata.get("bytes").unwrap(), "31.10 GB");
        assert_eq!(first_rel.1.rel_type, RelationType::DNS);
    }

    #[test]
    fn top_threat_emits_pair_wise_relation() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
    <table name="Top Threat">
        <id value="1">
            <Threat>tunnel.googlezip.net</Threat>
            <Category>Proxy Avoidance</Category>
            <Threat_Score>15,240 </Threat_Score>
            <Incidents>1,524 </Incidents>
        </id>
    </table>
</FortiAnalyzer_Report>"#;
        let triples = run(xml);
        // 1 self-loop + 1 radial + 1 pair-wise = 3
        assert_eq!(triples.len(), 3);

        let has_radial = triples.iter().any(|(s, r, d)| {
            s.entity_type == EntityType::Other("ReportContext".to_string())
                && d.id == "threat:tunnel.googlezip.net"
                && r.rel_type == RelationType::Connect
        });
        let has_pair = triples.iter().any(|(s, r, d)| {
            s.id == "threat:tunnel.googlezip.net"
                && d.id == "threat-category:Proxy Avoidance"
                && r.rel_type == RelationType::Connect
        });
        assert!(has_radial, "missing radial threat relation");
        assert!(has_pair, "missing pair-wise threat→category relation");

        let radial = triples
            .iter()
            .find(|(_, _, d)| d.id == "threat:tunnel.googlezip.net")
            .unwrap();
        assert_eq!(radial.1.metadata.get("threat_score").unwrap(), "15,240");
        assert_eq!(radial.1.metadata.get("incidents").unwrap(), "1,524");
    }

    #[test]
    fn compromised_host_flags_severity() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
    <chart name="Compromised Host">
        <id value="1">
            <Host_Name>Android_PHR9KIPN</Host_Name>
            <__of_Threats>1</__of_Threats>
            <Percent_of_Total>100.00%</Percent_of_Total>
        </id>
    </chart>
</FortiAnalyzer_Report>"#;
        let triples = run(xml);
        assert_eq!(triples.len(), 2); // self-loop + 1
        let host_triple = triples
            .iter()
            .find(|(_, _, d)| d.entity_type == EntityType::Host)
            .expect("expected a Host entity");
        assert_eq!(host_triple.2.id, "Android_PHR9KIPN");
        assert_eq!(
            host_triple.1.metadata.get("severity").unwrap(),
            "compromised"
        );
        assert_eq!(host_triple.1.metadata.get("threat_count").unwrap(), "1");
    }

    #[test]
    fn top_application_by_severity_emits_app_and_category() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
    <table name="Top Application by Severity">
        <id value="1">
            <Application>Proxy.HTTP</Application>
            <Category>Proxy</Category>
            <Risk> </Risk>
            <Sessions>71 </Sessions>
            <Bytes>1.99 MB</Bytes>
        </id>
    </table>
</FortiAnalyzer_Report>"#;
        let triples = run(xml);
        // self-loop + radial + pair = 3
        assert_eq!(triples.len(), 3);
        assert!(
            triples
                .iter()
                .any(|(_, _, d)| d.id == "application:Proxy.HTTP")
        );
        assert!(
            triples
                .iter()
                .any(|(s, _, d)| s.id == "application:Proxy.HTTP" && d.id == "app-category:Proxy")
        );
    }

    #[test]
    fn top_application_category_uses_positional_col() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
    <chart name="Top Application Category">
        <id value="1">
            <Col>Network.Service</Col>
            <Col>254.91 GB</Col>
            <Percent_of_Total>47.46 </Percent_of_Total>
        </id>
    </chart>
</FortiAnalyzer_Report>"#;
        let triples = run(xml);
        assert_eq!(triples.len(), 2); // self-loop + 1 radial
        let (_, rel, dst) = triples
            .iter()
            .find(|(_, _, d)| d.id == "app-category:Network.Service")
            .unwrap();
        assert_eq!(
            dst.entity_type,
            EntityType::Other("AppCategory".to_string())
        );
        assert_eq!(rel.metadata.get("bytes").unwrap(), "254.91 GB");
    }

    #[test]
    fn unknown_chart_uses_generic_fallback() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
    <chart name="Top DNS Requests">
        <id value="1">
            <Query>example.com</Query>
            <Count>42</Count>
        </id>
    </chart>
</FortiAnalyzer_Report>"#;
        let triples = run(xml);
        assert_eq!(triples.len(), 2); // self-loop + fallback result
        let (_, rel, dst) = triples
            .iter()
            .find(|(_, _, d)| d.id == "example.com")
            .expect("generic fallback should detect example.com as a Domain");
        assert_eq!(dst.entity_type, EntityType::Domain);
        assert_eq!(rel.rel_type, RelationType::DNS);
        assert_eq!(rel.metadata.get("handler").unwrap(), "generic_forti");
    }

    #[test]
    fn time_series_chart_is_skipped_but_timestamp_captured() {
        // The Daily Summary Top Traffic Line chart must produce zero
        // triples of its own but its first Time_Stamp becomes the
        // report context id suffix.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
    <chart name="Daily Summary Top Traffic Line">
        <id value="1">
            <Time_Stamp>1774926000</Time_Stamp>
            <Sent>155444383.000000</Sent>
            <Received>268879247.000000</Received>
        </id>
        <id value="2">
            <Time_Stamp>1774926600</Time_Stamp>
            <Sent>134005616.000000</Sent>
            <Received>246776289.000000</Received>
        </id>
    </chart>
    <chart name="Top User by Traffic">
        <id value="1">
            <User_Name>10.3.10.66</User_Name>
            <Bytes>100</Bytes>
            <Percent_of_Total>50%</Percent_of_Total>
        </id>
    </chart>
</FortiAnalyzer_Report>"#;
        let triples = run(xml);
        // 1 self-loop + 1 radial user = 2. The time-series chart
        // contributes nothing.
        assert_eq!(triples.len(), 2);
        // Context id embeds the first timestamp.
        let (src, _, _) = &triples[0];
        assert!(
            src.id.ends_with(":1774926000"),
            "context id should carry first Time_Stamp, got {}",
            src.id
        );
    }

    #[test]
    fn malformed_xml_recovers_gracefully() {
        // Truncated mid-tag. Parser should return whatever it got
        // without panicking.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
    <chart name="Top User by Traffic">
        <id value="1">
            <User_Name>10.3.10.66</User_Name>
            <Bytes>100</Bytes"#;
        let _ = run(xml); // no panic
    }

    #[test]
    fn full_file_integration_small_multi_section() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
    <chart name="Daily Summary Top Traffic Line">
        <id value="1">
            <Time_Stamp>1774926000</Time_Stamp>
            <Sent>100</Sent>
            <Received>200</Received>
        </id>
    </chart>
    <table name="Top Application by Severity">
        <id value="1">
            <Application>AnyDesk</Application>
            <Category>Remote.Access</Category>
            <Sessions>3021</Sessions>
            <Bytes>135.04 MB</Bytes>
        </id>
    </table>
    <chart name="Top Application Category">
        <id value="1">
            <Col>Network.Service</Col>
            <Col>254.91 GB</Col>
            <Percent_of_Total>47.46</Percent_of_Total>
        </id>
    </chart>
    <table name="Top Threat">
        <id value="1">
            <Threat>Failed Connection</Threat>
            <Category>Failed Connection</Category>
            <Threat_Score>131310</Threat_Score>
            <Incidents>26262</Incidents>
        </id>
    </table>
    <chart name="Top Website by Traffic">
        <id value="1">
            <Col>office.net</Col>
            <Col>31.10 GB</Col>
            <Percent_of_Total>33.36</Percent_of_Total>
        </id>
    </chart>
    <chart name="Compromised Host">
        <id value="1">
            <Host_Name>Android_PHR9KIPN</Host_Name>
            <__of_Threats>1</__of_Threats>
            <Percent_of_Total>100.00%</Percent_of_Total>
        </id>
    </chart>
    <chart name="Top User by Traffic">
        <id value="1">
            <User_Name>10.3.10.66</User_Name>
            <Bytes>5983237494</Bytes>
            <Percent_of_Total>29.18%</Percent_of_Total>
        </id>
    </chart>
</FortiAnalyzer_Report>"#;

        let triples = run(xml);
        // Expected triples:
        //   1 self-loop (context hub)
        //   2 from Top Application by Severity (radial + pair)
        //   1 from Top Application Category (radial only)
        //   2 from Top Threat (radial + pair)
        //   1 from Top Website by Traffic (radial only)
        //   1 from Compromised Host (radial only)
        //   1 from Top User by Traffic (radial only)
        //   ----
        //   9 triples total
        assert_eq!(
            triples.len(),
            9,
            "got {} triples, ids = {:?}",
            triples.len(),
            entity_ids(&triples)
        );

        let ids = entity_ids(&triples);
        // Sanity-check a few expected entity IDs made it through:
        assert!(ids.iter().any(|i| i == "10.3.10.66"));
        assert!(ids.iter().any(|i| i == "office.net"));
        assert!(ids.iter().any(|i| i == "Android_PHR9KIPN"));
        assert!(ids.iter().any(|i| i == "threat:Failed Connection"));
        assert!(ids.iter().any(|i| i == "application:AnyDesk"));
        assert!(ids.iter().any(|i| i == "app-category:Network.Service"));
        assert!(
            ids.iter()
                .any(|i| i.starts_with("faz:daily-summary-report:"))
        );
    }

    #[test]
    fn looks_like_ip_accepts_ipv4_and_ipv6() {
        assert!(looks_like_ip("10.3.10.66"));
        assert!(looks_like_ip("192.168.1.1"));
        assert!(looks_like_ip("::1"));
        assert!(looks_like_ip("2001:db8::1"));
        assert!(!looks_like_ip("example.com"));
        assert!(!looks_like_ip("not-an-ip"));
        assert!(!looks_like_ip(""));
    }

    #[test]
    fn looks_like_domain_basic_cases() {
        assert!(looks_like_domain("example.com"));
        assert!(looks_like_domain("googleapis.com"));
        assert!(looks_like_domain("office.microsoft.com"));
        assert!(!looks_like_domain("10.3.10.66")); // pure numeric → IP not domain
        assert!(!looks_like_domain("foo")); // no dot
        assert!(!looks_like_domain("has space.com"));
        assert!(!looks_like_domain(""));
    }

    #[test]
    fn slugify_handles_spaces_and_punctuation() {
        assert_eq!(slugify("Daily Summary Report"), "daily-summary-report");
        assert_eq!(slugify("Top-Threat"), "top-threat");
        assert_eq!(slugify("  padded   "), "padded");
        assert_eq!(slugify("Weekly (VPN) Report!"), "weekly-vpn-report");
    }

    #[test]
    fn handler_registry_custom_handler_overrides_default() {
        struct CustomHandler;
        impl ChartHandler for CustomHandler {
            fn names(&self) -> &[&'static str] {
                &["Top User by Traffic"]
            }
            fn extract(
                &self,
                _name: &str,
                _rows: &[Row],
                _ctx: &ReportContext,
            ) -> Vec<ParsedTriple> {
                Vec::new() // suppress
            }
        }

        let mut reg = HandlerRegistry::with_default_handlers();
        reg.register(Arc::new(CustomHandler));
        let parser = FortiAnalyzerXmlParser::with_registry(reg);

        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
    <chart name="Top User by Traffic">
        <id value="1">
            <User_Name>10.3.10.66</User_Name>
            <Bytes>100</Bytes>
        </id>
    </chart>
</FortiAnalyzer_Report>"#;
        let triples = parser.parse(xml);
        // Only the self-loop survives; the user row is suppressed.
        assert_eq!(triples.len(), 1);
    }

    // ── IP enrichment at parse time ──

    #[test]
    fn ip_entity_gets_classification_metadata() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
    <chart name="Top User by Traffic">
        <id value="1">
            <User_Name>10.3.10.66</User_Name>
            <Bytes>100</Bytes>
            <Percent_of_Total>50%</Percent_of_Total>
        </id>
        <id value="2">
            <User_Name>8.8.8.8</User_Name>
            <Bytes>50</Bytes>
            <Percent_of_Total>25%</Percent_of_Total>
        </id>
    </chart>
</FortiAnalyzer_Report>"#;
        let triples = run(xml);
        // Private IP
        let private_ip = triples
            .iter()
            .find(|(_, _, d)| d.id == "10.3.10.66")
            .unwrap();
        assert_eq!(private_ip.2.metadata.get("ip_class").unwrap(), "Private");
        assert_eq!(private_ip.2.metadata.get("is_internal").unwrap(), "true");
        assert_eq!(private_ip.2.metadata.get("subnet").unwrap(), "10.3.10.0/24");
        // Public IP
        let public_ip = triples.iter().find(|(_, _, d)| d.id == "8.8.8.8").unwrap();
        assert_eq!(public_ip.2.metadata.get("ip_class").unwrap(), "Public");
        assert_eq!(public_ip.2.metadata.get("is_internal").unwrap(), "false");
    }

    // ── Application service classification at parse time ──

    #[test]
    fn application_entity_gets_service_classification() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
    <table name="Top Application by Severity">
        <id value="1">
            <Application>AnyDesk</Application>
            <Category>Remote.Access</Category>
            <Sessions>3021</Sessions>
            <Bytes>135.04 MB</Bytes>
        </id>
        <id value="2">
            <Application>ADFS</Application>
            <Category>Authentication</Category>
            <Sessions>500</Sessions>
            <Bytes>10 MB</Bytes>
        </id>
    </table>
</FortiAnalyzer_Report>"#;
        let triples = run(xml);
        // AnyDesk → RemoteAccess, high
        let anydesk = triples
            .iter()
            .find(|(_, _, d)| d.id == "application:AnyDesk")
            .unwrap();
        assert_eq!(
            anydesk.2.metadata.get("service_category").unwrap(),
            "RemoteAccess"
        );
        assert_eq!(anydesk.2.metadata.get("risk_tag").unwrap(), "high");
        // Radial relation also gets service_category
        let anydesk_radial = triples
            .iter()
            .find(|(_, r, d)| {
                d.id == "application:AnyDesk"
                    && r.rel_type == RelationType::Connect
                    && r.source_id.starts_with("faz:")
            })
            .unwrap();
        assert_eq!(
            anydesk_radial.1.metadata.get("service_category").unwrap(),
            "RemoteAccess"
        );
        // ADFS → Authentication, info
        let adfs = triples
            .iter()
            .find(|(_, _, d)| d.id == "application:ADFS")
            .unwrap();
        assert_eq!(
            adfs.2.metadata.get("service_category").unwrap(),
            "Authentication"
        );
        assert_eq!(adfs.2.metadata.get("risk_tag").unwrap(), "info");
    }
}
