use std::collections::{HashMap, HashSet};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::entity::Entity;
use crate::generic::GenericParser;
use crate::parser::{LogParser, ParsedTriple};
use crate::relation::Relation;
use crate::types::{EntityType, RelationType};

/// Role a field can play during ingestion.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum FieldRole {
    /// Field is promoted to a graph node (entity).
    Node,
    /// Field is stored as metadata on the context anchor entity.
    Metadata,
    /// Field is completely ignored during ingestion.
    Ignore,
}

/// Preview result for a single field discovered in sample events.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FieldInfo {
    /// Original field name as it appears in the JSON.
    pub raw_name: String,
    /// Canonical target if GenericParser recognizes this field, else None.
    pub canonical_target: Option<String>,
    /// Number of events (in the sample) where this field had a non-empty value.
    pub occurrence_count: usize,
    /// Up to 5 distinct sample values.
    pub sample_values: Vec<String>,
    /// Current role: Node if canonical, Metadata otherwise.
    pub current_role: FieldRole,
    /// Suggested entity type if promoted to a node.
    pub suggested_entity_type: Option<String>,
    /// Where the suggested entity type came from: `"name"`, `"values"`,
    /// `"canonical"`, or `"default"`. Empty when no suggestion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion_source: Option<String>,
}

/// User's decision for a single field.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FieldMapping {
    /// Original field name.
    pub raw_name: String,
    /// Desired role.
    pub role: FieldRole,
    /// Entity type to use when role is Node.
    pub entity_type: Option<String>,
    /// Optional chrono format string used when this field carries the event
    /// timestamp and the built-in auto-detection fails (e.g. `"%b %d, %Y, %I:%M %p"`
    /// for Zoho's `"abr 19, 2026, 9:29 AM"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_format: Option<String>,
    /// Optional locale tag (e.g. `"es"`, `"en"`) applied before format parsing
    /// to translate localized month names into English. Only relevant when
    /// `timestamp_format` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
}

/// Collection of user field mappings for configurable ingestion.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FieldConfig {
    pub mappings: Vec<FieldMapping>,
}

/// Scans sample events and returns metadata about each discovered field.
pub fn preview_fields(data: &str, sample_size: usize) -> Vec<FieldInfo> {
    let events = GenericParser::parse_events_limited(data, sample_size);
    preview_fields_from_events(&events)
}

/// M6: pluggable role classifier. The default heuristic (canonical
/// target → Node, else Metadata) handles 80% of fields that the
/// built-in catalog already knows about. For everything else,
/// implementors can vote with a confidence score; the preview pipeline
/// adopts the vote when the heuristic has no opinion (i.e. the field
/// has no canonical target) AND the vote's confidence clears
/// [`CLASSIFIER_MIN_CONFIDENCE`].
///
/// The trait stays in `graph_hunter_core` so adapters in
/// `graph_hunter_api` can plug in a `MappingLibraryClassifier` without
/// the core having to depend on the api layer. A reference
/// implementation that votes from approved
/// [`crate::mapping_library::MappingLibraryStore`] entries lives in
/// [`crate::mapping_library::library_classifier`].
pub trait FieldRoleClassifier: Send + Sync {
    fn classify(&self, raw_name: &str, sample_values: &[String]) -> Option<ClassifierVote>;
}

/// One classifier vote. `confidence` is `[0.0, 1.0]`; the preview
/// pipeline currently treats anything below
/// [`CLASSIFIER_MIN_CONFIDENCE`] as "no opinion".
#[derive(Debug, Clone)]
pub struct ClassifierVote {
    pub role: FieldRole,
    pub entity_type: Option<String>,
    pub confidence: f32,
}

/// Heuristic still wins in the canonical-known case. The classifier
/// only overrides when the field name has no built-in canonical target
/// AND the classifier's confidence clears this bar. Set high on
/// purpose — a wobbly classifier should not be silently rewriting the
/// preview that the analyst hand-tunes.
pub const CLASSIFIER_MIN_CONFIDENCE: f32 = 0.6;

/// Same as `preview_fields` but starts from already-parsed events. Useful for
/// source-specific adapters (e.g. CSV → row-object conversion) that need to
/// share the sample-stats + role-inference logic.
pub fn preview_fields_from_events(events: &[Value]) -> Vec<FieldInfo> {
    preview_fields_from_events_with_classifier(events, None)
}

/// Same as [`preview_fields_from_events`] but lets the caller plug in a
/// [`FieldRoleClassifier`] that votes on fields the heuristic doesn't
/// recognize. Pass `None` to keep the legacy heuristic-only behavior.
pub fn preview_fields_from_events_with_classifier(
    events: &[Value],
    classifier: Option<&dyn FieldRoleClassifier>,
) -> Vec<FieldInfo> {
    if events.is_empty() {
        return Vec::new();
    }

    // Track per-field: occurrence count, sample values
    let mut field_stats: HashMap<String, (usize, HashSet<String>)> = HashMap::new();

    for event in events {
        if let Some(obj) = event.as_object() {
            for (key, value) in obj {
                let val_str = match value.as_str() {
                    Some(s) if !s.is_empty() => Some(s.to_string()),
                    _ => match value {
                        Value::Number(n) => Some(n.to_string()),
                        Value::Bool(b) => Some(b.to_string()),
                        _ => None,
                    },
                };

                if let Some(v) = val_str {
                    let entry = field_stats
                        .entry(key.clone())
                        .or_insert_with(|| (0, HashSet::new()));
                    entry.0 += 1;
                    if entry.1.len() < 5 {
                        entry.1.insert(v);
                    }
                }
            }
        }
    }

    let mut fields: Vec<FieldInfo> = field_stats
        .into_iter()
        .map(|(raw_name, (count, samples))| {
            let canonical = GenericParser::canonical_field(&raw_name).map(|s| s.to_string());
            // Canonical-but-Skip fields (timestamp, action, outcome, severity,
            // message, command_line, ports, protocol) must default to Metadata.
            // If they land as Node, the UI suggests promotion, which either
            // (a) creates one entity per unique value (timestamp/action string
            // explosion) or (b) pushes the analyst to pick Ignore, which then
            // strips the field and kills `GenericParser::normalize`'s ability
            // to recover the event timestamp.
            let mut current_role = match canonical.as_deref() {
                Some(c) if GenericParser::canonical_to_entity_type(c) == "Skip" => {
                    FieldRole::Metadata
                }
                Some(_) => FieldRole::Node,
                None => FieldRole::Metadata,
            };
            let sample_values: Vec<String> = samples.into_iter().collect();
            let suggestion = suggest_entity_type_with_source(&raw_name, &sample_values);
            let (mut suggested_entity_type, mut suggestion_source) = match suggestion {
                Some(s) => {
                    let src = match s.source {
                        SuggestionSource::Name => "name",
                        SuggestionSource::Values => "values",
                    };
                    (Some(format!("{}", s.entity_type)), Some(src.to_string()))
                }
                None => (None, None),
            };

            // Classifier override: only fires when there is no canonical
            // target AND the vote clears the confidence bar. The
            // canonical/heuristic path always wins on known names;
            // this only fills in opinion for unknown fields.
            if canonical.is_none() {
                if let Some(c) = classifier {
                    if let Some(vote) = c.classify(&raw_name, &sample_values) {
                        if vote.confidence >= CLASSIFIER_MIN_CONFIDENCE {
                            current_role = vote.role.clone();
                            if let Some(et) = vote.entity_type {
                                suggested_entity_type = Some(et);
                                suggestion_source = Some("classifier".to_string());
                            }
                        }
                    }
                }
            }

            FieldInfo {
                raw_name,
                canonical_target: canonical,
                occurrence_count: count,
                sample_values,
                current_role,
                suggested_entity_type,
                suggestion_source,
            }
        })
        .collect();

    // Sort: Node fields first, then Metadata, then by name
    fields.sort_by(|a, b| {
        let role_ord = |r: &FieldRole| -> u8 {
            match r {
                FieldRole::Node => 0,
                FieldRole::Metadata => 1,
                FieldRole::Ignore => 2,
            }
        };
        role_ord(&a.current_role)
            .cmp(&role_ord(&b.current_role))
            .then(a.raw_name.cmp(&b.raw_name))
    });

    fields
}

/// Source of a field-type suggestion — lets the UI show *why* we
/// guessed what we guessed (name heuristic vs. value regex).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SuggestionSource {
    /// Matched by column-name keyword heuristic.
    Name,
    /// Matched by value regex (sample_values content).
    Values,
}

/// Result of a suggestion: entity type + where it came from.
#[derive(Clone, Debug)]
pub struct Suggestion {
    pub entity_type: EntityType,
    pub source: SuggestionSource,
}

/// Heuristic: suggest an entity type based on field name patterns and sample values.
///
/// Falls back through two tiers:
///   1. Column-name keyword match (the English heuristic from earlier releases).
///   2. Value-regex inference over `sample_values` — if ≥60% of non-empty
///      samples match a canonical pattern (IPv4, IPv6, email, MD5/SHA-1/
///      SHA-256, URL, domain), surface that type. Fires only when the name
///      heuristic is silent, so explicit column names always win.
pub fn suggest_entity_type(field_name: &str, sample_values: &[String]) -> Option<EntityType> {
    suggest_entity_type_with_source(field_name, sample_values).map(|s| s.entity_type)
}

/// Same as [`suggest_entity_type`] but also reports whether the suggestion
/// came from the column name or from sample values. Preferred by callers
/// that want to surface the reasoning in the UI.
pub fn suggest_entity_type_with_source(
    field_name: &str,
    sample_values: &[String],
) -> Option<Suggestion> {
    if let Some(et) = suggest_by_name(field_name) {
        return Some(Suggestion {
            entity_type: et,
            source: SuggestionSource::Name,
        });
    }
    if let Some(et) = suggest_by_values(sample_values) {
        return Some(Suggestion {
            entity_type: et,
            source: SuggestionSource::Values,
        });
    }
    // Low-cardinality columns (few distinct values across many rows) are
    // almost always status / severity / outcome / action labels — promoting
    // them to nodes creates one singleton per unique string and no edges.
    // Return None so `preview_fields_from_events` defaults the role to
    // Metadata instead of suggesting a node type the UI will eagerly accept.
    if looks_like_categorical_label(sample_values) {
        return None;
    }
    None
}

/// True when the sample set looks like a categorical label column (INFO,
/// severity, outcome): at least 5 total samples with ≤4 distinct values,
/// OR a distinct/total ratio ≤ 0.25. Used by `suggest_entity_type_with_source`
/// to *suppress* a node-type suggestion so the UI doesn't push the analyst
/// to promote it.
fn looks_like_categorical_label(samples: &[String]) -> bool {
    let non_empty: Vec<&str> = samples
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if non_empty.len() < 5 {
        return false;
    }
    let mut seen = HashSet::new();
    for v in &non_empty {
        seen.insert(v.to_ascii_lowercase());
    }
    let distinct = seen.len();
    // Hard cap: ≤4 distinct labels is clearly categorical.
    if distinct <= 4 {
        return true;
    }
    // Soft ratio: distinct/total ≤ 0.25 also qualifies (e.g. 5 labels across
    // 30 rows).
    (distinct as f32) / (non_empty.len() as f32) <= 0.25
}

fn suggest_by_name(field_name: &str) -> Option<EntityType> {
    let lower = field_name.to_lowercase();

    // IP-related
    if lower.contains("ip") || lower.contains("addr") || lower.contains("address") {
        return Some(EntityType::IP);
    }

    // Host-related
    if lower.contains("host")
        || lower.contains("computer")
        || lower.contains("machine")
        || lower.contains("device")
        || lower.contains("workstation")
    {
        return Some(EntityType::Host);
    }

    // User-related
    if lower.contains("user")
        || lower.contains("account")
        || lower.contains("actor")
        || lower.contains("principal")
        || lower.contains("caller")
    {
        return Some(EntityType::User);
    }

    // Process-related
    if lower.contains("process")
        || lower.contains("image")
        || lower.contains("exe")
        || lower.contains("pid")
        || lower.contains("cmdline")
        || lower.contains("commandline")
        || lower.contains("command")
    {
        return Some(EntityType::Process);
    }

    // File-related
    if lower.contains("file")
        || lower.contains("path")
        || lower.contains("folder")
        || lower.contains("filename")
    {
        return Some(EntityType::File);
    }

    // Domain-related
    if lower.contains("domain")
        || lower.contains("dns")
        || lower.contains("query")
        || lower.contains("fqdn")
    {
        return Some(EntityType::Domain);
    }

    // URL-related
    if lower.contains("url") || lower.contains("uri") {
        return Some(EntityType::URL);
    }

    // Registry-related
    if lower.contains("registry") || lower.contains("regkey") {
        return Some(EntityType::Registry);
    }

    // Port-related → treat as metadata about an IP/connection, suggest IP
    if lower.contains("port") {
        return Some(EntityType::IP);
    }

    // Service-related
    if lower.contains("service") {
        return Some(EntityType::Service);
    }

    // Hash-related (maps to Other("Hash") via parse_entity_type).
    if lower.contains("hash")
        || lower.contains("md5")
        || lower.contains("sha1")
        || lower.contains("sha256")
    {
        return Some(EntityType::Other("Hash".to_string()));
    }

    // Email → User (a mailbox identifies a principal).
    if lower.contains("email") || lower.contains("mail") {
        return Some(EntityType::User);
    }

    None
}

/// Classifies a single string value. Order matters — more specific
/// patterns (hashes, IPs) are tried before loose ones (domains).
fn classify_value(raw: &str) -> Option<EntityType> {
    let v = raw.trim();
    if v.is_empty() {
        return None;
    }
    // IPv4: 4 dot-separated octets each 0–255.
    if is_ipv4(v) || is_ipv6(v) {
        return Some(EntityType::IP);
    }
    // Hex hashes: MD5 (32), SHA-1 (40), SHA-256 (64).
    let hex_len = v.len();
    if (hex_len == 32 || hex_len == 40 || hex_len == 64) && v.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Some(EntityType::Other("Hash".to_string()));
    }
    // Email: local@host.tld — host must contain a dot.
    if let Some(at) = v.find('@') {
        let (local, rest) = v.split_at(at);
        let host = &rest[1..];
        if !local.is_empty()
            && host.contains('.')
            && !host.starts_with('.')
            && !host.ends_with('.')
            && !local.contains(' ')
            && !host.contains(' ')
        {
            return Some(EntityType::User);
        }
    }
    // URL: scheme://
    if v.starts_with("http://") || v.starts_with("https://") || v.starts_with("ftp://") {
        return Some(EntityType::URL);
    }
    // Domain-like: bare host with at least one dot and a TLD-ish tail.
    if is_domain(v) {
        return Some(EntityType::Domain);
    }
    None
}

fn is_ipv4(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty()
            && p.len() <= 3
            && p.chars().all(|c| c.is_ascii_digit())
            && p.parse::<u8>().is_ok()
    })
}

fn is_ipv6(v: &str) -> bool {
    // Minimal IPv6 heuristic: at least two colons + only hex/colon chars.
    // Rejects plain numbers and URLs.
    let colons = v.chars().filter(|c| *c == ':').count();
    if colons < 2 {
        return false;
    }
    v.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
}

fn is_domain(v: &str) -> bool {
    if v.len() > 253 || v.contains(' ') || v.contains('/') || v.contains('@') {
        return false;
    }
    let labels: Vec<&str> = v.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    // All labels non-empty, alphanumeric + hyphen.
    if !labels.iter().all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    }) {
        return false;
    }
    // TLD must be all-alphabetic and ≥2 chars (rules out "1.2.3.4" already
    // caught by is_ipv4 but double-safe for "10.0.0.5").
    let tld = labels.last().copied().unwrap_or("");
    tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
}

/// Returns the most-common classified type across `samples`, if at least
/// 60% of non-empty samples agree. Ties (e.g. 50/50) return None.
fn suggest_by_values(samples: &[String]) -> Option<EntityType> {
    if samples.is_empty() {
        return None;
    }
    let mut counts: HashMap<EntityType, usize> = HashMap::new();
    let mut non_empty = 0usize;
    for s in samples {
        if s.trim().is_empty() {
            continue;
        }
        non_empty += 1;
        if let Some(et) = classify_value(s) {
            *counts.entry(et).or_insert(0) += 1;
        }
    }
    if non_empty == 0 {
        return None;
    }
    let (best, n) = counts.into_iter().max_by_key(|(_, n)| *n)?;
    // Require a clear majority so two stray IPs in a 10-row sample
    // don't mislabel a `description` column.
    if n * 5 >= non_empty * 3 {
        Some(best)
    } else {
        None
    }
}

/// Infers the relation type to use when connecting a promoted field entity to
/// its context anchor.
fn infer_relation_type(entity_type: &EntityType) -> RelationType {
    match entity_type {
        EntityType::File => RelationType::Write,
        EntityType::Domain => RelationType::DNS,
        EntityType::IP => RelationType::Connect,
        EntityType::URL => RelationType::Connect,
        EntityType::Registry => RelationType::Modify,
        EntityType::Process => RelationType::Execute,
        EntityType::User => RelationType::Auth,
        EntityType::Host => RelationType::Connect,
        EntityType::Service => RelationType::Connect,
        EntityType::Any | EntityType::Other(_) => RelationType::Connect,
    }
}

/// Maps a free-text action/event-type string to a relation type when the
/// match is unambiguous. Returns `None` for unknown actions so callers fall
/// back to the entity-type-driven default.
///
/// Substring matching is intentionally loose because audit-log action
/// fields vary widely: `"User.Login"`, `"file_downloaded"`,
/// `"UPLOAD_SUCCESS"`, `"DeleteItem"`. Order matters — more-specific tokens
/// (`delete`, `upload`) are checked before less-specific ones
/// (`write`, `read`) to avoid wrong labels on compound strings.
pub fn infer_relation_from_action(action: &str) -> Option<RelationType> {
    let a = action.to_lowercase();
    if a.is_empty() {
        return None;
    }
    // Delete / remove — very specific, always wins.
    if a.contains("delete") || a.contains("remove") || a.contains("drop") {
        return Some(RelationType::Delete);
    }
    // Auth / login / logon.
    if a.contains("login")
        || a.contains("logon")
        || a.contains("sign_in")
        || a.contains("signin")
        || a.contains("auth")
    {
        return Some(RelationType::Auth);
    }
    // Spawn (process-specific; keep before generic "run"/"exec").
    if a.contains("spawn") || a.contains("fork") {
        return Some(RelationType::Spawn);
    }
    // Execute / run / launch.
    if a.contains("execute")
        || a.contains("exec")
        || a.contains("run")
        || a.contains("launch")
        || a.contains("invoke")
    {
        return Some(RelationType::Execute);
    }
    // DNS-specific lookups.
    if a.contains("dns") || a.contains("resolve") || a.contains("query") {
        return Some(RelationType::DNS);
    }
    // Write / upload / create / modify / update.
    if a.contains("upload")
        || a.contains("write")
        || a.contains("create")
        || a.contains("modify")
        || a.contains("update")
        || a.contains("edit")
        || a.contains("add")
        || a.contains("put")
        || a.contains("post")
    {
        return Some(RelationType::Write);
    }
    // Read / download / get / view / open.
    if a.contains("download")
        || a.contains("read")
        || a.contains("view")
        || a.contains("open")
        || a.contains("access")
        || a.contains("fetch")
        || a.contains("get_")
    {
        return Some(RelationType::Read);
    }
    // Connect / open-socket / network.
    if a.contains("connect") || a.contains("tcp") || a.contains("udp") {
        return Some(RelationType::Connect);
    }
    None
}

/// Parses entity type from string (mirrors Tauri's parse_entity_type).
fn parse_entity_type(s: &str) -> Option<EntityType> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    match t {
        "IP" => Some(EntityType::IP),
        "Host" => Some(EntityType::Host),
        "User" => Some(EntityType::User),
        "Process" => Some(EntityType::Process),
        "File" => Some(EntityType::File),
        "Domain" => Some(EntityType::Domain),
        "Registry" => Some(EntityType::Registry),
        "URL" => Some(EntityType::URL),
        "Service" => Some(EntityType::Service),
        "*" | "Any" => Some(EntityType::Any),
        _ => Some(EntityType::Other(t.to_string())),
    }
}

/// A parser that applies user-defined field configuration.
///
/// First runs GenericParser normalization to get standard triples,
/// then applies user overrides: promotes "Node" fields to entities,
/// attaches "Metadata" fields to the context anchor, and ignores "Ignore" fields.
pub struct ConfigurableParser {
    config: FieldConfig,
}

impl ConfigurableParser {
    pub fn new(config: FieldConfig) -> Self {
        Self { config }
    }

    /// Finds the best context anchor from a normalized event.
    ///
    /// Priority walks source-side first (process → user → host → source_ip),
    /// then falls back to target-side fields for exports where only the
    /// target survived (DNS, proxy, DLP). Target fallbacks cover user, host,
    /// ip, domain, and file. Returning an anchor from the target side lets
    /// user-promoted nodes still attach somewhere instead of dropping the
    /// row as "no_anchor".
    fn find_context_anchor(n: &crate::generic::NormalizedEvent) -> Option<(String, EntityType)> {
        if let Some(ref p) = n.source_process {
            return Some((p.clone(), EntityType::Process));
        }
        if let Some(ref u) = n.source_user {
            return Some((u.clone(), EntityType::User));
        }
        if let Some(ref h) = n.source_host {
            return Some((h.clone(), EntityType::Host));
        }
        if let Some(ref ip) = n.source_ip {
            return Some((ip.clone(), EntityType::IP));
        }
        if let Some(ref ip) = n.target_ip {
            return Some((ip.clone(), EntityType::IP));
        }
        if let Some(ref u) = n.target_user {
            return Some((u.clone(), EntityType::User));
        }
        if let Some(ref d) = n.target_domain {
            return Some((d.clone(), EntityType::Domain));
        }
        if let Some(ref f) = n.target_file {
            return Some((f.clone(), EntityType::File));
        }
        None
    }

    /// Pre-processes the event before `GenericParser::parse_event` sees it:
    ///
    /// 1. For mappings with a `timestamp_format` hint, rewrites the matching
    ///    raw field to an ISO-8601 string so downstream timestamp logic picks
    ///    it up natively.
    /// 2. For `FieldRole::Ignore` mappings, strips the field from the event
    ///    entirely — required because the default canonical handler would
    ///    otherwise still pick up the field even when the user asked to skip
    ///    it (e.g. user says "don't treat EVENT_BY as a user" but the
    ///    canonical alias table maps `event_by → source_user`).
    /// 3. For `FieldRole::Node` mappings on fields that are *also* in the
    ///    canonical alias table, strips the field so `parse_event` doesn't
    ///    run its default interpretation. The outer override loop then
    ///    promotes the field with the user's chosen entity_type. This is
    ///    how "remap EVENT_BY to Host instead of User" actually takes effect.
    ///
    /// Returns the (possibly identical) event when no mappings apply.
    fn apply_timestamp_hints(&self, event: &Value) -> Value {
        let has_work = self.config.mappings.iter().any(|m| {
            m.timestamp_format.is_some()
                || matches!(m.role, FieldRole::Ignore)
                || matches!(m.role, FieldRole::Node)
        });
        if has_work == false {
            return event.clone();
        }
        let mut obj = match event.as_object() {
            Some(o) => o.clone(),
            None => return event.clone(),
        };

        // 1. Timestamp rewrites.
        for m in self.config.mappings.iter() {
            let fmt = match m.timestamp_format.as_deref() {
                Some(f) => f,
                None => continue,
            };
            let raw = match obj.get(&m.raw_name).and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            if let Some(epoch) =
                GenericParser::parse_timestamp_with_hint(&raw, fmt, m.locale.as_deref())
            {
                if let Some(dt) = chrono::DateTime::from_timestamp(epoch, 0) {
                    obj.insert(
                        m.raw_name.clone(),
                        Value::String(dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
                    );
                }
            }
        }

        // 2+3. Strip fields the user overrode in a way that actually differs
        //      from the canonical default. Rationale: when the preview UI
        //      proposes `EVENT_BY → User` and the user accepts (i.e. the
        //      mapping entity_type matches what the canonical alias table
        //      would have inferred), stripping would break anchor detection
        //      — `source_user` would vanish, no anchor would resolve, and
        //      the user-override Node promotion loop produces zero triples
        //      because it requires an anchor. We only intervene when the
        //      user genuinely diverges from canonical behavior.
        for m in self.config.mappings.iter() {
            match m.role {
                FieldRole::Ignore => {
                    // Ignore is an explicit opt-out; always strip.
                    obj.remove(&m.raw_name);
                }
                FieldRole::Node => {
                    let canonical = GenericParser::canonical_field(&m.raw_name);
                    let canonical_default = canonical
                        .map(GenericParser::canonical_to_entity_type)
                        .unwrap_or("Skip");
                    let user_choice = m.entity_type.as_deref().unwrap_or("");
                    let matches_default =
                        !user_choice.is_empty() && user_choice == canonical_default;
                    // Only strip when:
                    //   a) the field is canonical (otherwise canonical
                    //      inference never claims it, stripping is moot), and
                    //   b) the user's entity_type actually differs from the
                    //      canonical default (otherwise we'd regress the
                    //      accept-the-suggestion happy path).
                    if canonical.is_some() && !matches_default {
                        obj.remove(&m.raw_name);
                    }
                }
                FieldRole::Metadata => {
                    // Metadata role is advisory; leave the field in place so
                    // canonical inference still fires.
                }
            }
        }

        Value::Object(obj)
    }

    /// Processes a single event with user field config applied.
    fn parse_event_with_config(&self, event: &Value) -> Vec<ParsedTriple> {
        // Apply any user-supplied timestamp-format hints + strip fields the
        // user has explicitly overridden so canonical inference doesn't claim
        // them first.
        let event_owned = self.apply_timestamp_hints(event);
        let stripped = &event_owned;

        // Canonical triples come from the STRIPPED event — this is where
        // Ignore/Node overrides actually take effect.
        let mut triples = GenericParser::parse_event(stripped);

        // But for the user-override loop below, iterate the ORIGINAL event's
        // keys. Otherwise fields we just stripped would be invisible to their
        // own overrides and no Node promotion would ever run.
        let obj = match event.as_object() {
            Some(o) => o,
            None => return triples,
        };

        // Build lookup of user overrides by raw field name
        let overrides: HashMap<&str, &FieldMapping> = self
            .config
            .mappings
            .iter()
            .map(|m| (m.raw_name.as_str(), m))
            .collect();

        // Anchor detection uses the stripped event — a field the user
        // explicitly overrode should NOT serve as anchor via its canonical
        // interpretation.
        let normalized = GenericParser::normalize(stripped);
        let anchor = Self::find_context_anchor(&normalized);

        // Action-aware relation override: if the event carries a canonical
        // `action` field (English: action/operation/event_type, also the
        // multilingual aliases accion/acción/ação/action), use it to pick
        // the rel_type for user-promoted nodes instead of the static
        // entity→relation table. Computed once per event.
        let action_rel: Option<RelationType> = obj.iter().find_map(|(k, v)| {
            if GenericParser::canonical_field(k) == Some("action") {
                v.as_str().and_then(infer_relation_from_action)
            } else {
                None
            }
        });

        for (key, value) in obj {
            // Skip canonical fields in the override loop unless the user is
            // genuinely diverging from the canonical default. Two cases:
            //   - no override → canonical processing already handled it
            //   - override matches canonical default → canonical processing
            //     already produced the right entity (e.g. "Joel Canepa":User);
            //     re-processing here would also create "EVENT_BY:Joel Canepa"
            //     as a duplicate User node tied to the same anchor.
            let user_override = overrides.get(key.as_str());
            if let Some(canonical) = GenericParser::canonical_field(key) {
                let canonical_default = GenericParser::canonical_to_entity_type(canonical);
                let override_matches_default = user_override
                    .and_then(|m| m.entity_type.as_deref())
                    .map(|et| et == canonical_default)
                    .unwrap_or(false);
                if user_override.is_none() || override_matches_default {
                    continue;
                }
            }

            let val_str = match value.as_str() {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => match value {
                    Value::Number(n) => n.to_string(),
                    _ => continue,
                },
            };

            if let Some(mapping) = user_override {
                match mapping.role {
                    FieldRole::Node => {
                        // Promote to entity node
                        let et = mapping
                            .entity_type
                            .as_deref()
                            .and_then(parse_entity_type)
                            .or_else(|| suggest_entity_type(key, &[val_str.clone()]))
                            .unwrap_or(EntityType::Process);

                        // Entity ID prefixed with field name to avoid collisions
                        let entity_id = format!("{}:{}", key, val_str);
                        let dst = Entity::new(&entity_id, et.clone())
                            .with_metadata("raw_field", key)
                            .with_metadata("raw_value", &val_str);

                        if let Some((ref anchor_id, ref anchor_type)) = anchor {
                            let rel_type = action_rel
                                .clone()
                                .unwrap_or_else(|| infer_relation_type(&et));
                            let src = Entity::new(anchor_id, anchor_type.clone());
                            let rel = Relation::new(
                                anchor_id,
                                &entity_id,
                                rel_type,
                                normalized.timestamp,
                            );
                            triples.push((src, rel, dst));
                        }
                    }
                    FieldRole::Ignore => {
                        // Do nothing
                    }
                    FieldRole::Metadata => {
                        // Metadata fields are already handled by GenericParser's
                        // entity metadata or simply not extracted. No extra action needed
                        // since we can't easily attach arbitrary metadata to existing
                        // triples after the fact. The field remains in the JSON source.
                    }
                }
            }
        }

        triples
    }
}

impl ConfigurableParser {
    /// Produces the list of events this parser would operate on, using the
    /// same JSON-first, CSV-fallback logic as `parse()`.
    fn collect_events(data: &str) -> Vec<Value> {
        let mut events = GenericParser::parse_events(data);
        if events.is_empty() {
            events = crate::csv_parser::CsvParser::sample_events(data, usize::MAX);
        }
        events
    }
}

impl LogParser for ConfigurableParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        let events = Self::collect_events(data);
        if events.is_empty() {
            return Vec::new();
        }

        events
            .par_iter()
            .flat_map(|event| self.parse_event_with_config(event))
            .collect()
    }

    fn parse_with_stats(&self, data: &str) -> (Vec<ParsedTriple>, crate::parser::ParseStats) {
        let events = Self::collect_events(data);
        crate::generic::parse_events_with_stats(&events, |event| {
            self.parse_event_with_config(event)
        })
    }
}
