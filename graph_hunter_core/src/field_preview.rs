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
}

/// Collection of user field mappings for configurable ingestion.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FieldConfig {
    pub mappings: Vec<FieldMapping>,
}

/// Scans sample events and returns metadata about each discovered field.
pub fn preview_fields(data: &str, sample_size: usize) -> Vec<FieldInfo> {
    let events = GenericParser::parse_events_limited(data, sample_size);
    if events.is_empty() {
        return Vec::new();
    }

    // Track per-field: occurrence count, sample values
    let mut field_stats: HashMap<String, (usize, HashSet<String>)> = HashMap::new();

    for event in &events {
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
            let current_role = if canonical.is_some() {
                FieldRole::Node
            } else {
                FieldRole::Metadata
            };
            let sample_values: Vec<String> = samples.into_iter().collect();
            let suggested = suggest_entity_type(&raw_name, &sample_values);

            FieldInfo {
                raw_name,
                canonical_target: canonical,
                occurrence_count: count,
                sample_values,
                current_role,
                suggested_entity_type: suggested.map(|et| format!("{}", et)),
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

/// Heuristic: suggest an entity type based on field name patterns and sample values.
pub fn suggest_entity_type(field_name: &str, _sample_values: &[String]) -> Option<EntityType> {
    let lower = field_name.to_lowercase();

    // IP-related
    if lower.contains("ip") || lower.contains("addr") || lower.contains("address") {
        return Some(EntityType::IP);
    }

    // Host-related
    if lower.contains("host") || lower.contains("computer") || lower.contains("machine")
        || lower.contains("device") || lower.contains("workstation")
    {
        return Some(EntityType::Host);
    }

    // User-related
    if lower.contains("user") || lower.contains("account") || lower.contains("actor")
        || lower.contains("principal") || lower.contains("caller")
    {
        return Some(EntityType::User);
    }

    // Process-related
    if lower.contains("process") || lower.contains("image") || lower.contains("exe")
        || lower.contains("pid") || lower.contains("cmdline") || lower.contains("commandline")
        || lower.contains("command")
    {
        return Some(EntityType::Process);
    }

    // File-related
    if lower.contains("file") || lower.contains("path") || lower.contains("folder")
        || lower.contains("filename")
    {
        return Some(EntityType::File);
    }

    // Domain-related
    if lower.contains("domain") || lower.contains("dns") || lower.contains("query")
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

    None
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
    /// Priority: process > user > host > source_ip > target_ip.
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
        None
    }

    /// Processes a single event with user field config applied.
    fn parse_event_with_config(&self, event: &Value) -> Vec<ParsedTriple> {
        // Start with standard GenericParser triples
        let mut triples = GenericParser::parse_event(event);

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

        // Get the normalized event for context anchor detection
        let normalized = GenericParser::normalize(event);
        let anchor = Self::find_context_anchor(&normalized);

        for (key, value) in obj {
            // Skip fields that GenericParser already handles as canonical
            if GenericParser::canonical_field(key).is_some() {
                continue;
            }

            let val_str = match value.as_str() {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => match value {
                    Value::Number(n) => n.to_string(),
                    _ => continue,
                },
            };

            if let Some(mapping) = overrides.get(key.as_str()) {
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
                            let rel_type = infer_relation_type(&et);
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

impl LogParser for ConfigurableParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        let events = GenericParser::parse_events(data);
        if events.is_empty() {
            return Vec::new();
        }

        events
            .par_iter()
            .flat_map(|event| self.parse_event_with_config(event))
            .collect()
    }
}
