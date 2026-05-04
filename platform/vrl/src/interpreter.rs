//! Minimal in-process interpreter for the subset of VRL that
//! [`crate::compiler::field_config_to_vrl`] emits today.
//!
//! Why not embed the upstream `vrl` crate directly? Because doing so
//! pulls in 5+ MB of binary and a transitive dep tree we want gated
//! behind a `vrl-runtime` feature. The wedge proposition for M3 is
//! "FieldConfig compiles to VRL deterministically and the resulting
//! pipeline is observably equivalent to the legacy parser path." We
//! can validate that proposition without paying for the full runtime.
//!
//! This interpreter does not parse the textual VRL source. It walks the
//! same `FieldConfig` the compiler walked. The textual program is the
//! audit artifact; this is the executable. They evolve together.

use graph_hunter_core::field_preview::{FieldConfig, FieldMapping, FieldRole};
use serde_json::{Map, Value};

#[derive(Debug)]
pub enum InterpretError {
    NotAnObject,
}

impl std::fmt::Display for InterpretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterpretError::NotAnObject => write!(f, "input event was not a JSON object"),
        }
    }
}

impl std::error::Error for InterpretError {}

/// Run the compiled program (represented by its source FieldConfig)
/// against one event.
///
/// Returns the canonical block the compiled VRL program would have
/// produced: an object with `entities[]`, `metadata{}`, `timestamp`.
pub fn run_program(cfg: &FieldConfig, event: &Value) -> Result<Value, InterpretError> {
    let obj = event.as_object().ok_or(InterpretError::NotAnObject)?;

    let mut entities: Vec<Value> = Vec::new();
    let mut metadata = Map::new();
    let mut timestamp: Value = Value::Null;

    let mut sorted: Vec<&FieldMapping> = cfg.mappings.iter().collect();
    sorted.sort_by(|a, b| a.raw_name.cmp(&b.raw_name));

    for m in sorted {
        let Some(v) = obj.get(&m.raw_name) else {
            continue;
        };
        if v.is_null() {
            continue;
        }
        match m.role {
            FieldRole::Ignore => {}
            FieldRole::Metadata => {
                metadata.insert(m.raw_name.clone(), v.clone());
            }
            FieldRole::Node => {
                let val_str = stringify(v);
                if val_str.is_empty() {
                    continue;
                }
                let et = m.entity_type.as_deref().unwrap_or("Unknown");
                let mut e = Map::new();
                e.insert("type".to_string(), Value::String(et.to_string()));
                e.insert("value".to_string(), Value::String(val_str));
                e.insert("raw".to_string(), Value::String(m.raw_name.clone()));
                entities.push(Value::Object(e));

                // Timestamp pickup: if a Node carries a `timestamp_format`,
                // mirror the compiler and try to surface a parsed timestamp.
                // We do *not* attempt locale translation here — that is
                // the runtime's job in production. The interpreter just
                // reports the raw value so downstream code can decide.
                if m.timestamp_format.is_some() && timestamp.is_null() {
                    timestamp = v.clone();
                }
            }
        }
    }

    let mut canonical = Map::new();
    canonical.insert("entities".to_string(), Value::Array(entities));
    canonical.insert("metadata".to_string(), Value::Object(metadata));
    canonical.insert("timestamp".to_string(), timestamp);
    Ok(Value::Object(canonical))
}

fn stringify(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        _ => v.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg() -> FieldConfig {
        FieldConfig {
            mappings: vec![
                FieldMapping {
                    raw_name: "User".into(),
                    role: FieldRole::Node,
                    entity_type: Some("User".into()),
                    timestamp_format: None,
                    locale: None,
                },
                FieldMapping {
                    raw_name: "Image".into(),
                    role: FieldRole::Node,
                    entity_type: Some("Process".into()),
                    timestamp_format: None,
                    locale: None,
                },
                FieldMapping {
                    raw_name: "Internal".into(),
                    role: FieldRole::Metadata,
                    entity_type: None,
                    timestamp_format: None,
                    locale: None,
                },
            ],
        }
    }

    #[test]
    fn produces_entities_in_sorted_order() {
        let out = run_program(
            &cfg(),
            &json!({"User": "alice", "Image": "/usr/bin/foo", "Internal": "x"}),
        )
        .unwrap();
        let ents = out["entities"].as_array().unwrap();
        assert_eq!(ents.len(), 2);
        // Sorted alphabetically by raw_name → Image first, then User.
        assert_eq!(ents[0]["raw"], "Image");
        assert_eq!(ents[0]["type"], "Process");
        assert_eq!(ents[1]["raw"], "User");
        assert_eq!(ents[1]["type"], "User");
        assert_eq!(out["metadata"]["Internal"], "x");
    }

    #[test]
    fn missing_fields_are_skipped() {
        let out = run_program(&cfg(), &json!({"User": "alice"})).unwrap();
        assert_eq!(out["entities"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn null_values_are_skipped() {
        let out = run_program(&cfg(), &json!({"User": null, "Image": "/foo"})).unwrap();
        assert_eq!(out["entities"].as_array().unwrap().len(), 1);
        assert_eq!(out["entities"][0]["raw"], "Image");
    }

    #[test]
    fn rejects_non_objects() {
        assert!(matches!(
            run_program(&cfg(), &json!([1, 2, 3])),
            Err(InterpretError::NotAnObject)
        ));
    }
}
