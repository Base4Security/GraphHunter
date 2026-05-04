//! M6.a smoke test: every program the deterministic VRL compiler emits
//! must validate under the subset grammar. If this fails the wedge
//! breaks — the compiler would be producing source the validator
//! refuses to accept, leaving `parser_generator` no way to ever return
//! a refinement.

use graph_hunter_constrained_decode::{GrammarValidator, VrlSubsetValidator};
use graph_hunter_core::field_preview::{FieldConfig, FieldMapping, FieldRole};
use graph_hunter_vrl::field_config_to_vrl;

fn cfg(rows: Vec<FieldMapping>) -> FieldConfig {
    FieldConfig { mappings: rows }
}

fn fm(name: &str, role: FieldRole, et: Option<&str>) -> FieldMapping {
    FieldMapping {
        raw_name: name.into(),
        role,
        entity_type: et.map(|s| s.into()),
        timestamp_format: None,
        locale: None,
    }
}

#[test]
fn empty_field_config_compiles_and_validates() {
    let v = VrlSubsetValidator::new();
    let p = field_config_to_vrl(&cfg(vec![]));
    v.validate(&p.source).unwrap();
}

#[test]
fn mixed_roles_compile_and_validate() {
    let v = VrlSubsetValidator::new();
    let p = field_config_to_vrl(&cfg(vec![
        fm("User", FieldRole::Node, Some("User")),
        fm("Image", FieldRole::Node, Some("Process")),
        fm("ParentImage", FieldRole::Node, Some("Process")),
        fm("CommandLine", FieldRole::Metadata, None),
        fm("Hashes", FieldRole::Metadata, None),
        fm("dropped_field", FieldRole::Ignore, None),
    ]));
    v.validate(&p.source)
        .unwrap_or_else(|e| panic!("compiler output failed validation: {e}\n\n{}", p.source));
}

#[test]
fn timestamp_with_locale_compiles_and_validates() {
    let v = VrlSubsetValidator::new();
    let p = field_config_to_vrl(&cfg(vec![FieldMapping {
        raw_name: "occurred_at".into(),
        role: FieldRole::Node,
        entity_type: Some("Time".into()),
        timestamp_format: Some("%b %d, %Y, %I:%M %p".into()),
        locale: Some("es".into()),
    }]));
    v.validate(&p.source).unwrap();
}

#[test]
fn dotted_field_names_compile_and_validate() {
    let v = VrlSubsetValidator::new();
    let p = field_config_to_vrl(&cfg(vec![
        fm("user.name", FieldRole::Node, Some("User")),
        fm("event.action", FieldRole::Metadata, None),
    ]));
    v.validate(&p.source).unwrap();
}
