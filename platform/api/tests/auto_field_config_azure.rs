//! Regression tests for the Azure portal Activity Log CSV ("Download as
//! CSV" on a subscription's Activity log), which ingested as zero entities
//! and zero relations with no error.
//!
//! Two causes. The actor column is named "Event initiated by" — the portal's
//! label for `caller` — which matched no canonical alias, so the event had no
//! anchor and no promoted column could be linked to anything. And the name
//! heuristic's `contains("ip")` matched "Subscription", mapping the
//! subscription GUID to an IP node.

use graph_hunter_api::operations::ingestion::auto_field_config_for;
use graph_hunter_core::parser::LogParser;
use graph_hunter_core::{ConfigurableParser, EntityType, FieldRole};

/// Header + rows lifted from a real export (the subscription id and resource
/// paths anonymized, shape preserved). The last row has no initiator, as the
/// provider-emitted events in the real file do.
const AZURE_SAMPLE: &str = "\
\"Correlation id\",\"Operation name\",\"Status\",\"Event category\",\"Level\",\"Time\",\"Subscription\",\"Event initiated by\",\"Resource type\",\"Resource group\",\"Resource\"
\"d1d8bf4e-c217-4d7d-bf62-b5ae2b9c36a2\",\"Delete Virtual Machine\",\"Succeeded\",\"Administrative\",\"Informational\",\"2026-09-05T04:30:31.108Z\",\"00000000-1111-2222-3333-444444444444\",\"ana.perez@example.com\",\"microsoft.compute/virtualmachines\",\"rg_prod\",\"/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg_prod/providers/microsoft.compute/virtualMachines/vm-01\"
\"a1d8bf4e-c217-4d7d-bf62-b5ae2b9c36a3\",\"Create or Update Network Security Group\",\"Started\",\"Administrative\",\"Informational\",\"2026-09-05T04:31:02.000Z\",\"00000000-1111-2222-3333-444444444444\",\"juan.gomez@example.com\",\"microsoft.network/networksecuritygroups\",\"rg_net\",\"/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg_net/providers/microsoft.network/networkSecurityGroups/nsg-01\"
\"b1d8bf4e-c217-4d7d-bf62-b5ae2b9c36a4\",\"Validate Tagged Traffic Consumer\",\"Succeeded\",\"Administrative\",\"Informational\",\"2026-09-05T04:32:00.000Z\",\"00000000-1111-2222-3333-444444444444\",\"\",\"microsoft.network/virtualNetworks/taggedTrafficConsumers\",\"rg_net\",\"/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg_net/providers/microsoft.network/virtualNetworks/vnet/taggedTrafficConsumers/x\"
";

fn role(cfg: &graph_hunter_core::FieldConfig, raw: &str) -> FieldRole {
    cfg.mappings
        .iter()
        .find(|m| m.raw_name == raw)
        .unwrap_or_else(|| panic!("no mapping for {raw}"))
        .role
        .clone()
}

#[test]
fn subscription_guid_is_not_an_ip() {
    let cfg = auto_field_config_for("csv", AZURE_SAMPLE).expect("config");
    assert_eq!(role(&cfg, "Subscription"), FieldRole::Metadata);
}

#[test]
fn activity_log_links_initiator_to_resource() {
    let cfg = auto_field_config_for("csv", AZURE_SAMPLE).expect("config");
    let triples = ConfigurableParser::new(cfg).parse(AZURE_SAMPLE);
    let links = |user: &str, res: &str| {
        triples.iter().any(|(s, _, d)| {
            s.entity_type == EntityType::User && s.id == user && d.id.ends_with(res)
        })
    };
    assert!(links("ana.perez@example.com", "vm-01"), "{triples:#?}");
    assert!(links("juan.gomez@example.com", "nsg-01"), "{triples:#?}");
    assert!(
        triples
            .iter()
            .all(|(s, _, d)| s.entity_type != EntityType::IP && d.entity_type != EntityType::IP),
        "no IP entities: the file has no IP column"
    );
    // The operation drives the relation type (Delete Virtual Machine).
    assert!(
        triples
            .iter()
            .any(|(s, r, _)| s.id == "ana.perez@example.com"
                && r.rel_type == graph_hunter_core::RelationType::Delete)
    );
    // Event time is the `Time` column, not ingest time.
    assert!(triples.iter().all(|(_, r, _)| r.timestamp > 0));
}
