//! Pure projection between `(Entity, Relation, Entity)` triples and
//! `OcsfEvent`. These functions are deterministic and total — every triple
//! maps to exactly one `OcsfEvent` (possibly `OcsfEvent::Other`) and every
//! typed `OcsfEvent` in the shipping subset round-trips at the id+type
//! level. Metadata flows one-way (triple → event); reverse rebuilds a
//! fresh entity/relation pair without the original metadata map, which is
//! fine for the audit trail (provenance lives on the event itself).

use graph_hunter_core::entity::Entity;
use graph_hunter_core::parser::ParsedTriple;
use graph_hunter_core::relation::Relation;
use graph_hunter_core::types::{EntityType, RelationType};

use crate::ocsf::{
    AuthenticationEvent, DnsActivityEvent, DnsQuery, EndpointRef, FileRef, FileSystemActivityEvent,
    NetworkActivityEvent, OcsfEvent, OtherEvent, ProcessActivityEvent, ProcessRef,
    RegistryKeyActivityEvent, RegistryKeyRef, UserRef, activity_id, class_uid,
};
use crate::provenance::ProvenanceCtx;

/// Projects a graph triple onto its canonical OCSF event. Shapes outside
/// the shipping subset fall into `OcsfEvent::Other` with a diagnostic
/// reason so the mapping audit can flag them.
pub fn triple_to_ocsf(
    source: &Entity,
    relation: &Relation,
    dest: &Entity,
    prov: &ProvenanceCtx,
) -> OcsfEvent {
    use EntityType::*;
    use RelationType::*;

    let time = relation.timestamp;
    let provenance = prov.clone();

    match (&source.entity_type, &relation.rel_type, &dest.entity_type) {
        (User, Auth, Host) | (User, Auth, IP) => OcsfEvent::Authentication(AuthenticationEvent {
            class_uid: class_uid::AUTHENTICATION,
            activity_id: activity_id::authentication::LOGON,
            time,
            actor_user: Some(user_ref(source)),
            dst_endpoint: Some(endpoint_ref(dest, None)),
            auth_protocol: relation.metadata.get("auth_protocol").cloned(),
            status: relation.metadata.get("status").cloned(),
            provenance,
        }),

        (User, Execute, Process) => OcsfEvent::ProcessActivity(ProcessActivityEvent {
            class_uid: class_uid::PROCESS_ACTIVITY,
            activity_id: activity_id::process_activity::LAUNCH,
            time,
            actor_user: Some(user_ref(source)),
            parent_process: None,
            process: process_ref(dest),
            provenance,
        }),

        (Process, Spawn, Process) => OcsfEvent::ProcessActivity(ProcessActivityEvent {
            class_uid: class_uid::PROCESS_ACTIVITY,
            activity_id: activity_id::process_activity::LAUNCH,
            time,
            actor_user: None,
            parent_process: Some(process_ref(source)),
            process: process_ref(dest),
            provenance,
        }),

        (IP, Connect, IP) | (Host, Connect, IP) | (IP, Connect, Host) => {
            OcsfEvent::NetworkActivity(NetworkActivityEvent {
                class_uid: class_uid::NETWORK_ACTIVITY,
                activity_id: activity_id::network_activity::OPEN,
                time,
                src_endpoint: Some(endpoint_ref(
                    source,
                    port_from(&relation.metadata, "source_port"),
                )),
                dst_endpoint: Some(endpoint_ref(
                    dest,
                    port_from(&relation.metadata, "dest_port"),
                )),
                protocol: relation.metadata.get("protocol").cloned(),
                provenance,
            })
        }

        (Host, DNS, Domain) => OcsfEvent::DnsActivity(DnsActivityEvent {
            class_uid: class_uid::DNS_ACTIVITY,
            activity_id: activity_id::dns_activity::QUERY,
            time,
            src_endpoint: Some(EndpointRef {
                ip: None,
                hostname: Some(source.id.clone()),
                port: None,
            }),
            query: DnsQuery {
                hostname: dest.id.clone(),
                qtype: relation.metadata.get("query_type").cloned(),
            },
            provenance,
        }),

        (Process, Read, File) => file_event(
            source,
            dest,
            time,
            activity_id::file_system_activity::READ,
            provenance,
        ),
        (Process, Write, File) => file_event(
            source,
            dest,
            time,
            activity_id::file_system_activity::CREATE,
            provenance,
        ),
        (Process, Modify, File) => file_event(
            source,
            dest,
            time,
            activity_id::file_system_activity::UPDATE,
            provenance,
        ),
        (Process, Delete, File) => file_event(
            source,
            dest,
            time,
            activity_id::file_system_activity::DELETE,
            provenance,
        ),

        (Process, Modify, Registry) => OcsfEvent::RegistryKeyActivity(RegistryKeyActivityEvent {
            class_uid: class_uid::REGISTRY_KEY_ACTIVITY,
            activity_id: activity_id::registry_key_activity::MODIFY,
            time,
            actor_process: Some(process_ref(source)),
            reg_key: RegistryKeyRef {
                path: dest.id.clone(),
                value: dest.metadata.get("value").cloned(),
            },
            provenance,
        }),

        _ => OcsfEvent::Other(OtherEvent {
            class_uid: class_uid::OTHER,
            time,
            rel_type: relation.rel_type.to_string(),
            source_type: source.entity_type.to_string(),
            source_id: source.id.clone(),
            dest_type: dest.entity_type.to_string(),
            dest_id: dest.id.clone(),
            reason: reason_for_other(source, relation, dest),
            provenance,
        }),
    }
}

/// Projects a canonical OCSF event back into a graph triple. Returns
/// `None` when the event lacks the observables required to rebuild both
/// endpoints (e.g. a `ProcessActivity` with neither `parent_process` nor
/// `actor_user`).
pub fn ocsf_to_triple(event: &OcsfEvent) -> Option<ParsedTriple> {
    match event {
        OcsfEvent::Authentication(e) => {
            let user = e.actor_user.as_ref()?;
            let ep = e.dst_endpoint.as_ref()?;
            let (dst_id, dst_type) = endpoint_identity(ep)?;
            let source = Entity::new(user.name.clone(), EntityType::User);
            let dest = Entity::new(dst_id.clone(), dst_type);
            let relation = Relation::new(user.name.clone(), dst_id, RelationType::Auth, e.time);
            Some((source, relation, dest))
        }

        OcsfEvent::ProcessActivity(e) => {
            if let Some(parent) = &e.parent_process {
                let source = Entity::new(parent.name.clone(), EntityType::Process);
                let dest = Entity::new(e.process.name.clone(), EntityType::Process);
                let relation = Relation::new(
                    parent.name.clone(),
                    e.process.name.clone(),
                    RelationType::Spawn,
                    e.time,
                );
                Some((source, relation, dest))
            } else if let Some(user) = &e.actor_user {
                let source = Entity::new(user.name.clone(), EntityType::User);
                let dest = Entity::new(e.process.name.clone(), EntityType::Process);
                let relation = Relation::new(
                    user.name.clone(),
                    e.process.name.clone(),
                    RelationType::Execute,
                    e.time,
                );
                Some((source, relation, dest))
            } else {
                None
            }
        }

        OcsfEvent::NetworkActivity(e) => {
            let src_ep = e.src_endpoint.as_ref()?;
            let dst_ep = e.dst_endpoint.as_ref()?;
            let (src_id, src_type) = endpoint_identity(src_ep)?;
            let (dst_id, dst_type) = endpoint_identity(dst_ep)?;
            let source = Entity::new(src_id.clone(), src_type);
            let dest = Entity::new(dst_id.clone(), dst_type);
            let relation = Relation::new(src_id, dst_id, RelationType::Connect, e.time);
            Some((source, relation, dest))
        }

        OcsfEvent::DnsActivity(e) => {
            let ep = e.src_endpoint.as_ref()?;
            let hostname = ep.hostname.as_ref()?;
            let source = Entity::new(hostname.clone(), EntityType::Host);
            let dest = Entity::new(e.query.hostname.clone(), EntityType::Domain);
            let relation = Relation::new(
                hostname.clone(),
                e.query.hostname.clone(),
                RelationType::DNS,
                e.time,
            );
            Some((source, relation, dest))
        }

        OcsfEvent::FileSystemActivity(e) => {
            let proc = e.actor_process.as_ref()?;
            let rel_type = match e.activity_id {
                activity_id::file_system_activity::READ => RelationType::Read,
                activity_id::file_system_activity::CREATE => RelationType::Write,
                activity_id::file_system_activity::UPDATE => RelationType::Modify,
                activity_id::file_system_activity::DELETE => RelationType::Delete,
                _ => return None,
            };
            let source = Entity::new(proc.name.clone(), EntityType::Process);
            let dest = Entity::new(e.file.path.clone(), EntityType::File);
            let relation = Relation::new(proc.name.clone(), e.file.path.clone(), rel_type, e.time);
            Some((source, relation, dest))
        }

        OcsfEvent::RegistryKeyActivity(e) => {
            let proc = e.actor_process.as_ref()?;
            let source = Entity::new(proc.name.clone(), EntityType::Process);
            let dest = Entity::new(e.reg_key.path.clone(), EntityType::Registry);
            let relation = Relation::new(
                proc.name.clone(),
                e.reg_key.path.clone(),
                RelationType::Modify,
                e.time,
            );
            Some((source, relation, dest))
        }

        OcsfEvent::Other(e) => {
            let src_type = parse_entity_type(&e.source_type);
            let dst_type = parse_entity_type(&e.dest_type);
            let rel_type = parse_relation_type(&e.rel_type);
            let source = Entity::new(e.source_id.clone(), src_type);
            let dest = Entity::new(e.dest_id.clone(), dst_type);
            let relation = Relation::new(e.source_id.clone(), e.dest_id.clone(), rel_type, e.time);
            Some((source, relation, dest))
        }
    }
}

// ─── helpers ───────────────────────────────────────────────────────────────

fn user_ref(e: &Entity) -> UserRef {
    UserRef {
        name: e.id.clone(),
        uid: e.metadata.get("uid").cloned(),
        domain: e.metadata.get("domain").cloned(),
    }
}

fn process_ref(e: &Entity) -> ProcessRef {
    ProcessRef {
        name: e.id.clone(),
        pid: e.metadata.get("pid").and_then(|s| s.parse().ok()),
        cmd_line: e.metadata.get("cmdline").cloned(),
        file: None,
    }
}

fn endpoint_ref(e: &Entity, port: Option<u16>) -> EndpointRef {
    match e.entity_type {
        EntityType::IP => EndpointRef {
            ip: Some(e.id.clone()),
            hostname: None,
            port,
        },
        _ => EndpointRef {
            ip: None,
            hostname: Some(e.id.clone()),
            port,
        },
    }
}

fn endpoint_identity(ep: &EndpointRef) -> Option<(String, EntityType)> {
    if let Some(ip) = &ep.ip {
        return Some((ip.clone(), EntityType::IP));
    }
    if let Some(host) = &ep.hostname {
        return Some((host.clone(), EntityType::Host));
    }
    None
}

fn port_from(meta: &std::collections::HashMap<String, String>, key: &str) -> Option<u16> {
    meta.get(key).and_then(|s| s.parse().ok())
}

fn file_event(
    source: &Entity,
    dest: &Entity,
    time: i64,
    aid: u32,
    prov: ProvenanceCtx,
) -> OcsfEvent {
    OcsfEvent::FileSystemActivity(FileSystemActivityEvent {
        class_uid: class_uid::FILE_SYSTEM_ACTIVITY,
        activity_id: aid,
        time,
        actor_process: Some(process_ref(source)),
        file: FileRef {
            path: dest.id.clone(),
            name: dest.metadata.get("name").cloned(),
            hashes: None,
        },
        provenance: prov,
    })
}

fn reason_for_other(source: &Entity, relation: &Relation, dest: &Entity) -> String {
    format!(
        "no_dedicated_class:{}-{}-{}",
        source.entity_type, relation.rel_type, dest.entity_type
    )
}

fn parse_entity_type(s: &str) -> EntityType {
    match s {
        "IP" => EntityType::IP,
        "Host" => EntityType::Host,
        "User" => EntityType::User,
        "Process" => EntityType::Process,
        "File" => EntityType::File,
        "Domain" => EntityType::Domain,
        "Registry" => EntityType::Registry,
        "URL" => EntityType::URL,
        "Service" => EntityType::Service,
        "*" => EntityType::Any,
        other => EntityType::Other(other.to_string()),
    }
}

fn parse_relation_type(s: &str) -> RelationType {
    match s {
        "Auth" => RelationType::Auth,
        "Connect" => RelationType::Connect,
        "Execute" => RelationType::Execute,
        "Read" => RelationType::Read,
        "Write" => RelationType::Write,
        "DNS" => RelationType::DNS,
        "Modify" => RelationType::Modify,
        "Spawn" => RelationType::Spawn,
        "Delete" => RelationType::Delete,
        "*" => RelationType::Any,
        other => RelationType::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prov() -> ProvenanceCtx {
        ProvenanceCtx::for_builtin_parser("sysmon", "ds-test", b"{}")
    }

    fn triple(src: Entity, rel: Relation, dst: Entity) -> (Entity, Relation, Entity) {
        (src, rel, dst)
    }

    fn assert_round_trip(input: (Entity, Relation, Entity)) {
        let ev = triple_to_ocsf(&input.0, &input.1, &input.2, &prov());
        let back = ocsf_to_triple(&ev).expect("must round-trip");
        assert_eq!(back.0.id, input.0.id);
        assert_eq!(back.0.entity_type, input.0.entity_type);
        assert_eq!(back.2.id, input.2.id);
        assert_eq!(back.2.entity_type, input.2.entity_type);
        assert_eq!(back.1.rel_type, input.1.rel_type);
        assert_eq!(back.1.timestamp, input.1.timestamp);
    }

    // ─── per-class golden round-trip tests ────────────────────────────────

    #[test]
    fn authentication_user_host_round_trips() {
        assert_round_trip(triple(
            Entity::new("alice", EntityType::User),
            Relation::new("alice", "dc-01", RelationType::Auth, 1_700_000_000),
            Entity::new("dc-01", EntityType::Host),
        ));
    }

    #[test]
    fn authentication_user_ip_round_trips() {
        assert_round_trip(triple(
            Entity::new("bob", EntityType::User),
            Relation::new("bob", "10.0.0.5", RelationType::Auth, 1_700_000_000),
            Entity::new("10.0.0.5", EntityType::IP),
        ));
    }

    #[test]
    fn process_activity_user_execute_round_trips() {
        assert_round_trip(triple(
            Entity::new("alice", EntityType::User),
            Relation::new("alice", "powershell.exe", RelationType::Execute, 42),
            Entity::new("powershell.exe", EntityType::Process),
        ));
    }

    #[test]
    fn process_activity_parent_spawn_round_trips() {
        assert_round_trip(triple(
            Entity::new("cmd.exe", EntityType::Process),
            Relation::new("cmd.exe", "whoami.exe", RelationType::Spawn, 42),
            Entity::new("whoami.exe", EntityType::Process),
        ));
    }

    #[test]
    fn network_activity_ip_ip_round_trips() {
        assert_round_trip(triple(
            Entity::new("10.0.0.1", EntityType::IP),
            Relation::new("10.0.0.1", "8.8.8.8", RelationType::Connect, 1),
            Entity::new("8.8.8.8", EntityType::IP),
        ));
    }

    #[test]
    fn network_activity_host_ip_round_trips() {
        assert_round_trip(triple(
            Entity::new("workstation-01", EntityType::Host),
            Relation::new("workstation-01", "8.8.8.8", RelationType::Connect, 1),
            Entity::new("8.8.8.8", EntityType::IP),
        ));
    }

    #[test]
    fn dns_activity_host_domain_round_trips() {
        assert_round_trip(triple(
            Entity::new("workstation-01", EntityType::Host),
            Relation::new("workstation-01", "evil.example.com", RelationType::DNS, 7),
            Entity::new("evil.example.com", EntityType::Domain),
        ));
    }

    #[test]
    fn filesystem_read_round_trips() {
        assert_round_trip(triple(
            Entity::new("powershell.exe", EntityType::Process),
            Relation::new("powershell.exe", "C:/secrets.txt", RelationType::Read, 3),
            Entity::new("C:/secrets.txt", EntityType::File),
        ));
    }

    #[test]
    fn filesystem_write_round_trips() {
        assert_round_trip(triple(
            Entity::new("malware.exe", EntityType::Process),
            Relation::new("malware.exe", "C:/dropped.dll", RelationType::Write, 3),
            Entity::new("C:/dropped.dll", EntityType::File),
        ));
    }

    #[test]
    fn filesystem_modify_round_trips() {
        assert_round_trip(triple(
            Entity::new("editor.exe", EntityType::Process),
            Relation::new("editor.exe", "C:/cfg.ini", RelationType::Modify, 3),
            Entity::new("C:/cfg.ini", EntityType::File),
        ));
    }

    #[test]
    fn filesystem_delete_round_trips() {
        assert_round_trip(triple(
            Entity::new("cleaner.exe", EntityType::Process),
            Relation::new("cleaner.exe", "C:/evidence.log", RelationType::Delete, 3),
            Entity::new("C:/evidence.log", EntityType::File),
        ));
    }

    #[test]
    fn registry_modify_round_trips() {
        assert_round_trip(triple(
            Entity::new("regedit.exe", EntityType::Process),
            Relation::new(
                "regedit.exe",
                "HKLM/Software/Run/Startup",
                RelationType::Modify,
                3,
            ),
            Entity::new("HKLM/Software/Run/Startup", EntityType::Registry),
        ));
    }

    // ─── unmapped shape falls through to Other ───────────────────────────

    #[test]
    fn unmapped_shape_falls_to_other() {
        let src = Entity::new("alice", EntityType::User);
        let rel = Relation::new("alice", "evil.example.com", RelationType::DNS, 1);
        let dst = Entity::new("evil.example.com", EntityType::Domain);
        let ev = triple_to_ocsf(&src, &rel, &dst, &prov());
        assert!(matches!(ev, OcsfEvent::Other(_)));
    }

    // ─── metadata flows triple → ocsf on typed variants ──────────────────

    #[test]
    fn process_activity_carries_pid_and_cmdline() {
        let mut dest = Entity::new("powershell.exe", EntityType::Process);
        dest.metadata.insert("pid".to_string(), "4321".to_string());
        dest.metadata
            .insert("cmdline".to_string(), "powershell.exe -enc ...".to_string());
        let src = Entity::new("alice", EntityType::User);
        let rel = Relation::new("alice", "powershell.exe", RelationType::Execute, 1);
        let ev = triple_to_ocsf(&src, &rel, &dest, &prov());
        match ev {
            OcsfEvent::ProcessActivity(e) => {
                assert_eq!(e.process.pid, Some(4321));
                assert_eq!(
                    e.process.cmd_line.as_deref(),
                    Some("powershell.exe -enc ...")
                );
            }
            _ => panic!("expected ProcessActivity"),
        }
    }

    #[test]
    fn network_activity_carries_protocol_and_ports() {
        let src = Entity::new("10.0.0.1", EntityType::IP);
        let dst = Entity::new("8.8.8.8", EntityType::IP);
        let mut rel = Relation::new("10.0.0.1", "8.8.8.8", RelationType::Connect, 0);
        rel.metadata
            .insert("protocol".to_string(), "tcp".to_string());
        rel.metadata
            .insert("source_port".to_string(), "54321".to_string());
        rel.metadata
            .insert("dest_port".to_string(), "53".to_string());
        let ev = triple_to_ocsf(&src, &rel, &dst, &prov());
        match ev {
            OcsfEvent::NetworkActivity(e) => {
                assert_eq!(e.protocol.as_deref(), Some("tcp"));
                assert_eq!(e.src_endpoint.unwrap().port, Some(54321));
                assert_eq!(e.dst_endpoint.unwrap().port, Some(53));
            }
            _ => panic!("expected NetworkActivity"),
        }
    }

    #[test]
    fn authentication_carries_status_and_protocol() {
        let src = Entity::new("alice", EntityType::User);
        let dst = Entity::new("dc-01", EntityType::Host);
        let mut rel = Relation::new("alice", "dc-01", RelationType::Auth, 0);
        rel.metadata
            .insert("status".to_string(), "failure".to_string());
        rel.metadata
            .insert("auth_protocol".to_string(), "Kerberos".to_string());
        let ev = triple_to_ocsf(&src, &rel, &dst, &prov());
        match ev {
            OcsfEvent::Authentication(e) => {
                assert_eq!(e.status.as_deref(), Some("failure"));
                assert_eq!(e.auth_protocol.as_deref(), Some("Kerberos"));
            }
            _ => panic!("expected Authentication"),
        }
    }

    #[test]
    fn provenance_travels_on_typed_event() {
        let src = Entity::new("alice", EntityType::User);
        let rel = Relation::new("alice", "dc-01", RelationType::Auth, 0);
        let dst = Entity::new("dc-01", EntityType::Host);
        let ev = triple_to_ocsf(&src, &rel, &dst, &prov());
        match ev {
            OcsfEvent::Authentication(e) => {
                assert_eq!(e.provenance.parser_name, "sysmon");
                assert_eq!(e.provenance.schema_version, ProvenanceCtx::SCHEMA_TAG);
            }
            _ => panic!("expected Authentication"),
        }
    }

    #[test]
    fn other_round_trips_ids_and_types() {
        let src = Entity::new("alice", EntityType::User);
        let dst = Entity::new("evil.example.com", EntityType::Domain);
        let rel = Relation::new(
            "alice",
            "evil.example.com",
            RelationType::DNS,
            1_700_000_000,
        );
        let ev = triple_to_ocsf(&src, &rel, &dst, &prov());
        let back = ocsf_to_triple(&ev).expect("other must round-trip");
        assert_eq!(back.0.id, "alice");
        assert_eq!(back.2.id, "evil.example.com");
        assert_eq!(back.1.timestamp, 1_700_000_000);
        assert_eq!(back.0.entity_type, EntityType::User);
        assert_eq!(back.2.entity_type, EntityType::Domain);
        assert_eq!(back.1.rel_type, RelationType::DNS);
    }
}
