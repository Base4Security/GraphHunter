//! What lets several sources meet in one graph.
//!
//! Found with `scripts/eval/gen_multisource.py`: an endpoint log, a
//! firewall and an identity provider describing one intrusion. These pin
//! the pieces that make the shared entities actually join.

use graph_hunter_core::generic::GenericParser;
use graph_hunter_core::parser::LogParser;
use graph_hunter_core::{Entity, EntityType, GraphHunter, Relation, RelationType};

/// A DNS query event names a domain and the addresses it resolved to. The
/// addresses must become `IP` nodes linked from the domain — not `Domain`
/// nodes: the first source to mention an id fixes its type, so a mistyped
/// address made later firewall flows to it miss `IP -[Connect]-> IP`.
#[test]
fn dns_answers_become_resolve_edges_to_ip_nodes() {
    let event = r#"{"EventID":22,"UtcTime":"2024-06-15 14:20:00.000","Computer":"srv-07","Image":"beacon.exe","QueryName":"c2.badactor.example","QueryResults":"type:  5 cdn.badactor.example;::ffff:203.0.113.42;203.0.113.43;","QueryType":"A"}"#;
    let triples = GenericParser.parse(event);

    let resolved: Vec<&str> = triples
        .iter()
        .filter(|(_, rel, _)| rel.rel_type == RelationType::Other("Resolve".to_string()))
        .map(|(src, _, dst)| {
            assert_eq!(src.id, "c2.badactor.example");
            assert_eq!(src.entity_type, EntityType::Domain);
            assert_eq!(dst.entity_type, EntityType::IP);
            dst.id.as_str()
        })
        .collect();
    assert_eq!(resolved, vec!["203.0.113.42", "203.0.113.43"]);

    // Neither the record type nor the raw answer string is a node.
    for (src, _, dst) in &triples {
        for e in [src, dst] {
            assert_ne!(e.id.to_lowercase(), "a", "QueryType became a node");
            assert!(
                !(e.entity_type == EntityType::Domain && e.id.starts_with("203.")),
                "address typed as Domain: {}",
                e.id
            );
        }
    }
}

/// Searching a hostname must return the host first. Process ids are
/// scoped (`host|guid|image`), so they all contain the hostname too.
#[test]
fn search_returns_the_exact_entity_before_ids_that_merely_contain_it() {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("srv-07", EntityType::Host))
        .unwrap();
    g.add_entity(Entity::new("user-1", EntityType::User))
        .unwrap();
    for n in 0..40 {
        let proc_id = format!("srv-07|{{{n:04x}}}|C:\\Windows\\System32\\cmd.exe");
        g.add_entity(Entity::new(proc_id.clone(), EntityType::Process))
            .unwrap();
        // Each process is better connected than the host, so only the
        // match quality can put the host first.
        for k in 0..3 {
            g.add_relation(Relation::new(
                "user-1".to_string(),
                proc_id.clone(),
                RelationType::Execute,
                1_700_000_000 + (n * 3 + k) as i64,
            ))
            .unwrap();
        }
    }

    let hits = g.search_entities("SRV-07", None, 5);
    assert_eq!(hits.len(), 5);
    assert_eq!(hits[0].id, "srv-07");
    assert_eq!(hits[0].entity_type, "Host");

    // Deterministic: the same query gives the same list.
    let again = g.search_entities("SRV-07", None, 5);
    let ids = |v: &[graph_hunter_core::analytics::SearchResult]| {
        v.iter().map(|r| r.id.clone()).collect::<Vec<_>>()
    };
    assert_eq!(ids(&hits), ids(&again));
}

/// A user-defined relation must show up in the relation schema under its
/// own name. The schema is where a client learns which relation names it
/// can hunt on; they all share one tag, and grouping by tag listed them
/// as an empty string.
#[test]
fn relation_schema_names_user_defined_relations() {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("c2.badactor.example", EntityType::Domain))
        .unwrap();
    g.add_entity(Entity::new("203.0.113.42", EntityType::IP))
        .unwrap();
    g.add_relation(Relation::new(
        "c2.badactor.example".to_string(),
        "203.0.113.42".to_string(),
        RelationType::Other("Resolve".to_string()),
        1_700_000_000,
    ))
    .unwrap();

    let schema = g.get_relation_schema();
    assert_eq!(schema.len(), 1);
    assert_eq!(schema[0].rel_type, "Resolve");
    assert_eq!(schema[0].source_type, "Domain");
    assert_eq!(schema[0].target_type, "IP");
    assert!(schema[0].metadata_keys.is_empty());
}

/// The question several sources exist to answer: an address that an
/// account signed in from (identity provider) and that an internal host
/// connects to (firewall). Both edges point *into* the address, so no
/// chain can express it — it takes a pattern joined by bindings. The DSL
/// parsed these all along; the search rejected them with "type mismatch"
/// because it applied the chain rule to every pattern.
#[test]
fn convergent_pattern_joins_two_sources_on_a_shared_node() {
    let mut g = GraphHunter::new();
    for (id, et) in [
        ("svc-backup@corp.example", EntityType::User),
        ("ana@corp.example", EntityType::User),
        ("srv-07", EntityType::Host),
        ("ws-01", EntityType::Host),
        ("203.0.113.42", EntityType::IP),
        ("192.0.2.10", EntityType::IP),
        ("198.51.100.7", EntityType::IP),
    ] {
        g.add_entity(Entity::new(id, et)).unwrap();
    }
    for (src, dst, rel, ts) in [
        // Identity provider: sign-ins.
        (
            "svc-backup@corp.example",
            "203.0.113.42",
            RelationType::Auth,
            100,
        ),
        ("ana@corp.example", "192.0.2.10", RelationType::Auth, 110),
        // Firewall / endpoint: connections.
        ("srv-07", "203.0.113.42", RelationType::Connect, 200),
        ("ws-01", "198.51.100.7", RelationType::Connect, 210),
    ] {
        g.add_relation(Relation::new(src.to_string(), dst.to_string(), rel, ts))
            .unwrap();
    }
    g.sort_edges_by_timestamp().unwrap();

    let hypothesis =
        graph_hunter_core::parse_dsl("User u -[Auth]-> IP i; Host h -[Connect]-> IP i", None)
            .unwrap()
            .hypothesis;
    let (paths, truncated) = g.search_temporal_pattern(&hypothesis, None, None).unwrap();
    assert!(!truncated);
    assert_eq!(paths.len(), 1, "exactly one address is shared: {paths:?}");
    let nodes: Vec<&str> = paths[0].iter().map(|s| s.as_ref()).collect();
    for expected in ["svc-backup@corp.example", "203.0.113.42", "srv-07"] {
        assert!(
            nodes.contains(&expected),
            "{expected} missing from {nodes:?}"
        );
    }
    assert!(!nodes.contains(&"ana@corp.example"));
}

/// The field-covering sample reads untrusted logs. A file where every
/// event invents a field name must not turn the sample into the file.
#[test]
fn covering_sample_is_bounded_when_every_event_adds_a_field() {
    let head = 50;
    let total = head + GenericParser::MAX_LATE_FIELD_EVENTS + 3_000;
    let mut ndjson = String::new();
    for i in 0..total {
        ndjson.push_str(&format!("{{\"host\":\"ws-01\",\"field_{i}\":1}}\n"));
    }
    let (sample, incomplete) = GenericParser::parse_events_covering(&ndjson, head);
    assert_eq!(sample.len(), head + GenericParser::MAX_LATE_FIELD_EVENTS);
    // Hitting the cap is reported, never silent: padding a log with junk
    // fields must not be a quiet way to push a real field out of the mapping.
    assert!(incomplete);

    // An ordinary log stays well inside the caps and is complete.
    let ordinary = "{\"host\":\"ws-01\"}\n".repeat(300) + "{\"host\":\"ws-01\",\"rare\":1}\n";
    let (sample, incomplete) = GenericParser::parse_events_covering(&ordinary, head);
    assert_eq!(sample.len(), head + 1);
    assert!(!incomplete);
}

/// A firewall knows addresses and an endpoint log knows host names. The
/// endpoint's own connection events carry both, and that is the only place
/// the two meet: without the edge, the 480 MB a firewall saw leave
/// `10.20.206.10` cannot be tied to `srv-07` inside the graph.
#[test]
fn endpoint_connection_ties_the_host_to_its_own_address() {
    let has_address = |line: &str| -> Vec<(String, String)> {
        GenericParser
            .parse(line)
            .into_iter()
            .filter(|(_, rel, _)| rel.rel_type == RelationType::Other("HasAddress".to_string()))
            .map(|(src, _, dst)| {
                assert_eq!(src.entity_type, EntityType::Host);
                assert_eq!(dst.entity_type, EntityType::IP);
                (src.id, dst.id)
            })
            .collect()
    };

    let outbound = r#"{"EventID":3,"UtcTime":"2024-06-15 14:32:00.000","Computer":"SRV-07","Image":"beacon.exe","Initiated":"true","SourceIp":"10.20.206.10","DestinationIp":"203.0.113.42","DestinationPort":443}"#;
    assert_eq!(
        has_address(outbound),
        vec![("srv-07".to_string(), "10.20.206.10".to_string())]
    );

    // Accepted connection: the source is the remote peer, not this host.
    let inbound = r#"{"EventID":3,"UtcTime":"2024-06-15 14:32:00.000","Computer":"SRV-07","Image":"svchost.exe","Initiated":"false","SourceIp":"203.0.113.42","DestinationIp":"10.20.206.10","DestinationPort":3389}"#;
    assert!(has_address(inbound).is_empty());

    // Appliance log: `hostname` is the firewall, the source is a client.
    let appliance = r#"{"timestamp":"2024-06-15T14:32:00Z","hostname":"fw-edge-01","src_ip":"10.20.206.10","dst_ip":"203.0.113.42"}"#;
    assert!(has_address(appliance).is_empty());

    // No direction: not guessed from one row, but counted so the gap is
    // visible — unless another row of the batch already ties the host.
    let undirected = outbound.replace(r#""Initiated":"true","#, "");
    assert!(has_address(&undirected).is_empty());
    let (_, stats) = GenericParser.parse_with_stats(&format!("{undirected}\n{inbound}"));
    assert_eq!(stats.host_address_unverified, 1, "only the undirected row");
    let (_, stats) =
        GenericParser.parse_with_stats(&format!("{undirected}\n{outbound}\n{inbound}"));
    assert_eq!(
        stats.host_address_unverified, 0,
        "the outbound row ties srv-07"
    );
}

/// An endpoint log that never says which way a connection went still
/// carries the host's own address on every one of them, as source or as
/// destination. That address is inferred, so a firewall's flows reach the
/// host; a host that only talks to one proxy, or that made too few
/// connections, is left untied and counted.
#[test]
fn a_host_address_is_inferred_from_undirected_connections() {
    let conn = |host: &str, src: &str, dst: &str, minute: u32| {
        format!(
            r#"{{"EventID":3,"UtcTime":"2024-06-15 14:{minute:02}:00.000","Computer":"{host}","Image":"C:\\Windows\\System32\\svchost.exe","SourceIp":"{src}","DestinationIp":"{dst}","DestinationPort":443}}"#
        )
    };
    let mut lines = Vec::new();
    // ws-03 (10.20.206.13): six connections out, two accepted.
    for m in 0..6 {
        lines.push(conn(
            "ws-03",
            "10.20.206.13",
            &format!("203.0.113.{}", 10 + m),
            m,
        ));
    }
    lines.push(conn("ws-03", "198.51.100.7", "10.20.206.13", 6));
    lines.push(conn("ws-03", "198.51.100.8", "10.20.206.13", 7));
    // ws-04 only talks to its proxy: two addresses on every row.
    for m in 0..6 {
        lines.push(conn("ws-04", "10.20.206.14", "10.20.0.1", 10 + m));
    }
    // ws-05: too few connections to tell.
    for m in 0..3 {
        lines.push(conn(
            "ws-05",
            "10.20.206.15",
            &format!("203.0.113.{}", 30 + m),
            20 + m,
        ));
    }

    let (triples, stats) = GenericParser.parse_with_stats(&lines.join("\n"));
    assert_eq!(stats.host_address_inferred, 1, "only ws-03");
    assert_eq!(stats.host_address_unverified, 6 + 3, "ws-04 and ws-05 rows");
    let inferred: Vec<_> = triples
        .iter()
        .filter(|(_, rel, _)| rel.rel_type == RelationType::Other("HasAddress".to_string()))
        .collect();
    // One per row of ws-03, at that row's time, marked as inferred.
    assert_eq!(inferred.len(), 8);
    for (src, rel, dst) in &inferred {
        assert_eq!(
            (src.id.as_str(), dst.id.as_str()),
            ("ws-03", "10.20.206.13")
        );
        assert_eq!(
            rel.metadata.get("inferred").map(String::as_str),
            Some("constant_ip")
        );
    }

    // The firewall saw the address leave; the join now reaches the host.
    let mut g = GraphHunter::new();
    g.insert_triples(triples, Some("sysmon")).unwrap();
    g.insert_triples(
        vec![(
            Entity::new("10.20.206.13", EntityType::IP),
            Relation::new(
                "10.20.206.13",
                "203.0.113.99",
                RelationType::Connect,
                1_718_462_000,
            ),
            Entity::new("203.0.113.99", EntityType::IP),
        )],
        Some("firewall"),
    )
    .unwrap();
    g.sort_edges_by_timestamp().unwrap();
    let hypothesis =
        graph_hunter_core::parse_dsl("Host h -[HasAddress]-> IP a; IP a -[Connect]-> IP d", None)
            .unwrap()
            .hypothesis;
    let (paths, _) = g.search_temporal_pattern(&hypothesis, None, None).unwrap();
    assert_eq!(paths.len(), 1, "{paths:?}");
    let nodes: Vec<&str> = paths[0].iter().map(|s| s.as_ref()).collect();
    for expected in ["ws-03", "10.20.206.13", "203.0.113.99"] {
        assert!(
            nodes.contains(&expected),
            "{expected} missing from {nodes:?}"
        );
    }
}

/// Logs repeat: a host reports its address on every connection. A joined
/// pattern answers with nodes, so the repeats are one finding, not one
/// per observation — counted that way they also eat the result cap.
#[test]
fn repeated_edges_are_one_result_in_a_joined_pattern() {
    let mut g = GraphHunter::new();
    for (id, et) in [
        ("svc-backup@corp.example", EntityType::User),
        ("srv-07", EntityType::Host),
        ("203.0.113.42", EntityType::IP),
    ] {
        g.add_entity(Entity::new(id, et)).unwrap();
    }
    g.add_relation(Relation::new(
        "svc-backup@corp.example".to_string(),
        "203.0.113.42".to_string(),
        RelationType::Auth,
        100,
    ))
    .unwrap();
    for ts in 200..250 {
        g.add_relation(Relation::new(
            "srv-07".to_string(),
            "203.0.113.42".to_string(),
            RelationType::Connect,
            ts,
        ))
        .unwrap();
    }
    g.sort_edges_by_timestamp().unwrap();

    let hypothesis =
        graph_hunter_core::parse_dsl("User u -[Auth]-> IP i; Host h -[Connect]-> IP i", None)
            .unwrap()
            .hypothesis;
    let (paths, truncated) = g.search_temporal_pattern(&hypothesis, None, None).unwrap();
    assert!(!truncated);
    assert_eq!(paths.len(), 1, "{paths:?}");
}

/// A graph of `(src, rel, dst, ts)` edges over typed nodes, sorted.
fn timed_graph(
    nodes: &[(&str, EntityType)],
    edges: &[(&str, &str, RelationType, i64)],
) -> GraphHunter {
    let mut g = GraphHunter::new();
    for (id, et) in nodes {
        g.add_entity(Entity::new(*id, et.clone())).unwrap();
    }
    for (src, dst, rel, ts) in edges {
        g.add_relation(Relation::new(
            src.to_string(),
            dst.to_string(),
            rel.clone(),
            *ts,
        ))
        .unwrap();
    }
    g.sort_edges_by_timestamp().unwrap();
    g
}

fn hosts_found(g: &GraphHunter, dsl: &str) -> Vec<String> {
    let hypothesis = graph_hunter_core::parse_dsl(dsl, None).unwrap().hypothesis;
    let (paths, truncated) = g.search_temporal_pattern(&hypothesis, None, None).unwrap();
    assert!(!truncated);
    let mut hosts: Vec<String> = paths
        .iter()
        .flat_map(|p| p.iter())
        .filter(|n| n.starts_with("srv-") || n.starts_with("ws-"))
        .map(|n| n.to_string())
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// User-defined relations share one type tag; their name lives beside the
/// edge. `-[HasAddress]->` must not match a SNAT between the same types,
/// in a chain or in a joined pattern.
#[test]
fn a_user_defined_relation_matches_by_its_name() {
    let ip = "10.20.206.10";
    let g = timed_graph(
        &[
            ("svc-backup@corp.example", EntityType::User),
            ("srv-07", EntityType::Host),
            ("ws-03", EntityType::Host),
            (ip, EntityType::IP),
            ("203.0.113.42", EntityType::IP),
        ],
        &[
            (
                "svc-backup@corp.example",
                "203.0.113.42",
                RelationType::Auth,
                100,
            ),
            (ip, "203.0.113.42", RelationType::Connect, 200),
            ("srv-07", ip, RelationType::Other("HasAddress".into()), 200),
            ("ws-03", ip, RelationType::Other("SNAT".into()), 200),
        ],
    );
    assert_eq!(hosts_found(&g, "Host h -[HasAddress]-> IP s"), ["srv-07"]);
    assert_eq!(hosts_found(&g, "Host h -[SNAT]-> IP s"), ["ws-03"]);
    assert_eq!(
        hosts_found(
            &g,
            "User u -[Auth]-> IP i; IP s -[Connect]-> IP i; Host h -[HasAddress]-> IP s"
        ),
        ["srv-07"]
    );
    assert_eq!(
        hosts_found(&g, "Host h -[Resolve]-> IP s"),
        Vec::<String>::new()
    );
    assert_eq!(hosts_found(&g, "Host h -[*]-> IP s"), ["srv-07", "ws-03"]);
}

/// The first source to name an id fixes its type. When a later one types
/// it differently its triples still land on the existing node, so a
/// pattern on the later type silently misses it: the conflict is kept,
/// counted once per entity however many rows repeat it, and reported.
#[test]
fn a_type_conflict_between_sources_is_reported() {
    let ip = "10.20.206.10";
    let triple = |src: (&str, EntityType), dst: (&str, EntityType), ts| {
        (
            Entity::new(src.0, src.1),
            Relation::new(src.0, dst.0, RelationType::Connect, ts),
            Entity::new(dst.0, dst.1),
        )
    };
    let mut g = GraphHunter::new();
    g.insert_triples(
        vec![triple(
            (ip, EntityType::IP),
            ("203.0.113.42", EntityType::IP),
            1,
        )],
        Some("firewall"),
    )
    .unwrap();
    assert!(g.type_conflicts().is_empty());
    g.insert_triples(
        (0..3)
            .map(|ts| triple((ip, EntityType::Host), ("203.0.113.42", EntityType::IP), ts))
            .collect(),
        Some("cmdb"),
    )
    .unwrap();

    assert_eq!(g.get_entity(ip).unwrap().entity_type, EntityType::IP);
    let conflicts = g.type_conflicts();
    assert_eq!(conflicts.len(), 1, "{conflicts:?}");
    let c = &conflicts[0];
    assert_eq!((&c.kept, &c.refused), (&EntityType::IP, &EntityType::Host));
    assert_eq!((c.entities, c.example.as_str()), (1, ip));
}

/// `HAVING` counts a binding, and a joined result holds one node per
/// binding, not a chain: `h` must be the host and `LAST` the last
/// clause's destination (the IP), per first-clause origin (the user).
/// Alice signs in from one address two hosts use; Bob from two addresses
/// one host uses, so counting the wrong column flips the answer.
#[test]
fn having_counts_the_named_binding_in_a_joined_pattern() {
    let g = timed_graph(
        &[
            ("alice@corp.example", EntityType::User),
            ("bob@corp.example", EntityType::User),
            ("srv-07", EntityType::Host),
            ("ws-03", EntityType::Host),
            ("ws-09", EntityType::Host),
            ("203.0.113.42", EntityType::IP),
            ("198.51.100.5", EntityType::IP),
            ("198.51.100.6", EntityType::IP),
        ],
        &[
            (
                "alice@corp.example",
                "203.0.113.42",
                RelationType::Auth,
                100,
            ),
            ("srv-07", "203.0.113.42", RelationType::Connect, 200),
            ("ws-03", "203.0.113.42", RelationType::Connect, 200),
            ("bob@corp.example", "198.51.100.5", RelationType::Auth, 100),
            ("bob@corp.example", "198.51.100.6", RelationType::Auth, 100),
            ("ws-09", "198.51.100.5", RelationType::Connect, 200),
            ("ws-09", "198.51.100.6", RelationType::Connect, 200),
        ],
    );
    let pattern = "User u -[Auth]-> IP i; Host h -[Connect]-> IP i";
    assert_eq!(
        hosts_found(&g, &format!("{pattern} HAVING count(distinct h) >= 2")),
        ["srv-07", "ws-03"]
    );
    assert_eq!(
        hosts_found(&g, &format!("{pattern} HAVING count(distinct LAST) >= 2")),
        ["ws-09"]
    );
    assert_eq!(
        hosts_found(&g, &format!("{pattern} HAVING count(distinct h) >= 1")),
        ["srv-07", "ws-03", "ws-09"]
    );
}

/// An address is held by different hosts over a day. A joined pattern
/// binds nodes, so without a window it ties the 14:32 connection to every
/// host that ever held its source address. `WITHIN` must hold over the
/// edges each match takes — a lease from the morning is not this flow.
#[test]
fn within_keeps_only_the_host_holding_the_address_at_the_time() {
    let ip = "10.20.206.10";
    let mut edges = vec![
        (
            "svc-backup@corp.example",
            "203.0.113.42",
            RelationType::Auth,
            49_800,
        ),
        (ip, "203.0.113.42", RelationType::Connect, 52_320),
    ];
    let lease = RelationType::Other("HasAddress".to_string());
    for t in (1_000..40_000).step_by(3_000) {
        edges.push(("ws-150", ip, lease.clone(), t)); // until noon
    }
    for t in (44_000..86_000).step_by(3_000) {
        edges.push(("srv-07", ip, lease.clone(), t)); // after noon
    }
    let g = timed_graph(
        &[
            ("svc-backup@corp.example", EntityType::User),
            ("203.0.113.42", EntityType::IP),
            (ip, EntityType::IP),
            ("ws-150", EntityType::Host),
            ("srv-07", EntityType::Host),
        ],
        &edges,
    );
    let pattern = "User u -[Auth]-> IP i; IP s -[Connect]-> IP i; Host h -[HasAddress]-> IP s";
    assert_eq!(hosts_found(&g, pattern), vec!["srv-07", "ws-150"]);
    assert_eq!(
        hosts_found(&g, &format!("{pattern} WITHIN 1h")),
        vec!["srv-07"]
    );
    // Narrower than the gap between sign-in and flow: nothing co-occurs.
    assert!(hosts_found(&g, &format!("{pattern} WITHIN 10m")).is_empty());
}

/// The usable observation of a pair is not always its first: the window
/// has to look at every timestamp, and a standing fact (`timestamp == 0`)
/// is true at any time.
#[test]
fn within_picks_the_observation_that_fits_and_ignores_standing_facts() {
    let lease = RelationType::Other("HasAddress".to_string());
    let g = timed_graph(
        &[
            ("u@corp.example", EntityType::User),
            ("203.0.113.42", EntityType::IP),
            ("10.0.0.5", EntityType::IP),
            ("srv-07", EntityType::Host),
        ],
        &[
            ("u@corp.example", "203.0.113.42", RelationType::Auth, 1_000),
            ("u@corp.example", "203.0.113.42", RelationType::Auth, 90_000),
            ("10.0.0.5", "203.0.113.42", RelationType::Connect, 90_300),
            ("srv-07", "10.0.0.5", lease, 0),
        ],
    );
    let pattern =
        "User u -[Auth]-> IP i; IP s -[Connect]-> IP i; Host h -[HasAddress]-> IP s WITHIN 10m";
    assert_eq!(hosts_found(&g, pattern), vec!["srv-07"]);
}

/// A busy shared address (an office many accounts sign in from and many
/// hosts browse) matches a cross-source pattern a hundred times; the one
/// that matters matches once. Under a result cap the rare one must come
/// back: grouping on the shared node, smaller groups first, and without a
/// cap the set is unchanged.
#[test]
fn a_busy_shared_node_does_not_crowd_out_a_rare_one_under_the_cap() {
    let mut nodes: Vec<(String, EntityType)> = vec![
        ("203.0.113.7".into(), EntityType::IP),
        ("203.0.113.42".into(), EntityType::IP),
        ("svc-backup@corp.example".into(), EntityType::User),
        ("srv-07".into(), EntityType::Host),
    ];
    let mut edges: Vec<(String, String, RelationType, i64)> = Vec::new();
    // Inserted first, so a walk in first-seen order meets it first.
    for k in 0..10 {
        nodes.push((format!("user{k}@corp.example"), EntityType::User));
        nodes.push((format!("ws-{k:03}"), EntityType::Host));
        edges.push((
            format!("user{k}@corp.example"),
            "203.0.113.7".into(),
            RelationType::Auth,
            100 + k,
        ));
        edges.push((
            format!("ws-{k:03}"),
            "203.0.113.7".into(),
            RelationType::Connect,
            200 + k,
        ));
    }
    edges.push((
        "svc-backup@corp.example".into(),
        "203.0.113.42".into(),
        RelationType::Auth,
        900,
    ));
    edges.push((
        "srv-07".into(),
        "203.0.113.42".into(),
        RelationType::Connect,
        950,
    ));
    let node_refs: Vec<(&str, EntityType)> =
        nodes.iter().map(|(n, t)| (n.as_str(), t.clone())).collect();
    let edge_refs: Vec<(&str, &str, RelationType, i64)> = edges
        .iter()
        .map(|(a, b, r, t)| (a.as_str(), b.as_str(), r.clone(), *t))
        .collect();
    let g = timed_graph(&node_refs, &edge_refs);

    let hypothesis =
        graph_hunter_core::parse_dsl("User u -[Auth]-> IP i; Host h -[Connect]-> IP i", None)
            .unwrap()
            .hypothesis;
    let (all, truncated) = g.search_temporal_pattern(&hypothesis, None, None).unwrap();
    assert!(!truncated);
    assert_eq!(all.len(), 101);

    let (capped, truncated) = g
        .search_temporal_pattern(&hypothesis, None, Some(5))
        .unwrap();
    assert!(truncated);
    assert_eq!(capped.len(), 5);
    assert!(
        capped
            .iter()
            .any(|p| p.iter().any(|n| &**n == "203.0.113.42")),
        "the rare address must be in the capped result: {capped:?}"
    );
}

/// A joined result is one node per binding, not a chain, so its sources,
/// times and summary have to be read from its clauses. Read as consecutive
/// nodes it reported one source and a zero-length span for a match that
/// crossed three logs over 42 minutes.
#[test]
fn a_joined_result_reports_its_own_edges_sources_and_episode() {
    let ip = "10.20.206.10";
    let c2 = "203.0.113.42";
    let lease = RelationType::Other("HasAddress".to_string());
    let mut g = GraphHunter::new();
    let insert = |g: &mut GraphHunter,
                  src: (&str, EntityType),
                  rel: RelationType,
                  dst: (&str, EntityType),
                  ts: i64,
                  ds: &str| {
        g.insert_triples(
            vec![(
                Entity::new(src.0, src.1),
                Relation::new(src.0, dst.0, rel, ts),
                Entity::new(dst.0, dst.1),
            )],
            Some(ds),
        )
        .unwrap();
    };
    insert(
        &mut g,
        ("svc-backup@corp.example", EntityType::User),
        RelationType::Auth,
        (c2, EntityType::IP),
        49_800,
        "idp",
    );
    insert(
        &mut g,
        (ip, EntityType::IP),
        RelationType::Connect,
        (c2, EntityType::IP),
        52_320,
        "firewall",
    );
    for t in (44_000..86_000).step_by(3_000) {
        insert(
            &mut g,
            ("srv-07", EntityType::Host),
            lease.clone(),
            (ip, EntityType::IP),
            t,
            "sysmon",
        );
    }
    // Same two nodes, another relation, early in the day: not this clause.
    insert(
        &mut g,
        ("srv-07", EntityType::Host),
        RelationType::Connect,
        (ip, EntityType::IP),
        1_000,
        "sysmon",
    );
    g.sort_edges_by_timestamp().unwrap();

    let hypothesis = graph_hunter_core::parse_dsl(
        "User u -[Auth]-> IP i; IP s -[Connect]-> IP i; Host h -[HasAddress]-> IP s WITHIN 1h",
        None,
    )
    .unwrap()
    .hypothesis;
    let (paths, _) = g.search_temporal_pattern(&hypothesis, None, None).unwrap();
    assert_eq!(paths.len(), 1);
    let clauses = graph_hunter_core::yannakakis::joined_clauses(&hypothesis).unwrap();
    let (scored, _) = g.score_and_paginate_shaped(
        &paths,
        0,
        50,
        None,
        graph_hunter_core::DedupMode::None,
        Some(&clauses),
    );
    let row = &scored[0];

    let mut sources = row.datasets_used.clone();
    sources.sort();
    assert_eq!(sources, vec!["firewall", "idp", "sysmon"]);
    // Sign-in to exfiltration; the lease at 50_000 lies inside it.
    assert_eq!((row.time_start, row.time_end), (49_800, 52_320));
    assert!(
        row.chain_summary
            .contains("srv-07 -[HasAddress]-> 10.20.206.10"),
        "{}",
        row.chain_summary
    );
    // Chains keep their old reading.
    assert!(
        graph_hunter_core::yannakakis::joined_clauses(
            &graph_hunter_core::parse_dsl("User -[Auth]-> IP", None)
                .unwrap()
                .hypothesis
        )
        .is_none()
    );
}
