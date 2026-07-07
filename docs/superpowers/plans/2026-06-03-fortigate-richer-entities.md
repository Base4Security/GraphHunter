# FortiGate Richer Entity Extraction (SP-A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the FortiGate KV parser promote SNAT egress, service, and policy from edge-metadata to graph nodes, so firewall flows produce a richer, correlatable graph instead of collapsing to 2 IP nodes.

**Architecture:** Additive change to `parse_kv_line` in `platform/parsers/src/fortigate.rs`. After the existing `srcip -[Connect]-> dstip` triple, emit up to 3 conditional satellite triples (Model 1, semantic by owner): `srcip -[SNAT]-> transip`, `dstip -[Exposes]-> Service("dstip:port")`, `srcip -[MatchedPolicy]-> Policy(policyname)`. No core/enum changes (`IP`, `Service`, `Other(String)` already exist). The `Connect` edge and IPS `Signature`/`Triggered` triple are untouched.

**Tech Stack:** Rust (`graph_hunter_parsers` crate).

## Build/test commands (no cargo workspace)
- Parser tests: `cargo test --manifest-path platform/parsers/Cargo.toml fortigate`
- Full parser lib: `cargo test --manifest-path platform/parsers/Cargo.toml --lib`

## Current code (verified)
`parse_kv_line` (`fortigate.rs:202`) returns `Vec<ParsedTriple>` where `ParsedTriple = (Entity, Relation, Entity)`. It builds:
```rust
let src = Entity::new(&srcip, EntityType::IP);
let dst = Entity::new(&dstip, EntityType::IP);
let mut rel = Relation::new(&srcip, &dstip, RelationType::Connect, timestamp);
rel.metadata = edge_meta.clone();
triples.push((src.clone(), rel, dst));   // src.clone() -> `src` still owned; `dst` is MOVED
// then optional IPS triple that moves `src`
```
Imports already present (`fortigate.rs:44-47`): `Entity`, `Relation`, `LogParser`, `ParsedTriple`, `EntityType`, `RelationType`. `kv: HashMap<String,String>` holds all fields (`transip`, `trandisp`, `dstport`, `service`, `policyname`, `policyid`, `devname`, …). `Entity` has a public `metadata: HashMap<String,String>` (set via `.metadata.insert(...)`). `timestamp: i64` is already derived above.

---

## Task 1: Emit SNAT / Service / Policy satellite triples

**Files:**
- Modify: `platform/parsers/src/fortigate.rs` (`parse_kv_line`, ~after line 222)
- Test: same file, `#[cfg(test)]` module (mirror existing tests ~line 501+)

- [ ] **Step 1: Write the failing tests**

Add to the test module in `fortigate.rs`. Helper to find a triple by relation type + endpoints (adapt to the file's existing test style — they index `triples[i] = (src, rel, dst)` and read `.entity_type`, `.id`, `.rel_type`):

```rust
#[test]
fn snat_flow_emits_all_satellite_nodes() {
    let line = r#"date=2026-05-28 time=14:14:20 devname="FW_FGT_VPN" srcip="172.25.15.1" dstip="192.168.53.96" dstport=9699 action=close policyid=348 policyname="MIGRACION TELECARGA" service="TELECARGA" trandisp="snat" transip="128.36.11.249""#;
    let triples = parse_kv_line(line);

    // Connect edge still present and unchanged (back-compat).
    let connect = triples.iter().find(|(_, r, _)| r.rel_type == RelationType::Connect)
        .expect("Connect edge");
    assert_eq!(connect.0.id, "172.25.15.1");
    assert_eq!(connect.2.id, "192.168.53.96");

    // SNAT: srcip -> transip (IP)
    let snat = triples.iter().find(|(_, r, _)| r.rel_type == RelationType::Other("SNAT".to_string()))
        .expect("SNAT edge");
    assert_eq!(snat.0.id, "172.25.15.1");
    assert_eq!(snat.2.id, "128.36.11.249");
    assert_eq!(snat.2.entity_type, EntityType::IP);

    // Exposes: dstip -> Service("dstip:port")
    let exp = triples.iter().find(|(_, r, _)| r.rel_type == RelationType::Other("Exposes".to_string()))
        .expect("Exposes edge");
    assert_eq!(exp.0.id, "192.168.53.96");
    assert_eq!(exp.2.id, "192.168.53.96:9699");
    assert_eq!(exp.2.entity_type, EntityType::Service);
    assert_eq!(exp.2.metadata.get("port").map(String::as_str), Some("9699"));
    assert_eq!(exp.2.metadata.get("service").map(String::as_str), Some("TELECARGA"));

    // MatchedPolicy: srcip -> Policy(policyname)
    let pol = triples.iter().find(|(_, r, _)| r.rel_type == RelationType::Other("MatchedPolicy".to_string()))
        .expect("MatchedPolicy edge");
    assert_eq!(pol.0.id, "172.25.15.1");
    assert_eq!(pol.2.id, "MIGRACION TELECARGA");
    assert_eq!(pol.2.entity_type, EntityType::Other("Policy".to_string()));
    assert_eq!(pol.2.metadata.get("policyid").map(String::as_str), Some("348"));
}

#[test]
fn noop_flow_emits_no_snat_edge() {
    // FW_INTERNO style: trandisp=noop, no transip.
    let line = r#"date=2026-05-28 time=14:14:13 devname="FW_FGT_INTERNO" srcip="172.25.15.1" dstip="192.168.53.96" dstport=9181 action=close policyid=1710 policyname="SGDC-551684_I" trandisp="noop""#;
    let triples = parse_kv_line(line);
    assert!(triples.iter().all(|(_, r, _)| r.rel_type != RelationType::Other("SNAT".to_string())),
        "noop flow must not emit a SNAT edge");
    // but Exposes + MatchedPolicy + Connect are present
    assert!(triples.iter().any(|(_, r, _)| r.rel_type == RelationType::Other("Exposes".to_string())));
    assert!(triples.iter().any(|(_, r, _)| r.rel_type == RelationType::Other("MatchedPolicy".to_string())));
    assert!(triples.iter().any(|(_, r, _)| r.rel_type == RelationType::Connect));
}

#[test]
fn missing_policy_emits_no_policy_edge() {
    let line = r#"srcip="10.0.0.1" dstip="10.0.0.2" dstport=443 action=close trandisp="noop""#;
    let triples = parse_kv_line(line);
    assert!(triples.iter().all(|(_, r, _)| r.rel_type != RelationType::Other("MatchedPolicy".to_string())),
        "no policyname -> no MatchedPolicy edge");
    // Service still emitted (dstport present): id "10.0.0.2:443"
    let exp = triples.iter().find(|(_, r, _)| r.rel_type == RelationType::Other("Exposes".to_string()))
        .expect("Exposes edge");
    assert_eq!(exp.2.id, "10.0.0.2:443");
}
```

> Adjust the test helpers to the file's existing conventions if they differ (e.g. how `parse_kv_line` is invoked, whether KV lines use quotes). The existing tests around line 501-613 show the real invocation/assertion style — match it. If `Entity.metadata` is not directly public, use the file's accessor.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --manifest-path platform/parsers/Cargo.toml fortigate`
Expected: FAIL — the SNAT/Exposes/MatchedPolicy edges don't exist yet (`.expect(...)` panics).

- [ ] **Step 3: Implement the satellite triples**

In `parse_kv_line`, immediately AFTER the `triples.push((src.clone(), rel, dst));` line (the Connect triple, ~line 222) and BEFORE the IPS `attack` block (~line 224), insert:

```rust
    // Satellite triple: srcip -[SNAT]-> transip (only on source NAT).
    if kv.get("trandisp").map(|d| d == "snat").unwrap_or(false) {
        if let Some(transip) = kv.get("transip").filter(|v| !v.is_empty()) {
            let egress = Entity::new(transip, EntityType::IP);
            let rel = Relation::new(
                &srcip, transip,
                RelationType::Other("SNAT".to_string()), timestamp,
            );
            triples.push((src.clone(), rel, egress));
        }
    }

    // Satellite triple: dstip -[Exposes]-> Service("dstip:port").
    if let Some(port) = kv.get("dstport").filter(|v| !v.is_empty()) {
        let svc_id = format!("{dstip}:{port}");
        let mut svc = Entity::new(&svc_id, EntityType::Service);
        svc.metadata.insert("port".into(), port.clone());
        if let Some(name) = kv.get("service").filter(|v| !v.is_empty()) {
            svc.metadata.insert("service".into(), name.clone());
        }
        // `dst` was moved into the Connect triple; rebuild the dst IP node
        // (same id -> dedups on ingest).
        let dst_node = Entity::new(&dstip, EntityType::IP);
        let rel = Relation::new(
            &dstip, &svc_id,
            RelationType::Other("Exposes".to_string()), timestamp,
        );
        triples.push((dst_node, rel, svc));
    }

    // Satellite triple: srcip -[MatchedPolicy]-> Policy(policyname).
    if let Some(policy_name) = kv.get("policyname").filter(|v| !v.is_empty()) {
        let mut policy = Entity::new(policy_name, EntityType::Other("Policy".to_string()));
        if let Some(pid) = kv.get("policyid").filter(|v| !v.is_empty()) {
            policy.metadata.insert("policyid".into(), pid.clone());
        }
        if let Some(dev) = kv.get("devname").filter(|v| !v.is_empty()) {
            policy.metadata.insert("devname".into(), dev.clone());
        }
        let rel = Relation::new(
            &srcip, policy_name,
            RelationType::Other("MatchedPolicy".to_string()), timestamp,
        );
        triples.push((src.clone(), rel, policy));
    }
```

Notes for the implementer:
- `src` is owned (the Connect push used `src.clone()`), so `src.clone()` here is valid; the later IPS block can still move `src`.
- `dst` was MOVED into the Connect triple — rebuild `dst_node` from `&dstip` for the Exposes edge (same id → dedups at ingest).
- If `Entity::new` borrows differ (e.g. takes `impl Into<String>`), match the existing call style at line 218-219.
- Do NOT change `edge_meta`, the `Connect` triple, or the IPS block.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --manifest-path platform/parsers/Cargo.toml fortigate`
Expected: the 3 new tests PASS.

- [ ] **Step 5: Regression — existing parser tests still green**

Run: `cargo test --manifest-path platform/parsers/Cargo.toml --lib`
Expected: all existing FortiGate tests still pass (the `Connect` edge + metadata + IPS `Triggered` behavior is unchanged; new tests added).

- [ ] **Step 6: Commit**

```bash
git add platform/parsers/src/fortigate.rs
git commit -m "feat(parsers): FortiGate promotes SNAT egress, service, policy to nodes"
```

---

## Task 2: Verification gate

**Files:** none (verification only)

- [ ] **Step 1: Parser crate suite**

Run: `cargo test --manifest-path platform/parsers/Cargo.toml --lib`
Expected: all green incl. `snat_flow_emits_all_satellite_nodes`, `noop_flow_emits_no_snat_edge`, `missing_policy_emits_no_policy_edge`.

- [ ] **Step 2: Downstream crate still builds (parser is consumed by api)**

Run: `cargo check --manifest-path platform/api/Cargo.toml`
Expected: clean (the parser's public `parse`/`LogParser` surface is unchanged — only more triples emitted; no signature change).

- [ ] **Step 3: Real-data smoke (operator)**

Convert + ingest the real FW_VPN export (the CSV/xlsx the analyst has) through the FortiGate format and confirm in GraphHunter:
- A `Service` node `192.168.53.96:9699` exists with `dstip -[Exposes]->` it.
- An `IP` node `128.36.11.249` exists with `172.25.15.1 -[SNAT]->` it.
- A `Policy` node `MIGRACION TELECARGA` exists with `172.25.15.1 -[MatchedPolicy]->` it.
- The `9181` Service node is shared between the FW_INTERNO and FW_VPN ingests (same `192.168.53.96:9181` id) — confirms cross-source correlation.

---

## Self-review notes

- **Spec coverage:** §4 model — SNAT/Exposes/MatchedPolicy triples (Task 1 Step 3); §4.1 node ids (Service `dstip:port` + port/service metadata; Policy by name + policyid/devname metadata; egress IP) all in Step 3 and asserted in Step 1; §4.3 conditional emission (trandisp==snat for SNAT, dstport for Service, policyname for Policy) implemented + tested (`noop_flow_emits_no_snat_edge`, `missing_policy_emits_no_policy_edge`); §5 back-compat (Connect + IPS untouched) — regression Step 5; §6 testing — all listed cases present.
- **Type consistency:** `RelationType::Other("SNAT"|"Exposes"|"MatchedPolicy")` strings identical between the implementation (Step 3) and the test assertions (Step 1); `EntityType::Service` for the service node, `EntityType::Other("Policy")` for policy, `EntityType::IP` for egress — consistent across spec/plan/tests.
- **Known soft spots flagged:** `Entity.metadata` accessibility and `Entity::new` arg style (Task 1 Step 1/3 notes — match the file's existing usage at lines 218-219, 226); the real-data smoke (Task 2 Step 3) needs the analyst's ingest path.
