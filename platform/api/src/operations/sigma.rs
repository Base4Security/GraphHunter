//! Save-hypothesis-as-Sigma: consume a DSL pattern + current IoC set,
//! produce a Sigma YAML rule.
//!
//! The mapping from Graph Hunter concepts to Sigma is best-effort. The
//! canonical cloud-identity and endpoint chains are handled explicitly
//! (Auth, Connect, Execute, Spawn, DNS); unknown combos emit a comment
//! block marking the gap so the analyst knows to customize.

use graph_hunter_core::{Hypothesis, Predicate, format_hypothesis, parse_dsl};

use crate::dto::sigma::{SaveHypothesisAsSigmaRequest, SigmaRuleResponse};
use crate::{ApiError, ApiResult, GraphHunterApi};

impl GraphHunterApi {
    /// Convert a hypothesis DSL + current IoC tag set into a Sigma rule
    /// YAML.
    pub fn save_hypothesis_as_sigma(
        &self,
        req: SaveHypothesisAsSigmaRequest,
    ) -> ApiResult<SigmaRuleResponse> {
        if req.title.trim().is_empty() {
            return Err(ApiError::InvalidInput("title is required".into()));
        }
        let hypothesis = parse_dsl(req.hypothesis_dsl.trim(), Some(req.title.as_str()))
            .map_err(|e| ApiError::InvalidInput(e.to_string()))?
            .hypothesis;

        let prefix = req.tag_prefix.unwrap_or_else(|| "ioc:".to_string());

        let session = self.resolve_session(req.session.as_ref())?;
        let items: Vec<(String, String)> = {
            let tags = session
                .tags
                .read()
                .map_err(|e| ApiError::Internal(format!("tags lock poisoned: {e}")))?;
            let graph = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            let mut out = Vec::new();
            for t in tags.iter() {
                if !prefix.is_empty() && !t.tag.starts_with(&prefix) {
                    continue;
                }
                let etype = graph
                    .get_entity(&t.node_id)
                    .map(|e| format!("{}", e.entity_type))
                    .unwrap_or_else(|| "Unknown".to_string());
                out.push((t.node_id.clone(), etype));
            }
            out
        };

        let (yaml, fully_mapped) = build_sigma_from_hypothesis(
            &hypothesis,
            &req.title,
            req.level.as_deref().unwrap_or("medium"),
            &items,
        );
        Ok(SigmaRuleResponse {
            yaml,
            title: req.title,
            fully_mapped,
        })
    }
}

/// Pure function: hypothesis + title + level + IoC set → Sigma YAML.
pub fn build_sigma_from_hypothesis(
    hypothesis: &Hypothesis,
    title: &str,
    level: &str,
    iocs: &[(String, String)],
) -> (String, bool) {
    let mut out = String::new();
    let uuid = deterministic_uuid(title);

    out.push_str(&format!("title: {}\n", yaml_safe(title)));
    out.push_str(&format!("id: {}\n", uuid));
    out.push_str("status: experimental\n");
    out.push_str(&format!(
        "description: |\n  Auto-generated from Graph Hunter hypothesis. Pattern: {}.\n  Review selection fields and timeframe before deploying.\n",
        yaml_safe(&format_hypothesis(hypothesis))
    ));
    out.push_str("author: GraphHunter\n");
    out.push_str("references:\n  - https://github.com/base4sec/graph-hunter\n");

    // Logsource derived from first step; multi-step patterns compile down
    // to one base logsource + filters.
    let first = match hypothesis.steps.first() {
        Some(s) => s,
        None => {
            out.push_str("logsource:\n  category: unknown\n");
            out.push_str("detection:\n  condition: selection\nlevel: ");
            out.push_str(level);
            out.push('\n');
            return (out, false);
        }
    };
    let rel = format!("{}", first.relation_type);
    let dst = format!("{}", first.dest_type);
    let src = format!("{}", first.origin_type);
    let (logsource_yaml, fields, known) = logsource_for(&src, &rel, &dst);
    out.push_str(&logsource_yaml);

    out.push_str("detection:\n");
    out.push_str("  selection:\n");
    if let Some(eid) = fields.rel_event_id {
        out.push_str(&format!("    EventID: {eid}\n"));
    }
    emit_predicates_as_selection(&mut out, first, &fields);

    let (ip_iocs, domain_iocs, user_iocs, file_iocs): (Vec<&str>, Vec<&str>, Vec<&str>, Vec<&str>) = {
        let mut ips = Vec::new();
        let mut ds = Vec::new();
        let mut us = Vec::new();
        let mut fs = Vec::new();
        for (id, et) in iocs {
            match et.as_str() {
                "IP" => ips.push(id.as_str()),
                "Domain" => ds.push(id.as_str()),
                "User" => us.push(id.as_str()),
                "File" => fs.push(id.as_str()),
                _ => {}
            }
        }
        (ips, ds, us, fs)
    };
    if let Some(ip_field) = fields.ip_field {
        if !ip_iocs.is_empty() {
            out.push_str(&format!("    {ip_field}:\n"));
            for ip in &ip_iocs {
                out.push_str(&format!("      - '{ip}'\n"));
            }
        }
    }
    if let Some(domain_field) = fields.domain_field {
        if !domain_iocs.is_empty() {
            out.push_str(&format!("    {domain_field}:\n"));
            for d in &domain_iocs {
                out.push_str(&format!("      - '{d}'\n"));
            }
        }
    }
    if let Some(user_field) = fields.user_field {
        if !user_iocs.is_empty() {
            out.push_str(&format!("    {user_field}:\n"));
            for u in &user_iocs {
                out.push_str(&format!("      - '{u}'\n"));
            }
        }
    }
    if let Some(file_field) = fields.file_field {
        if !file_iocs.is_empty() {
            out.push_str(&format!("    {file_field}:\n"));
            for f in &file_iocs {
                out.push_str(&format!("      - '{f}'\n"));
            }
        }
    }

    let condition = if let Some(agg) = hypothesis.aggregations.first() {
        let by_field = sigma_field_for_column(&agg.column, &fields);
        format!(
            "selection | count() by {} > {}",
            by_field,
            agg.min_distinct.saturating_sub(1)
        )
    } else {
        "selection".to_string()
    };
    out.push_str(&format!("  condition: {}\n", condition));

    if let Some(w) = hypothesis.window_seconds {
        out.push_str("  # NOTE: Sigma's `timeframe` is a rule-level key. Moved below.\n");
        let tf = format_timeframe(w);
        out.push_str(&format!("timeframe: {tf}\n"));
    }

    out.push_str("fields:\n");
    if let Some(f) = fields.ip_field {
        out.push_str(&format!("  - {f}\n"));
    }
    if let Some(f) = fields.domain_field {
        out.push_str(&format!("  - {f}\n"));
    }
    if let Some(f) = fields.user_field {
        out.push_str(&format!("  - {f}\n"));
    }

    out.push_str("falsepositives:\n  - Legitimate administrative activity\n");
    out.push_str(&format!("level: {level}\n"));

    if !known {
        out.push_str(&format!(
            "\n# NOTE: the pattern `{} -[{}]-> {}` has no canonical Sigma\n# logsource mapping in GraphHunter. Replace the logsource block\n# above with the correct category/product for your SIEM.\n",
            src, rel, dst,
        ));
    }

    (out, known)
}

#[derive(Default)]
struct SigmaFields {
    ip_field: Option<&'static str>,
    domain_field: Option<&'static str>,
    user_field: Option<&'static str>,
    file_field: Option<&'static str>,
    rel_event_id: Option<u32>,
    status_field: Option<&'static str>,
    app_field: Option<&'static str>,
}

fn logsource_for(src: &str, rel: &str, dst: &str) -> (String, SigmaFields, bool) {
    match (src, rel, dst) {
        ("User", "Auth", "IP") => (
            "logsource:\n  product: azure\n  service: signinlogs\n".to_string(),
            SigmaFields {
                ip_field: Some("IPAddress"),
                user_field: Some("UserPrincipalName"),
                status_field: Some("ResultType"),
                app_field: Some("AppDisplayName"),
                ..Default::default()
            },
            true,
        ),
        ("User", "Auth", "Host") | ("Host", "Auth", "User") => (
            "logsource:\n  product: windows\n  service: security\n".to_string(),
            SigmaFields {
                ip_field: Some("IpAddress"),
                user_field: Some("TargetUserName"),
                rel_event_id: Some(4624),
                status_field: Some("LogonType"),
                ..Default::default()
            },
            true,
        ),
        ("Host", "Connect", "IP") | ("Process", "Connect", "IP") => (
            "logsource:\n  category: network_connection\n  product: windows\n".to_string(),
            SigmaFields {
                ip_field: Some("DestinationIp"),
                ..Default::default()
            },
            true,
        ),
        ("Process", "DNS", "Domain") => (
            "logsource:\n  category: dns\n  product: windows\n".to_string(),
            SigmaFields {
                domain_field: Some("QueryName"),
                ..Default::default()
            },
            true,
        ),
        ("User", "Execute", "Process") | ("Process", "Spawn", "Process") => (
            "logsource:\n  category: process_creation\n  product: windows\n".to_string(),
            SigmaFields {
                user_field: Some("User"),
                file_field: Some("Image"),
                rel_event_id: Some(1),
                ..Default::default()
            },
            true,
        ),
        ("Process", "Write", "File") | ("Process", "Read", "File") => (
            "logsource:\n  category: file_event\n  product: windows\n".to_string(),
            SigmaFields {
                file_field: Some("TargetFilename"),
                ..Default::default()
            },
            true,
        ),
        ("Process", "Modify", "Registry") => (
            "logsource:\n  category: registry_event\n  product: windows\n".to_string(),
            SigmaFields::default(),
            true,
        ),
        _ => (
            "logsource:\n  category: unknown\n".to_string(),
            SigmaFields::default(),
            false,
        ),
    }
}

fn emit_predicates_as_selection(
    out: &mut String,
    step: &graph_hunter_core::HypothesisStep,
    fields: &SigmaFields,
) {
    for p in &step.edge_predicates {
        match p {
            Predicate::Eq { key, value } => {
                let field = map_predicate_key_to_field(key, fields);
                out.push_str(&format!("    {field}: '{}'\n", yaml_escape_value(value)));
            }
            Predicate::Neq { key, value } => {
                let field = map_predicate_key_to_field(key, fields);
                out.push_str(&format!(
                    "    # note: add filter:\\n    #   {field}: '{}' and adjust condition with `and not filter`.\n",
                    yaml_escape_value(value)
                ));
            }
            Predicate::Match { key, value } => {
                let field = map_predicate_key_to_field(key, fields);
                out.push_str(&format!(
                    "    {field}|contains: '{}'\n",
                    yaml_escape_value(value)
                ));
            }
            Predicate::In { key, values } => {
                let field = map_predicate_key_to_field(key, fields);
                out.push_str(&format!("    {field}:\n"));
                for v in values {
                    out.push_str(&format!("      - '{}'\n", yaml_escape_value(v)));
                }
            }
            Predicate::NotIn { key, values } => {
                let field = map_predicate_key_to_field(key, fields);
                out.push_str(&format!("    # note: add filter:\\n    #   {field}:\\n"));
                for v in values {
                    out.push_str(&format!("    #     - '{}'\\n", yaml_escape_value(v)));
                }
            }
        }
    }
}

fn map_predicate_key_to_field(key: &str, fields: &SigmaFields) -> String {
    match key {
        "status" => fields.status_field.unwrap_or("ResultType").to_string(),
        "app" => fields.app_field.unwrap_or("AppDisplayName").to_string(),
        other => other.to_string(),
    }
}

fn sigma_field_for_column(col: &graph_hunter_core::AggColumn, fields: &SigmaFields) -> String {
    match col {
        graph_hunter_core::AggColumn::First => {
            fields.user_field.unwrap_or("UserPrincipalName").to_string()
        }
        graph_hunter_core::AggColumn::Last => fields.ip_field.unwrap_or("IPAddress").to_string(),
        graph_hunter_core::AggColumn::Named(n) => n.clone(),
    }
}

fn format_timeframe(secs: i64) -> String {
    if secs % 86_400 == 0 {
        format!("{}d", secs / 86_400)
    } else if secs % 3600 == 0 {
        format!("{}h", secs / 3600)
    } else if secs % 60 == 0 {
        format!("{}m", secs / 60)
    } else {
        format!("{}s", secs)
    }
}

fn yaml_safe(s: &str) -> String {
    let needs = s
        .chars()
        .any(|c| matches!(c, ':' | '#' | '&' | '*' | '?' | '!' | '\n'));
    if needs {
        format!("\"{}\"", s.replace('"', "\\\""))
    } else {
        s.to_string()
    }
}

fn yaml_escape_value(s: &str) -> String {
    s.replace('\'', "''").replace('\n', " ")
}

fn deterministic_uuid(title: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in title.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (hash >> 32) as u32,
        (hash >> 16) as u16 & 0xffff,
        (hash as u16) & 0xffff,
        (hash >> 48) as u16 & 0xffff,
        hash & 0xffff_ffff_ffff,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigma_rule_for_aad_password_spray_has_correct_logsource() {
        let h = parse_dsl(
            r#"User -[Auth {status="Failure"}]-> IP HAVING count(distinct IP) >= 3 WITHIN 24h"#,
            None,
        )
        .unwrap()
        .hypothesis;
        let (yaml, fully) = build_sigma_from_hypothesis(&h, "Password Spray", "high", &[]);
        assert!(fully);
        assert!(yaml.contains("product: azure"));
        assert!(yaml.contains("service: signinlogs"));
        assert!(yaml.contains("ResultType: 'Failure'"));
        assert!(yaml.contains("timeframe: 1d") || yaml.contains("timeframe: 24h"));
        assert!(yaml.contains("count() by IPAddress > 2"));
        assert!(yaml.contains("level: high"));
    }

    #[test]
    fn sigma_rule_for_process_spawn_maps_to_process_creation() {
        let h = parse_dsl(r#"Process -[Spawn]-> Process"#, None)
            .unwrap()
            .hypothesis;
        let (yaml, fully) = build_sigma_from_hypothesis(&h, "Spawn chain", "medium", &[]);
        assert!(fully);
        assert!(yaml.contains("category: process_creation"));
        assert!(yaml.contains("EventID: 1"));
    }

    #[test]
    fn unknown_triple_produces_commented_gap() {
        let h = parse_dsl(r#"Service -[Connect]-> Domain"#, None)
            .unwrap()
            .hypothesis;
        let (yaml, fully) = build_sigma_from_hypothesis(&h, "Weird pattern", "low", &[]);
        assert!(!fully);
        assert!(yaml.contains("category: unknown"));
        assert!(yaml.contains("# NOTE: the pattern"));
    }

    #[test]
    fn iocs_seed_detection_fields() {
        let h = parse_dsl(r#"User -[Auth]-> IP"#, None).unwrap().hypothesis;
        let iocs = vec![
            ("1.2.3.4".to_string(), "IP".to_string()),
            ("5.6.7.8".to_string(), "IP".to_string()),
        ];
        let (yaml, _) = build_sigma_from_hypothesis(&h, "AAD spray", "medium", &iocs);
        assert!(yaml.contains("IPAddress:"));
        assert!(yaml.contains("'1.2.3.4'"));
        assert!(yaml.contains("'5.6.7.8'"));
    }

    #[test]
    fn deterministic_uuid_stable_for_same_title() {
        let a = deterministic_uuid("Password Spray");
        let b = deterministic_uuid("Password Spray");
        let c = deterministic_uuid("Password Spray — v2");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
