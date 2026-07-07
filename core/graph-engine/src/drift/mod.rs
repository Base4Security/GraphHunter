//! Per-batch drift statistics collector (M5 Win 3 D4).
//!
//! Attaches a minimal schema-drift sketch to each parse batch:
//! for every observed field, a type-tag histogram and a null count.
//! D4 ships type-histogram + null-rate only — HLL cardinality and
//! bloom "seen-before" filters are deferred to the full M5 drop.
//!
//! The collector is called once per event by
//! [`crate::generic::parse_events_with_stats`]; the snapshot rides
//! along on [`crate::parser::ParseStats::drift`] so any caller that
//! already consumes `ParseStats` gets drift for free.
//!
//! The D6 Prometheus exporter and the D5 SQLite persist layer both
//! consume [`DriftSnapshot`] — `merge()` is the aggregation surface.

pub mod store;

pub use store::{DriftStore, DriftStoreError};

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Coarse type tag for a single observed value. Deliberately flat
/// (not the entity-type taxonomy) so shifts between e.g. "was an IP,
/// now a Domain" surface without the catalog coupling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldTypeTag {
    Null,
    Bool,
    Integer,
    Float,
    Datetime,
    Ip,
    Email,
    Url,
    Domain,
    Hash,
    String,
    Other,
}

impl FieldTypeTag {
    pub fn as_str(&self) -> &'static str {
        match self {
            FieldTypeTag::Null => "null",
            FieldTypeTag::Bool => "bool",
            FieldTypeTag::Integer => "integer",
            FieldTypeTag::Float => "float",
            FieldTypeTag::Datetime => "datetime",
            FieldTypeTag::Ip => "ip",
            FieldTypeTag::Email => "email",
            FieldTypeTag::Url => "url",
            FieldTypeTag::Domain => "domain",
            FieldTypeTag::Hash => "hash",
            FieldTypeTag::String => "string",
            FieldTypeTag::Other => "other",
        }
    }
}

/// Per-field drift stats for one parse batch.
#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FieldDriftStats {
    /// Times this field was observed (present in the event, whether
    /// populated or null/empty).
    pub total: usize,
    /// Subset of `total` where the value was null or an empty string.
    pub null: usize,
    /// Subset of `total` where the value was present and non-empty.
    pub non_null: usize,
    /// Histogram of type tags across all non-null observations. Keyed
    /// by [`FieldTypeTag::as_str`] for stable JSON ordering.
    #[serde(default)]
    pub type_histogram: HashMap<String, usize>,
}

impl FieldDriftStats {
    pub fn null_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.null as f64 / self.total as f64
        }
    }

    pub fn dominant_tag(&self) -> Option<&str> {
        self.type_histogram
            .iter()
            .max_by_key(|(_, c)| *c)
            .map(|(k, _)| k.as_str())
    }

    pub fn merge(&mut self, other: &FieldDriftStats) {
        self.total += other.total;
        self.null += other.null;
        self.non_null += other.non_null;
        for (tag, count) in &other.type_histogram {
            *self.type_histogram.entry(tag.clone()).or_default() += count;
        }
    }
}

/// Aggregate drift snapshot for one parse batch.
#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DriftSnapshot {
    pub rows_observed: usize,
    pub fields: HashMap<String, FieldDriftStats>,
}

impl DriftSnapshot {
    pub fn merge(&mut self, other: &DriftSnapshot) {
        self.rows_observed += other.rows_observed;
        for (k, v) in &other.fields {
            self.fields.entry(k.clone()).or_default().merge(v);
        }
    }

    pub fn null_rate(&self, field: &str) -> Option<f64> {
        self.fields.get(field).map(FieldDriftStats::null_rate)
    }
}

/// Single-batch drift accumulator. Not thread-safe — intended to be
/// used inside the sequential event loop of `parse_events_with_stats`.
pub struct DriftCollector {
    snapshot: DriftSnapshot,
}

impl DriftCollector {
    pub fn new() -> Self {
        Self {
            snapshot: DriftSnapshot::default(),
        }
    }

    /// Observe a JSON event. Each key/value pair contributes one
    /// observation to the corresponding field.
    pub fn observe_event(&mut self, event: &Value) {
        self.snapshot.rows_observed += 1;
        let Some(obj) = event.as_object() else {
            return;
        };
        for (key, value) in obj {
            let tag = classify_value(value);
            let stats = self.snapshot.fields.entry(key.clone()).or_default();
            stats.total += 1;
            if matches!(tag, FieldTypeTag::Null) {
                stats.null += 1;
            } else {
                stats.non_null += 1;
                *stats
                    .type_histogram
                    .entry(tag.as_str().to_string())
                    .or_default() += 1;
            }
        }
    }

    pub fn into_snapshot(self) -> DriftSnapshot {
        self.snapshot
    }
}

impl Default for DriftCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Classify one JSON value to a coarse type tag. Strings go through
/// [`classify_string`] to detect structured content (ip, email, ...).
pub fn classify_value(v: &Value) -> FieldTypeTag {
    match v {
        Value::Null => FieldTypeTag::Null,
        Value::Bool(_) => FieldTypeTag::Bool,
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                FieldTypeTag::Integer
            } else {
                FieldTypeTag::Float
            }
        }
        Value::String(s) => classify_string(s),
        Value::Array(_) | Value::Object(_) => FieldTypeTag::Other,
    }
}

fn classify_string(s: &str) -> FieldTypeTag {
    let v = s.trim();
    if v.is_empty() {
        return FieldTypeTag::Null;
    }
    if looks_like_ip(v) {
        return FieldTypeTag::Ip;
    }
    if looks_like_hash(v) {
        return FieldTypeTag::Hash;
    }
    if looks_like_email(v) {
        return FieldTypeTag::Email;
    }
    if v.starts_with("http://") || v.starts_with("https://") || v.starts_with("ftp://") {
        return FieldTypeTag::Url;
    }
    if looks_like_datetime(v) {
        return FieldTypeTag::Datetime;
    }
    if v.parse::<i64>().is_ok() || v.parse::<u64>().is_ok() {
        return FieldTypeTag::Integer;
    }
    if v.parse::<f64>().is_ok() {
        return FieldTypeTag::Float;
    }
    if looks_like_domain(v) {
        return FieldTypeTag::Domain;
    }
    FieldTypeTag::String
}

fn looks_like_ip(s: &str) -> bool {
    // IPv4: four 0..=255 octets
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u8>().is_ok())
    {
        return true;
    }
    // IPv6 loose heuristic
    if s.contains(':') {
        let segments: Vec<&str> = s.split(':').collect();
        let colons = s.matches(':').count();
        if colons >= 2
            && segments.iter().all(|seg| {
                seg.is_empty() || (seg.len() <= 4 && seg.chars().all(|c| c.is_ascii_hexdigit()))
            })
        {
            return true;
        }
    }
    false
}

fn looks_like_hash(s: &str) -> bool {
    matches!(s.len(), 32 | 40 | 64) && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn looks_like_email(s: &str) -> bool {
    let Some(at) = s.find('@') else {
        return false;
    };
    let (local, rest) = s.split_at(at);
    let host = &rest[1..];
    !local.is_empty()
        && host.contains('.')
        && !host.starts_with('.')
        && !host.ends_with('.')
        && !local.contains(' ')
        && !host.contains(' ')
}

fn looks_like_datetime(s: &str) -> bool {
    // ISO-8601 prefix: YYYY-MM-DD
    if s.len() >= 10 {
        let bytes = s.as_bytes();
        let year_ok = bytes[..4].iter().all(|b| b.is_ascii_digit());
        if year_ok && bytes[4] == b'-' && bytes[7] == b'-' {
            return true;
        }
    }
    // Unix epoch seconds in the 2001-2100 range
    if let Ok(n) = s.parse::<i64>() {
        if (1_000_000_000..4_000_000_000).contains(&n) {
            return true;
        }
    }
    // Unix epoch millis in the 2001-2100 range
    if let Ok(n) = s.parse::<i64>() {
        if (1_000_000_000_000..4_000_000_000_000).contains(&n) {
            return true;
        }
    }
    false
}

fn looks_like_domain(s: &str) -> bool {
    // Conservative: at least one dot, labels are alnum/hyphen, tld 2+ chars
    if !s.contains('.') || s.starts_with('.') || s.ends_with('.') || s.contains(' ') {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let tld = *labels.last().unwrap();
    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    labels.iter().all(|lab| {
        !lab.is_empty()
            && lab.len() <= 63
            && lab.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !lab.starts_with('-')
            && !lab.ends_with('-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classify_scalars_by_json_kind() {
        assert_eq!(classify_value(&Value::Null), FieldTypeTag::Null);
        assert_eq!(classify_value(&json!(true)), FieldTypeTag::Bool);
        assert_eq!(classify_value(&json!(42)), FieldTypeTag::Integer);
        assert_eq!(classify_value(&json!(3.14)), FieldTypeTag::Float);
    }

    #[test]
    fn classify_strings_by_shape() {
        assert_eq!(classify_value(&json!("")), FieldTypeTag::Null);
        assert_eq!(classify_value(&json!("   ")), FieldTypeTag::Null);
        assert_eq!(classify_value(&json!("10.0.0.1")), FieldTypeTag::Ip);
        assert_eq!(classify_value(&json!("2001:db8::1")), FieldTypeTag::Ip);
        assert_eq!(
            classify_value(&json!("alice@example.com")),
            FieldTypeTag::Email
        );
        assert_eq!(
            classify_value(&json!("https://example.com/a")),
            FieldTypeTag::Url
        );
        assert_eq!(classify_value(&json!("example.com")), FieldTypeTag::Domain);
        assert_eq!(
            classify_value(&json!("2024-01-15T10:00:00Z")),
            FieldTypeTag::Datetime
        );
        assert_eq!(classify_value(&json!("1700000000")), FieldTypeTag::Datetime);
        assert_eq!(
            classify_value(&json!("5d41402abc4b2a76b9719d911017c592")),
            FieldTypeTag::Hash
        );
        assert_eq!(classify_value(&json!("42")), FieldTypeTag::Integer);
        assert_eq!(classify_value(&json!("3.14")), FieldTypeTag::Float);
        assert_eq!(classify_value(&json!("hello world")), FieldTypeTag::String);
    }

    #[test]
    fn collector_counts_presence_and_null() {
        let mut c = DriftCollector::new();
        c.observe_event(
            &json!({"src_ip": "10.0.0.1", "user": "alice", "ts": "2024-01-15T10:00:00Z"}),
        );
        c.observe_event(&json!({"src_ip": "10.0.0.2", "user": "", "ts": null}));
        c.observe_event(
            &json!({"src_ip": "not-an-ip", "user": "bob", "ts": "2024-01-15T11:00:00Z"}),
        );

        let snap = c.into_snapshot();
        assert_eq!(snap.rows_observed, 3);

        let src = snap.fields.get("src_ip").unwrap();
        assert_eq!(src.total, 3);
        assert_eq!(src.null, 0);
        assert_eq!(src.non_null, 3);
        assert_eq!(src.type_histogram.get("ip"), Some(&2));
        assert_eq!(src.type_histogram.get("string"), Some(&1));

        let user = snap.fields.get("user").unwrap();
        assert_eq!(user.null, 1);
        assert_eq!(user.non_null, 2);
        assert!((user.null_rate() - 1.0 / 3.0).abs() < 1e-9);

        let ts = snap.fields.get("ts").unwrap();
        assert_eq!(ts.null, 1);
        assert_eq!(ts.type_histogram.get("datetime"), Some(&2));
    }

    #[test]
    fn merge_combines_snapshots() {
        let mut a = DriftCollector::new();
        a.observe_event(&json!({"f": "10.0.0.1"}));
        a.observe_event(&json!({"f": "10.0.0.2"}));
        let mut merged = a.into_snapshot();

        let mut b = DriftCollector::new();
        b.observe_event(&json!({"f": "example.com"}));
        let b_snap = b.into_snapshot();

        merged.merge(&b_snap);
        assert_eq!(merged.rows_observed, 3);
        let f = merged.fields.get("f").unwrap();
        assert_eq!(f.total, 3);
        assert_eq!(f.type_histogram.get("ip"), Some(&2));
        assert_eq!(f.type_histogram.get("domain"), Some(&1));
    }

    #[test]
    fn dominant_tag_picks_majority() {
        let mut c = DriftCollector::new();
        c.observe_event(&json!({"x": "a"}));
        c.observe_event(&json!({"x": "b"}));
        c.observe_event(&json!({"x": 42}));
        let snap = c.into_snapshot();
        let f = snap.fields.get("x").unwrap();
        assert_eq!(f.dominant_tag(), Some("string"));
    }
}
