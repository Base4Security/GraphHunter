//! Elasticsearch query runner.
//!
//! Uses the Search API. Auth via optional ElasticAuth (from UI/params) or env: ELASTIC_API_KEY or ELASTIC_USER/ELASTIC_PASSWORD.

use serde_json::Value;

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
    let client = reqwest::blocking::Client::new();
    let base = url.trim_end_matches('/');
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
    if !auth_applied {
        if let Ok(api_key) = std::env::var("ELASTIC_API_KEY") {
            req = req.header("Authorization", format!("ApiKey {}", api_key));
        } else if let (Ok(user), Ok(pass)) = (
            std::env::var("ELASTIC_USER"),
            std::env::var("ELASTIC_PASSWORD"),
        ) {
            req = req.basic_auth(user, Some(pass));
        }
    }

    let resp = req.send().map_err(|e| format!("search request failed: {}", e))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
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
