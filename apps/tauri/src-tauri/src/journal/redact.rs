use serde_json::Value;

fn is_secret_key(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    k == "azure_client_secret"
        || k == "azure_client_id"
        || k.contains("secret")
        || k.contains("token")
        || k.contains("password")
}

/// Deep-clone `v`, replacing any secret-bearing field's value with "[REDACTED]".
pub fn redact_secrets(v: &Value) -> Value {
    match v {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, val)| {
                    if is_secret_key(k) {
                        (k.clone(), Value::String("[REDACTED]".into()))
                    } else {
                        (k.clone(), redact_secrets(val))
                    }
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(redact_secrets).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn redacts_azure_secret_and_tokenish_keys() {
        let v = json!({
            "kql": "SigninLogs | take 1",
            "azure_client_secret": "supersecret",
            "azure_client_id": "id-123",
            "nested": { "api_token": "abc", "keep": "ok" },
            "list": [{ "password": "pw" }]
        });
        let r = redact_secrets(&v);
        assert_eq!(r["azure_client_secret"], "[REDACTED]");
        assert_eq!(r["azure_client_id"], "[REDACTED]");
        assert_eq!(r["nested"]["api_token"], "[REDACTED]");
        assert_eq!(r["list"][0]["password"], "[REDACTED]");
        assert_eq!(r["kql"], "SigninLogs | take 1"); // non-secret preserved
        assert_eq!(r["nested"]["keep"], "ok");
        // original untouched
        assert_eq!(v["azure_client_secret"], "supersecret");
    }
}
