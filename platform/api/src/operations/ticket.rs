//! File-a-ticket — async HTTP POST into Jira Cloud or ServiceNow.
//!
//! The three-gate safety pattern is enforced here, not in the
//! transports: env flag `GRAPHHUNTER_TICKET_PUBLISH_ENABLED=1` to turn
//! the feature on process-wide, explicit `confirm: true` to proceed with
//! a real post, and `dry_run: true` to short-circuit to payload preview.

use crate::dto::ticket::{FileTicketRequest, TicketResponse};
use crate::{ApiError, ApiResult, GraphHunterApi};

impl GraphHunterApi {
    /// File an incident / issue ticket. Returns the built payload in
    /// dry-run mode; posts and records the ticket key/number otherwise.
    pub async fn file_ticket(&self, req: FileTicketRequest) -> ApiResult<TicketResponse> {
        if !is_publish_enabled() {
            return Err(ApiError::InvalidInput(
                "Ticket filing is disabled. Set GRAPHHUNTER_TICKET_PUBLISH_ENABLED=1 in the environment and restart the app to enable."
                    .into(),
            ));
        }
        if !req.dry_run && !req.confirm {
            return Err(ApiError::InvalidInput(
                "Filing a ticket mutates an external system. Pass `confirm: true` to proceed, or `dry_run: true` to preview the payload.".into(),
            ));
        }
        if req.title.trim().is_empty() {
            return Err(ApiError::InvalidInput("title is required".into()));
        }

        match req.system.as_str() {
            "jira" => file_jira(req.title, req.body, req.priority, req.assignee, req.dry_run).await,
            "servicenow" => {
                file_servicenow(req.title, req.body, req.priority, req.assignee, req.dry_run).await
            }
            other => Err(ApiError::InvalidInput(format!(
                "unsupported ticket system: '{other}'. Use 'jira' or 'servicenow'."
            ))),
        }
    }
}

fn is_publish_enabled() -> bool {
    std::env::var("GRAPHHUNTER_TICKET_PUBLISH_ENABLED")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "True"))
        .unwrap_or(false)
}

fn env_required(key: &str) -> ApiResult<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(ApiError::InvalidInput(format!(
            "{key} must be set in the environment (check your .env)"
        ))),
    }
}

async fn file_jira(
    title: String,
    body: String,
    priority: Option<String>,
    assignee: Option<String>,
    dry_run: bool,
) -> ApiResult<TicketResponse> {
    let base_url = env_required("JIRA_BASE_URL")?;
    let email = env_required("JIRA_EMAIL")?;
    let api_token = env_required("JIRA_API_TOKEN")?;
    let project_key = env_required("JIRA_PROJECT_KEY")?;
    let issue_type = std::env::var("JIRA_ISSUE_TYPE").unwrap_or_else(|_| "Task".into());

    let target_url = format!("{}/rest/api/3/issue", base_url.trim_end_matches('/'));
    let payload = build_jira_payload(
        &project_key,
        &issue_type,
        &title,
        &body,
        priority.as_deref(),
        assignee.as_deref(),
    );

    if dry_run {
        return Ok(TicketResponse {
            posted: false,
            dry_run: true,
            system: "jira".into(),
            target_url,
            payload,
            http_status: None,
            ticket_id: None,
            response_body: None,
        });
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| ApiError::Internal(format!("reqwest build failed: {e}")))?;
    let resp = client
        .post(&target_url)
        .basic_auth(&email, Some(&api_token))
        .json(&payload)
        .send()
        .await
        .map_err(|e| ApiError::Upstream {
            service: "jira".into(),
            message: format!("POST failed: {e}"),
        })?;
    let status = resp.status().as_u16();
    let body_text = resp.text().await.unwrap_or_default();

    let ticket_id = serde_json::from_str::<serde_json::Value>(&body_text)
        .ok()
        .and_then(|v| v.get("key").and_then(|k| k.as_str().map(|s| s.to_string())));

    Ok(TicketResponse {
        posted: true,
        dry_run: false,
        system: "jira".into(),
        target_url,
        payload,
        http_status: Some(status),
        ticket_id,
        response_body: Some(body_text),
    })
}

async fn file_servicenow(
    title: String,
    body: String,
    priority: Option<String>,
    assignee: Option<String>,
    dry_run: bool,
) -> ApiResult<TicketResponse> {
    let instance = env_required("SERVICENOW_INSTANCE")?;
    let username = env_required("SERVICENOW_USERNAME")?;
    let password = env_required("SERVICENOW_PASSWORD")?;
    let table = std::env::var("SERVICENOW_TABLE").unwrap_or_else(|_| "incident".into());

    let target_url = format!("https://{instance}.service-now.com/api/now/table/{table}");
    let payload = build_servicenow_payload(&title, &body, priority.as_deref(), assignee.as_deref());

    if dry_run {
        return Ok(TicketResponse {
            posted: false,
            dry_run: true,
            system: "servicenow".into(),
            target_url,
            payload,
            http_status: None,
            ticket_id: None,
            response_body: None,
        });
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| ApiError::Internal(format!("reqwest build failed: {e}")))?;
    let resp = client
        .post(&target_url)
        .basic_auth(&username, Some(&password))
        .header("Accept", "application/json")
        .json(&payload)
        .send()
        .await
        .map_err(|e| ApiError::Upstream {
            service: "servicenow".into(),
            message: format!("POST failed: {e}"),
        })?;
    let status = resp.status().as_u16();
    let body_text = resp.text().await.unwrap_or_default();

    let ticket_id = serde_json::from_str::<serde_json::Value>(&body_text)
        .ok()
        .and_then(|v| {
            v.get("result")
                .and_then(|r| r.get("number"))
                .and_then(|n| n.as_str().map(|s| s.to_string()))
        });

    Ok(TicketResponse {
        posted: true,
        dry_run: false,
        system: "servicenow".into(),
        target_url,
        payload,
        http_status: Some(status),
        ticket_id,
        response_body: Some(body_text),
    })
}

/// Pure function: build Jira's Atlassian Document Format body.
pub fn build_jira_payload(
    project_key: &str,
    issue_type: &str,
    title: &str,
    body: &str,
    priority: Option<&str>,
    assignee: Option<&str>,
) -> serde_json::Value {
    let mut fields = serde_json::json!({
        "project": { "key": project_key },
        "issuetype": { "name": issue_type },
        "summary": title,
        "description": {
            "type": "doc",
            "version": 1,
            "content": [{
                "type": "paragraph",
                "content": [{ "type": "text", "text": body }]
            }]
        },
    });
    if let Some(p) = priority {
        fields["priority"] = serde_json::json!({ "name": p });
    }
    if let Some(a) = assignee {
        fields["assignee"] = serde_json::json!({ "accountId": a });
    }
    serde_json::json!({ "fields": fields })
}

/// Pure function: build ServiceNow incident payload.
pub fn build_servicenow_payload(
    title: &str,
    body: &str,
    priority: Option<&str>,
    assignee: Option<&str>,
) -> serde_json::Value {
    let mut v = serde_json::json!({
        "short_description": title,
        "description": body,
    });
    if let Some(p) = priority {
        v["urgency"] = serde_json::Value::String(p.to_string());
    }
    if let Some(a) = assignee {
        v["assigned_to"] = serde_json::Value::String(a.to_string());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jira_payload_has_adf_description_and_project() {
        let v = build_jira_payload(
            "SEC",
            "Task",
            "Spray campaign",
            "26 IoCs confirmed",
            Some("High"),
            None,
        );
        assert_eq!(v["fields"]["project"]["key"], "SEC");
        assert_eq!(v["fields"]["issuetype"]["name"], "Task");
        assert_eq!(v["fields"]["summary"], "Spray campaign");
        assert_eq!(v["fields"]["priority"]["name"], "High");
        let txt = &v["fields"]["description"]["content"][0]["content"][0]["text"];
        assert_eq!(txt, "26 IoCs confirmed");
    }

    #[test]
    fn servicenow_payload_uses_urgency_key() {
        let v = build_servicenow_payload("title", "body", Some("2"), Some("alice"));
        assert_eq!(v["short_description"], "title");
        assert_eq!(v["description"], "body");
        assert_eq!(v["urgency"], "2");
        assert_eq!(v["assigned_to"], "alice");
    }

    #[test]
    fn payloads_omit_optional_fields_when_none() {
        let j = build_jira_payload("X", "Bug", "t", "b", None, None);
        assert!(j["fields"].get("priority").is_none());
        assert!(j["fields"].get("assignee").is_none());
        let s = build_servicenow_payload("t", "b", None, None);
        assert!(s.get("urgency").is_none());
        assert!(s.get("assigned_to").is_none());
    }
}
