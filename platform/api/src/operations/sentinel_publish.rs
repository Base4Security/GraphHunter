//! C.2 — Publish tagged IoCs to an Azure Sentinel Watchlist.
//!
//! Mutates external state (the Sentinel tenant). Gated by THREE things:
//! 1. Runtime env flag `GRAPHHUNTER_IOC_PUBLISH_ENABLED=1` — operator
//!    opt-in at the process level.
//! 2. Explicit `confirm: true` parameter — per-call opt-in.
//! 3. Optional `dry_run: true` — returns the payload + target URL
//!    without posting.
//!
//! Auth: client_credentials against
//! `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` with
//! scope `https://management.azure.com/.default`. The Watchlist API
//! lives in the management plane (ARM), NOT in Log Analytics ingestion.

use crate::dto::sentinel::{PublishIocsRequest, PublishIocsResponse};
use crate::operations::export::build_sentinel_watchlist_csv;
use crate::{ApiError, ApiResult, GraphHunterApi};

const TOKEN_SCOPE: &str = "https://management.azure.com/.default";
const ARM_API_VERSION: &str = "2023-02-01";

impl GraphHunterApi {
    /// Publish the resolved session's tagged IoCs as a Sentinel
    /// Watchlist. See module docs for the three-gate safety shape.
    pub async fn publish_iocs_to_sentinel(
        &self,
        req: PublishIocsRequest,
    ) -> ApiResult<PublishIocsResponse> {
        if !is_publish_enabled() {
            return Err(ApiError::InvalidInput(
                "IoC publishing is disabled. Set GRAPHHUNTER_IOC_PUBLISH_ENABLED=1 in the environment and restart the app to enable this tool."
                    .into(),
            ));
        }
        if !req.dry_run && !req.confirm {
            return Err(ApiError::InvalidInput(
                "Publishing to Sentinel Watchlist mutates the tenant. Pass `confirm: true` to proceed, or `dry_run: true` to preview the payload without posting.".into(),
            ));
        }
        if req.watchlist_name.trim().is_empty() {
            return Err(ApiError::InvalidInput("watchlist_name is required".into()));
        }

        // Build payload before reading creds so dry-run works even
        // without Azure creds configured — the analyst can preview the
        // CSV shape ahead of wiring up the tenant.
        let prefix = req.tag_prefix.unwrap_or_else(|| "ioc:".to_string());
        let items = {
            let session = self.resolve_session(req.session.as_ref())?;
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
                out.push((t.node_id.clone(), etype, t.tag.clone(), t.reason.clone()));
            }
            out
        };
        if items.is_empty() {
            return Err(ApiError::InvalidInput(format!(
                "No tagged entities match prefix `{prefix}`. Tag at least one entity first (see `tag_entity`)."
            )));
        }
        let raw_content = build_sentinel_watchlist_csv(&items);
        let watchlist_alias = to_watchlist_alias(&req.watchlist_name);
        let payload = build_watchlist_payload(
            &req.watchlist_name,
            req.display_name.as_deref(),
            req.description.as_deref(),
            items.len(),
            &raw_content,
        );

        let creds = AzureCreds::from_env()?;
        let target_url = build_watchlist_url(&creds, &watchlist_alias);

        if req.dry_run {
            return Ok(PublishIocsResponse {
                posted: false,
                dry_run: true,
                target_url,
                watchlist_alias,
                items_count: items.len(),
                http_status: None,
                payload,
                azure_response_body: None,
            });
        }

        let token = acquire_token(&creds).await?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| ApiError::Internal(format!("reqwest build failed: {e}")))?;
        let resp = client
            .put(&target_url)
            .bearer_auth(&token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| ApiError::Upstream {
                service: "sentinel".into(),
                message: format!("PUT failed: {e}"),
            })?;
        let status = resp.status().as_u16();
        let body_text = resp.text().await.unwrap_or_default();

        Ok(PublishIocsResponse {
            posted: true,
            dry_run: false,
            target_url,
            watchlist_alias,
            items_count: items.len(),
            http_status: Some(status),
            payload,
            azure_response_body: Some(body_text),
        })
    }
}

fn is_publish_enabled() -> bool {
    std::env::var("GRAPHHUNTER_IOC_PUBLISH_ENABLED")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "True"))
        .unwrap_or(false)
}

/// Normalize a user-supplied watchlist name to a valid ARM alias:
/// lowercase, spaces → underscores, strip non-alphanumeric.
pub fn to_watchlist_alias(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if ch == ' ' || ch == '-' || ch == '_' {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("graphhunter_iocs");
    }
    out
}

pub struct AzureCreds {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub subscription_id: String,
    pub resource_group: String,
    pub workspace_name: String,
}

impl AzureCreds {
    pub fn from_env() -> ApiResult<Self> {
        let read = |key: &str| -> ApiResult<String> {
            match std::env::var(key) {
                Ok(v) if !v.is_empty() => Ok(v),
                _ => Err(ApiError::InvalidInput(format!(
                    "{key} must be set in the environment (check your .env)"
                ))),
            }
        };
        Ok(Self {
            tenant_id: read("AZURE_TENANT_ID")?,
            client_id: read("AZURE_CLIENT_ID")?,
            client_secret: read("AZURE_CLIENT_SECRET")?,
            subscription_id: read("AZURE_SUBSCRIPTION_ID")?,
            resource_group: read("AZURE_RESOURCE_GROUP")?,
            workspace_name: read("AZURE_WORKSPACE_NAME")?,
        })
    }
}

/// Pure function: build the ARM JSON body for a Watchlist PUT.
pub fn build_watchlist_payload(
    watchlist_name: &str,
    display_name: Option<&str>,
    description: Option<&str>,
    item_count: usize,
    raw_content_csv: &str,
) -> serde_json::Value {
    let default_desc;
    serde_json::json!({
        "properties": {
            "displayName": display_name.unwrap_or(watchlist_name),
            "source": "GraphHunter",
            "provider": "GraphHunter",
            "description": match description {
                Some(d) => d,
                None => {
                    default_desc = format!("IoC set exported from GraphHunter ({item_count} items).");
                    default_desc.as_str()
                }
            },
            "itemsSearchKey": "ioc_value",
            "contentType": "text/csv",
            "numberOfLinesToSkip": 0,
            "rawContent": raw_content_csv,
        }
    })
}

pub fn build_watchlist_url(creds: &AzureCreds, alias: &str) -> String {
    format!(
        "https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}/providers/Microsoft.SecurityInsights/watchlists/{alias}?api-version={api}",
        sub = creds.subscription_id,
        rg = creds.resource_group,
        ws = creds.workspace_name,
        alias = alias,
        api = ARM_API_VERSION,
    )
}

async fn acquire_token(creds: &AzureCreds) -> ApiResult<String> {
    let url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        creds.tenant_id
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| ApiError::Internal(format!("reqwest build failed: {e}")))?;
    let params = [
        ("grant_type", "client_credentials"),
        ("client_id", creds.client_id.as_str()),
        ("client_secret", creds.client_secret.as_str()),
        ("scope", TOKEN_SCOPE),
    ];
    let resp = client
        .post(&url)
        .form(&params)
        .send()
        .await
        .map_err(|e| ApiError::Upstream {
            service: "azure-token".into(),
            message: format!("request failed: {e}"),
        })?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(ApiError::Upstream {
            service: "azure-token".into(),
            message: format!("{status}: {body}"),
        });
    }
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| ApiError::Internal(format!("token response parse failed: {e}")))?;
    let token = json
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::Internal("token response missing access_token".into()))?;
    Ok(token.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_normalizes_spaces_and_case() {
        assert_eq!(
            to_watchlist_alias("GraphHunter IoCs 2024"),
            "graphhunter_iocs_2024"
        );
        assert_eq!(
            to_watchlist_alias("spray-campaign-apr"),
            "spray_campaign_apr"
        );
        assert_eq!(to_watchlist_alias(""), "graphhunter_iocs");
        assert_eq!(to_watchlist_alias("!@#$%"), "graphhunter_iocs");
    }

    #[test]
    fn url_is_management_plane_with_correct_api_version() {
        let creds = AzureCreds {
            tenant_id: "t".into(),
            client_id: "c".into(),
            client_secret: "s".into(),
            subscription_id: "sub-uuid".into(),
            resource_group: "my-rg".into(),
            workspace_name: "my-ws".into(),
        };
        let url = build_watchlist_url(&creds, "my_alias");
        assert!(url.starts_with("https://management.azure.com/"));
        assert!(url.contains("/subscriptions/sub-uuid/"));
        assert!(url.contains("/resourceGroups/my-rg/"));
        assert!(url.contains("/workspaces/my-ws/"));
        assert!(url.contains("/watchlists/my_alias"));
        assert!(url.contains("api-version=2023-02-01"));
    }

    #[test]
    fn payload_has_required_sentinel_watchlist_fields() {
        let csv = "ioc_value,ioc_type,tag,reason\n1.2.3.4,ipv4,ioc:malicious,\"spray\"\n";
        let v = build_watchlist_payload("Spray Apr 2026", None, None, 1, csv);
        let props = &v["properties"];
        assert_eq!(props["displayName"], "Spray Apr 2026");
        assert_eq!(props["source"], "GraphHunter");
        assert_eq!(props["provider"], "GraphHunter");
        assert_eq!(props["itemsSearchKey"], "ioc_value");
        assert_eq!(props["contentType"], "text/csv");
        assert_eq!(props["numberOfLinesToSkip"], 0);
        assert!(
            props["rawContent"]
                .as_str()
                .unwrap()
                .starts_with("ioc_value,ioc_type,tag,reason")
        );
        assert!(props["description"].as_str().unwrap().contains("1 items"));
    }

    #[test]
    fn payload_honors_explicit_display_name_and_description() {
        let v = build_watchlist_payload("x", Some("Custom DN"), Some("Custom Desc"), 0, "");
        assert_eq!(v["properties"]["displayName"], "Custom DN");
        assert_eq!(v["properties"]["description"], "Custom Desc");
    }
}
