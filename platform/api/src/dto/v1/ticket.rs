//! DTOs for external ticket filing (Jira Cloud, ServiceNow).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTicketRequest {
    /// `"jira"` or `"servicenow"`.
    pub system: String,
    pub title: String,
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    /// When `true`, returns the payload without calling the external
    /// service. Overrides `confirm`.
    #[serde(default)]
    pub dry_run: bool,
    /// Required for real posts. Mutating external systems without explicit
    /// confirmation is a footgun; the API refuses unless `dry_run=true`
    /// OR `confirm=true`.
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketResponse {
    pub posted: bool,
    pub dry_run: bool,
    pub system: String,
    pub target_url: String,
    pub payload: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    /// Ticket key (Jira: `SEC-123`) or incident number (ServiceNow:
    /// `INC0012345`). Extracted from the response on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<String>,
}
