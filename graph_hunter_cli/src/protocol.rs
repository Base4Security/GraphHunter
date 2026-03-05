use serde::{Deserialize, Serialize};

/// Incoming request from the Go gateway (one JSON line on stdin).
#[derive(Debug, Deserialize)]
pub struct Request {
    pub id: String,
    pub cmd: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// Outgoing message to the Go gateway (one JSON line on stdout).
#[derive(Debug, Serialize)]
pub struct Response {
    pub id: String,
    #[serde(rename = "type")]
    pub msg_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    pub fn ready() -> Self {
        Self {
            id: String::new(),
            msg_type: "ready".to_string(),
            data: None,
            error: None,
        }
    }

    pub fn result(id: &str, data: serde_json::Value) -> Self {
        Self {
            id: id.to_string(),
            msg_type: "result".to_string(),
            data: Some(data),
            error: None,
        }
    }

    pub fn error(id: &str, msg: impl Into<String>) -> Self {
        Self {
            id: id.to_string(),
            msg_type: "error".to_string(),
            data: None,
            error: Some(msg.into()),
        }
    }

    pub fn progress(id: &str, data: serde_json::Value) -> Self {
        Self {
            id: id.to_string(),
            msg_type: "progress".to_string(),
            data: Some(data),
            error: None,
        }
    }
}
