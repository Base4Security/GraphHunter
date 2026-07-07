//! F4.9 / ADR-004 §D5 — API self-description.
//!
//! `GET /v1/schema` returns the set of stable endpoints plus lightweight
//! metadata. MCP contract tests fetch this and assert that every path a
//! migrated tool depends on is registered. When someone renames or
//! removes an endpoint without updating the registry, the MCP test
//! suite fails before a client IA hits the broken path in production.
//!
//! Full JSON Schema for every DTO is out of scope for the first cut —
//! the `schema` crate would have to derive across ~22 DTO modules. For
//! now the response lists paths + method + description, which is
//! enough to catch the class of breakage we care about (endpoint
//! rename / removal). A fuller JSON-Schema body can land later without
//! a contract change (additive).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaResponse {
    /// Contract version — bumps when `endpoints` acquires a breaking
    /// change. Additive endpoint additions do not bump this.
    pub version: String,
    pub endpoints: Vec<EndpointMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointMeta {
    pub path: String,
    pub method: HttpMethod,
    /// One-line human description; stable enough to be fine in the
    /// contract. If you need to rewrite it, treat it like a DTO field
    /// change — bump the version or add a new endpoint.
    pub description: String,
    /// True for endpoints that may touch high-degree graph nodes and
    /// need the extended MCP timeout (see `HEAVY_TIMEOUT_MS`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub heavy: bool,
    /// Stability tier, mirroring `ToolStability` on the MCP side.
    pub stability: Stability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stability {
    Stable,
    Experimental,
    Deprecated,
}

fn is_false(b: &bool) -> bool {
    !*b
}
