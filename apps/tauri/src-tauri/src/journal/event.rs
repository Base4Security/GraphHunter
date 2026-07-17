use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HuntEvent {
    pub seq: u64,
    pub ts: i64,
    pub kind: String,
    pub endpoint: String,
    pub params: Value,
    pub result: EventResult,
    pub topology: Topology,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventResult {
    pub status: u16,
    pub duration_ms: u64,
    pub row_count: Option<u64>,
    pub new_entities: Option<u64>,
    pub new_relations: Option<u64>,
    pub body_bytes: u64,
    pub est_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Topology {
    pub graph_before: GraphCounts,
    pub graph_after: GraphCounts,
    pub touched: Option<Touched>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GraphCounts {
    pub entities: u64,
    pub relations: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Touched {
    pub nodes: Vec<Value>,
    pub edges: Vec<String>,
    pub path: Option<Vec<Value>>,
}
