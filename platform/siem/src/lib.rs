//! SIEM query runners for Azure Sentinel and Elasticsearch.
//!
//! Fetches log data via API, normalizes to parser-ready JSON string,
//! and returns pagination state for "new query after each task".

pub mod elastic;
pub mod sentinel;
pub mod sentinel_streaming;

pub use elastic::{ElasticAuth, run_elastic_query};
pub use sentinel::{QueryStats, SentinelAuth, parse_query_stats, run_sentinel_query};
pub use sentinel_streaming::{
    HttpSentinelTransport, KqlQueryBuilder, SentinelPollingConfig, SentinelTokenCache,
    SentinelTransport, SentinelWatermarkStore, TokenResponse, normalize_response,
};
