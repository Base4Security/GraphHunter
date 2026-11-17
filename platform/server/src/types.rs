//! Wire types shared by the HTTP handlers and the desktop commands.

use graph_hunter_core::ScoredPath;
use serde::Serialize;

#[derive(Serialize)]
pub struct PaginatedHuntResults {
    pub total_paths: usize,
    pub filtered_paths: usize,
    pub page: usize,
    pub page_size: usize,
    pub paths: Vec<ScoredPath>,
}
