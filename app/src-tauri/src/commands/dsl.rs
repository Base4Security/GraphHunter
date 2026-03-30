use graph_hunter_core::{CatalogEntry, get_catalog, parse_dsl, format_hypothesis};

use crate::error::CommandError;
use crate::types::DslResult;

/// Parses a DSL string into a Hypothesis.
#[tauri::command]
pub fn cmd_parse_dsl(input: String, name: Option<String>) -> Result<DslResult, CommandError> {
    let result = parse_dsl(&input, name.as_deref()).map_err(|e| CommandError::ParseError(e.to_string()))?;
    Ok(DslResult {
        hypothesis: result.hypothesis,
        formatted: result.formatted,
    })
}

/// Returns the ATT&CK hypothesis catalog.
#[tauri::command]
pub fn cmd_get_catalog() -> Vec<CatalogEntry> {
    get_catalog().to_vec()
}

/// Parses a catalog entry's DSL pattern into a Hypothesis.
#[tauri::command]
pub fn cmd_load_catalog_hypothesis(catalog_id: String) -> Result<DslResult, CommandError> {
    let catalog = get_catalog();
    let entry = catalog.iter().find(|e| e.id == catalog_id)
        .ok_or_else(|| CommandError::InvalidInput(format!("Catalog entry not found: {}", catalog_id)))?;
    let result = parse_dsl(entry.dsl_pattern, Some(entry.name))
        .map_err(|e| CommandError::ParseError(format!("Failed to parse catalog pattern: {}", e)))?;
    let mut hypothesis = result.hypothesis;
    hypothesis.k_simplicity = entry.k_simplicity;
    let formatted = format_hypothesis(&hypothesis);
    Ok(DslResult {
        hypothesis,
        formatted,
    })
}
