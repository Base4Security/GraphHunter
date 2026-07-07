use std::io::Write;

use serde::Serialize;

use crate::analytics::ScoredPath;
use crate::errors::GraphError;

/// Lightweight subgraph node for export (avoids depending on the Tauri crate types).
#[derive(Serialize)]
pub struct ExportSubgraphNode<'a> {
    pub id: &'a str,
    pub entity_type: &'a str,
    pub score: f64,
}

#[derive(Serialize)]
pub struct ExportSubgraphEdge<'a> {
    pub source: &'a str,
    pub target: &'a str,
    pub rel_type: &'a str,
    pub timestamp: i64,
}

#[derive(Serialize)]
struct ExportSubgraph<'a> {
    nodes: &'a [ExportSubgraphNode<'a>],
    edges: &'a [ExportSubgraphEdge<'a>],
}

/// Writes subgraph nodes and edges as CSV.
///
/// Format: two sections separated by a blank line.
/// Section 1 (nodes): id, entity_type, score
/// Section 2 (edges): source, target, rel_type, timestamp
pub fn export_subgraph_csv(
    nodes: &[ExportSubgraphNode<'_>],
    edges: &[ExportSubgraphEdge<'_>],
    writer: &mut impl Write,
) -> Result<(), GraphError> {
    write_all(writer, b"id,entity_type,score\n")?;
    for n in nodes {
        write_all(
            writer,
            format!(
                "{},{},{:.2}\n",
                csv_escape(n.id),
                csv_escape(n.entity_type),
                n.score
            )
            .as_bytes(),
        )?;
    }
    write_all(writer, b"\nsource,target,rel_type,timestamp\n")?;
    for e in edges {
        write_all(
            writer,
            format!(
                "{},{},{},{}\n",
                csv_escape(e.source),
                csv_escape(e.target),
                csv_escape(e.rel_type),
                e.timestamp
            )
            .as_bytes(),
        )?;
    }
    Ok(())
}

/// Writes subgraph nodes and edges as JSON using serde.
pub fn export_subgraph_json(
    nodes: &[ExportSubgraphNode<'_>],
    edges: &[ExportSubgraphEdge<'_>],
    writer: &mut impl Write,
) -> Result<(), GraphError> {
    let wrapper = ExportSubgraph { nodes, edges };
    let json = serde_json::to_string(&wrapper)
        .map_err(|e| GraphError::InvalidHypothesis(format!("JSON serialization failed: {e}")))?;
    write_all(writer, json.as_bytes())
}

/// Writes hunt result paths as CSV.
///
/// Each row: path_index, then the scored path fields.
pub fn export_hunt_results_csv(
    paths: &[ScoredPath],
    writer: &mut impl Write,
) -> Result<(), GraphError> {
    write_all(writer, b"index,chain_summary,edge_count,max_score,total_score,time_start,time_end,anomaly_score,path\n")?;
    for (i, sp) in paths.iter().enumerate() {
        let anomaly = sp
            .anomaly_score
            .map(|s| format!("{:.4}", s))
            .unwrap_or_default();
        let path_joined = sp.path.join(" -> ");
        write_all(
            writer,
            format!(
                "{},{},{},{:.2},{:.2},{},{},{},{}\n",
                i + 1,
                csv_escape(&sp.chain_summary),
                sp.edge_count,
                sp.max_score,
                sp.total_score,
                sp.time_start,
                sp.time_end,
                anomaly,
                csv_escape(&path_joined),
            )
            .as_bytes(),
        )?;
    }
    Ok(())
}

/// Writes hunt result paths as JSON.
pub fn export_hunt_results_json(
    paths: &[ScoredPath],
    writer: &mut impl Write,
) -> Result<(), GraphError> {
    // ScoredPath derives Serialize, so use serde_json for correctness.
    let json = serde_json::to_string(paths)
        .map_err(|e| GraphError::InvalidHypothesis(format!("JSON serialization failed: {e}")))?;
    write_all(writer, json.as_bytes())
}

// ── helpers ──

fn write_all(writer: &mut impl Write, data: &[u8]) -> Result<(), GraphError> {
    writer
        .write_all(data)
        .map_err(|e| GraphError::InvalidHypothesis(format!("Write failed: {e}")))
}

/// Escapes a CSV field: wraps in double-quotes if it contains comma, quote, or newline.
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csv_escape_plain() {
        assert_eq!(csv_escape("hello"), "hello");
    }

    #[test]
    fn test_csv_escape_comma() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
    }

    #[test]
    fn test_csv_escape_quote() {
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn test_subgraph_csv() {
        let nodes = vec![
            ExportSubgraphNode {
                id: "10.0.0.1",
                entity_type: "IP",
                score: 42.5,
            },
            ExportSubgraphNode {
                id: "host-a",
                entity_type: "Host",
                score: 10.0,
            },
        ];
        let edges = vec![ExportSubgraphEdge {
            source: "10.0.0.1",
            target: "host-a",
            rel_type: "Connect",
            timestamp: 1000,
        }];
        let mut buf = Vec::new();
        export_subgraph_csv(&nodes, &edges, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("id,entity_type,score"));
        assert!(output.contains("10.0.0.1,IP,42.50"));
        assert!(output.contains("source,target,rel_type,timestamp"));
        assert!(output.contains("10.0.0.1,host-a,Connect,1000"));
    }

    #[test]
    fn test_subgraph_json() {
        let nodes = vec![ExportSubgraphNode {
            id: "n1",
            entity_type: "User",
            score: 5.0,
        }];
        let edges = vec![];
        let mut buf = Vec::new();
        export_subgraph_json(&nodes, &edges, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["nodes"][0]["id"], "n1");
        assert!(parsed["edges"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_hunt_results_csv() {
        let paths = vec![ScoredPath {
            path: vec!["A".into(), "B".into()],
            max_score: 80.0,
            total_score: 120.0,
            time_start: 100,
            time_end: 200,
            chain_summary: "A -> B".into(),
            anomaly_score: Some(0.75),
            anomaly_breakdown: None,
            edge_count: 1,
            datasets_used: Vec::new(),
        }];
        let mut buf = Vec::new();
        export_hunt_results_csv(&paths, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("index,chain_summary,edge_count"));
        assert!(output.contains("A -> B"));
        assert!(output.contains("0.7500"));
    }

    #[test]
    fn test_hunt_results_json() {
        let paths = vec![ScoredPath {
            path: vec!["X".into()],
            max_score: 10.0,
            total_score: 10.0,
            time_start: 0,
            time_end: 0,
            chain_summary: "X".into(),
            anomaly_score: None,
            anomaly_breakdown: None,
            edge_count: 1,
            datasets_used: Vec::new(),
        }];
        let mut buf = Vec::new();
        export_hunt_results_json(&paths, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed[0]["path"][0], "X");
    }
}
