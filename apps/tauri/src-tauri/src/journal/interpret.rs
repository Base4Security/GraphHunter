use super::event::Touched;
use serde_json::Value;

/// Classifies the endpoint path to a semantic kind.
pub fn classify_kind(path: &str) -> &'static str {
    if path.starts_with("/sentinel/seed") {
        "seed"
    } else if path.starts_with("/graph/build") {
        "build"
    } else if path.starts_with("/graph/neighbors")
        || path.starts_with("/graph/path")
        || path.starts_with("/graph/anomaly")
    {
        "traverse"
    } else if path.starts_with("/kql") {
        "query"
    } else if path.starts_with("/notes") {
        "note"
    } else if path.starts_with("/tag") || path.starts_with("/untag") {
        "tag"
    } else if path.starts_with("/save_hypothesis_as_sigma") {
        "finding"
    } else if path.starts_with("/export_")
        || path.starts_with("/file_ticket")
        || path.starts_with("/publish_")
    {
        "export"
    } else {
        "other"
    }
}

/// Extracts result metadata from a JSON response.
/// Returns (row_count, new_entities, new_relations).
pub fn extract_result_meta(resp: &Value) -> (Option<u64>, Option<u64>, Option<u64>) {
    let row_count = resp["row_count"].as_u64();
    let new_entities = resp["new_entities"].as_u64();
    let new_relations = resp["new_relations"].as_u64();
    (row_count, new_entities, new_relations)
}

/// Extracts the touched subgraph from a graph-traversal response.
/// For /graph/neighbors, maps neighbors to Touched.
/// For /graph/path, maps paths if present.
/// Returns None for non-traversal paths.
pub fn extract_touched(path: &str, resp: &Value) -> Option<Touched> {
    if path.starts_with("/graph/neighbors") {
        extract_touched_neighbors(resp)
    } else if path.starts_with("/graph/path") {
        extract_touched_path(resp)
    } else {
        None
    }
}

fn extract_touched_neighbors(resp: &Value) -> Option<Touched> {
    let neighbors_arr = resp.get("neighbors")?;
    let neighbors_arr = neighbors_arr.as_array()?;

    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    for neighbor in neighbors_arr {
        if let Some(edge) = neighbor.get("edge").and_then(|e| e.as_str()) {
            edges.push(edge.to_string());
        }
        if let Some(node) = neighbor.get("node") {
            nodes.push(node.clone());
        }
    }

    Some(Touched {
        nodes,
        edges,
        path: None,
    })
}

fn extract_touched_path(resp: &Value) -> Option<Touched> {
    let paths_arr = resp.get("paths")?;
    let paths_arr = paths_arr.as_array()?;

    // For simplicity, if there's at least one path, extract its hops
    if let Some(first_path) = paths_arr.first()
        && let Some(hops) = first_path.get("hops").and_then(|h| h.as_array())
    {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        for hop in hops {
            // Extract node
            if let Some(node) = hop.get("node") {
                nodes.push(node.clone());
            }
            // Extract edge if present
            if let Some(edge) = hop.get("edge").and_then(|e| e.as_str()) {
                edges.push(edge.to_string());
            }
        }

        return Some(Touched {
            nodes: nodes.clone(),
            edges,
            path: Some(nodes),
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classifies_known_endpoints() {
        assert_eq!(classify_kind("/sentinel/seed"), "seed");
        assert_eq!(classify_kind("/graph/build"), "build");
        assert_eq!(classify_kind("/graph/neighbors"), "traverse");
        assert_eq!(classify_kind("/graph/path"), "traverse");
        assert_eq!(classify_kind("/kql"), "query");
        assert_eq!(classify_kind("/notes"), "note");
        assert_eq!(classify_kind("/something_new"), "other");
    }

    #[test]
    fn extracts_query_row_count_and_build_counts() {
        let (rows, _, _) = extract_result_meta(&json!({"row_count": 54}));
        assert_eq!(rows, Some(54));
        let (_, ne, nr) = extract_result_meta(&json!({"new_entities": 8, "new_relations": 227}));
        assert_eq!((ne, nr), (Some(8), Some(227)));
    }

    #[test]
    fn extracts_touched_from_neighbors() {
        let resp = json!({"entity": {"class":"User","value":"a@b.com"},
                          "neighbors": [{"edge":"Connect","node":{"class":"IP","value":"1.1.1.1"}}]});
        let t = extract_touched("/graph/neighbors", &resp).expect("touched");
        assert_eq!(t.edges, vec!["Connect"]);
        assert_eq!(t.nodes.len(), 1);
    }
}
