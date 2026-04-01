use std::sync::Arc;
use tauri::Emitter;

use crate::state::SessionState;

pub fn path_is_evtx(path: &str) -> bool {
    std::path::Path::new(path)
        .extension()
        .map(|e| e.eq_ignore_ascii_case("evtx"))
        .unwrap_or(false)
}

/// EVTX files start with magic "ElfFile" (7 bytes). Detect so we don't read binary as UTF-8.
pub fn file_looks_like_evtx(path: &str) -> bool {
    use std::io::Read;
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut buf = [0u8; 8];
    if f.read_exact(&mut buf).is_err() {
        return false;
    }
    buf.starts_with(b"ElfFile")
}

/// Converts a Windows EVTX file to Sysmon-style NDJSON (one JSON object per line)
/// so the existing Sysmon parser can ingest it. Normalizes Event/System/EventData
/// structure to flat EventID, UtcTime, Computer, and EventData name/value pairs.
pub fn evtx_to_sysmon_ndjson(path: &str) -> Result<String, String> {
    use evtx::EvtxParser;

    let mut parser = EvtxParser::from_path(path)
        .map_err(|e| format!("Failed to open EVTX file: {}", e))?;

    let mut lines: Vec<String> = Vec::new();
    for record in parser.records_json_value() {
        let serialized = record.map_err(|e| format!("EVTX record error: {}", e))?;
        let ev = &serialized.data;
        let normalized = evtx_record_to_sysmon_like(ev);
        if let Some(obj) = normalized {
            if let Ok(s) = serde_json::to_string(&obj) {
                lines.push(s);
            }
        }
    }
    Ok(lines.join("\n"))
}

/// Streams EVTX records in batches, parsing and inserting triples directly into the graph.
/// Never holds more than one batch (~50K records) in memory.
pub fn evtx_ingest_streaming(
    path: &str,
    parser: &dyn graph_hunter_core::LogParser,
    session: &Arc<SessionState>,
    dataset_id: &str,
    app: &tauri::AppHandle,
    _job_id: &str,
) -> Result<(usize, usize), String> {
    use evtx::EvtxParser;

    const BATCH_SIZE: usize = 50_000;

    let mut evtx_parser = EvtxParser::from_path(path)
        .map_err(|e| format!("Failed to open EVTX file: {}", e))?;

    let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    let mut total_new_entities = 0usize;
    let mut total_new_relations = 0usize;
    let mut batch_lines: Vec<String> = Vec::with_capacity(BATCH_SIZE);
    let mut records_processed = 0u64;

    for record in evtx_parser.records_json_value() {
        let serialized = match record {
            Ok(r) => r,
            Err(_) => continue,
        };
        let ev = &serialized.data;
        let normalized = evtx_record_to_sysmon_like(ev);
        if let Some(obj) = normalized {
            if let Ok(s) = serde_json::to_string(&obj) {
                batch_lines.push(s);
            }
        }
        records_processed += 1;

        if batch_lines.len() >= BATCH_SIZE {
            // Parse batch and insert into graph
            let batch_str = batch_lines.join("\n");
            let triples = parser.parse(&batch_str);
            let (ne, nr) = match session.graph.write() {
                Ok(mut graph) => graph.insert_triples(triples, Some(dataset_id)).map_err(|e| e.to_string())?,
                Err(_) => return Err("Graph lock poisoned".to_string()),
            };
            total_new_entities += ne;
            total_new_relations += nr;

            // Emit progress
            let _ = app.emit("ingest-progress", serde_json::json!({
                "phase": "parsing",
                "bytes_read": records_processed, // use record count as proxy
                "bytes_total": file_size,
                "entities": total_new_entities,
                "relations": total_new_relations,
            }));

            batch_lines.clear();
        }
    }

    // Process remaining records
    if !batch_lines.is_empty() {
        let batch_str = batch_lines.join("\n");
        let triples = parser.parse(&batch_str);
        let (ne, nr) = match session.graph.write() {
            Ok(mut graph) => graph.insert_triples(triples, Some(dataset_id)).map_err(|e| e.to_string())?,
            Err(_) => return Err("Graph lock poisoned".to_string()),
        };
        total_new_entities += ne;
        total_new_relations += nr;
    }

    Ok((total_new_entities, total_new_relations))
}

/// Reads a sample of EVTX records for preview (first N records).
pub fn evtx_preview_sample(path: &str, max_records: usize) -> Result<String, String> {
    use evtx::EvtxParser;

    let mut parser = EvtxParser::from_path(path)
        .map_err(|e| format!("Failed to open EVTX file: {}", e))?;

    let mut lines: Vec<String> = Vec::new();
    for record in parser.records_json_value() {
        if lines.len() >= max_records {
            break;
        }
        let serialized = match record {
            Ok(r) => r,
            Err(_) => continue,
        };
        let ev = &serialized.data;
        if let Some(obj) = evtx_record_to_sysmon_like(ev) {
            if let Ok(s) = serde_json::to_string(&obj) {
                lines.push(s);
            }
        }
    }
    Ok(lines.join("\n"))
}

/// Normalizes a single EVTX JSON record (evtx crate output) to Sysmon-like flat object:
/// EventID, UtcTime, Computer, plus EventData name/value pairs.
/// Handles multiple shapes: Event wrapper, root-level System/EventData, and case variants.
pub fn evtx_record_to_sysmon_like(ev: &serde_json::Value) -> Option<serde_json::Value> {
    use serde_json::{Map, Number, Value};

    let obj = ev.as_object()?;
    // Event may be under "Event" or root may be the event (has System or EventData)
    let event = obj
        .get("Event")
        .and_then(|v| v.as_object())
        .or_else(|| {
            if obj.contains_key("System")
                || obj.contains_key("EventData")
                || obj.contains_key("system")
                || obj.contains_key("eventdata")
            {
                Some(obj)
            } else {
                None
            }
        })
        .or(Some(obj)); // fallback: use root as event (flatten whatever we have)
    let event = event.expect("event is always Some after or(Some(obj))");

    let system = event
        .get("System")
        .and_then(|v| v.as_object())
        .or_else(|| event.get("system").and_then(|v| v.as_object()));

    let event_id = system
        .and_then(|s| extract_event_id(s.get("EventID")))
        .or_else(|| extract_event_id(event.get("EventID")))
        .unwrap_or(0);

    let time_created = system
        .and_then(|s| extract_timestamp_str(s.get("TimeCreated")))
        .or_else(|| extract_timestamp_str(event.get("TimeCreated")))
        .unwrap_or_else(|| "".to_string());

    let computer = system
        .and_then(|s| extract_str_value(s.get("Computer")))
        .or_else(|| extract_str_value(event.get("Computer")))
        .unwrap_or_else(|| "".to_string());

    let mut out = Map::new();
    out.insert(
        "EventID".to_string(),
        Value::Number(Number::from(event_id)),
    );
    out.insert("UtcTime".to_string(), Value::String(time_created));
    out.insert("Computer".to_string(), Value::String(computer));

    // Extract fields from EventData and UserData (many providers use one or the other)
    let event_data = event
        .get("EventData")
        .or_else(|| event.get("eventdata"));
    let user_data = event
        .get("UserData")
        .or_else(|| event.get("userdata"));

    for data_section in [event_data, user_data].into_iter().flatten() {
        flatten_data_section(data_section, &mut out);
    }

    // If event is the root and we have no EventData, flatten all string/number fields from event
    if !out.contains_key("NewProcessName") && !out.contains_key("TargetUserName") && !out.contains_key("Image") {
        for (k, v) in event.iter() {
            if out.contains_key(k) {
                continue;
            }
            match v {
                Value::String(s) => {
                    out.insert(k.clone(), Value::String(s.clone()));
                }
                Value::Number(n) => {
                    out.insert(k.clone(), Value::Number(n.clone()));
                }
                _ => {}
            }
        }
    }

    Some(Value::Object(out))
}

/// Flattens a data section (EventData or UserData) into the output map.
/// Handles: Data[@Name] arrays, Data objects, direct key-value pairs,
/// and nested provider-specific elements (common in UserData).
fn flatten_data_section(section: &serde_json::Value, out: &mut serde_json::Map<String, serde_json::Value>) {
    use serde_json::Value;

    // Try Data array: [{@Name: "Field", #text: "Value"}, ...]
    if let Some(data_arr) = section
        .get("Data")
        .or_else(|| section.get("data"))
        .and_then(|v| v.as_array())
    {
        for item in data_arr {
            if let Some(o) = item.as_object() {
                let name = o
                    .get("@Name")
                    .or_else(|| o.get("Name"))
                    .and_then(|v| v.as_str())
                    .or_else(|| o.get("#text").and_then(|v| v.as_str()));
                let value = o.get("#text").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(name) = name {
                    out.insert(name.to_string(), Value::String(value.to_string()));
                }
            }
        }
    } else if let Some(data_obj) = section
        .get("Data")
        .or_else(|| section.get("data"))
        .and_then(|v| v.as_object())
    {
        // Data as flat object: {Field1: "val1", Field2: "val2"}
        for (k, v) in data_obj {
            if let Some(s) = v.as_str() {
                out.insert(k.clone(), Value::String(s.to_string()));
            }
        }
    }

    // Direct key-value pairs on the section itself
    if let Some(obj) = section.as_object() {
        for (k, v) in obj {
            if k == "Data" || k == "data" || k.starts_with('@') {
                continue;
            }
            match v {
                Value::String(s) => {
                    out.entry(k.clone()).or_insert_with(|| Value::String(s.clone()));
                }
                Value::Number(n) => {
                    out.entry(k.clone()).or_insert_with(|| Value::Number(n.clone()));
                }
                // Nested provider element (UserData/<ProviderElement>/{fields})
                Value::Object(nested) => {
                    for (nk, nv) in nested {
                        if nk.starts_with('@') {
                            continue; // skip xmlns attributes
                        }
                        match nv {
                            Value::String(s) => {
                                out.entry(nk.clone())
                                    .or_insert_with(|| Value::String(s.clone()));
                            }
                            Value::Number(n) => {
                                out.entry(nk.clone())
                                    .or_insert_with(|| Value::Number(n.clone()));
                            }
                            // Handle #text inside nested objects
                            Value::Object(inner) => {
                                if let Some(text) = inner.get("#text").and_then(|t| t.as_str()) {
                                    out.entry(nk.clone())
                                        .or_insert_with(|| Value::String(text.to_string()));
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

fn extract_event_id(v: Option<&serde_json::Value>) -> Option<u64> {
    let v = v?;
    v.as_u64()
        .or_else(|| v.as_i64().map(|i| i as u64))
        .or_else(|| v.get("#text").and_then(|t| t.as_str()).and_then(|s| s.parse().ok()))
}

fn extract_timestamp_str(v: Option<&serde_json::Value>) -> Option<String> {
    let v = v?;
    v.as_str()
        .map(String::from)
        .or_else(|| v.get("@SystemTime").and_then(|t| t.as_str()).map(String::from))
        .or_else(|| v.get("#text").and_then(|t| t.as_str()).map(String::from))
}

fn extract_str_value(v: Option<&serde_json::Value>) -> Option<String> {
    let v = v?;
    v.as_str()
        .map(String::from)
        .or_else(|| v.get("#text").and_then(|t| t.as_str()).map(String::from))
}
