//! Native parser for the NODLINK ETW traces (PKU-ASAL `Simulated-Data`:
//! `hw20`, `win10`) — the datasets the TPCSA paper evaluates on.
//!
//! Newline-delimited JSON, one ETW event per line, every value a string:
//!
//! ```json
//! {"MSec":"2342.5097","PID":"3820","PName":"chrome","EventName":"Process/Start",
//!  "ParentID":"2428","PPName":"unknown","ImageFileName":"chrome.exe",
//!  "CommandLine":"...","is_warn":"False"}
//! {"MSec":"210.2299","PID":"680","PName":"svchost","EventName":"FileIO/Read","FileName":"C:\\..."}
//! {"MSec":"93.6627","PID":"88","PName":"","EventName":"TcpIp/Send","saddr":"192.168.0.95","daddr":"111.205.230.211","dport":"39,184","sport":"3,389"}
//! ```
//!
//! # Direction is causal flow
//!
//! Arcs point from who acts to what is acted on, so a time-respecting path
//! is a causal explanation: `parent → child` (start), `process → file`
//! (write), `file → process` (read, load), `process → ip` (send),
//! `ip → process` (recv). `Process/Stop` produces no edge.
//!
//! # Process identity
//!
//! `PID|image|generation`, where generation is the number of
//! `Process/Start` events seen for that PID before this one. Without it a
//! 20-hour trace fuses every process that ever reused a PID. The parent
//! of a start uses the parent PID's *current* generation.
//!
//! # Time
//!
//! `MSec` is milliseconds from trace start with four decimals. The edge
//! `timestamp` is the engine's seconds (floored); the full value survives
//! on the edge as `ts_us` (integer microseconds) so a millisecond ε is
//! meaningful downstream. Every edge also carries `event_type` ∈ {start,
//! read, write, load, send, recv} — the type whose rarity prices the arc.

use std::collections::HashMap;

use graph_hunter_core::entity::Entity;
use graph_hunter_core::parser::{LogParser, ParsedTriple};
use graph_hunter_core::relation::Relation;
use graph_hunter_core::types::{EntityType, RelationType};
use serde_json::Value;

/// Detects NODLINK ETW JSONL: a handful of leading non-blank lines that
/// each carry `"EventName"` and `"MSec"`.
pub fn looks_like_etw_nodlink(contents: &str) -> bool {
    let mut checked = 0;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !(line.starts_with('{') && line.contains("\"EventName\"") && line.contains("\"MSec\"")) {
            return false;
        }
        checked += 1;
        if checked >= 3 {
            return true;
        }
    }
    checked > 0
}

/// Numbers in these traces come as strings with thousands separators
/// (`"3,820"`); strip them before parsing.
fn digits(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
        .collect()
}

fn field<'a>(row: &'a Value, key: &str) -> &'a str {
    row.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Per-PID generation counter (see module docs).
#[derive(Default)]
struct Generations(HashMap<u64, u32>);

impl Generations {
    /// Generation of the instance running now: one less than the number
    /// of starts seen (0 when the process predates the trace).
    fn current(&self, pid: u64) -> u32 {
        self.0.get(&pid).map(|c| c.saturating_sub(1)).unwrap_or(0)
    }
    /// Generation for a fresh start of `pid`; bumps the counter for the
    /// events that follow.
    fn start(&mut self, pid: u64) -> u32 {
        let g = self.0.entry(pid).or_insert(0);
        let this = *g;
        *g += 1;
        this
    }
}

fn process_id(pid: u64, name: &str, generation: u32) -> String {
    format!("{pid}|{name}|{generation}")
}

pub struct EtwNodlinkParser;

impl EtwNodlinkParser {
    fn parse_inner(&self, data: &str) -> Vec<ParsedTriple> {
        let mut gens = Generations::default();
        let mut triples = Vec::new();
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let row: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let event = field(&row, "EventName");
            let Some(pid) = digits(field(&row, "PID")).parse::<u64>().ok() else {
                continue;
            };
            let pname = field(&row, "PName");
            let msec: f64 = match digits(field(&row, "MSec")).parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let ts_us = (msec * 1000.0).round() as i64;
            let ts_seconds = (msec / 1000.0).floor() as i64;

            let (event_type, rel_type) = match event {
                "Process/Start" => ("start", RelationType::Spawn),
                "FileIO/Read" => ("read", RelationType::Read),
                "FileIO/Write" => ("write", RelationType::Write),
                "Image/Load" => ("load", RelationType::Other("Load".into())),
                "TcpIp/Send" => ("send", RelationType::Connect),
                "TcpIp/Recv" => ("recv", RelationType::Connect),
                _ => continue,
            };

            let (src, dst) = match event_type {
                "start" => {
                    // Generation for the parent is the one running *now*;
                    // the child's start then bumps its own PID's counter.
                    let parent_pid = digits(field(&row, "ParentID")).parse::<u64>().unwrap_or(0);
                    let parent_name = field(&row, "PPName");
                    let parent = Entity::new(
                        process_id(parent_pid, parent_name, gens.current(parent_pid)),
                        EntityType::Process,
                    )
                    .with_metadata("name", parent_name)
                    .with_metadata("pid", parent_pid.to_string());
                    let generation = gens.start(pid);
                    let is_warn = field(&row, "is_warn").eq_ignore_ascii_case("true");
                    let child =
                        Entity::new(process_id(pid, pname, generation), EntityType::Process)
                            .with_metadata("name", pname)
                            .with_metadata("pid", pid.to_string())
                            .with_metadata("image", field(&row, "ImageFileName"))
                            .with_metadata("cmdline", field(&row, "CommandLine"))
                            .with_metadata("is_warn", if is_warn { "true" } else { "false" });
                    (parent, child)
                }
                "read" | "load" | "write" => {
                    let path = field(&row, "FileName");
                    if path.is_empty() {
                        continue;
                    }
                    let proc_ = Entity::new(
                        process_id(pid, pname, gens.current(pid)),
                        EntityType::Process,
                    )
                    .with_metadata("name", pname)
                    .with_metadata("pid", pid.to_string());
                    let file = Entity::new(path, EntityType::File).with_metadata("name", path);
                    if event_type == "write" {
                        (proc_, file)
                    } else {
                        (file, proc_)
                    }
                }
                _ => {
                    // send / recv: the remote endpoint is `daddr`.
                    let remote = field(&row, "daddr");
                    if remote.is_empty() {
                        continue;
                    }
                    let proc_ = Entity::new(
                        process_id(pid, pname, gens.current(pid)),
                        EntityType::Process,
                    )
                    .with_metadata("name", pname)
                    .with_metadata("pid", pid.to_string());
                    let ip = Entity::new(remote, EntityType::IP);
                    if event_type == "send" {
                        (proc_, ip)
                    } else {
                        (ip, proc_)
                    }
                }
            };

            let mut rel = Relation::new(&src.id, &dst.id, rel_type, ts_seconds)
                .with_metadata("event_type", event_type)
                .with_metadata("ts_us", ts_us.to_string());
            if event_type == "send" || event_type == "recv" {
                rel = rel
                    .with_metadata("dport", digits(field(&row, "dport")))
                    .with_metadata("sport", digits(field(&row, "sport")));
            }
            triples.push((src, rel, dst));
        }
        triples
    }
}

impl LogParser for EtwNodlinkParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        self.parse_inner(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
{"MSec": "81.7004", "PID": "88", "PName": "", "TID": "-1", "EventName": "TcpIp/Recv", "daddr": "111.205.230.211", "saddr": "192.168.0.95", "dport": "39,130", "sport": "3,389", "size": "117"}
{"MSec": "2342.5097", "PID": "3820", "PName": "chrome", "TID": "-1", "EventName": "Process/Start", "ProcessID": "3,820", "ParentID": "2428", "ImageFileName": "chrome.exe", "CommandLine": "&quot;C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe&quot; ", "is_warn": "False", "PPName": "unknown"}
{"MSec": "2349.3797", "PID": "7100", "PName": "chrome", "TID": "-1", "EventName": "Process/Start", "ProcessID": "7,100", "ParentID": "3820", "ImageFileName": "chrome.exe", "CommandLine": "x", "is_warn": "True", "PPName": "chrome"}
{"MSec": "2350.0000", "PID": "7100", "PName": "chrome", "TID": "1", "EventName": "FileIO/Read", "FileName": "C:\\Windows\\a.dll"}
{"MSec": "2351.0000", "PID": "7100", "PName": "chrome", "TID": "1", "EventName": "Image/Load", "FileName": "C:\\Windows\\b.dll"}
{"MSec": "2352.0000", "PID": "7100", "PName": "chrome", "TID": "1", "EventName": "FileIO/Write", "FileName": "C:\\Users\\x\\out.txt"}
{"MSec": "2353.0000", "PID": "7100", "PName": "chrome", "TID": "1", "EventName": "TcpIp/Send", "size": "341", "daddr": "8.8.8.8", "saddr": "192.168.0.95", "dport": "443", "sport": "50,000"}
{"MSec": "2354.0000", "PID": "7100", "PName": "chrome", "TID": "1", "EventName": "Process/Stop", "ProcessID": "7,100"}
"#;

    #[test]
    fn detects_the_format_and_rejects_others() {
        assert!(looks_like_etw_nodlink(SAMPLE));
        assert!(!looks_like_etw_nodlink(
            r#"{"datum":{"com.bbn.tc.schema.avro.cdm18.Event":{}}}"#
        ));
        assert!(!looks_like_etw_nodlink("ts,src,dst\n1,a,b\n"));
        assert!(!looks_like_etw_nodlink(""));
    }

    #[test]
    fn every_event_kind_gets_the_causal_direction() {
        let t = EtwNodlinkParser.parse(SAMPLE);
        let by_type: Vec<(&str, &str, &str)> = t
            .iter()
            .map(|(s, r, d)| {
                (
                    r.metadata["event_type"].as_str(),
                    s.id.as_str(),
                    d.id.as_str(),
                )
            })
            .collect();
        assert_eq!(
            by_type,
            vec![
                ("recv", "111.205.230.211", "88||0"),
                ("start", "2428|unknown|0", "3820|chrome|0"),
                ("start", "3820|chrome|0", "7100|chrome|0"),
                ("read", "C:\\Windows\\a.dll", "7100|chrome|0"),
                ("load", "C:\\Windows\\b.dll", "7100|chrome|0"),
                ("write", "7100|chrome|0", "C:\\Users\\x\\out.txt"),
                ("send", "7100|chrome|0", "8.8.8.8"),
            ],
            "Process/Stop yields nothing; read/load flow file→process, write process→file"
        );
        let types: Vec<String> = t.iter().map(|(_, r, _)| r.rel_type.to_string()).collect();
        assert_eq!(
            types,
            vec![
                "Connect", "Spawn", "Spawn", "Read", "Load", "Write", "Connect"
            ]
        );
    }

    #[test]
    fn entity_types_and_labels() {
        let t = EtwNodlinkParser.parse(SAMPLE);
        let (ip, _, proc_) = &t[0];
        assert_eq!(ip.entity_type, EntityType::IP);
        assert_eq!(proc_.entity_type, EntityType::Process);
        let (_, _, child) = &t[2];
        assert_eq!(child.metadata["is_warn"], "true");
        assert_eq!(child.metadata["image"], "chrome.exe");
        let (_, _, child0) = &t[1];
        assert_eq!(child0.metadata["is_warn"], "false");
        let (file, _, _) = &t[3];
        assert_eq!(file.entity_type, EntityType::File);
    }

    #[test]
    fn timestamps_keep_microseconds_and_floor_seconds() {
        let t = EtwNodlinkParser.parse(SAMPLE);
        let rel = &t[1].1;
        assert_eq!(rel.timestamp, 2, "2342.5097 ms → 2 s");
        assert_eq!(
            rel.metadata["ts_us"], "2342510",
            "rounded to the microsecond"
        );
        let first = &t[0].1;
        assert_eq!(first.timestamp, 0);
        assert_eq!(first.metadata["ts_us"], "81700");
        assert_eq!(first.metadata["dport"], "39130");
    }

    #[test]
    fn pid_reuse_gets_a_new_generation() {
        let reuse = r#"
{"MSec": "1.0", "PID": "10", "PName": "cmd", "EventName": "FileIO/Read", "FileName": "C:\\pre.txt"}
{"MSec": "2.0", "PID": "10", "PName": "cmd", "EventName": "Process/Start", "ParentID": "1", "PPName": "svc", "is_warn": "False"}
{"MSec": "3.0", "PID": "10", "PName": "cmd", "EventName": "FileIO/Write", "FileName": "C:\\a.txt"}
{"MSec": "4.0", "PID": "10", "PName": "cmd", "EventName": "Process/Start", "ParentID": "1", "PPName": "svc", "is_warn": "False"}
{"MSec": "5.0", "PID": "10", "PName": "cmd", "EventName": "FileIO/Write", "FileName": "C:\\b.txt"}
{"MSec": "6.0", "PID": "20", "PName": "child", "EventName": "Process/Start", "ParentID": "10", "PPName": "cmd", "is_warn": "False"}
"#;
        let t = EtwNodlinkParser.parse(reuse);
        let procs: Vec<&str> = t
            .iter()
            .map(|(s, r, d)| {
                if r.metadata["event_type"] == "read" {
                    d.id.as_str()
                } else if r.metadata["event_type"] == "write" {
                    s.id.as_str()
                } else {
                    d.id.as_str()
                }
            })
            .collect();
        // Pre-start event: generation 0 (no start seen yet). First start: still 0
        // (zero previous starts). Second start: 1. The child of PID 10 hangs off generation 1.
        assert_eq!(
            procs,
            vec![
                "10|cmd|0",
                "10|cmd|0",
                "10|cmd|0",
                "10|cmd|1",
                "10|cmd|1",
                "20|child|0"
            ]
        );
        assert_eq!(t[5].0.id, "10|cmd|1", "parent uses its current generation");
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let bad = "not json\n{\"MSec\": \"x\", \"PID\": \"1\", \"EventName\": \"FileIO/Read\", \"FileName\": \"f\"}\n{\"MSec\": \"1.0\", \"PID\": \"1\", \"PName\": \"p\", \"EventName\": \"FileIO/Read\", \"FileName\": \"f\"}\n";
        assert_eq!(EtwNodlinkParser.parse(bad).len(), 1);
    }
}
