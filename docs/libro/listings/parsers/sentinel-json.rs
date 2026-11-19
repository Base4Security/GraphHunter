/// Parser for Azure Sentinel (Microsoft Sentinel) log exports.
///
/// Supports the following Sentinel tables:
///
/// | Table                  | Triples Produced                                           |
/// |------------------------|------------------------------------------------------------|
/// | SecurityEvent (4624/25)| User -[Auth]-> Host                                        |
/// | SecurityEvent (4688)   | User -[Execute]-> Process, Parent -[Execute]-> Child       |
/// | SecurityEvent (4663)   | Process -[Read]-> File                                     |
/// | SigninLogs             | User -[Auth]-> IP                                          |
/// | DeviceProcessEvents    | User -[Execute]-> Process, Parent -[Execute]-> Child       |
/// | DeviceNetworkEvents    | Host -[Connect]-> IP                                       |
/// | DeviceFileEvents       | Process -[Write/Read]-> File                               |
/// | CommonSecurityLog      | IP(src) -[Connect]-> IP(dst)                               |
///
/// # Expected JSON Format
///
/// The parser accepts either:
/// - A JSON array of event objects: `[{...}, {...}]`
/// - Newline-delimited JSON (NDJSON): one event per line
///
/// Each record is auto-classified by its `Type` field (preferred) or by
/// heuristic field presence (fallback).
///
/// Timestamps are parsed from `TimeGenerated` or `Timestamp` fields using
/// ISO 8601 format.
pub struct SentinelJsonParser;
