//! Preview / proposed field-to-entity-type mapping for ingestion UI.
//! Used by the frontend to show detected fields and let the user adjust before ingesting.

use crate::generic::GenericParser;

/// Returns the proposed (field_name, suggested_entity_type) list for Sysmon format.
/// Entity type is one of: User, Process, Host, IP, File, Domain, Skip.
pub fn preview_sysmon() -> Vec<(String, String)> {
    vec![
        ("EventID".into(), "Skip".into()),
        ("UtcTime".into(), "Skip".into()),
        ("User".into(), "User".into()),
        ("Image".into(), "Process".into()),
        ("CommandLine".into(), "Skip".into()),
        ("ProcessId".into(), "Skip".into()),
        ("ParentImage".into(), "Process".into()),
        ("ParentProcessId".into(), "Skip".into()),
        ("Computer".into(), "Host".into()),
        ("SourceIp".into(), "Skip".into()),
        ("SourcePort".into(), "Skip".into()),
        ("DestinationIp".into(), "IP".into()),
        ("DestinationPort".into(), "Skip".into()),
        ("DestinationHostname".into(), "Skip".into()),
        ("Protocol".into(), "Skip".into()),
        ("TargetFilename".into(), "File".into()),
        ("Hashes".into(), "Skip".into()),
        ("QueryName".into(), "Domain".into()),
        ("QueryResults".into(), "Skip".into()),
        ("QueryType".into(), "Skip".into()),
    ]
}

/// Returns the proposed (field_name, suggested_entity_type) list for Sentinel format.
/// Covers common fields across SecurityEvent, SigninLogs, Device* tables.
pub fn preview_sentinel() -> Vec<(String, String)> {
    vec![
        ("Type".into(), "Skip".into()),
        ("TimeGenerated".into(), "Skip".into()),
        ("Timestamp".into(), "Skip".into()),
        ("EventID".into(), "Skip".into()),
        ("Computer".into(), "Host".into()),
        ("TargetUserName".into(), "User".into()),
        ("Account".into(), "User".into()),
        ("IpAddress".into(), "Skip".into()),
        ("SubjectUserName".into(), "User".into()),
        ("NewProcessName".into(), "Process".into()),
        ("Process".into(), "Process".into()),
        ("CommandLine".into(), "Skip".into()),
        ("ParentProcessName".into(), "Process".into()),
        ("ProcessName".into(), "Process".into()),
        ("ObjectName".into(), "File".into()),
        ("UserPrincipalName".into(), "User".into()),
        ("UserDisplayName".into(), "User".into()),
        ("IPAddress".into(), "IP".into()),
        ("AppDisplayName".into(), "Skip".into()),
        ("DeviceName".into(), "Host".into()),
        ("FileName".into(), "Process".into()),
        ("FolderPath".into(), "File".into()),
        ("InitiatingProcessFileName".into(), "Process".into()),
        ("InitiatingProcessFolderPath".into(), "Process".into()),
        ("InitiatingProcessAccountName".into(), "User".into()),
        ("InitiatingProcessParentFileName".into(), "Process".into()),
        ("RemoteIP".into(), "IP".into()),
        ("RemoteUrl".into(), "Skip".into()),
        ("SourceIP".into(), "IP".into()),
        ("DestinationIP".into(), "IP".into()),
        ("DestinationPort".into(), "Skip".into()),
        ("AccountName".into(), "User".into()),
    ]
}

/// Returns proposed (field_name, suggested_entity_type) for generic JSON or CSV.
/// Uses GenericParser's canonical mapping. Keys should be from first JSON object or CSV headers.
pub fn preview_generic_from_keys(keys: &[String]) -> Vec<(String, String)> {
    GenericParser::proposed_field_mapping(keys)
}
