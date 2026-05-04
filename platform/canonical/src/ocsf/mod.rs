//! OCSF v1.4 subset actually produced by the seven shipping parsers.
//!
//! We deliberately do not model the full spec: every class or field that
//! no current parser emits is excluded so the projection surface stays
//! auditable. Extending the subset is additive — new classes land here as
//! new parsers or VRL programs need them.
//!
//! Class id ranges follow the spec (categories 1..=7 with three-digit
//! suffixes). The shipping subset covers:
//!   * 3002 Authentication
//!   * 1007 Process Activity
//!   * 4001 Network Activity
//!   * 4003 DNS Activity
//!   * 1001 File System Activity
//!   * 5001 Registry Key Activity
//!
//! Anything else produced today falls into the generic `Other` variant and
//! is flagged for review in the mapping audit.

use serde::{Deserialize, Serialize};

use crate::provenance::ProvenanceCtx;

/// Canonical OCSF event, tagged with a class discriminant and a provenance
/// context. Serialization is flat: `class_uid`, `activity_id`, `time`,
/// `actor`, `src_endpoint`, `dst_endpoint`, plus class-specific slots.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "class_name", rename_all = "snake_case")]
pub enum OcsfEvent {
    Authentication(AuthenticationEvent),
    ProcessActivity(ProcessActivityEvent),
    NetworkActivity(NetworkActivityEvent),
    DnsActivity(DnsActivityEvent),
    FileSystemActivity(FileSystemActivityEvent),
    RegistryKeyActivity(RegistryKeyActivityEvent),
    /// Escape hatch for edges that do not map cleanly into the shipping
    /// subset. The mapping audit flags these; they are never silently
    /// dropped.
    Other(OtherEvent),
}

/// 3002 — Authentication. Maps to `User --Auth--> Host` / `User --Auth--> Service`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticationEvent {
    pub class_uid: u32,
    pub activity_id: u32,
    pub time: i64,
    pub actor_user: Option<UserRef>,
    pub dst_endpoint: Option<EndpointRef>,
    pub auth_protocol: Option<String>,
    pub status: Option<String>,
    pub provenance: ProvenanceCtx,
}

/// 1007 — Process Activity. Maps to `User --Execute--> Process` and
/// `Process --Spawn--> Process`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessActivityEvent {
    pub class_uid: u32,
    pub activity_id: u32,
    pub time: i64,
    pub actor_user: Option<UserRef>,
    pub parent_process: Option<ProcessRef>,
    pub process: ProcessRef,
    pub provenance: ProvenanceCtx,
}

/// 4001 — Network Activity. Maps to `IP --Connect--> IP` / `Host --Connect--> IP`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkActivityEvent {
    pub class_uid: u32,
    pub activity_id: u32,
    pub time: i64,
    pub src_endpoint: Option<EndpointRef>,
    pub dst_endpoint: Option<EndpointRef>,
    pub protocol: Option<String>,
    pub provenance: ProvenanceCtx,
}

/// 4003 — DNS Activity. Maps to `Host --DNS--> Domain`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsActivityEvent {
    pub class_uid: u32,
    pub activity_id: u32,
    pub time: i64,
    pub src_endpoint: Option<EndpointRef>,
    pub query: DnsQuery,
    pub provenance: ProvenanceCtx,
}

/// 1001 — File System Activity. Maps to `Process --{Read,Write,Modify,Delete}--> File`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileSystemActivityEvent {
    pub class_uid: u32,
    pub activity_id: u32,
    pub time: i64,
    pub actor_process: Option<ProcessRef>,
    pub file: FileRef,
    pub provenance: ProvenanceCtx,
}

/// 5001 — Registry Key Activity. Maps to `Process --Modify--> Registry`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryKeyActivityEvent {
    pub class_uid: u32,
    pub activity_id: u32,
    pub time: i64,
    pub actor_process: Option<ProcessRef>,
    pub reg_key: RegistryKeyRef,
    pub provenance: ProvenanceCtx,
}

/// Fallback for edges outside the shipping subset. Mapping audits flag the
/// `reason` so the subset is grown intentionally, not by accident.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OtherEvent {
    pub class_uid: u32,
    pub time: i64,
    pub rel_type: String,
    pub source_type: String,
    pub source_id: String,
    pub dest_type: String,
    pub dest_id: String,
    pub reason: String,
    pub provenance: ProvenanceCtx,
}

// ─── Observable / reference types ──────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserRef {
    pub name: String,
    pub uid: Option<String>,
    pub domain: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EndpointRef {
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessRef {
    pub name: String,
    pub pid: Option<u64>,
    pub cmd_line: Option<String>,
    pub file: Option<FileRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileRef {
    pub path: String,
    pub name: Option<String>,
    pub hashes: Option<Hashes>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryKeyRef {
    pub path: String,
    pub value: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsQuery {
    pub hostname: String,
    pub qtype: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Hashes {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}

// ─── Class / activity constants ────────────────────────────────────────────

/// OCSF class uid constants. These are wire-stable; changing them is a
/// breaking schema change and triggers a ProvenanceCtx version bump.
pub mod class_uid {
    pub const AUTHENTICATION: u32 = 3002;
    pub const PROCESS_ACTIVITY: u32 = 1007;
    pub const NETWORK_ACTIVITY: u32 = 4001;
    pub const DNS_ACTIVITY: u32 = 4003;
    pub const FILE_SYSTEM_ACTIVITY: u32 = 1001;
    pub const REGISTRY_KEY_ACTIVITY: u32 = 5001;
    pub const OTHER: u32 = 0;
}

/// Activity id constants per class. Only the values the shipping parsers
/// emit are modeled; expand as parsers grow.
pub mod activity_id {
    pub mod authentication {
        pub const LOGON: u32 = 1;
        pub const LOGOFF: u32 = 2;
    }
    pub mod process_activity {
        pub const LAUNCH: u32 = 1;
        pub const TERMINATE: u32 = 2;
    }
    pub mod network_activity {
        pub const OPEN: u32 = 1;
        pub const CLOSE: u32 = 2;
        pub const TRAFFIC: u32 = 6;
    }
    pub mod dns_activity {
        pub const QUERY: u32 = 1;
        pub const RESPONSE: u32 = 2;
    }
    pub mod file_system_activity {
        pub const CREATE: u32 = 1;
        pub const READ: u32 = 2;
        pub const UPDATE: u32 = 3;
        pub const DELETE: u32 = 4;
    }
    pub mod registry_key_activity {
        pub const MODIFY: u32 = 3;
    }
}
