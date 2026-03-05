//! ATT&CK Hypothesis Catalog — pre-built detection patterns mapped to MITRE techniques.

use serde::Serialize;

/// A catalog entry: a named hypothesis pattern with MITRE ATT&CK mapping.
#[derive(Clone, Debug, Serialize)]
pub struct CatalogEntry {
    pub id: &'static str,
    pub name: &'static str,
    pub mitre_id: &'static str,
    pub description: &'static str,
    pub dsl_pattern: &'static str,
    /// k-simplicity: max times a vertex can appear in a path. 1 = simple path (default).
    pub k_simplicity: usize,
}

/// Returns the full ATT&CK hypothesis catalog.
pub fn get_catalog() -> &'static [CatalogEntry] {
    CATALOG
}

const CATALOG: &[CatalogEntry] = &[
    CatalogEntry {
        id: "cat-001",
        name: "Valid Accounts — Lateral Auth",
        mitre_id: "T1078",
        description: "Compromised credentials used to authenticate across hosts, then execute processes.",
        dsl_pattern: "User -[Auth]-> Host -[Execute]-> Process",
        k_simplicity: 1,
    },
    CatalogEntry {
        id: "cat-002",
        name: "PowerShell Execution",
        mitre_id: "T1059.001",
        description: "User executes a process that spawns PowerShell (or child process) and writes to disk.",
        dsl_pattern: "User -[Execute]-> Process -[Spawn]-> Process -[Write]-> File",
        k_simplicity: 1,
    },
    CatalogEntry {
        id: "cat-003",
        name: "RDP Lateral Movement",
        mitre_id: "T1021.001",
        description: "IP connects to a host, authenticates as a user, then executes a process.",
        dsl_pattern: "IP -[Connect]-> Host -[Auth]-> User -[Execute]-> Process",
        k_simplicity: 1,
    },
    CatalogEntry {
        id: "cat-004",
        name: "Credential Dumping",
        mitre_id: "T1003",
        description: "Process reads sensitive files (e.g., SAM, NTDS.dit, credential stores).",
        dsl_pattern: "User -[Execute]-> Process -[Read]-> File",
        k_simplicity: 1,
    },
    CatalogEntry {
        id: "cat-005",
        name: "Application Layer Protocol — C2",
        mitre_id: "T1071",
        description: "Process resolves a domain via DNS, then connects to an external IP.",
        dsl_pattern: "Process -[DNS]-> Domain -[Connect]-> IP",
        k_simplicity: 1,
    },
    CatalogEntry {
        id: "cat-006",
        name: "Service Execution",
        mitre_id: "T1569.002",
        description: "User executes a process that creates or modifies a service.",
        dsl_pattern: "User -[Execute]-> Process -[Modify]-> Service",
        k_simplicity: 1,
    },
    CatalogEntry {
        id: "cat-007",
        name: "Scheduled Task",
        mitre_id: "T1053.005",
        description: "Process writes a file and spawns a child process (scheduled task pattern).",
        dsl_pattern: "Process -[Write]-> File -[Execute]-> Process",
        k_simplicity: 1,
    },
    CatalogEntry {
        id: "cat-008",
        name: "Process Injection",
        mitre_id: "T1055",
        description: "Process spawns another process that then writes to memory/file.",
        dsl_pattern: "Process -[Spawn]-> Process -[Write]-> File",
        k_simplicity: 1,
    },
    CatalogEntry {
        id: "cat-009",
        name: "DNS Exfiltration",
        mitre_id: "T1048.003",
        description: "Process resolves many domains (data exfiltration via DNS tunneling).",
        dsl_pattern: "User -[Execute]-> Process -[DNS]-> Domain",
        k_simplicity: 1,
    },
    CatalogEntry {
        id: "cat-010",
        name: "Malware Drop and Execute",
        mitre_id: "T1204.002",
        description: "Process writes a file, then that file is executed as a new process.",
        dsl_pattern: "Process -[Write]-> File -[Execute]-> Process",
        k_simplicity: 1,
    },
    CatalogEntry {
        id: "cat-011",
        name: "Registry Persistence",
        mitre_id: "T1547.001",
        description: "Process modifies registry for persistence, then spawns new process.",
        dsl_pattern: "Process -[Modify]-> Registry -[Execute]-> Process",
        k_simplicity: 1,
    },
    CatalogEntry {
        id: "cat-012",
        name: "Multi-stage Lateral Movement",
        mitre_id: "T1021",
        description: "Full lateral movement chain: authentication, execution, file write, spawn.",
        dsl_pattern: "User -[Auth]-> Host -[Execute]-> Process -[Write]-> File",
        k_simplicity: 1,
    },
    // ── Cyclic patterns (k > 1) ──
    CatalogEntry {
        id: "cat-013",
        name: "C2 Callback Loop",
        mitre_id: "T1071",
        description: "Process resolves domain, connects to C2 IP, and callbacks to the originating process — forming a cycle.",
        dsl_pattern: "Process -[DNS]-> Domain -[Connect]-> IP -[Connect]-> Process {k=2}",
        k_simplicity: 2,
    },
    CatalogEntry {
        id: "cat-014",
        name: "Persistence Cycle",
        mitre_id: "T1547.001",
        description: "Process modifies registry for persistence, registry triggers execution of the same or similar process.",
        dsl_pattern: "Process -[Modify]-> Registry -[Execute]-> Process {k=2}",
        k_simplicity: 2,
    },
    CatalogEntry {
        id: "cat-015",
        name: "Lateral Movement with Return",
        mitre_id: "T1021",
        description: "Host authenticates user, user executes process, process connects back to the originating host.",
        dsl_pattern: "Host -[Auth]-> User -[Execute]-> Process -[Connect]-> Host {k=2}",
        k_simplicity: 2,
    },
    CatalogEntry {
        id: "cat-016",
        name: "Fileless Loop (Process re-exec)",
        mitre_id: "T1059",
        description: "Process spawns child process that executes another process, forming a fileless execution loop.",
        dsl_pattern: "Process -[Spawn]-> Process -[Execute]-> Process {k=2}",
        k_simplicity: 2,
    },
];
