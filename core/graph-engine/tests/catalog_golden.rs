//! Golden test for the built-in catalog.
//!
//! Asserts that the 30 built-in entries loaded from YAML have
//! byte-exact fields matching the pre-P2-C Rust consts. If this test
//! fails, a YAML edit accidentally changed a pattern, description, or
//! id, and downstream tools (MCP, frontend dropdowns, Sigma exports)
//! will see a silent contract break.
//!
//! Add a new entry: extend the `EXPECTED` array AND create a new YAML
//! in `graph_hunter_core/src/catalog/builtin/cat-NNN.yaml`.
//!
//! Intentionally NOT derived from `get_catalog()` output — this is a
//! frozen snapshot.

use graph_hunter_core::get_catalog;

struct Expected {
    id: &'static str,
    name: &'static str,
    mitre_id: &'static str,
    description: &'static str,
    dsl_pattern: &'static str,
    k_simplicity: usize,
}

const EXPECTED: &[Expected] = &[
    Expected {
        id: "cat-001",
        name: "Valid Accounts — Lateral Auth",
        mitre_id: "T1078",
        description: "Compromised credentials used to authenticate across hosts, then execute processes.",
        dsl_pattern: "User -[Auth]-> Host -[Execute]-> Process",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-002",
        name: "PowerShell Execution",
        mitre_id: "T1059.001",
        description: "User executes a process that spawns PowerShell (or child process) and writes to disk.",
        dsl_pattern: "User -[Execute]-> Process -[Spawn]-> Process -[Write]-> File",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-003",
        name: "RDP Lateral Movement",
        mitre_id: "T1021.001",
        description: "IP connects to a host, authenticates as a user, then executes a process.",
        dsl_pattern: "IP -[Connect]-> Host -[Auth]-> User -[Execute]-> Process",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-004",
        name: "Credential Dumping",
        mitre_id: "T1003",
        description: "Process reads sensitive files (e.g., SAM, NTDS.dit, credential stores).",
        dsl_pattern: "User -[Execute]-> Process -[Read]-> File",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-005",
        name: "Application Layer Protocol — C2",
        mitre_id: "T1071",
        description: "Process resolves a domain via DNS, then connects to an external IP.",
        dsl_pattern: "Process -[DNS]-> Domain -[Connect]-> IP",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-006",
        name: "Service Execution",
        mitre_id: "T1569.002",
        description: "User executes a process that creates or modifies a service.",
        dsl_pattern: "User -[Execute]-> Process -[Modify]-> Service",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-007",
        name: "Scheduled Task",
        mitre_id: "T1053.005",
        description: "Process writes a file and spawns a child process (scheduled task pattern).",
        dsl_pattern: "Process -[Write]-> File -[Execute]-> Process",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-008",
        name: "Process Injection",
        mitre_id: "T1055",
        description: "Process spawns another process that then writes to memory/file.",
        dsl_pattern: "Process -[Spawn]-> Process -[Write]-> File",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-009",
        name: "DNS Exfiltration",
        mitre_id: "T1048.003",
        description: "Process resolves many domains (data exfiltration via DNS tunneling).",
        dsl_pattern: "User -[Execute]-> Process -[DNS]-> Domain",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-010",
        name: "Malware Drop and Execute",
        mitre_id: "T1204.002",
        description: "Process writes a file, then that file is executed as a new process.",
        dsl_pattern: "Process -[Write]-> File -[Execute]-> Process",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-011",
        name: "Registry Persistence",
        mitre_id: "T1547.001",
        description: "Process modifies registry for persistence, then spawns new process.",
        dsl_pattern: "Process -[Modify]-> Registry -[Execute]-> Process",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-012",
        name: "Multi-stage Lateral Movement",
        mitre_id: "T1021",
        description: "Full lateral movement chain: authentication, execution, file write, spawn.",
        dsl_pattern: "User -[Auth]-> Host -[Execute]-> Process -[Write]-> File",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-013",
        name: "C2 Callback Loop",
        mitre_id: "T1071",
        description: "Process resolves domain, connects to C2 IP, and callbacks to the originating process — forming a cycle.",
        dsl_pattern: "Process -[DNS]-> Domain -[Connect]-> IP -[Connect]-> Process {k=2}",
        k_simplicity: 2,
    },
    Expected {
        id: "cat-014",
        name: "Persistence Cycle",
        mitre_id: "T1547.001",
        description: "Process modifies registry for persistence, registry triggers execution of the same or similar process.",
        dsl_pattern: "Process -[Modify]-> Registry -[Execute]-> Process {k=2}",
        k_simplicity: 2,
    },
    Expected {
        id: "cat-015",
        name: "Lateral Movement with Return",
        mitre_id: "T1021",
        description: "Host authenticates user, user executes process, process connects back to the originating host.",
        dsl_pattern: "Host -[Auth]-> User -[Execute]-> Process -[Connect]-> Host {k=2}",
        k_simplicity: 2,
    },
    Expected {
        id: "cat-016",
        name: "Fileless Loop (Process re-exec)",
        mitre_id: "T1059",
        description: "Process spawns child process that executes another process, forming a fileless execution loop.",
        dsl_pattern: "Process -[Spawn]-> Process -[Execute]-> Process {k=2}",
        k_simplicity: 2,
    },
    Expected {
        id: "cat-017",
        name: "Password Spraying",
        mitre_id: "T1110.003",
        description: "One user fails authentication against many distinct IPs inside a short window — the canonical spray signal on Azure AD / Entra / Okta.",
        dsl_pattern: "User -[Auth {status=\"Failure\"}]-> IP HAVING count(distinct IP) >= 3 WITHIN 24h",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-018",
        name: "AAD Reconnaissance via PowerShell",
        mitre_id: "T1087.004",
        description: "User authenticates from an Azure AD PowerShell client — frequently the first stage of graph-API directory enumeration.",
        dsl_pattern: "User -[Auth {app~\"PowerShell\"}]-> IP",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-019",
        name: "Anonymizing Service Login",
        mitre_id: "T1078.004",
        description: "User authenticates from an IP flagged as anonymizing / VPN / hosting — typical of credential-theft follow-on.",
        dsl_pattern: "User -[Auth {risk_tag=\"anonymizing\"}]-> IP",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-020",
        name: "Successful Auth after Failures",
        mitre_id: "T1110.003",
        description: "Same user shows both Success and Failure Auths — classic spray-confirm signature if the Success follows multiple Failures. Use alongside cat-017.",
        dsl_pattern: "User -[Auth {status=\"Success\"}]-> IP HAVING count(distinct IP) >= 2",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-021",
        name: "Impossible Travel",
        mitre_id: "T1078.004",
        description: "User authenticates from 2+ distinct IPs inside a short window — heuristic for geo-impossible travel before enrichment lands.",
        dsl_pattern: "User -[Auth]-> IP HAVING count(distinct IP) >= 2 WITHIN 6h",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-022",
        name: "Illicit OAuth Consent Grant",
        mitre_id: "T1528",
        description: "A user grants consent to an attacker-controlled OAuth app — often the initial foothold for AAD application-based persistence.",
        dsl_pattern: "User -[Consent]-> OAuthApp",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-023",
        name: "Service Principal Creation",
        mitre_id: "T1098.003",
        description: "User creates a Service Principal — baseline activity for admins but a red flag from a compromised user account.",
        dsl_pattern: "User -[Create]-> ServicePrincipal",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-024",
        name: "Role Assignment Escalation",
        mitre_id: "T1098.003",
        description: "User grants a privileged role to another user — the `admin promoting admin` chain that often follows credential compromise.",
        dsl_pattern: "User -[Assign]-> Role -[Grant]-> User",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-025",
        name: "Mailbox Forwarding Rule",
        mitre_id: "T1564.008",
        description: "User sets up an inbox forwarding rule to an external domain — classic attacker-established exfiltration channel via Outlook rules.",
        dsl_pattern: "User -[Create]-> MailboxRule -[Forward]-> Domain",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-026",
        name: "LOLBAS Execution Chain",
        mitre_id: "T1218",
        description: "A process spawns a LOLBAS binary (certutil / bitsadmin / mshta / regsvr32) — living-off-the-land signature.",
        dsl_pattern: "Process -[Spawn]-> Process {name~\"certutil\"}",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-027",
        name: "BYOVD Driver Load",
        mitre_id: "T1014",
        description: "A process loads a driver from an unusual path or with an unknown signer — Bring-Your-Own-Vulnerable-Driver precursor to EDR bypass.",
        dsl_pattern: "Process -[Load]-> File {path~\".sys\"}",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-028",
        name: "EDR Tampering",
        mitre_id: "T1562.001",
        description: "A process modifies a protected security-tool service (Defender / CrowdStrike / Sense).",
        dsl_pattern: "Process -[Modify]-> Service {name~\"Sense\"}",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-029",
        name: "Remote Scheduled Task",
        mitre_id: "T1053.005",
        description: "User authenticates to a host, creates a scheduled Task, and the Task triggers a Process — cross-host persistence installed over the network.",
        dsl_pattern: "User -[Auth]-> Host -[Create]-> Task -[Execute]-> Process",
        k_simplicity: 1,
    },
    Expected {
        id: "cat-030",
        name: "Impossible Travel (proxy)",
        mitre_id: "T1078.004",
        description: "Successful authentications by the same user from 2+ distinct IPs within a one-hour window — proxy for impossible travel. The DSL itself does not consult geo metadata; pair this match with GeoIP enrichment (`enrich_ip`) on the matched IPs to confirm physical impossibility versus benign roaming (VPN, mobile carriers). Complementary to cat-017 (password spraying, looser 24h spray window) and cat-019 (anonymizing service).",
        dsl_pattern: r#"User -[Auth {status="Success"}]-> IP HAVING count(distinct IP) >= 2 WITHIN 1h"#,
        k_simplicity: 1,
    },
];

#[test]
fn built_in_catalog_matches_frozen_snapshot() {
    let actual = get_catalog();
    assert_eq!(
        actual.len(),
        EXPECTED.len(),
        "catalog entry count drifted — update this fixture deliberately when adding new entries"
    );

    for (idx, (a, e)) in actual.iter().zip(EXPECTED.iter()).enumerate() {
        assert_eq!(a.id, e.id, "[{idx}] id drift");
        assert_eq!(a.name, e.name, "[{idx}] name drift for {}", e.id);
        assert_eq!(
            a.mitre_id, e.mitre_id,
            "[{idx}] mitre_id drift for {}",
            e.id
        );
        assert_eq!(
            a.description, e.description,
            "[{idx}] description drift for {}",
            e.id
        );
        assert_eq!(
            a.dsl_pattern, e.dsl_pattern,
            "[{idx}] dsl_pattern drift for {}",
            e.id
        );
        assert_eq!(
            a.k_simplicity, e.k_simplicity,
            "[{idx}] k_simplicity drift for {}",
            e.id
        );
    }
}
