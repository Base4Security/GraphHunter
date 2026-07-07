use serde::{Deserialize, Serialize};

/// High-level category for a network service or application, from a security
/// analysis perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceCategory {
    RemoteAccess,
    FileTransfer,
    WebBrowsing,
    Email,
    DNS,
    Authentication,
    CloudService,
    Proxy,
    VPN,
    Tunneling,
    Messaging,
    Database,
    Uncategorized,
}

/// Classification result for a network service/application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub category: ServiceCategory,
    /// Risk tag: "high", "medium", "low", or "info".
    pub risk_tag: &'static str,
    /// Human-readable description of the service.
    pub description: &'static str,
}

/// Returns `true` if the category implies a remote-access tool (high security
/// relevance for unauthorized access detection).
pub fn is_remote_access(cat: ServiceCategory) -> bool {
    matches!(cat, ServiceCategory::RemoteAccess)
}

/// Returns `true` if the category implies a file-transfer tool.
pub fn is_file_transfer(cat: ServiceCategory) -> bool {
    matches!(cat, ServiceCategory::FileTransfer)
}

// ── Dictionary ──
// Each entry: (normalized_name, category, risk_tag, description)
// Matching normalizes input to lowercase and strips `.`, `-`, `_` characters,
// then tries exact match, prefix, and substring in that order.

struct DictEntry {
    normalized: &'static str,
    category: ServiceCategory,
    risk_tag: &'static str,
    description: &'static str,
}

const DICTIONARY: &[DictEntry] = &[
    // ── Remote Access (risk: high) ──
    DictEntry {
        normalized: "rdp",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "Remote Desktop Protocol",
    },
    DictEntry {
        normalized: "msrdp",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "Microsoft RDP",
    },
    DictEntry {
        normalized: "rdpoverhttps",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "RDP over HTTPS tunnel",
    },
    DictEntry {
        normalized: "vnc",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "VNC remote desktop",
    },
    DictEntry {
        normalized: "ultravnc",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "UltraVNC remote desktop",
    },
    DictEntry {
        normalized: "tightvnc",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "TightVNC remote desktop",
    },
    DictEntry {
        normalized: "realvnc",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "RealVNC remote desktop",
    },
    DictEntry {
        normalized: "teamviewer",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "TeamViewer remote access",
    },
    DictEntry {
        normalized: "anydesk",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "AnyDesk remote access",
    },
    DictEntry {
        normalized: "ssh",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "Secure Shell",
    },
    DictEntry {
        normalized: "putty",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "PuTTY SSH/Telnet client",
    },
    DictEntry {
        normalized: "logmein",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "LogMeIn remote access",
    },
    DictEntry {
        normalized: "connectwise",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "ConnectWise remote access",
    },
    DictEntry {
        normalized: "screenconnect",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "ScreenConnect remote access",
    },
    DictEntry {
        normalized: "chromeremotedesktop",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "Chrome Remote Desktop",
    },
    DictEntry {
        normalized: "splashtop",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "Splashtop remote access",
    },
    DictEntry {
        normalized: "gotomypc",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "GoToMyPC remote access",
    },
    DictEntry {
        normalized: "parsec",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "Parsec remote desktop",
    },
    DictEntry {
        normalized: "dameware",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "Dameware remote support",
    },
    DictEntry {
        normalized: "citrixonline",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "Citrix remote access",
    },
    DictEntry {
        normalized: "citrix",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "Citrix remote access",
    },
    DictEntry {
        normalized: "mstsc",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "Microsoft Terminal Services Client",
    },
    DictEntry {
        normalized: "rustdesk",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "RustDesk remote desktop",
    },
    DictEntry {
        normalized: "ammyy",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "Ammyy Admin remote access",
    },
    DictEntry {
        normalized: "nomachine",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "NoMachine remote desktop",
    },
    DictEntry {
        normalized: "telnet",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "Telnet remote access (cleartext)",
    },
    DictEntry {
        normalized: "rlogin",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "Remote login (legacy)",
    },
    DictEntry {
        normalized: "remotedesktop",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "Remote Desktop",
    },
    DictEntry {
        normalized: "xrdp",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "XRDP remote desktop",
    },
    DictEntry {
        normalized: "radmin",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "Radmin remote access",
    },
    DictEntry {
        normalized: "bomgar",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "BeyondTrust (Bomgar) remote support",
    },
    DictEntry {
        normalized: "beyondtrust",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "BeyondTrust remote support",
    },
    DictEntry {
        normalized: "simplehelp",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "SimpleHelp remote support",
    },
    DictEntry {
        normalized: "simphelp",
        category: ServiceCategory::RemoteAccess,
        risk_tag: "high",
        description: "SimpleHelp remote support",
    },
    // ── File Transfer (risk: medium) ──
    DictEntry {
        normalized: "rclone",
        category: ServiceCategory::FileTransfer,
        risk_tag: "medium",
        description: "RClone cloud file sync",
    },
    DictEntry {
        normalized: "ftp",
        category: ServiceCategory::FileTransfer,
        risk_tag: "medium",
        description: "File Transfer Protocol",
    },
    DictEntry {
        normalized: "sftp",
        category: ServiceCategory::FileTransfer,
        risk_tag: "medium",
        description: "SSH File Transfer Protocol",
    },
    DictEntry {
        normalized: "scp",
        category: ServiceCategory::FileTransfer,
        risk_tag: "medium",
        description: "Secure Copy Protocol",
    },
    DictEntry {
        normalized: "smb",
        category: ServiceCategory::FileTransfer,
        risk_tag: "medium",
        description: "Server Message Block",
    },
    DictEntry {
        normalized: "cifs",
        category: ServiceCategory::FileTransfer,
        risk_tag: "medium",
        description: "Common Internet File System",
    },
    DictEntry {
        normalized: "webdav",
        category: ServiceCategory::FileTransfer,
        risk_tag: "medium",
        description: "WebDAV file access",
    },
    DictEntry {
        normalized: "winscp",
        category: ServiceCategory::FileTransfer,
        risk_tag: "medium",
        description: "WinSCP file transfer",
    },
    DictEntry {
        normalized: "filezilla",
        category: ServiceCategory::FileTransfer,
        risk_tag: "medium",
        description: "FileZilla FTP client",
    },
    DictEntry {
        normalized: "bittorrent",
        category: ServiceCategory::FileTransfer,
        risk_tag: "medium",
        description: "BitTorrent P2P transfer",
    },
    DictEntry {
        normalized: "mega",
        category: ServiceCategory::FileTransfer,
        risk_tag: "medium",
        description: "MEGA cloud storage",
    },
    DictEntry {
        normalized: "dropbox",
        category: ServiceCategory::FileTransfer,
        risk_tag: "medium",
        description: "Dropbox cloud storage",
    },
    DictEntry {
        normalized: "rsync",
        category: ServiceCategory::FileTransfer,
        risk_tag: "medium",
        description: "rsync file synchronization",
    },
    DictEntry {
        normalized: "onedrive",
        category: ServiceCategory::FileTransfer,
        risk_tag: "medium",
        description: "OneDrive cloud storage",
    },
    DictEntry {
        normalized: "googledrive",
        category: ServiceCategory::FileTransfer,
        risk_tag: "medium",
        description: "Google Drive cloud storage",
    },
    DictEntry {
        normalized: "wetransfer",
        category: ServiceCategory::FileTransfer,
        risk_tag: "medium",
        description: "WeTransfer file sharing",
    },
    DictEntry {
        normalized: "nfs",
        category: ServiceCategory::FileTransfer,
        risk_tag: "medium",
        description: "Network File System",
    },
    DictEntry {
        normalized: "tftp",
        category: ServiceCategory::FileTransfer,
        risk_tag: "medium",
        description: "Trivial File Transfer Protocol",
    },
    // ── Authentication (risk: info) ──
    DictEntry {
        normalized: "ldap",
        category: ServiceCategory::Authentication,
        risk_tag: "info",
        description: "Lightweight Directory Access Protocol",
    },
    DictEntry {
        normalized: "kerberos",
        category: ServiceCategory::Authentication,
        risk_tag: "info",
        description: "Kerberos authentication",
    },
    DictEntry {
        normalized: "adfs",
        category: ServiceCategory::Authentication,
        risk_tag: "info",
        description: "Active Directory Federation Services",
    },
    DictEntry {
        normalized: "saml",
        category: ServiceCategory::Authentication,
        risk_tag: "info",
        description: "Security Assertion Markup Language",
    },
    DictEntry {
        normalized: "radius",
        category: ServiceCategory::Authentication,
        risk_tag: "info",
        description: "RADIUS authentication",
    },
    DictEntry {
        normalized: "ntlm",
        category: ServiceCategory::Authentication,
        risk_tag: "info",
        description: "NT LAN Manager authentication",
    },
    DictEntry {
        normalized: "oauth",
        category: ServiceCategory::Authentication,
        risk_tag: "info",
        description: "OAuth authorization",
    },
    DictEntry {
        normalized: "sso",
        category: ServiceCategory::Authentication,
        risk_tag: "info",
        description: "Single Sign-On",
    },
    DictEntry {
        normalized: "activedirectory",
        category: ServiceCategory::Authentication,
        risk_tag: "info",
        description: "Active Directory",
    },
    // ── Tunneling (risk: high) ──
    DictEntry {
        normalized: "ngrok",
        category: ServiceCategory::Tunneling,
        risk_tag: "high",
        description: "ngrok tunnel",
    },
    DictEntry {
        normalized: "cloudflaretunnel",
        category: ServiceCategory::Tunneling,
        risk_tag: "high",
        description: "Cloudflare Tunnel",
    },
    DictEntry {
        normalized: "sshtunnel",
        category: ServiceCategory::Tunneling,
        risk_tag: "high",
        description: "SSH tunnel",
    },
    DictEntry {
        normalized: "localtunnel",
        category: ServiceCategory::Tunneling,
        risk_tag: "high",
        description: "localtunnel",
    },
    DictEntry {
        normalized: "pagekite",
        category: ServiceCategory::Tunneling,
        risk_tag: "high",
        description: "PageKite tunnel",
    },
    DictEntry {
        normalized: "chisel",
        category: ServiceCategory::Tunneling,
        risk_tag: "high",
        description: "Chisel TCP/UDP tunnel",
    },
    DictEntry {
        normalized: "frp",
        category: ServiceCategory::Tunneling,
        risk_tag: "high",
        description: "Fast Reverse Proxy tunnel",
    },
    // ── Proxy (risk: medium) ──
    DictEntry {
        normalized: "proxyhttp",
        category: ServiceCategory::Proxy,
        risk_tag: "medium",
        description: "HTTP Proxy",
    },
    DictEntry {
        normalized: "proxy",
        category: ServiceCategory::Proxy,
        risk_tag: "medium",
        description: "Network proxy",
    },
    DictEntry {
        normalized: "socks",
        category: ServiceCategory::Proxy,
        risk_tag: "medium",
        description: "SOCKS proxy",
    },
    DictEntry {
        normalized: "socks5",
        category: ServiceCategory::Proxy,
        risk_tag: "medium",
        description: "SOCKS5 proxy",
    },
    DictEntry {
        normalized: "tor",
        category: ServiceCategory::Proxy,
        risk_tag: "medium",
        description: "Tor anonymizing proxy",
    },
    DictEntry {
        normalized: "privoxy",
        category: ServiceCategory::Proxy,
        risk_tag: "medium",
        description: "Privoxy privacy proxy",
    },
    DictEntry {
        normalized: "squid",
        category: ServiceCategory::Proxy,
        risk_tag: "medium",
        description: "Squid proxy server",
    },
    // ── VPN (risk: low) ──
    DictEntry {
        normalized: "openvpn",
        category: ServiceCategory::VPN,
        risk_tag: "low",
        description: "OpenVPN",
    },
    DictEntry {
        normalized: "wireguard",
        category: ServiceCategory::VPN,
        risk_tag: "low",
        description: "WireGuard VPN",
    },
    DictEntry {
        normalized: "ipsec",
        category: ServiceCategory::VPN,
        risk_tag: "low",
        description: "IPSec VPN",
    },
    DictEntry {
        normalized: "l2tp",
        category: ServiceCategory::VPN,
        risk_tag: "low",
        description: "L2TP VPN",
    },
    DictEntry {
        normalized: "pptp",
        category: ServiceCategory::VPN,
        risk_tag: "low",
        description: "PPTP VPN (legacy)",
    },
    DictEntry {
        normalized: "forticlient",
        category: ServiceCategory::VPN,
        risk_tag: "low",
        description: "FortiClient VPN",
    },
    DictEntry {
        normalized: "globalprotect",
        category: ServiceCategory::VPN,
        risk_tag: "low",
        description: "Palo Alto GlobalProtect VPN",
    },
    DictEntry {
        normalized: "anyconnect",
        category: ServiceCategory::VPN,
        risk_tag: "low",
        description: "Cisco AnyConnect VPN",
    },
    DictEntry {
        normalized: "vpn",
        category: ServiceCategory::VPN,
        risk_tag: "low",
        description: "VPN connection",
    },
    // ── Web Browsing (risk: low) ──
    DictEntry {
        normalized: "http",
        category: ServiceCategory::WebBrowsing,
        risk_tag: "low",
        description: "HTTP web traffic",
    },
    DictEntry {
        normalized: "https",
        category: ServiceCategory::WebBrowsing,
        risk_tag: "low",
        description: "HTTPS encrypted web traffic",
    },
    DictEntry {
        normalized: "ssl",
        category: ServiceCategory::WebBrowsing,
        risk_tag: "low",
        description: "SSL/TLS encrypted traffic",
    },
    DictEntry {
        normalized: "webbrowsing",
        category: ServiceCategory::WebBrowsing,
        risk_tag: "low",
        description: "Web browsing",
    },
    DictEntry {
        normalized: "chrome",
        category: ServiceCategory::WebBrowsing,
        risk_tag: "low",
        description: "Google Chrome browser",
    },
    DictEntry {
        normalized: "firefox",
        category: ServiceCategory::WebBrowsing,
        risk_tag: "low",
        description: "Mozilla Firefox browser",
    },
    DictEntry {
        normalized: "edge",
        category: ServiceCategory::WebBrowsing,
        risk_tag: "low",
        description: "Microsoft Edge browser",
    },
    // ── Email (risk: low) ──
    DictEntry {
        normalized: "smtp",
        category: ServiceCategory::Email,
        risk_tag: "low",
        description: "Simple Mail Transfer Protocol",
    },
    DictEntry {
        normalized: "imap",
        category: ServiceCategory::Email,
        risk_tag: "low",
        description: "IMAP email retrieval",
    },
    DictEntry {
        normalized: "pop3",
        category: ServiceCategory::Email,
        risk_tag: "low",
        description: "POP3 email retrieval",
    },
    DictEntry {
        normalized: "exchange",
        category: ServiceCategory::Email,
        risk_tag: "low",
        description: "Microsoft Exchange",
    },
    DictEntry {
        normalized: "mapi",
        category: ServiceCategory::Email,
        risk_tag: "low",
        description: "MAPI email protocol",
    },
    // ── DNS (risk: info) ──
    DictEntry {
        normalized: "dns",
        category: ServiceCategory::DNS,
        risk_tag: "info",
        description: "Domain Name System",
    },
    DictEntry {
        normalized: "doh",
        category: ServiceCategory::DNS,
        risk_tag: "info",
        description: "DNS over HTTPS",
    },
    DictEntry {
        normalized: "dot",
        category: ServiceCategory::DNS,
        risk_tag: "info",
        description: "DNS over TLS",
    },
    // ── Cloud Services (risk: info) ──
    DictEntry {
        normalized: "o365",
        category: ServiceCategory::CloudService,
        risk_tag: "info",
        description: "Microsoft 365",
    },
    DictEntry {
        normalized: "microsoft365",
        category: ServiceCategory::CloudService,
        risk_tag: "info",
        description: "Microsoft 365",
    },
    DictEntry {
        normalized: "office365",
        category: ServiceCategory::CloudService,
        risk_tag: "info",
        description: "Microsoft Office 365",
    },
    DictEntry {
        normalized: "googleworkspace",
        category: ServiceCategory::CloudService,
        risk_tag: "info",
        description: "Google Workspace",
    },
    DictEntry {
        normalized: "aws",
        category: ServiceCategory::CloudService,
        risk_tag: "info",
        description: "Amazon Web Services",
    },
    DictEntry {
        normalized: "azure",
        category: ServiceCategory::CloudService,
        risk_tag: "info",
        description: "Microsoft Azure",
    },
    // ── Messaging (risk: low) ──
    DictEntry {
        normalized: "slack",
        category: ServiceCategory::Messaging,
        risk_tag: "low",
        description: "Slack messaging",
    },
    DictEntry {
        normalized: "teams",
        category: ServiceCategory::Messaging,
        risk_tag: "low",
        description: "Microsoft Teams",
    },
    DictEntry {
        normalized: "msteams",
        category: ServiceCategory::Messaging,
        risk_tag: "low",
        description: "Microsoft Teams",
    },
    DictEntry {
        normalized: "telegram",
        category: ServiceCategory::Messaging,
        risk_tag: "low",
        description: "Telegram messaging",
    },
    DictEntry {
        normalized: "zoom",
        category: ServiceCategory::Messaging,
        risk_tag: "low",
        description: "Zoom video conferencing",
    },
    DictEntry {
        normalized: "webex",
        category: ServiceCategory::Messaging,
        risk_tag: "low",
        description: "Webex conferencing",
    },
    // ── Database (risk: medium) ──
    DictEntry {
        normalized: "mysql",
        category: ServiceCategory::Database,
        risk_tag: "medium",
        description: "MySQL database",
    },
    DictEntry {
        normalized: "mssql",
        category: ServiceCategory::Database,
        risk_tag: "medium",
        description: "Microsoft SQL Server",
    },
    DictEntry {
        normalized: "postgres",
        category: ServiceCategory::Database,
        risk_tag: "medium",
        description: "PostgreSQL database",
    },
    DictEntry {
        normalized: "postgresql",
        category: ServiceCategory::Database,
        risk_tag: "medium",
        description: "PostgreSQL database",
    },
    DictEntry {
        normalized: "mongodb",
        category: ServiceCategory::Database,
        risk_tag: "medium",
        description: "MongoDB database",
    },
    DictEntry {
        normalized: "redis",
        category: ServiceCategory::Database,
        risk_tag: "medium",
        description: "Redis database",
    },
];

/// Normalizes an application name for dictionary matching: lowercase, strip
/// `.`, `-`, `_`, and whitespace.
fn normalize(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .filter(|c| !matches!(c, '.' | '-' | '_' | ' '))
        .collect()
}

/// Classifies an application name (e.g. from FortiAnalyzer) into a
/// [`ServiceCategory`] with risk level and description.
///
/// Matching strategy:
/// 1. Exact match (after normalization)
/// 2. Starts-with match (normalized input starts with dictionary key)
/// 3. Contains match (dictionary key is a substring of normalized input)
///
/// Returns `Uncategorized` with risk "info" if no match is found.
pub fn classify_application(app_name: &str) -> ServiceInfo {
    let norm = normalize(app_name);
    if norm.is_empty() {
        return ServiceInfo {
            category: ServiceCategory::Uncategorized,
            risk_tag: "info",
            description: "Unknown application",
        };
    }

    // 1. Exact match
    for entry in DICTIONARY {
        if norm == entry.normalized {
            return ServiceInfo {
                category: entry.category,
                risk_tag: entry.risk_tag,
                description: entry.description,
            };
        }
    }

    // 2. Input starts with a dictionary key (e.g. "rdpoverhttps" starts with "rdp")
    // Prefer longer matches to avoid false positives.
    let mut best_prefix: Option<&DictEntry> = None;
    for entry in DICTIONARY {
        if norm.starts_with(entry.normalized) {
            match best_prefix {
                None => best_prefix = Some(entry),
                Some(prev) if entry.normalized.len() > prev.normalized.len() => {
                    best_prefix = Some(entry);
                }
                _ => {}
            }
        }
    }
    if let Some(entry) = best_prefix {
        return ServiceInfo {
            category: entry.category,
            risk_tag: entry.risk_tag,
            description: entry.description,
        };
    }

    // 3. Dictionary key is a substring of the input
    // (e.g. "ms.rdp.over.https" contains "rdp")
    // Prefer longer matches.
    let mut best_contains: Option<&DictEntry> = None;
    for entry in DICTIONARY {
        if norm.contains(entry.normalized) {
            match best_contains {
                None => best_contains = Some(entry),
                Some(prev) if entry.normalized.len() > prev.normalized.len() => {
                    best_contains = Some(entry);
                }
                _ => {}
            }
        }
    }
    if let Some(entry) = best_contains {
        return ServiceInfo {
            category: entry.category,
            risk_tag: entry.risk_tag,
            description: entry.description,
        };
    }

    ServiceInfo {
        category: ServiceCategory::Uncategorized,
        risk_tag: "info",
        description: "Unknown application",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Remote Access ──

    #[test]
    fn rdp_exact() {
        let info = classify_application("RDP");
        assert_eq!(info.category, ServiceCategory::RemoteAccess);
        assert_eq!(info.risk_tag, "high");
    }

    #[test]
    fn ms_rdp_dotted() {
        let info = classify_application("MS.RDP");
        assert_eq!(info.category, ServiceCategory::RemoteAccess);
    }

    #[test]
    fn rdp_over_https() {
        let info = classify_application("RDP.Over.HTTPS");
        assert_eq!(info.category, ServiceCategory::RemoteAccess);
    }

    #[test]
    fn anydesk() {
        let info = classify_application("AnyDesk");
        assert_eq!(info.category, ServiceCategory::RemoteAccess);
        assert_eq!(info.risk_tag, "high");
    }

    #[test]
    fn teamviewer_lowercase() {
        let info = classify_application("teamviewer");
        assert_eq!(info.category, ServiceCategory::RemoteAccess);
    }

    #[test]
    fn putty_mixed_case() {
        let info = classify_application("PuTTY");
        assert_eq!(info.category, ServiceCategory::RemoteAccess);
    }

    #[test]
    fn vnc() {
        let info = classify_application("VNC");
        assert_eq!(info.category, ServiceCategory::RemoteAccess);
    }

    #[test]
    fn ssh_exact() {
        let info = classify_application("SSH");
        assert_eq!(info.category, ServiceCategory::RemoteAccess);
    }

    #[test]
    fn simphelp() {
        let info = classify_application("SimpleHelp");
        assert_eq!(info.category, ServiceCategory::RemoteAccess);
    }

    // ── File Transfer ──

    #[test]
    fn rclone() {
        let info = classify_application("RClone");
        assert_eq!(info.category, ServiceCategory::FileTransfer);
        assert_eq!(info.risk_tag, "medium");
    }

    #[test]
    fn ftp_exact() {
        let info = classify_application("FTP");
        assert_eq!(info.category, ServiceCategory::FileTransfer);
    }

    #[test]
    fn smb() {
        let info = classify_application("SMB");
        assert_eq!(info.category, ServiceCategory::FileTransfer);
    }

    // ── Authentication ──

    #[test]
    fn adfs() {
        let info = classify_application("ADFS");
        assert_eq!(info.category, ServiceCategory::Authentication);
        assert_eq!(info.risk_tag, "info");
    }

    #[test]
    fn kerberos() {
        let info = classify_application("Kerberos");
        assert_eq!(info.category, ServiceCategory::Authentication);
    }

    #[test]
    fn ldap() {
        let info = classify_application("LDAP");
        assert_eq!(info.category, ServiceCategory::Authentication);
    }

    // ── Tunneling ──

    #[test]
    fn ngrok() {
        let info = classify_application("ngrok");
        assert_eq!(info.category, ServiceCategory::Tunneling);
        assert_eq!(info.risk_tag, "high");
    }

    // ── VPN ──

    #[test]
    fn forticlient() {
        let info = classify_application("FortiClient");
        assert_eq!(info.category, ServiceCategory::VPN);
        assert_eq!(info.risk_tag, "low");
    }

    #[test]
    fn openvpn() {
        let info = classify_application("OpenVPN");
        assert_eq!(info.category, ServiceCategory::VPN);
    }

    // ── Proxy ──

    #[test]
    fn proxy_http() {
        let info = classify_application("Proxy.HTTP");
        assert_eq!(info.category, ServiceCategory::Proxy);
        assert_eq!(info.risk_tag, "medium");
    }

    #[test]
    fn tor() {
        let info = classify_application("Tor");
        assert_eq!(info.category, ServiceCategory::Proxy);
    }

    // ── Web ──

    #[test]
    fn https() {
        let info = classify_application("HTTPS");
        assert_eq!(info.category, ServiceCategory::WebBrowsing);
    }

    // ── DNS ──

    #[test]
    fn dns_exact() {
        let info = classify_application("DNS");
        assert_eq!(info.category, ServiceCategory::DNS);
    }

    // ── Uncategorized ──

    #[test]
    fn unknown_app() {
        let info = classify_application("SomeRandomApp");
        assert_eq!(info.category, ServiceCategory::Uncategorized);
        assert_eq!(info.risk_tag, "info");
    }

    #[test]
    fn empty_string() {
        let info = classify_application("");
        assert_eq!(info.category, ServiceCategory::Uncategorized);
    }

    // ── Helper functions ──

    #[test]
    fn is_remote_access_true() {
        assert!(is_remote_access(ServiceCategory::RemoteAccess));
    }

    #[test]
    fn is_remote_access_false() {
        assert!(!is_remote_access(ServiceCategory::FileTransfer));
        assert!(!is_remote_access(ServiceCategory::Uncategorized));
    }

    #[test]
    fn is_file_transfer_true() {
        assert!(is_file_transfer(ServiceCategory::FileTransfer));
    }

    #[test]
    fn is_file_transfer_false() {
        assert!(!is_file_transfer(ServiceCategory::RemoteAccess));
    }

    // ── FortiAnalyzer dot notation ──

    #[test]
    fn forti_dot_notation() {
        // FortiAnalyzer uses dots in app names
        assert_eq!(
            classify_application("MS.RDP").category,
            ServiceCategory::RemoteAccess
        );
        assert_eq!(
            classify_application("Proxy.HTTP").category,
            ServiceCategory::Proxy
        );
    }

    // ── Substring matching ──

    #[test]
    fn substring_rdp_in_longer_name() {
        // Something like "Windows.RDP.Client" should still match RDP
        let info = classify_application("Windows.RDP.Client");
        assert_eq!(info.category, ServiceCategory::RemoteAccess);
    }
}
