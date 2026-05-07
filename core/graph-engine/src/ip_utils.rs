use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Classification of an IP address by its allocation scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IpClass {
    Private,
    Loopback,
    LinkLocal,
    Multicast,
    Reserved,
    Public,
}

/// Classifies an IP address string. Returns `None` if the string is not a
/// valid IPv4 or IPv6 address.
pub fn classify_ip(s: &str) -> Option<IpClass> {
    let addr: IpAddr = s.trim().parse().ok()?;
    Some(classify_addr(addr))
}

fn classify_addr(addr: IpAddr) -> IpClass {
    match addr {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> IpClass {
    let octets = ip.octets();
    // Loopback: 127.0.0.0/8
    if octets[0] == 127 {
        return IpClass::Loopback;
    }
    // Link-local: 169.254.0.0/16
    if octets[0] == 169 && octets[1] == 254 {
        return IpClass::LinkLocal;
    }
    // Multicast: 224.0.0.0/4
    if octets[0] >= 224 && octets[0] <= 239 {
        return IpClass::Multicast;
    }
    // Reserved: 240.0.0.0/4 (future use) and 0.0.0.0/8 (this network)
    if octets[0] >= 240 || octets[0] == 0 {
        return IpClass::Reserved;
    }
    // RFC 1918 private ranges
    // 10.0.0.0/8
    if octets[0] == 10 {
        return IpClass::Private;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
        return IpClass::Private;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return IpClass::Private;
    }
    // CGNAT: 100.64.0.0/10 — treated as internal for forensic purposes
    if octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127) {
        return IpClass::Private;
    }
    // 198.18.0.0/15 — benchmarking, treated as reserved
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return IpClass::Reserved;
    }
    // 192.0.0.0/24 — IANA special, reserved
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return IpClass::Reserved;
    }
    // 192.0.2.0/24 (TEST-NET-1), 198.51.100.0/24 (TEST-NET-2),
    // 203.0.113.0/24 (TEST-NET-3) — documentation, treated as reserved
    if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
    {
        return IpClass::Reserved;
    }
    IpClass::Public
}

fn classify_v6(ip: Ipv6Addr) -> IpClass {
    // ::1 loopback
    if ip == Ipv6Addr::LOCALHOST {
        return IpClass::Loopback;
    }
    // :: unspecified
    if ip == Ipv6Addr::UNSPECIFIED {
        return IpClass::Reserved;
    }
    let segments = ip.segments();
    // fe80::/10 link-local
    if segments[0] & 0xffc0 == 0xfe80 {
        return IpClass::LinkLocal;
    }
    // ff00::/8 multicast
    if segments[0] & 0xff00 == 0xff00 {
        return IpClass::Multicast;
    }
    // fc00::/7 unique local (private)
    if segments[0] & 0xfe00 == 0xfc00 {
        return IpClass::Private;
    }
    // ::ffff:0:0/96 IPv4-mapped — classify the embedded IPv4
    if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0xffff
    {
        let v4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        );
        return classify_v4(v4);
    }
    // 2001:db8::/32 documentation
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return IpClass::Reserved;
    }
    // 100::/64 discard prefix
    if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 {
        return IpClass::Reserved;
    }
    IpClass::Public
}

/// Returns `true` if the IP is in a private/internal range (RFC 1918 + CGNAT).
pub fn is_private(s: &str) -> bool {
    classify_ip(s) == Some(IpClass::Private)
}

/// Returns `true` if the IP is publicly routable on the internet.
pub fn is_public(s: &str) -> bool {
    classify_ip(s) == Some(IpClass::Public)
}

/// Returns `true` for any address that should be considered "internal"
/// for analyst-facing rollups: private (RFC 1918 + CGNAT), loopback,
/// or link-local. The narrower `is_private` is RFC-1918-only and was
/// not the right signal for `subnet_analysis.is_internal` because a
/// /64 containing `::1` is plainly internal but classified as Loopback,
/// not Private.
pub fn is_internal(s: &str) -> bool {
    matches!(
        classify_ip(s),
        Some(IpClass::Private) | Some(IpClass::Loopback) | Some(IpClass::LinkLocal)
    )
}

/// Extracts the /24 subnet for IPv4 (e.g. `"10.3.10.0/24"`) or the /64
/// subnet for IPv6. Returns `None` for non-IP input.
pub fn subnet_24(s: &str) -> Option<String> {
    let addr: IpAddr = s.trim().parse().ok()?;
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!("{}.{}.{}.0/24", o[0], o[1], o[2]))
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            Some(format!(
                "{:x}:{:x}:{:x}:{:x}::/64",
                seg[0], seg[1], seg[2], seg[3]
            ))
        }
    }
}

/// Returns `true` if two IP addresses share the same /24 (IPv4) or /64 (IPv6)
/// subnet. Returns `false` if either string is not a valid IP or they differ
/// in address family.
pub fn same_subnet_24(a: &str, b: &str) -> bool {
    match (subnet_24(a), subnet_24(b)) {
        (Some(sa), Some(sb)) => sa == sb,
        _ => false,
    }
}

/// Groups a slice of IP strings by their /24 (IPv4) or /64 (IPv6) subnet.
/// Non-IP strings are silently skipped. Results are sorted by IP count
/// descending.
pub fn group_by_subnet(ips: &[&str]) -> Vec<(String, Vec<String>)> {
    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
    for &ip in ips {
        if let Some(subnet) = subnet_24(ip) {
            groups.entry(subnet).or_default().push(ip.to_string());
        }
    }
    let mut result: Vec<_> = groups.into_iter().collect();
    result.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── classify_ip ──

    #[test]
    fn private_rfc1918_10() {
        assert_eq!(classify_ip("10.0.0.1"), Some(IpClass::Private));
        assert_eq!(classify_ip("10.255.255.255"), Some(IpClass::Private));
    }

    #[test]
    fn private_rfc1918_172() {
        assert_eq!(classify_ip("172.16.0.1"), Some(IpClass::Private));
        assert_eq!(classify_ip("172.31.255.255"), Some(IpClass::Private));
        // 172.15.x and 172.32.x are NOT private
        assert_eq!(classify_ip("172.15.0.1"), Some(IpClass::Public));
        assert_eq!(classify_ip("172.32.0.1"), Some(IpClass::Public));
    }

    #[test]
    fn private_rfc1918_192_168() {
        assert_eq!(classify_ip("192.168.0.1"), Some(IpClass::Private));
        assert_eq!(classify_ip("192.168.255.255"), Some(IpClass::Private));
    }

    #[test]
    fn private_cgnat() {
        assert_eq!(classify_ip("100.64.0.1"), Some(IpClass::Private));
        assert_eq!(classify_ip("100.127.255.255"), Some(IpClass::Private));
        // Outside CGNAT range
        assert_eq!(classify_ip("100.63.255.255"), Some(IpClass::Public));
        assert_eq!(classify_ip("100.128.0.0"), Some(IpClass::Public));
    }

    #[test]
    fn loopback_v4() {
        assert_eq!(classify_ip("127.0.0.1"), Some(IpClass::Loopback));
        assert_eq!(classify_ip("127.255.255.255"), Some(IpClass::Loopback));
    }

    #[test]
    fn loopback_v6() {
        assert_eq!(classify_ip("::1"), Some(IpClass::Loopback));
    }

    #[test]
    fn link_local_v4() {
        assert_eq!(classify_ip("169.254.1.1"), Some(IpClass::LinkLocal));
    }

    #[test]
    fn link_local_v6() {
        assert_eq!(classify_ip("fe80::1"), Some(IpClass::LinkLocal));
    }

    #[test]
    fn multicast_v4() {
        assert_eq!(classify_ip("224.0.0.1"), Some(IpClass::Multicast));
        assert_eq!(classify_ip("239.255.255.255"), Some(IpClass::Multicast));
    }

    #[test]
    fn multicast_v6() {
        assert_eq!(classify_ip("ff02::1"), Some(IpClass::Multicast));
    }

    #[test]
    fn reserved_v4() {
        assert_eq!(classify_ip("0.0.0.0"), Some(IpClass::Reserved));
        assert_eq!(classify_ip("240.0.0.1"), Some(IpClass::Reserved));
        assert_eq!(classify_ip("255.255.255.255"), Some(IpClass::Reserved));
        // Documentation ranges
        assert_eq!(classify_ip("192.0.2.1"), Some(IpClass::Reserved));
        assert_eq!(classify_ip("198.51.100.1"), Some(IpClass::Reserved));
        assert_eq!(classify_ip("203.0.113.1"), Some(IpClass::Reserved));
    }

    #[test]
    fn public_v4() {
        assert_eq!(classify_ip("8.8.8.8"), Some(IpClass::Public));
        assert_eq!(classify_ip("1.1.1.1"), Some(IpClass::Public));
        assert_eq!(classify_ip("142.250.80.46"), Some(IpClass::Public));
    }

    #[test]
    fn public_v6() {
        assert_eq!(classify_ip("2001:4860:4860::8888"), Some(IpClass::Public));
    }

    #[test]
    fn private_v6_ula() {
        assert_eq!(classify_ip("fd00::1"), Some(IpClass::Private));
        assert_eq!(classify_ip("fc00::1"), Some(IpClass::Private));
    }

    #[test]
    fn reserved_v6_doc() {
        assert_eq!(classify_ip("2001:db8::1"), Some(IpClass::Reserved));
    }

    #[test]
    fn ipv4_mapped_v6() {
        // ::ffff:10.0.0.1 should classify as Private (embedded IPv4)
        assert_eq!(classify_ip("::ffff:10.0.0.1"), Some(IpClass::Private));
        assert_eq!(classify_ip("::ffff:8.8.8.8"), Some(IpClass::Public));
    }

    #[test]
    fn invalid_input() {
        assert_eq!(classify_ip("not-an-ip"), None);
        assert_eq!(classify_ip(""), None);
        assert_eq!(classify_ip("hello.world"), None);
    }

    #[test]
    fn whitespace_trimmed() {
        assert_eq!(classify_ip("  8.8.8.8  "), Some(IpClass::Public));
    }

    // ── is_private / is_public ──

    #[test]
    fn is_private_true() {
        assert!(is_private("10.3.10.66"));
        assert!(is_private("192.168.1.1"));
    }

    #[test]
    fn is_private_false() {
        assert!(!is_private("8.8.8.8"));
        assert!(!is_private("not-an-ip"));
    }

    #[test]
    fn is_public_true() {
        assert!(is_public("8.8.8.8"));
        assert!(is_public("1.1.1.1"));
    }

    #[test]
    fn is_public_false() {
        assert!(!is_public("10.0.0.1"));
        assert!(!is_public("127.0.0.1"));
    }

    // ── subnet_24 ──

    #[test]
    fn subnet_24_v4() {
        assert_eq!(subnet_24("10.3.10.66"), Some("10.3.10.0/24".to_string()));
        assert_eq!(
            subnet_24("192.168.1.42"),
            Some("192.168.1.0/24".to_string())
        );
    }

    #[test]
    fn subnet_24_v6() {
        assert_eq!(
            subnet_24("2001:db8:abcd:0012::1"),
            Some("2001:db8:abcd:12::/64".to_string())
        );
    }

    #[test]
    fn subnet_24_invalid() {
        assert_eq!(subnet_24("not-an-ip"), None);
    }

    // ── same_subnet_24 ──

    #[test]
    fn same_subnet_yes() {
        assert!(same_subnet_24("10.3.10.66", "10.3.10.100"));
    }

    #[test]
    fn same_subnet_no() {
        assert!(!same_subnet_24("10.3.10.66", "10.3.11.66"));
    }

    #[test]
    fn same_subnet_invalid() {
        assert!(!same_subnet_24("10.3.10.66", "not-an-ip"));
    }

    // ── group_by_subnet ──

    #[test]
    fn group_by_subnet_basic() {
        let ips = vec![
            "10.3.10.66",
            "10.3.10.100",
            "10.3.10.200",
            "10.3.11.1",
            "192.168.1.1",
            "not-an-ip",
        ];
        let groups = group_by_subnet(&ips);
        // 10.3.10.0/24 has 3 IPs — should be first
        assert_eq!(groups[0].0, "10.3.10.0/24");
        assert_eq!(groups[0].1.len(), 3);
        // Other groups have 1 IP each
        assert_eq!(groups.len(), 3);
    }

    #[test]
    fn group_by_subnet_empty() {
        let groups = group_by_subnet(&[]);
        assert!(groups.is_empty());
    }
}
