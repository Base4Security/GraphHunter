//! Best-effort L7 decoders for the PCAP flow ingest path.
//!
//! All three decoders share the same contract: *return `None` (or an
//! empty `Vec`) on malformed / truncated input, never panic, and stay
//! bounded in time. The aggregator calls them on the inner side of a
//! per-packet hot loop, so a single pathological packet must not be
//! able to wedge the ingest.
//!
//! ## Scope
//!
//! - [`extract_tls_client_hello`] — pulls SNI, computes the JA3
//!   fingerprint hash, detects TLS 1.3 ECH presence. Triggers on any
//!   TCP payload that begins with a TLS handshake record header
//!   (`0x16 0x03 …`); the port doesn't matter, so TLS on 8443 / 853 /
//!   3478 / etc. is covered without hard-coding.
//! - [`extract_dns_queries`] — pulls every QNAME from a DNS query
//!   packet. UDP/53 in practice; the function takes the raw DNS
//!   payload, so a future TCP/53 path can strip the 2-byte length
//!   prefix and re-use it.
//! - [`extract_http_host`] — pulls the `Host:` header from a plaintext
//!   HTTP/1.x request. Bounded to the first 8 KB of payload.
//!
//! ## Honesty
//!
//! The signal each decoder returns is what the analyst can trust as
//! decoded — anything that came back `None` ends up as
//! `l7_decoded="none"` (or `"encrypted"` for the ECH case) on the
//! Connect edge, never silently elided.

/// Maximum payload bytes we'll scan for any single decoder. Caps the
/// worst-case time on a pathological packet without falsely missing
/// signal: TLS ClientHello and HTTP request headers both fit easily
/// inside 16 KB.
const MAX_DECODE_BYTES: usize = 16 * 1024;

/// Outcome of TLS ClientHello inspection. `sni == None && ech_detected`
/// is the honest signal that the destination domain was deliberately
/// hidden (TLS 1.3 Encrypted Client Hello). `sni == None &&
/// !ech_detected` means the ClientHello was malformed or had no SNI
/// extension at all.
#[derive(Clone, Debug, Default)]
pub struct TlsClientHelloInfo {
    pub sni: Option<String>,
    /// MD5 hex of the JA3 string. `None` only when the ClientHello was
    /// too short to extract the JA3 inputs.
    pub ja3_hash: Option<String>,
    /// True if the `encrypted_client_hello` extension (0xfe0d) was
    /// observed. Mutually informative with `sni == None`.
    pub ech_detected: bool,
}

/// Try to parse a TLS ClientHello from a TCP payload slice. Returns
/// `None` when the payload isn't a TLS handshake record.
pub fn extract_tls_client_hello(payload: &[u8]) -> Option<TlsClientHelloInfo> {
    let payload = &payload[..payload.len().min(MAX_DECODE_BYTES)];
    if payload.len() < 5 {
        return None;
    }
    // TLS record header: type=0x16 (handshake), version major=0x03.
    if payload[0] != 0x16 || payload[1] != 0x03 {
        return None;
    }
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if record_len == 0 {
        return None;
    }
    // Be permissive about a fragment shorter than the declared record
    // length — Wireshark captures can clip large ClientHellos. Use
    // whatever bytes we have past the record header.
    let fragment_end = (5 + record_len).min(payload.len());
    let fragment = &payload[5..fragment_end];

    // Handshake header: msg_type(1) + length(3).
    if fragment.len() < 4 {
        return None;
    }
    if fragment[0] != 0x01 {
        // Not a ClientHello.
        return None;
    }
    let hs_len = ((fragment[1] as usize) << 16)
        | ((fragment[2] as usize) << 8)
        | (fragment[3] as usize);
    let body_end = (4 + hs_len).min(fragment.len());
    let body = &fragment[4..body_end];

    // body: legacy_version(2) + random(32) + session_id_len(1) + ...
    if body.len() < 34 + 1 {
        return None;
    }
    let legacy_version = u16::from_be_bytes([body[0], body[1]]);
    let mut p: usize = 34;

    let session_id_len = body[p] as usize;
    p += 1;
    if body.len() < p + session_id_len + 2 {
        return None;
    }
    p += session_id_len;

    // cipher_suites_len(2)
    let cs_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    if body.len() < p + cs_len + 1 {
        return None;
    }
    let cipher_suites_raw = &body[p..p + cs_len];
    p += cs_len;

    // compression_methods_len(1) + bytes
    let cm_len = body[p] as usize;
    p += 1;
    if body.len() < p + cm_len + 2 {
        return None;
    }
    p += cm_len;

    // extensions_len(2)
    let ext_total_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let ext_end = (p + ext_total_len).min(body.len());
    let extensions = &body[p..ext_end];

    let mut sni: Option<String> = None;
    let mut ech_detected = false;
    let mut extension_types: Vec<u16> = Vec::new();
    let mut supported_groups: Vec<u16> = Vec::new();
    let mut ec_point_formats: Vec<u8> = Vec::new();

    let mut i = 0;
    while i + 4 <= extensions.len() {
        let ext_type = u16::from_be_bytes([extensions[i], extensions[i + 1]]);
        let ext_len = u16::from_be_bytes([extensions[i + 2], extensions[i + 3]]) as usize;
        let ext_start = i + 4;
        let ext_data_end = (ext_start + ext_len).min(extensions.len());
        let ext_data = &extensions[ext_start..ext_data_end];
        extension_types.push(ext_type);

        match ext_type {
            0x0000 => sni = parse_sni_extension(ext_data),
            0x000a => supported_groups = parse_u16_list(ext_data, 2),
            0x000b => {
                if !ext_data.is_empty() {
                    let n = ext_data[0] as usize;
                    let take_end = (1 + n).min(ext_data.len());
                    ec_point_formats.extend_from_slice(&ext_data[1..take_end]);
                }
            }
            0xfe0d => ech_detected = true,
            _ => {}
        }
        // Always advance by the declared length, not what we read —
        // otherwise a malformed extension would desynchronize the
        // remainder of the parse.
        i = ext_start + ext_len;
    }

    let ciphers = parse_u16_list(cipher_suites_raw, 0);
    let ja3_string = build_ja3_string(
        legacy_version,
        &ciphers,
        &extension_types,
        &supported_groups,
        &ec_point_formats,
    );
    let ja3_hash = Some(format!("{:x}", md5::compute(ja3_string.as_bytes())));

    Some(TlsClientHelloInfo {
        sni,
        ja3_hash,
        ech_detected,
    })
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    // list_len(2) + name_type(1) + name_len(2)
    let name_type = data[2];
    if name_type != 0 {
        // 0 = host_name; anything else is non-standard for SNI.
        return None;
    }
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + name_len || name_len == 0 || name_len > 253 {
        return None;
    }
    let bytes = &data[5..5 + name_len];
    let s = std::str::from_utf8(bytes).ok()?;
    // SNI must be a hostname — reject if it contains characters that
    // would never appear (NULs, control chars).
    if s.bytes().any(|b| b < 0x20) {
        return None;
    }
    Some(s.to_string())
}

/// Parse a length-prefixed list of u16 big-endian values.
/// `prefix_bytes` is 2 for `list_len(u16) + values(u16 each)`, 0 for a
/// flat `values(u16 each)` slice.
fn parse_u16_list(data: &[u8], prefix_bytes: usize) -> Vec<u16> {
    let body = if prefix_bytes == 2 {
        if data.len() < 2 {
            return Vec::new();
        }
        let n = u16::from_be_bytes([data[0], data[1]]) as usize;
        let end = (2 + n).min(data.len());
        &data[2..end]
    } else {
        data
    };
    let mut out = Vec::with_capacity(body.len() / 2);
    let mut j = 0;
    while j + 2 <= body.len() {
        out.push(u16::from_be_bytes([body[j], body[j + 1]]));
        j += 2;
    }
    out
}

/// True for a GREASE value (RFC 8701). GREASE rotates per connection
/// to keep middleboxes honest; including it in the JA3 string makes
/// the hash unstable across handshakes from the same client. Filter.
fn is_grease_u16(v: u16) -> bool {
    (v & 0x0F0F) == 0x0A0A
}

fn build_ja3_string(
    version: u16,
    ciphers: &[u16],
    extensions: &[u16],
    curves: &[u16],
    formats: &[u8],
) -> String {
    let join_u16 = |list: &[u16], filter_grease: bool| -> String {
        list.iter()
            .filter(|v| !filter_grease || !is_grease_u16(**v))
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    let join_u8 = |list: &[u8]| -> String {
        list.iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    format!(
        "{},{},{},{},{}",
        version,
        join_u16(ciphers, true),
        join_u16(extensions, true),
        join_u16(curves, true),
        join_u8(formats),
    )
}

/// Pull all QNAMEs out of a DNS message. Returns empty when the
/// payload isn't a DNS query or is malformed past recovery.
pub fn extract_dns_queries(payload: &[u8]) -> Vec<String> {
    let payload = &payload[..payload.len().min(MAX_DECODE_BYTES)];
    if payload.len() < 12 {
        return Vec::new();
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if qdcount == 0 || qdcount > 32 {
        // Cap at 32 questions — real packets almost always have 1.
        return Vec::new();
    }
    let mut names = Vec::with_capacity(qdcount.min(8));
    let mut p = 12;
    for _ in 0..qdcount {
        let (name, next) = match read_qname(payload, p) {
            Some(v) => v,
            None => break,
        };
        if !name.is_empty() && name.len() <= 253 && looks_like_domain(&name) {
            names.push(name);
        }
        // Skip qtype(2) + qclass(2).
        if next + 4 > payload.len() {
            break;
        }
        p = next + 4;
    }
    names
}

/// Read a DNS QNAME starting at `p`. Returns `(name, byte_offset_past_qname)`.
/// Compression pointers (`0xC0` prefix) shouldn't appear inside queries,
/// but we follow at most one to avoid an infinite loop on a crafted
/// packet.
fn read_qname(payload: &[u8], mut p: usize) -> Option<(String, usize)> {
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut total_len = 0usize;
    let mut hops = 0u8;
    loop {
        if p >= payload.len() {
            return None;
        }
        let len = payload[p];
        if len == 0 {
            return Some((render_labels(&labels), p + 1));
        }
        if len & 0xC0 == 0xC0 {
            if p + 1 >= payload.len() {
                return None;
            }
            hops += 1;
            if hops > 1 {
                return None;
            }
            let pointer = (((len & 0x3F) as usize) << 8) | (payload[p + 1] as usize);
            if pointer >= payload.len() || pointer == p {
                // Self-reference or past EOF — bail.
                return None;
            }
            // Continue resolving from the pointed-to location, but
            // remember that the *original* qname ends at p+2.
            let saved_end = p + 2;
            // Walk the pointed chain inline.
            let rest = read_qname_no_compression(payload, pointer)?;
            for label in rest {
                total_len += label.len() + 1;
                if total_len > 255 {
                    return None;
                }
                labels.push(label);
            }
            return Some((render_labels(&labels), saved_end));
        }
        if len > 63 {
            return None;
        }
        let llen = len as usize;
        if p + 1 + llen > payload.len() {
            return None;
        }
        let label = &payload[p + 1..p + 1 + llen];
        total_len += llen + 1;
        if total_len > 255 {
            return None;
        }
        labels.push(label);
        p += 1 + llen;
    }
}

fn read_qname_no_compression<'a>(
    payload: &'a [u8],
    mut p: usize,
) -> Option<Vec<&'a [u8]>> {
    let mut out: Vec<&[u8]> = Vec::new();
    let mut total = 0usize;
    loop {
        if p >= payload.len() {
            return None;
        }
        let len = payload[p];
        if len == 0 {
            return Some(out);
        }
        if len & 0xC0 != 0 {
            // Another compression — bail to avoid recursion.
            return Some(out);
        }
        let llen = len as usize;
        if p + 1 + llen > payload.len() {
            return None;
        }
        out.push(&payload[p + 1..p + 1 + llen]);
        total += llen + 1;
        if total > 255 {
            return None;
        }
        p += 1 + llen;
    }
}

fn render_labels(labels: &[&[u8]]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(labels.len());
    for l in labels {
        match std::str::from_utf8(l) {
            Ok(s) => parts.push(s.to_string()),
            Err(_) => return String::new(),
        }
    }
    parts.join(".")
}

fn looks_like_domain(s: &str) -> bool {
    if s.is_empty() || !s.contains('.') {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
}

/// Pull the `Host:` header from an HTTP/1.x request. Returns `None`
/// when the payload doesn't look like an HTTP request or the header
/// is missing.
pub fn extract_http_host(payload: &[u8]) -> Option<String> {
    let payload = &payload[..payload.len().min(MAX_DECODE_BYTES)];
    let methods: &[&[u8]] = &[
        b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ",
        b"CONNECT ",
    ];
    if !methods.iter().any(|m| payload.starts_with(m)) {
        return None;
    }
    // Headers end at the first \r\n\r\n.
    let headers_end = payload
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(payload.len().min(MAX_DECODE_BYTES));
    let headers = &payload[..headers_end];
    let s = std::str::from_utf8(headers).ok()?;
    for line in s.split("\r\n").skip(1) {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case("host") {
                let host = value.trim();
                // Strip optional :port.
                let host_no_port =
                    host.rsplit_once(':').map(|(a, _)| a).unwrap_or(host);
                if looks_like_domain(host_no_port) || is_ip_literal(host_no_port) {
                    return Some(host_no_port.to_string());
                }
                return None;
            }
        }
    }
    None
}

fn is_ip_literal(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

// ─── PR1a decoders: SSH banner, FTP USER, SMB2 detection ─────────────

/// SSH version banner that opens any SSH/2 session. RFC 4253 §4.2.
/// Always the *very first* line on TCP/22 in both directions: client
/// and server each send their banner before any encrypted bytes flow.
/// We strip the trailing CR/LF and cap the version string at 96 bytes
/// (RFC says ≤ 255 chars including CR/LF — 96 is more than enough for
/// every real banner ever seen in the wild).
pub fn extract_ssh_banner(payload: &[u8]) -> Option<String> {
    // Both `SSH-2.0-...` and the very rare legacy `SSH-1.99-...` (a
    // server signalling backward compatibility) start with `SSH-`.
    if !payload.starts_with(b"SSH-") {
        return None;
    }
    // Find end of the first line. SSH bans embedded CR/LF in the
    // banner so the first \r or \n terminates it.
    let max = payload.len().min(MAX_DECODE_BYTES).min(256);
    let end = payload[..max]
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(max);
    if end < 6 || end > 96 {
        // < 6 means "SSH-" with not enough version info; > 96 means
        // an over-long line that's almost certainly not a banner.
        return None;
    }
    let raw = &payload[..end];
    // Banner is required to be 7-bit ASCII printable (RFC 4253 §4.2).
    if !raw.iter().all(|b| (0x20..=0x7e).contains(b)) {
        return None;
    }
    Some(String::from_utf8_lossy(raw).into_owned())
}

/// FTP `USER` command (RFC 959 §4.1.1). Plaintext request from the
/// client of the form `USER <username>\r\n`. We accept any of the
/// historical separators (`\r\n`, `\n`, or even `\r` on a few stacks)
/// and clamp the username at 128 bytes — same upper bound the major
/// servers (vsftpd, ProFTPD) enforce.
///
/// Returns the trimmed username. Returns `None` for any of:
/// - payload doesn't start with `USER ` (case-insensitive).
/// - line termination is missing or beyond the bounded scan.
/// - username is empty after trim, or contains a `\0` (almost
///   certainly a binary-protocol false positive).
pub fn extract_ftp_user(payload: &[u8]) -> Option<String> {
    let scan = &payload[..payload.len().min(MAX_DECODE_BYTES)];
    if scan.len() < 6 {
        return None;
    }
    // Case-insensitive "USER " prefix. RFC 959 says commands are
    // case-insensitive; real captures show both "USER" and "user".
    let head = &scan[..5];
    if !head.eq_ignore_ascii_case(b"USER ") {
        return None;
    }
    // Find end of line. Cap the search at 256 bytes — well past any
    // real FTP USER line — to avoid scanning a multi-MB pathological
    // payload that happens to start with "USER ".
    let max = scan.len().min(256);
    let end = scan[5..max]
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')?;
    let line = &scan[5..5 + end];
    if line.is_empty() || line.len() > 128 || line.contains(&0u8) {
        return None;
    }
    let s = std::str::from_utf8(line).ok()?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

/// SMB2 / SMB3 protocol identifier check. The SMB2 header always
/// starts with the 4-byte magic `\xfeSMB` followed by a 2-byte struct
/// size (always `0x0040`). When that prefix matches, we return the
/// 16-bit `Command` field at offset 12 — which lets us tell a
/// `SESSION_SETUP` (cmd `0x0001`) from a `TREE_CONNECT` (`0x0003`) or
/// any other operation.
///
/// PR1a scope: detection only. User extraction from the embedded
/// NTLMSSP / GSS-API blob is deferred to PR1b (needs minimal ASN.1
/// walker + NTLMSSP Type 3 parser).
///
/// Returns `None` on any of:
/// - payload too short for an SMB2 header (< 64 bytes).
/// - missing `\xfeSMB` magic.
/// - `struct_size` field isn't `0x0040` (malformed / not SMB2).
pub fn detect_smb2_command(payload: &[u8]) -> Option<u16> {
    let scan = &payload[..payload.len().min(MAX_DECODE_BYTES)];
    // SMB2 header is exactly 64 bytes. Anything less is a partial
    // packet we can't trust to read the Command field from.
    if scan.len() < 64 {
        return None;
    }
    if &scan[0..4] != b"\xfeSMB" {
        return None;
    }
    // StructureSize (offset 4, LE u16). Per [MS-SMB2] §2.2.1.1 +
    // §2.2.1.2 this is *always* 0x0040 for both sync and async
    // headers. Real SMB2 traffic has never observed any other value.
    let struct_size = u16::from_le_bytes([scan[4], scan[5]]);
    if struct_size != 0x0040 {
        return None;
    }
    // Command (offset 12, LE u16). Values 0x0000..=0x0012 in the
    // current spec. We don't filter by valid command IDs here — let
    // the caller decide if `cmd > 0x0020` is suspect.
    let cmd = u16::from_le_bytes([scan[12], scan[13]]);
    Some(cmd)
}

/// SMB2 command opcodes worth surfacing as service names. Used by
/// the caller to put a human-readable string on the edge metadata.
pub fn smb2_command_name(cmd: u16) -> Option<&'static str> {
    Some(match cmd {
        0x0000 => "NEGOTIATE",
        0x0001 => "SESSION_SETUP",
        0x0002 => "LOGOFF",
        0x0003 => "TREE_CONNECT",
        0x0004 => "TREE_DISCONNECT",
        0x0005 => "CREATE",
        0x0006 => "CLOSE",
        0x0007 => "FLUSH",
        0x0008 => "READ",
        0x0009 => "WRITE",
        0x000a => "LOCK",
        0x000b => "IOCTL",
        0x000c => "CANCEL",
        0x000d => "ECHO",
        0x000e => "QUERY_DIRECTORY",
        0x000f => "CHANGE_NOTIFY",
        0x0010 => "QUERY_INFO",
        0x0011 => "SET_INFO",
        0x0012 => "OPLOCK_BREAK",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello_with_sni(sni: &str) -> Vec<u8> {
        // Build extension blob with one SNI extension.
        let mut sni_ext = Vec::new();
        // server_name_list_length (filled below) + name_type(0) + name_len + name
        let inner_list = {
            let mut v = Vec::new();
            v.push(0u8); // name_type = host_name
            v.extend_from_slice(&(sni.len() as u16).to_be_bytes());
            v.extend_from_slice(sni.as_bytes());
            v
        };
        sni_ext.extend_from_slice(&(inner_list.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(&inner_list);

        let mut ext_blob = Vec::new();
        // SNI extension: type=0x0000
        ext_blob.extend_from_slice(&0x0000u16.to_be_bytes());
        ext_blob.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        ext_blob.extend_from_slice(&sni_ext);
        // ec_point_formats extension (0x000b) with one byte payload
        // so the JA3 string has all five fields populated.
        ext_blob.extend_from_slice(&0x000bu16.to_be_bytes());
        ext_blob.extend_from_slice(&3u16.to_be_bytes());
        ext_blob.extend_from_slice(&[1u8, 0u8, 1u8]);

        // ClientHello body: version(2) + random(32) + session_id_len(1)
        // + cipher_suites_len(2) + ciphers (one TLS_AES_128_GCM_SHA256
        // = 0x1301) + compression_methods_len(1) + null + ext_len(2)
        // + ext_blob.
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // TLS 1.2 legacy
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0u8); // session_id_len = 0
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites_len
        body.extend_from_slice(&0x1301u16.to_be_bytes()); // TLS_AES_128_GCM_SHA256
        body.push(1u8); // compression_methods_len
        body.push(0u8); // null compression
        body.extend_from_slice(&(ext_blob.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_blob);

        // Handshake header: msg_type=0x01 (ClientHello) + length(3 bytes)
        let mut hs = Vec::new();
        hs.push(0x01);
        let body_len = body.len() as u32;
        hs.push(((body_len >> 16) & 0xff) as u8);
        hs.push(((body_len >> 8) & 0xff) as u8);
        hs.push((body_len & 0xff) as u8);
        hs.extend_from_slice(&body);

        // TLS record header: type=0x16 + version(2) + length(2)
        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&0x0303u16.to_be_bytes());
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        rec
    }

    #[test]
    fn tls_extracts_sni_and_ja3() {
        let payload = build_client_hello_with_sni("example.com");
        let info = extract_tls_client_hello(&payload).expect("decoded");
        assert_eq!(info.sni.as_deref(), Some("example.com"));
        assert!(!info.ech_detected);
        let ja3 = info.ja3_hash.expect("ja3 present");
        // JA3 hash is MD5 hex — 32 chars.
        assert_eq!(ja3.len(), 32);
        assert!(ja3.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn tls_rejects_non_handshake() {
        // App data record (type 0x17), not handshake.
        let payload = vec![0x17, 0x03, 0x03, 0x00, 0x10, 0u8, 0, 0, 0, 0];
        assert!(extract_tls_client_hello(&payload).is_none());
    }

    #[test]
    fn tls_detects_ech_extension() {
        // Hand-craft a ClientHello whose only extension is ECH (0xfe0d).
        let mut ext_blob = Vec::new();
        ext_blob.extend_from_slice(&0xfe0du16.to_be_bytes());
        ext_blob.extend_from_slice(&0u16.to_be_bytes()); // ext_len = 0
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(0u8);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1u8);
        body.push(0u8);
        body.extend_from_slice(&(ext_blob.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_blob);
        let mut hs = Vec::new();
        hs.push(0x01);
        let body_len = body.len() as u32;
        hs.extend_from_slice(&[
            ((body_len >> 16) & 0xff) as u8,
            ((body_len >> 8) & 0xff) as u8,
            (body_len & 0xff) as u8,
        ]);
        hs.extend_from_slice(&body);
        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&0x0303u16.to_be_bytes());
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        let info = extract_tls_client_hello(&rec).expect("decoded");
        assert_eq!(info.sni, None);
        assert!(info.ech_detected);
    }

    fn build_dns_query(qname: &str) -> Vec<u8> {
        let mut out = Vec::new();
        // Header: ID + flags + qdcount=1 + rest=0
        out.extend_from_slice(&0xabcdu16.to_be_bytes()); // id
        out.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query
        out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        out.extend_from_slice(&0u16.to_be_bytes()); // ancount
        out.extend_from_slice(&0u16.to_be_bytes()); // nscount
        out.extend_from_slice(&0u16.to_be_bytes()); // arcount
        for label in qname.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0u8); // root label
        out.extend_from_slice(&1u16.to_be_bytes()); // qtype = A
        out.extend_from_slice(&1u16.to_be_bytes()); // qclass = IN
        out
    }

    #[test]
    fn dns_extracts_single_query() {
        let payload = build_dns_query("evo.example.com");
        let queries = extract_dns_queries(&payload);
        assert_eq!(queries, vec!["evo.example.com".to_string()]);
    }

    #[test]
    fn dns_handles_empty_payload() {
        assert!(extract_dns_queries(&[]).is_empty());
        assert!(extract_dns_queries(&[0u8; 11]).is_empty());
    }

    #[test]
    fn dns_rejects_obscene_qdcount() {
        // qdcount = 9999 — way too many.
        let mut payload = vec![0u8; 12];
        payload[4..6].copy_from_slice(&9999u16.to_be_bytes());
        assert!(extract_dns_queries(&payload).is_empty());
    }

    #[test]
    fn http_extracts_host_from_get() {
        let payload = b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        assert_eq!(
            extract_http_host(payload).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn http_strips_port_from_host() {
        let payload =
            b"POST /api HTTP/1.1\r\nhost: api.example.com:8080\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            extract_http_host(payload).as_deref(),
            Some("api.example.com")
        );
    }

    #[test]
    fn http_rejects_non_http() {
        let payload = b"\x16\x03\x03\x00\x10\x01\x00\x00\x00";
        assert!(extract_http_host(payload).is_none());
    }

    #[test]
    fn http_missing_host_header_returns_none() {
        let payload = b"GET / HTTP/1.0\r\nUser-Agent: test\r\n\r\n";
        assert!(extract_http_host(payload).is_none());
    }

    #[test]
    fn grease_filtered_from_ja3() {
        assert!(is_grease_u16(0x0a0a));
        assert!(is_grease_u16(0x1a1a));
        assert!(is_grease_u16(0xfafa));
        assert!(!is_grease_u16(0x1301));
        assert!(!is_grease_u16(0x0000));
    }

    #[test]
    fn looks_like_domain_accepts_normal_names() {
        assert!(looks_like_domain("example.com"));
        assert!(looks_like_domain("sub.example.co.uk"));
        assert!(!looks_like_domain("no-dot"));
        assert!(!looks_like_domain(""));
        assert!(!looks_like_domain("has space.com"));
    }

    // ── PR1a tests ───────────────────────────────────────────────

    #[test]
    fn ssh_banner_extracts_openssh_version() {
        let payload = b"SSH-2.0-OpenSSH_9.4 Ubuntu-2ubuntu1\r\n";
        let banner = extract_ssh_banner(payload).expect("decoded");
        assert_eq!(banner, "SSH-2.0-OpenSSH_9.4 Ubuntu-2ubuntu1");
    }

    #[test]
    fn ssh_banner_accepts_legacy_1_99_signalling() {
        let payload = b"SSH-1.99-MockClient_1\n";
        assert_eq!(
            extract_ssh_banner(payload).as_deref(),
            Some("SSH-1.99-MockClient_1"),
        );
    }

    #[test]
    fn ssh_banner_rejects_non_ssh() {
        // HTTP request — common false-positive on TCP/22 honeypot scans.
        assert!(extract_ssh_banner(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_none());
        // TLS ClientHello.
        assert!(extract_ssh_banner(&[0x16, 0x03, 0x03, 0x00, 0x10]).is_none());
        // Empty.
        assert!(extract_ssh_banner(&[]).is_none());
    }

    #[test]
    fn ssh_banner_rejects_overlong_line() {
        // 200 ASCII printable bytes with no terminator — clearly not
        // a real banner, must not be accepted.
        let mut payload = b"SSH-2.0-".to_vec();
        payload.extend(std::iter::repeat(b'X').take(200));
        assert!(extract_ssh_banner(&payload).is_none());
    }

    #[test]
    fn ssh_banner_rejects_non_printable() {
        // Banner with a NUL byte — must reject (real banners are
        // 7-bit ASCII printable per RFC 4253).
        let payload = b"SSH-2.0-Mock\x00bin\r\n";
        assert!(extract_ssh_banner(payload).is_none());
    }

    #[test]
    fn ftp_user_extracts_username() {
        let payload = b"USER anonymous\r\n";
        assert_eq!(extract_ftp_user(payload).as_deref(), Some("anonymous"));
    }

    #[test]
    fn ftp_user_is_case_insensitive() {
        let payload = b"user alice\r\n";
        assert_eq!(extract_ftp_user(payload).as_deref(), Some("alice"));
    }

    #[test]
    fn ftp_user_handles_bare_lf_terminator() {
        // Some legacy clients send LF without CR.
        let payload = b"USER bob\n";
        assert_eq!(extract_ftp_user(payload).as_deref(), Some("bob"));
    }

    #[test]
    fn ftp_user_rejects_non_ftp_commands() {
        assert!(extract_ftp_user(b"PASS hunter2\r\n").is_none());
        assert!(extract_ftp_user(b"GET / HTTP/1.1\r\n").is_none());
        assert!(extract_ftp_user(b"").is_none());
    }

    #[test]
    fn ftp_user_rejects_empty_username() {
        assert!(extract_ftp_user(b"USER \r\n").is_none());
        assert!(extract_ftp_user(b"USER   \r\n").is_none());
    }

    #[test]
    fn ftp_user_rejects_unterminated_line() {
        // No CR/LF — refuse to extract rather than guess where the
        // username ends.
        let payload = b"USER thisisaverylongnamebutitneverendswithanewline";
        assert!(extract_ftp_user(payload).is_none());
    }

    fn smb2_session_setup_request() -> Vec<u8> {
        // Minimal SMB2 sync header (64 bytes):
        //   0..4   "\xfeSMB" magic
        //   4..6   StructureSize = 0x0040
        //   6..8   CreditCharge
        //   8..12  Status
        //   12..14 Command = 0x0001 (SESSION_SETUP)
        //   14..16 CreditRequest
        //   16..20 Flags
        //   20..24 NextCommand
        //   24..32 MessageId
        //   32..36 Reserved
        //   36..40 TreeId
        //   40..48 SessionId
        //   48..64 Signature
        let mut h = vec![0u8; 64];
        h[0..4].copy_from_slice(b"\xfeSMB");
        h[4..6].copy_from_slice(&0x0040u16.to_le_bytes());
        h[12..14].copy_from_slice(&0x0001u16.to_le_bytes());
        h
    }

    #[test]
    fn smb2_detects_session_setup_command() {
        let payload = smb2_session_setup_request();
        assert_eq!(detect_smb2_command(&payload), Some(0x0001));
    }

    #[test]
    fn smb2_detects_other_commands() {
        let mut payload = smb2_session_setup_request();
        // Flip Command to TREE_CONNECT.
        payload[12..14].copy_from_slice(&0x0003u16.to_le_bytes());
        assert_eq!(detect_smb2_command(&payload), Some(0x0003));
    }

    #[test]
    fn smb2_rejects_smb1_magic() {
        // SMB1 (CIFS) starts with \xffSMB, not \xfeSMB. We must not
        // accidentally accept it — SMB1 has a totally different header
        // layout and the offset-12 byte means something else.
        let mut payload = smb2_session_setup_request();
        payload[0] = 0xff;
        assert!(detect_smb2_command(&payload).is_none());
    }

    #[test]
    fn smb2_rejects_wrong_struct_size() {
        let mut payload = smb2_session_setup_request();
        // Wrong StructureSize — corruption marker.
        payload[4..6].copy_from_slice(&0x1234u16.to_le_bytes());
        assert!(detect_smb2_command(&payload).is_none());
    }

    #[test]
    fn smb2_rejects_short_payload() {
        // Less than 64 bytes — can't read all required fields.
        let payload = b"\xfeSMB".to_vec();
        assert!(detect_smb2_command(&payload).is_none());
    }

    #[test]
    fn smb2_command_name_covers_known_opcodes() {
        assert_eq!(smb2_command_name(0x0001), Some("SESSION_SETUP"));
        assert_eq!(smb2_command_name(0x0005), Some("CREATE"));
        assert_eq!(smb2_command_name(0x000b), Some("IOCTL"));
        assert_eq!(smb2_command_name(0x0012), Some("OPLOCK_BREAK"));
        assert_eq!(smb2_command_name(0xabcd), None);
    }
}
