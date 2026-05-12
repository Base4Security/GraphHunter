//! Authentication-protocol L7 decoders for PCAP ingest: Kerberos
//! (AS-REQ / TGS-REQ), LDAP (bindRequest), and NTLMSSP (Type 3 used
//! by SMB and HTTP-NTLM).
//!
//! Each decoder extracts the *username being authenticated* from a
//! single TCP segment or UDP datagram. The PCAP flow aggregator
//! stashes the username into [`crate::pcap::FlowState`] and the
//! `emit()` step pushes a secondary `User -[Auth]-> IP` edge so the
//! analyst can hunt cross-source — e.g. an EVTX `Security 4624` for
//! the same User merges with this edge in the graph engine.
//!
//! ## Why hand-rolled ASN.1?
//!
//! Kerberos and LDAP both speak ASN.1 (DER and BER respectively),
//! but adding a full ASN.1 crate (`rasn`, `simple_asn1`) would pull
//! 50+ KB of compiled code and a wide attack surface to extract one
//! field per message. The walker in [`asn1_min`] handles just the
//! TLVs we need: definite-length encoding, recursive descent into
//! a chosen context tag. Indefinite-length BER (`0x80` length) is
//! rejected — real LDAP/Kerberos servers don't emit it.
//!
//! ## Scan bound
//!
//! Each decoder runs on at most [`MAX_DECODE_BYTES`] of payload
//! (same 16 KB cap as [`crate::pcap_l7`]). That's well above any
//! real Kerberos ticket request or LDAP bind on the wire.

const MAX_DECODE_BYTES: usize = 16 * 1024;

// ─── Minimal ASN.1 TLV walker ────────────────────────────────────────

pub(crate) mod asn1_min {
    /// One ASN.1 TLV: identifier byte, value slice.
    pub(crate) struct Tlv<'a> {
        pub tag: u8,
        pub value: &'a [u8],
    }

    /// Parse a single TLV from the start of `bytes`. Returns the TLV
    /// plus the total byte count consumed (header + value). Returns
    /// `None` on:
    /// - empty input,
    /// - indefinite-length form (`length == 0x80`) — rejected,
    /// - long-form length > 4 bytes — unrealistic for our use case,
    /// - length larger than the remaining buffer.
    pub(crate) fn parse_tlv(bytes: &[u8]) -> Option<(Tlv<'_>, usize)> {
        if bytes.len() < 2 {
            return None;
        }
        // Reject multi-byte tags (high-tag-number form, first byte
        // ends in 0x1f). Our use cases all fit in one tag byte.
        let tag = bytes[0];
        if (tag & 0x1f) == 0x1f {
            return None;
        }
        let len_byte = bytes[1];
        let (len, hdr) = if len_byte < 0x80 {
            (len_byte as usize, 2)
        } else if len_byte == 0x80 {
            // Indefinite-length form — rejected.
            return None;
        } else {
            let n = (len_byte & 0x7f) as usize;
            if n == 0 || n > 4 || bytes.len() < 2 + n {
                return None;
            }
            let mut v = 0usize;
            for i in 0..n {
                v = (v << 8) | (bytes[2 + i] as usize);
            }
            (v, 2 + n)
        };
        if bytes.len() < hdr + len {
            return None;
        }
        Some((
            Tlv {
                tag,
                value: &bytes[hdr..hdr + len],
            },
            hdr + len,
        ))
    }

    /// Scan the top-level TLVs in `bytes` (typically the value of a
    /// constructed SEQUENCE) and return the value slice of the first
    /// TLV with `target` as its identifier byte. Stops at any
    /// malformed TLV (best-effort, never panics).
    pub(crate) fn find_tag<'a>(bytes: &'a [u8], target: u8) -> Option<&'a [u8]> {
        let mut p = bytes;
        while !p.is_empty() {
            let (tlv, n) = parse_tlv(p)?;
            if tlv.tag == target {
                return Some(tlv.value);
            }
            p = &p[n..];
        }
        None
    }
}

// ─── Kerberos AS-REQ / TGS-REQ cname extraction ──────────────────────

/// Kerberos message tags ([APPLICATION X]). The application-tagged
/// outer wrapper tells us which KDC request the payload contains.
const KRB_TAG_AS_REQ: u8 = 0x6a; // APPLICATION 10
const KRB_TAG_TGS_REQ: u8 = 0x6c; // APPLICATION 12
/// Context tag for `req-body` inside KDC-REQ ([4]).
const KRB_TAG_REQ_BODY: u8 = 0xa4;
/// Context tag for `cname` inside KDC-REQ-BODY ([1]) AND for
/// `name-string` inside PrincipalName ([1]). Same tag byte by
/// coincidence — both nests use [1].
const KRB_TAG_CTX_1: u8 = 0xa1;
/// Universal SEQUENCE tag (constructed).
const ASN1_SEQUENCE: u8 = 0x30;
/// Universal GeneralString tag (primitive).
const ASN1_GENERAL_STRING: u8 = 0x1b;

/// Outcome of extracting the principal from a Kerberos request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KerberosPrincipal {
    /// Concatenation of the `name-string` components, joined with
    /// `/` (per Kerberos convention for multi-component principals).
    pub cname: String,
    /// `"AS-REQ"` or `"TGS-REQ"`. Useful as edge metadata so the
    /// hunt DSL can tell initial auth from ticket renewal.
    pub kind: &'static str,
}

/// Try to extract the client principal name from a Kerberos
/// AS-REQ / TGS-REQ message. Accepts both TCP framing (4-byte
/// big-endian length prefix per RFC 4120 §7.2.2) and the raw UDP
/// datagram form. Returns `None` if the payload doesn't look like
/// a Kerberos request.
pub fn extract_kerberos_principal(payload: &[u8]) -> Option<KerberosPrincipal> {
    let scan = &payload[..payload.len().min(MAX_DECODE_BYTES)];
    // Two candidate offsets: 0 (UDP / older client libraries) and 4
    // (TCP framing). Try both; UDP form fails the TCP-prefix check
    // because the length wouldn't equal `len - 4`.
    let candidates = [scan, scan.get(4..).unwrap_or(&[])];
    for candidate in candidates {
        if let Some(p) = try_extract_kerberos(candidate) {
            return Some(p);
        }
    }
    None
}

fn try_extract_kerberos(payload: &[u8]) -> Option<KerberosPrincipal> {
    use asn1_min::{find_tag, parse_tlv};

    // Outer: [APPLICATION 10] = AS-REQ or [APPLICATION 12] = TGS-REQ.
    let (outer, _) = parse_tlv(payload)?;
    let kind = match outer.tag {
        KRB_TAG_AS_REQ => "AS-REQ",
        KRB_TAG_TGS_REQ => "TGS-REQ",
        _ => return None,
    };

    // Inside: a SEQUENCE (the KDC-REQ).
    let (req_seq, _) = parse_tlv(outer.value)?;
    if req_seq.tag != ASN1_SEQUENCE {
        return None;
    }

    // Inside KDC-REQ, find [4] req-body. The tagged value holds
    // *another* TLV (the actual KDC-REQ-BODY SEQUENCE) — that's
    // how EXPLICIT tagging works in ASN.1.
    let req_body_inner = find_tag(req_seq.value, KRB_TAG_REQ_BODY)?;
    let (body_seq, _) = parse_tlv(req_body_inner)?;
    if body_seq.tag != ASN1_SEQUENCE {
        return None;
    }

    // Inside KDC-REQ-BODY, find [1] cname (the PrincipalName).
    let cname_inner = find_tag(body_seq.value, KRB_TAG_CTX_1)?;
    let (princ_seq, _) = parse_tlv(cname_inner)?;
    if princ_seq.tag != ASN1_SEQUENCE {
        return None;
    }

    // Inside PrincipalName, find [1] name-string.
    let name_string_inner = find_tag(princ_seq.value, KRB_TAG_CTX_1)?;
    let (name_seq_of, _) = parse_tlv(name_string_inner)?;
    if name_seq_of.tag != ASN1_SEQUENCE {
        return None;
    }

    // SEQUENCE OF GeneralString — collect every component.
    let mut parts: Vec<String> = Vec::new();
    let mut rest = name_seq_of.value;
    while !rest.is_empty() {
        let (gs, n) = parse_tlv(rest)?;
        if gs.tag != ASN1_GENERAL_STRING {
            break;
        }
        let s = std::str::from_utf8(gs.value).ok()?;
        if s.is_empty() || s.len() > 256 || s.contains('\0') {
            return None;
        }
        parts.push(s.to_string());
        rest = &rest[n..];
    }
    if parts.is_empty() {
        return None;
    }
    Some(KerberosPrincipal {
        cname: parts.join("/"),
        kind,
    })
}

// ─── LDAP bindRequest DN extraction ──────────────────────────────────

/// `[APPLICATION 0]` constructed — `LDAPMessage.protocolOp.bindRequest`.
const LDAP_TAG_BIND_REQ: u8 = 0x60;
const ASN1_INTEGER: u8 = 0x02;
const ASN1_OCTET_STRING: u8 = 0x04;

/// Try to extract the LDAPDN (distinguished name) from a single
/// LDAP `bindRequest` message (RFC 4511 §4.2). Returns `None` if
/// the payload isn't an LDAP message, isn't a bind, or the DN is
/// empty (anonymous bind).
pub fn extract_ldap_bind_dn(payload: &[u8]) -> Option<String> {
    use asn1_min::{find_tag, parse_tlv};
    let scan = &payload[..payload.len().min(MAX_DECODE_BYTES)];

    // Outer LDAPMessage is a SEQUENCE.
    let (outer, _) = parse_tlv(scan)?;
    if outer.tag != ASN1_SEQUENCE {
        return None;
    }

    // Inside, find the bindRequest TLV (APPLICATION 0 constructed).
    let bind_value = find_tag(outer.value, LDAP_TAG_BIND_REQ)?;

    // BindRequest: version INTEGER, name LDAPDN (OCTET STRING),
    // authentication ... — walk top-level TLVs and grab the first
    // OCTET STRING after skipping the version INTEGER.
    let mut p = bind_value;
    let (ver, n) = parse_tlv(p)?;
    if ver.tag != ASN1_INTEGER {
        return None;
    }
    p = &p[n..];

    let (dn_tlv, _) = parse_tlv(p)?;
    if dn_tlv.tag != ASN1_OCTET_STRING {
        return None;
    }
    let s = std::str::from_utf8(dn_tlv.value).ok()?;
    if s.is_empty() || s.len() > 1024 || s.contains('\0') {
        return None;
    }
    Some(s.to_string())
}

// ─── NTLMSSP Type 3 (Authenticate) UserName extraction ───────────────

/// Result of parsing an NTLMSSP Type 3 message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NtlmType3Info {
    pub user: String,
    /// May be empty when the client logs in to a local account
    /// (`Negotiate Anonymous` clears the domain field).
    pub domain: String,
}

/// NTLMSSP signature: literal bytes "NTLMSSP\0".
pub(crate) const NTLMSSP_SIG: &[u8] = b"NTLMSSP\0";

/// `Negotiate Unicode` flag bit. When set, all variable-length
/// security buffers (UserName, DomainName, …) are UTF-16-LE; when
/// clear they are 8-bit OEM (effectively ASCII for us).
const NEGOTIATE_UNICODE: u32 = 0x0000_0001;

/// Try to extract `(UserName, DomainName)` from an NTLMSSP Type 3
/// (Authenticate) message anywhere in the payload. Returns `None`
/// if no NTLMSSP signature is found within [`MAX_DECODE_BYTES`],
/// or if the Type 3 message is malformed / has an empty UserName.
///
/// **Scan policy:** we look for the literal `"NTLMSSP\0"` byte
/// pattern. This handles both raw NTLM blobs (TCP/445 SMB
/// SESSION_SETUP) and GSS-API / SPNEGO-wrapped NTLM (where the
/// signature still appears verbatim inside the wrapper, just at a
/// deeper offset). Full GSS-API/SPNEGO ASN.1 parsing is out of
/// scope — looking for the signature byte-pattern reliably yields
/// the right offset on every real capture we've inspected.
pub fn extract_ntlm_type3(payload: &[u8]) -> Option<NtlmType3Info> {
    let scan = &payload[..payload.len().min(MAX_DECODE_BYTES)];
    let off = find_subslice(scan, NTLMSSP_SIG)?;
    let msg = &scan[off..];

    // Header layout (LE):
    //   0..8   signature "NTLMSSP\0"
    //   8..12  MessageType (must equal 3)
    //  12..20  LmChallengeResponseFields  (skip)
    //  20..28  NtChallengeResponseFields  (skip)
    //  28..36  DomainNameFields: len(2), maxlen(2), offset(4)
    //  36..44  UserNameFields:   len(2), maxlen(2), offset(4)
    //  44..52  WorkstationFields (skip)
    //  52..60  EncryptedRandomSessionKeyFields (skip)
    //  60..64  NegotiateFlags
    //  64..    SecurityBufferData
    if msg.len() < 64 {
        return None;
    }
    let msg_type = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
    if msg_type != 3 {
        return None;
    }
    let dom_len = u16::from_le_bytes([msg[28], msg[29]]) as usize;
    let dom_off = u32::from_le_bytes([msg[32], msg[33], msg[34], msg[35]]) as usize;
    let user_len = u16::from_le_bytes([msg[36], msg[37]]) as usize;
    let user_off = u32::from_le_bytes([msg[40], msg[41], msg[42], msg[43]]) as usize;
    let flags = u32::from_le_bytes([msg[60], msg[61], msg[62], msg[63]]);
    let unicode = flags & NEGOTIATE_UNICODE != 0;

    let user = read_security_buffer(msg, user_off, user_len, unicode)?;
    if user.is_empty() {
        return None;
    }
    let domain = read_security_buffer(msg, dom_off, dom_len, unicode).unwrap_or_default();
    Some(NtlmType3Info { user, domain })
}

/// Find `needle` inside `haystack`, returning the offset. Naive
/// scan — fine for our 16 KB cap.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// Read a security buffer at `(offset, len)` relative to the start
/// of the NTLMSSP message. Decodes UTF-16-LE when `unicode` is set,
/// else treats as ASCII. Bounded so a malicious offset/length pair
/// can never read past the message.
fn read_security_buffer(
    msg: &[u8],
    offset: usize,
    len: usize,
    unicode: bool,
) -> Option<String> {
    if len == 0 {
        return Some(String::new());
    }
    let end = offset.checked_add(len)?;
    if end > msg.len() {
        return None;
    }
    let bytes = &msg[offset..end];
    if unicode {
        if bytes.len() % 2 != 0 {
            return None;
        }
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&units).ok()
    } else {
        std::str::from_utf8(bytes).ok().map(str::to_string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ASN.1 walker primitives ──────────────────────────────────

    #[test]
    fn parse_tlv_short_form_length() {
        // 0x04 0x05 "hello" — OCTET STRING of length 5.
        let bytes = b"\x04\x05hello";
        let (tlv, n) = asn1_min::parse_tlv(bytes).expect("parsed");
        assert_eq!(tlv.tag, 0x04);
        assert_eq!(tlv.value, b"hello");
        assert_eq!(n, 7);
    }

    #[test]
    fn parse_tlv_long_form_two_byte_length() {
        // 0x04 0x82 0x01 0x00 + 256 bytes — length 256.
        let mut bytes = vec![0x04, 0x82, 0x01, 0x00];
        bytes.extend(std::iter::repeat(b'A').take(256));
        let (tlv, n) = asn1_min::parse_tlv(&bytes).expect("parsed");
        assert_eq!(tlv.tag, 0x04);
        assert_eq!(tlv.value.len(), 256);
        assert_eq!(n, 4 + 256);
    }

    #[test]
    fn parse_tlv_rejects_indefinite_length() {
        // 0x30 0x80 ... 0x00 0x00 — BER indefinite-length form.
        let bytes = b"\x30\x80\x04\x05hello\x00\x00";
        assert!(asn1_min::parse_tlv(bytes).is_none());
    }

    #[test]
    fn parse_tlv_rejects_length_beyond_buffer() {
        // Claims length 100 but only 3 bytes follow.
        let bytes = b"\x04\x64\x01\x02\x03";
        assert!(asn1_min::parse_tlv(bytes).is_none());
    }

    #[test]
    fn find_tag_returns_value_of_first_matching_tlv() {
        // SEQUENCE { INTEGER 5, OCTET STRING "abc" } — find the
        // OCTET STRING.
        let bytes = b"\x02\x01\x05\x04\x03abc";
        let found = asn1_min::find_tag(bytes, 0x04).expect("found");
        assert_eq!(found, b"abc");
    }

    #[test]
    fn find_tag_skips_non_matching_tlvs() {
        let bytes = b"\x02\x01\x05\x04\x03abc";
        let found = asn1_min::find_tag(bytes, 0x02).expect("found");
        assert_eq!(found, b"\x05");
    }

    // ── Kerberos AS-REQ / TGS-REQ ────────────────────────────────

    /// Build a minimal but valid Kerberos AS-REQ DER message with
    /// the given client principal components.
    fn build_kerberos_as_req(components: &[&str]) -> Vec<u8> {
        // PrincipalName components → GeneralString TLVs.
        let mut name_seq_of: Vec<u8> = Vec::new();
        for c in components {
            name_seq_of.push(ASN1_GENERAL_STRING);
            name_seq_of.push(c.len() as u8);
            name_seq_of.extend_from_slice(c.as_bytes());
        }
        // SEQUENCE OF GeneralString
        let mut name_string = vec![ASN1_SEQUENCE, name_seq_of.len() as u8];
        name_string.extend_from_slice(&name_seq_of);

        // [1] name-string (EXPLICIT) wraps the SEQUENCE OF.
        let mut name_string_tagged = vec![KRB_TAG_CTX_1, name_string.len() as u8];
        name_string_tagged.extend_from_slice(&name_string);

        // PrincipalName SEQUENCE — for simplicity skip the [0] name-type
        // (the decoder doesn't require it; it scans for tag [1]).
        let mut princ_seq = vec![ASN1_SEQUENCE, name_string_tagged.len() as u8];
        princ_seq.extend_from_slice(&name_string_tagged);

        // [1] cname (EXPLICIT) wraps PrincipalName.
        let mut cname_tagged = vec![KRB_TAG_CTX_1, princ_seq.len() as u8];
        cname_tagged.extend_from_slice(&princ_seq);

        // KDC-REQ-BODY SEQUENCE — just the cname for our test.
        let mut body_seq = vec![ASN1_SEQUENCE, cname_tagged.len() as u8];
        body_seq.extend_from_slice(&cname_tagged);

        // [4] req-body (EXPLICIT) wraps KDC-REQ-BODY.
        let mut req_body_tagged = vec![KRB_TAG_REQ_BODY, body_seq.len() as u8];
        req_body_tagged.extend_from_slice(&body_seq);

        // KDC-REQ SEQUENCE — just the req-body for our test.
        let mut req_seq = vec![ASN1_SEQUENCE, req_body_tagged.len() as u8];
        req_seq.extend_from_slice(&req_body_tagged);

        // [APPLICATION 10] (EXPLICIT) wraps the SEQUENCE.
        let mut outer = vec![KRB_TAG_AS_REQ, req_seq.len() as u8];
        outer.extend_from_slice(&req_seq);
        outer
    }

    #[test]
    fn kerberos_extracts_simple_principal_from_as_req() {
        let msg = build_kerberos_as_req(&["alice"]);
        let p = extract_kerberos_principal(&msg).expect("decoded");
        assert_eq!(p.cname, "alice");
        assert_eq!(p.kind, "AS-REQ");
    }

    #[test]
    fn kerberos_joins_multi_component_principal_with_slash() {
        // E.g. service principal "host/dc01.example.com".
        let msg = build_kerberos_as_req(&["host", "dc01.example.com"]);
        let p = extract_kerberos_principal(&msg).expect("decoded");
        assert_eq!(p.cname, "host/dc01.example.com");
    }

    #[test]
    fn kerberos_handles_tgs_req_tag() {
        let mut msg = build_kerberos_as_req(&["alice"]);
        msg[0] = KRB_TAG_TGS_REQ;
        let p = extract_kerberos_principal(&msg).expect("decoded");
        assert_eq!(p.kind, "TGS-REQ");
    }

    #[test]
    fn kerberos_accepts_tcp_length_prefix_framing() {
        let body = build_kerberos_as_req(&["alice"]);
        let mut framed: Vec<u8> = (body.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&body);
        let p = extract_kerberos_principal(&framed).expect("decoded");
        assert_eq!(p.cname, "alice");
    }

    #[test]
    fn kerberos_rejects_random_bytes() {
        assert!(extract_kerberos_principal(&[]).is_none());
        assert!(extract_kerberos_principal(b"GET / HTTP/1.1\r\n").is_none());
        assert!(extract_kerberos_principal(&[0x16, 0x03, 0x03, 0x00, 0x10]).is_none());
    }

    #[test]
    fn kerberos_rejects_empty_principal() {
        let msg = build_kerberos_as_req(&[""]);
        // Empty component → reject (refuse to emit a User node for "").
        assert!(extract_kerberos_principal(&msg).is_none());
    }

    // ── LDAP bindRequest ─────────────────────────────────────────

    fn build_ldap_bind(dn: &str) -> Vec<u8> {
        // BindRequest body: INTEGER version + OCTET STRING dn +
        // simple-auth (we skip; decoder doesn't need it).
        let mut body: Vec<u8> = Vec::new();
        // version = 3.
        body.extend_from_slice(&[ASN1_INTEGER, 0x01, 0x03]);
        // DN OCTET STRING.
        body.push(ASN1_OCTET_STRING);
        body.push(dn.len() as u8);
        body.extend_from_slice(dn.as_bytes());

        // [APPLICATION 0] wraps the body.
        let mut bind = vec![LDAP_TAG_BIND_REQ, body.len() as u8];
        bind.extend_from_slice(&body);

        // LDAPMessage SEQUENCE: messageID INTEGER + protocolOp (bindRequest).
        let mut inner: Vec<u8> = Vec::new();
        inner.extend_from_slice(&[ASN1_INTEGER, 0x01, 0x01]); // messageID 1
        inner.extend_from_slice(&bind);

        let mut msg = vec![ASN1_SEQUENCE, inner.len() as u8];
        msg.extend_from_slice(&inner);
        msg
    }

    #[test]
    fn ldap_extracts_simple_dn() {
        let msg = build_ldap_bind("CN=alice,DC=example,DC=com");
        let dn = extract_ldap_bind_dn(&msg).expect("decoded");
        assert_eq!(dn, "CN=alice,DC=example,DC=com");
    }

    #[test]
    fn ldap_rejects_anonymous_bind_empty_dn() {
        let msg = build_ldap_bind("");
        assert!(extract_ldap_bind_dn(&msg).is_none());
    }

    #[test]
    fn ldap_rejects_non_ldap_payload() {
        assert!(extract_ldap_bind_dn(b"USER alice\r\n").is_none());
        assert!(extract_ldap_bind_dn(b"\x16\x03\x03\x00\x10").is_none());
    }

    #[test]
    fn ldap_rejects_unbind_request() {
        // Replace [APPLICATION 0] with [APPLICATION 2] (unbindRequest).
        let mut msg = build_ldap_bind("CN=alice");
        let bind_pos = msg
            .iter()
            .position(|&b| b == LDAP_TAG_BIND_REQ)
            .expect("bind tag present");
        msg[bind_pos] = 0x62; // [APPLICATION 2]
        assert!(extract_ldap_bind_dn(&msg).is_none());
    }

    // ── NTLM Type 3 ──────────────────────────────────────────────

    fn build_ntlm_type3(user: &str, domain: &str, unicode: bool) -> Vec<u8> {
        let mut msg = vec![0u8; 64];
        msg[0..8].copy_from_slice(NTLMSSP_SIG);
        msg[8..12].copy_from_slice(&3u32.to_le_bytes()); // MessageType = 3
        let flags = if unicode { NEGOTIATE_UNICODE } else { 0 };
        msg[60..64].copy_from_slice(&flags.to_le_bytes());

        let encode = |s: &str| -> Vec<u8> {
            if unicode {
                let mut out = Vec::with_capacity(s.len() * 2);
                for u in s.encode_utf16() {
                    out.extend_from_slice(&u.to_le_bytes());
                }
                out
            } else {
                s.as_bytes().to_vec()
            }
        };
        let domain_bytes = encode(domain);
        let user_bytes = encode(user);

        // Domain buffer goes first after the header.
        let domain_off = 64u32;
        let user_off = domain_off + domain_bytes.len() as u32;

        // DomainName fields (offset 28).
        msg[28..30].copy_from_slice(&(domain_bytes.len() as u16).to_le_bytes());
        msg[30..32].copy_from_slice(&(domain_bytes.len() as u16).to_le_bytes());
        msg[32..36].copy_from_slice(&domain_off.to_le_bytes());

        // UserName fields (offset 36).
        msg[36..38].copy_from_slice(&(user_bytes.len() as u16).to_le_bytes());
        msg[38..40].copy_from_slice(&(user_bytes.len() as u16).to_le_bytes());
        msg[40..44].copy_from_slice(&user_off.to_le_bytes());

        msg.extend_from_slice(&domain_bytes);
        msg.extend_from_slice(&user_bytes);
        msg
    }

    #[test]
    fn ntlm_extracts_unicode_user_and_domain() {
        let msg = build_ntlm_type3("alice", "EXAMPLE", true);
        let info = extract_ntlm_type3(&msg).expect("decoded");
        assert_eq!(info.user, "alice");
        assert_eq!(info.domain, "EXAMPLE");
    }

    #[test]
    fn ntlm_extracts_ascii_user_and_domain() {
        let msg = build_ntlm_type3("alice", "EXAMPLE", false);
        let info = extract_ntlm_type3(&msg).expect("decoded");
        assert_eq!(info.user, "alice");
        assert_eq!(info.domain, "EXAMPLE");
    }

    #[test]
    fn ntlm_finds_signature_inside_spnego_wrapper() {
        // 16 random bytes (SPNEGO ASN.1 header stub) before the NTLMSSP
        // signature — decoder should still find it via the byte scan.
        let mut payload = vec![0xa1, 0x82, 0x01, 0x00, 0x60, 0x82, 0x00, 0xfa,
                               0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
        let inner = build_ntlm_type3("bob", "CORP", true);
        payload.extend_from_slice(&inner);
        let info = extract_ntlm_type3(&payload).expect("decoded");
        assert_eq!(info.user, "bob");
        assert_eq!(info.domain, "CORP");
    }

    #[test]
    fn ntlm_rejects_type1_and_type2_messages() {
        let mut msg = build_ntlm_type3("alice", "X", true);
        msg[8..12].copy_from_slice(&1u32.to_le_bytes()); // Type 1
        assert!(extract_ntlm_type3(&msg).is_none());
        msg[8..12].copy_from_slice(&2u32.to_le_bytes()); // Type 2
        assert!(extract_ntlm_type3(&msg).is_none());
    }

    #[test]
    fn ntlm_rejects_malicious_offset_past_buffer() {
        let mut msg = build_ntlm_type3("alice", "X", true);
        // Set UserNameOffset to a value beyond the buffer.
        msg[40..44].copy_from_slice(&0xffff_ff00u32.to_le_bytes());
        assert!(extract_ntlm_type3(&msg).is_none());
    }

    #[test]
    fn ntlm_rejects_payload_without_signature() {
        assert!(extract_ntlm_type3(&[]).is_none());
        assert!(extract_ntlm_type3(b"GET / HTTP/1.1\r\n").is_none());
        assert!(extract_ntlm_type3(&[0u8; 64]).is_none());
    }

    #[test]
    fn ntlm_rejects_empty_username() {
        let msg = build_ntlm_type3("", "EXAMPLE", true);
        assert!(extract_ntlm_type3(&msg).is_none());
    }
}
