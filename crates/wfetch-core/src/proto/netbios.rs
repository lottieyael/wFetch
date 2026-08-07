//! NetBIOS Name Service (RFC 1002).
//!
//! A node status query on UDP 137 makes a Windows host volunteer its computer
//! name, its workgroup or domain, the services it runs and its MAC address —
//! from an unprivileged socket, with no credentials, in one packet.
//!
//! It remains useful despite its age: `Get-NetNeighbor` cannot name a host, and
//! a Windows machine that blocks ICMP and answers nothing on mDNS will usually
//! still answer this. Samba servers answer it too.
//!
//! The awkward part is the level-1 name encoding, which expands each of the 16
//! name bytes into two characters. It is easy to implement subtly wrong in a way
//! that still produces plausible output, so it is tested in both directions.

use serde::{Deserialize, Serialize};

use crate::mac::MacAddr;

pub const NETBIOS_NS_PORT: u16 = 137;

/// `NBSTAT`: the node status record type.
const QTYPE_NBSTAT: u16 = 0x0021;
const QCLASS_IN: u16 = 0x0001;

/// Length of a NetBIOS name before encoding.
const NETBIOS_NAME_LEN: usize = 16;
/// Length after level-1 encoding: two characters per byte.
const ENCODED_NAME_LEN: usize = 32;

/// Encodes a NetBIOS name using the RFC 1001 level-1 encoding.
///
/// The name is padded with spaces to 15 bytes, the 16th byte is the service
/// suffix, and each byte is then split into two nibbles, each added to `'A'`.
pub fn encode_name(name: &str, suffix: u8) -> Vec<u8> {
    let mut raw = [b' '; NETBIOS_NAME_LEN];
    // Names are uppercase on the wire and truncated at 15 bytes.
    for (i, b) in name.bytes().take(NETBIOS_NAME_LEN - 1).enumerate() {
        raw[i] = b.to_ascii_uppercase();
    }
    raw[NETBIOS_NAME_LEN - 1] = suffix;

    let mut out = Vec::with_capacity(ENCODED_NAME_LEN);
    for b in raw {
        out.push(b'A' + (b >> 4));
        out.push(b'A' + (b & 0x0f));
    }
    out
}

/// Decodes a level-1 encoded name, returning the trimmed name and its suffix.
pub fn decode_name(encoded: &[u8]) -> Option<(String, u8)> {
    if encoded.len() < ENCODED_NAME_LEN {
        return None;
    }
    let mut raw = [0u8; NETBIOS_NAME_LEN];
    for i in 0..NETBIOS_NAME_LEN {
        let hi = encoded[i * 2].checked_sub(b'A')?;
        let lo = encoded[i * 2 + 1].checked_sub(b'A')?;
        // Each half must be a single nibble; anything larger is not level-1.
        if hi > 0x0f || lo > 0x0f {
            return None;
        }
        raw[i] = (hi << 4) | lo;
    }
    let suffix = raw[NETBIOS_NAME_LEN - 1];
    // Real hosts pad with spaces, but the wildcard name pads with NULs, and
    // `trim_end` does not treat NUL as whitespace. Trimming only spaces leaves
    // a name of "*\0\0\0..." that matches nothing.
    let name = String::from_utf8_lossy(&raw[..NETBIOS_NAME_LEN - 1])
        .trim_end_matches([' ', '\0'])
        .to_string();
    Some((name, suffix))
}

/// Builds a node status request.
///
/// The wildcard name `*` asks the host to report everything it knows about
/// itself, which is what makes one packet enough.
pub fn build_node_status_request(transaction_id: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(50);
    pkt.extend_from_slice(&transaction_id.to_be_bytes());
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // flags: query, no recursion
    pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // qdcount
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // ancount
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // nscount
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // arcount

    // The wildcard name is 0x2A followed by nulls, not spaces.
    let mut raw = [0u8; NETBIOS_NAME_LEN];
    raw[0] = b'*';
    let mut encoded = Vec::with_capacity(ENCODED_NAME_LEN);
    for b in raw {
        encoded.push(b'A' + (b >> 4));
        encoded.push(b'A' + (b & 0x0f));
    }

    pkt.push(ENCODED_NAME_LEN as u8);
    pkt.extend_from_slice(&encoded);
    pkt.push(0); // root label

    pkt.extend_from_slice(&QTYPE_NBSTAT.to_be_bytes());
    pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
    pkt
}

/// What a NetBIOS name's suffix byte says the entry is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameKind {
    /// `0x00` on a unique name: the computer name.
    Workstation,
    /// `0x00` on a group name: the workgroup or domain.
    WorkgroupOrDomain,
    Messenger,
    /// `0x20`: the file and printer sharing service.
    FileServer,
    DomainMasterBrowser,
    DomainController,
    MasterBrowser,
    BrowserElection,
    Other(u8),
}

fn classify_suffix(suffix: u8, is_group: bool) -> NameKind {
    match (suffix, is_group) {
        (0x00, false) => NameKind::Workstation,
        (0x00, true) => NameKind::WorkgroupOrDomain,
        (0x03, _) => NameKind::Messenger,
        (0x20, _) => NameKind::FileServer,
        (0x1b, _) => NameKind::DomainMasterBrowser,
        (0x1c, _) => NameKind::DomainController,
        (0x1d, _) => NameKind::MasterBrowser,
        (0x1e, _) => NameKind::BrowserElection,
        (s, _) => NameKind::Other(s),
    }
}

/// One name from a node status response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetbiosName {
    pub name: String,
    pub suffix: u8,
    pub is_group: bool,
    pub kind: NameKind,
}

/// A decoded node status response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStatus {
    pub names: Vec<NetbiosName>,
    /// The adapter MAC, which the response carries in its statistics block.
    pub mac: Option<MacAddr>,
}

impl NodeStatus {
    /// The computer name: the unique name with suffix `0x00`.
    pub fn computer_name(&self) -> Option<&str> {
        self.names
            .iter()
            .find(|n| n.kind == NameKind::Workstation)
            .map(|n| n.name.as_str())
    }

    /// The workgroup or domain: the group name with suffix `0x00`.
    pub fn workgroup(&self) -> Option<&str> {
        self.names
            .iter()
            .find(|n| n.kind == NameKind::WorkgroupOrDomain)
            .map(|n| n.name.as_str())
    }

    /// Whether the host offers file and printer sharing.
    pub fn is_file_server(&self) -> bool {
        self.names.iter().any(|n| n.kind == NameKind::FileServer)
    }

    /// Whether the host claims a domain controller role.
    pub fn is_domain_controller(&self) -> bool {
        self.names
            .iter()
            .any(|n| matches!(n.kind, NameKind::DomainController | NameKind::DomainMasterBrowser))
    }
}

/// Parses a node status response.
///
/// Layout after the 12-byte header: the queried name, the record header, then a
/// count byte followed by that many 18-byte entries (15 name bytes, a suffix
/// byte and a 2-byte flags field), then the statistics block whose first six
/// bytes are the adapter MAC.
pub fn parse_node_status(data: &[u8]) -> Option<NodeStatus> {
    if data.len() < 12 {
        return None;
    }
    // Bit 15 of the flags word marks a response.
    let flags = u16::from_be_bytes([data[2], data[3]]);
    if flags & 0x8000 == 0 {
        return None;
    }
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 {
        return None;
    }

    let mut pos = 12usize;

    // Skip the echoed question name: a length-prefixed label sequence.
    loop {
        let len = *data.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        // A compression pointer here would be malformed for NBNS.
        if len & 0xc0 != 0 {
            return None;
        }
        pos += len;
        if pos > data.len() {
            return None;
        }
    }

    // Record header: type (2), class (2), TTL (4), rdlength (2).
    pos += 10;
    let count = *data.get(pos)? as usize;
    pos += 1;

    let mut names = Vec::with_capacity(count.min(64));
    for _ in 0..count {
        let entry = data.get(pos..pos + 18)?;
        let raw_name = &entry[..15];
        let suffix = entry[15];
        let name_flags = u16::from_be_bytes([entry[16], entry[17]]);
        // Bit 15 of the name flags distinguishes a group name from a unique one.
        let is_group = name_flags & 0x8000 != 0;

        let name = String::from_utf8_lossy(raw_name).trim_end().to_string();
        if !name.is_empty() {
            names.push(NetbiosName {
                name,
                suffix,
                is_group,
                kind: classify_suffix(suffix, is_group),
            });
        }
        pos += 18;
    }

    // The statistics block opens with the adapter's MAC.
    let mac = data.get(pos..pos + 6).and_then(|b| {
        let mut m = [0u8; 6];
        m.copy_from_slice(b);
        let m = MacAddr::new(m);
        if m.is_zero() {
            None
        } else {
            Some(m)
        }
    });

    Some(NodeStatus { names, mac })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- name encoding -----------------------------------------------------

    #[test]
    fn encodes_the_documented_rfc1001_example() {
        // RFC 1001 §4.1. Each byte splits into two nibbles, each added to 'A':
        // F=0x46 -> EG, R=0x52 -> FC, E=0x45 -> EF, D=0x44 -> EE.
        let e = encode_name("FRED", 0x20);
        assert_eq!(e.len(), ENCODED_NAME_LEN);
        assert_eq!(&e[..8], b"EGFCEFEE", "F,R,E,D should encode as EG FC EF EE");
        // Padding spaces (0x20) encode as 'C','A'.
        assert_eq!(&e[8..10], b"CA");
        // The suffix occupies the final byte.
        assert_eq!(&e[30..32], b"CA");
    }

    #[test]
    fn encoding_round_trips_through_decoding() {
        for (name, suffix) in [
            ("WORKSTATION1", 0x00u8),
            ("FILESRV", 0x20),
            ("A", 0x03),
            ("WORKGROUP", 0x1e),
        ] {
            let e = encode_name(name, suffix);
            let (decoded, s) = decode_name(&e).unwrap();
            assert_eq!(decoded, name, "name round trip");
            assert_eq!(s, suffix, "suffix round trip");
        }
    }

    #[test]
    fn names_are_uppercased_and_truncated_to_fifteen_bytes() {
        let (n, _) = decode_name(&encode_name("lowercase", 0)).unwrap();
        assert_eq!(n, "LOWERCASE");

        // 20 characters must be cut to 15, leaving room for the suffix byte.
        let (n, s) = decode_name(&encode_name("ABCDEFGHIJKLMNOPQRST", 0x20)).unwrap();
        assert_eq!(n, "ABCDEFGHIJKLMNO");
        assert_eq!(n.len(), 15);
        assert_eq!(s, 0x20);
    }

    #[test]
    fn an_empty_name_encodes_as_all_padding() {
        let (n, s) = decode_name(&encode_name("", 0x00)).unwrap();
        assert_eq!(n, "");
        assert_eq!(s, 0);
    }

    #[test]
    fn every_byte_value_survives_the_nibble_split() {
        // The encoding must be lossless for all 256 suffix values.
        for suffix in 0u8..=255 {
            let (_, s) = decode_name(&encode_name("HOST", suffix)).unwrap();
            assert_eq!(s, suffix, "suffix {suffix:#04x} did not round trip");
        }
    }

    #[test]
    fn both_space_and_nul_padding_are_trimmed() {
        // Hosts pad with spaces; the wildcard name pads with NULs. `trim_end`
        // alone does not strip NUL, leaving a name that matches nothing.
        let mut nul_padded = [0u8; NETBIOS_NAME_LEN];
        nul_padded[0] = b'*';
        let mut encoded = Vec::new();
        for b in nul_padded {
            encoded.push(b'A' + (b >> 4));
            encoded.push(b'A' + (b & 0x0f));
        }
        assert_eq!(decode_name(&encoded).unwrap().0, "*");

        // Space padding, the ordinary case.
        assert_eq!(decode_name(&encode_name("HOST", 0)).unwrap().0, "HOST");
    }

    #[test]
    fn decoding_rejects_input_that_is_not_level_1_encoded() {
        // Characters below 'A' underflow, above 'P' exceed a nibble.
        assert!(decode_name(&[b'@'; 32]).is_none());
        assert!(decode_name(&[b'Z'; 32]).is_none());
        assert!(decode_name(&[b'A'; 31]).is_none(), "too short");
        assert!(decode_name(&[]).is_none());
    }

    // ---- request construction ----------------------------------------------

    #[test]
    fn node_status_request_is_well_formed() {
        let p = build_node_status_request(0x1234);
        assert_eq!(u16::from_be_bytes([p[0], p[1]]), 0x1234);
        assert_eq!(u16::from_be_bytes([p[2], p[3]]), 0x0000, "must be a query");
        assert_eq!(u16::from_be_bytes([p[4], p[5]]), 1, "one question");
        assert_eq!(p[12], ENCODED_NAME_LEN as u8, "label length prefix");
        assert_eq!(p[13 + ENCODED_NAME_LEN], 0, "root label terminator");

        let n = p.len();
        assert_eq!(u16::from_be_bytes([p[n - 4], p[n - 3]]), QTYPE_NBSTAT);
        assert_eq!(u16::from_be_bytes([p[n - 2], p[n - 1]]), QCLASS_IN);
    }

    #[test]
    fn the_wildcard_name_is_padded_with_nulls_not_spaces() {
        // Padding with spaces makes hosts ignore the query, which is a silent
        // and very confusing failure.
        let p = build_node_status_request(1);
        let encoded = &p[13..13 + ENCODED_NAME_LEN];
        let (name, suffix) = decode_name(encoded).unwrap();
        assert_eq!(name, "*");
        assert_eq!(suffix, 0x00);
        // 0x00 encodes as 'A','A'; a space would be 'C','A'.
        assert_eq!(&encoded[2..4], b"AA");
    }

    // ---- response parsing --------------------------------------------------

    /// Builds a node status response carrying the given names and MAC.
    fn response(entries: &[(&str, u8, bool)], mac: [u8; 6]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&0x1234u16.to_be_bytes());
        p.extend_from_slice(&0x8400u16.to_be_bytes()); // response
        p.extend_from_slice(&0u16.to_be_bytes()); // qdcount
        p.extend_from_slice(&1u16.to_be_bytes()); // ancount
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());

        // Echoed question name.
        let mut raw = [0u8; NETBIOS_NAME_LEN];
        raw[0] = b'*';
        p.push(ENCODED_NAME_LEN as u8);
        for b in raw {
            p.push(b'A' + (b >> 4));
            p.push(b'A' + (b & 0x0f));
        }
        p.push(0);

        // Record header.
        p.extend_from_slice(&QTYPE_NBSTAT.to_be_bytes());
        p.extend_from_slice(&QCLASS_IN.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes()); // rdlength, unchecked

        p.push(entries.len() as u8);
        for (name, suffix, is_group) in entries {
            let mut n = [b' '; 15];
            for (i, b) in name.bytes().take(15).enumerate() {
                n[i] = b;
            }
            p.extend_from_slice(&n);
            p.push(*suffix);
            p.extend_from_slice(&(if *is_group { 0x8000u16 } else { 0x0400 }).to_be_bytes());
        }
        p.extend_from_slice(&mac);
        p.extend_from_slice(&[0u8; 40]); // rest of the statistics block
        p
    }

    #[test]
    fn parses_a_realistic_windows_workstation_response() {
        let p = response(
            &[
                ("DESKTOP-A1B2C3", 0x00, false),
                ("WORKGROUP", 0x00, true),
                ("DESKTOP-A1B2C3", 0x20, false),
            ],
            [0x00, 0x0c, 0x29, 0x1a, 0x2b, 0x3c],
        );
        let s = parse_node_status(&p).unwrap();

        assert_eq!(s.computer_name(), Some("DESKTOP-A1B2C3"));
        assert_eq!(s.workgroup(), Some("WORKGROUP"));
        assert!(s.is_file_server());
        assert!(!s.is_domain_controller());
        assert_eq!(
            s.mac,
            Some(MacAddr::new([0x00, 0x0c, 0x29, 0x1a, 0x2b, 0x3c]))
        );
    }

    #[test]
    fn the_group_bit_distinguishes_the_workgroup_from_the_computer_name() {
        // Both carry suffix 0x00; only the group flag tells them apart, and
        // getting it wrong swaps the machine name with its domain.
        let p = response(&[("HOSTNAME", 0x00, false), ("MYDOMAIN", 0x00, true)], [1; 6]);
        let s = parse_node_status(&p).unwrap();
        assert_eq!(s.computer_name(), Some("HOSTNAME"));
        assert_eq!(s.workgroup(), Some("MYDOMAIN"));
    }

    #[test]
    fn classifies_the_documented_service_suffixes() {
        let cases = [
            (0x00u8, false, NameKind::Workstation),
            (0x00, true, NameKind::WorkgroupOrDomain),
            (0x03, false, NameKind::Messenger),
            (0x20, false, NameKind::FileServer),
            (0x1b, false, NameKind::DomainMasterBrowser),
            (0x1c, true, NameKind::DomainController),
            (0x1d, false, NameKind::MasterBrowser),
            (0x1e, true, NameKind::BrowserElection),
            (0x42, false, NameKind::Other(0x42)),
        ];
        for (suffix, group, expected) in cases {
            assert_eq!(classify_suffix(suffix, group), expected, "suffix {suffix:#04x}");
        }
    }

    #[test]
    fn detects_a_domain_controller() {
        let p = response(&[("DC01", 0x00, false), ("CORP", 0x1c, true)], [1; 6]);
        assert!(parse_node_status(&p).unwrap().is_domain_controller());
    }

    #[test]
    fn queries_are_not_parsed_as_responses() {
        let q = build_node_status_request(1);
        assert!(parse_node_status(&q).is_none());
    }

    #[test]
    fn responses_with_no_answers_are_rejected() {
        let mut p = response(&[("X", 0, false)], [1; 6]);
        p[6..8].copy_from_slice(&0u16.to_be_bytes()); // ancount = 0
        assert!(parse_node_status(&p).is_none());
    }

    #[test]
    fn an_all_zero_mac_is_reported_as_absent() {
        let p = response(&[("HOST", 0x00, false)], [0; 6]);
        assert_eq!(parse_node_status(&p).unwrap().mac, None);
    }

    #[test]
    fn a_truncated_name_table_does_not_panic() {
        // Claims three entries but supplies one.
        let mut p = response(&[("HOST", 0x00, false)], [1; 6]);
        let count_pos = p.len() - 6 - 40 - 18 - 1;
        p[count_pos] = 3;
        p.truncate(count_pos + 1 + 18);
        assert!(parse_node_status(&p).is_none());
    }

    #[test]
    fn short_and_empty_inputs_are_rejected() {
        for len in 0..12 {
            assert!(parse_node_status(&vec![0u8; len]).is_none(), "len {len}");
        }
    }

    #[test]
    fn arbitrary_byte_soup_never_panics() {
        let mut seed = 0xb105u32;
        for _ in 0..3000 {
            let len = (seed % 160) as usize;
            let mut buf: Vec<u8> = (0..len)
                .map(|i| {
                    seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                    (seed >> ((i % 4) * 8)) as u8
                })
                .collect();
            // Force the response bit often enough to reach the parsing body.
            if buf.len() > 8 {
                buf[2] = 0x84;
                buf[7] = 1;
            }
            let _ = parse_node_status(&buf);
        }
    }
}
