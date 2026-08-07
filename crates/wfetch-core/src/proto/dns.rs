//! A minimal DNS message codec.
//!
//! Shared by reverse DNS lookups and by mDNS/DNS-SD, which use the same message
//! format on a different transport. Only the record types the scanner reads are
//! decoded: PTR, A, AAAA, TXT and SRV.
//!
//! The delicate part is name decompression (RFC 1035 §4.1.4). A name may end in
//! a pointer to an earlier offset, and a malicious or buggy responder can make
//! two pointers reference each other. A naive decoder loops forever on that, so
//! this one bounds both the number of pointers followed and requires each jump
//! to move strictly backwards.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Record types the scanner understands.
pub mod rtype {
    pub const A: u16 = 1;
    pub const PTR: u16 = 12;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
    /// A request for any record type.
    pub const ANY: u16 = 255;
}

/// Record classes.
pub mod rclass {
    pub const IN: u16 = 1;
    /// In mDNS queries the top bit of the class field is the "unicast reply
    /// requested" flag rather than part of the class.
    pub const UNICAST_RESPONSE: u16 = 0x8000;
    /// In mDNS responses the same bit is the cache-flush flag.
    pub const CACHE_FLUSH: u16 = 0x8000;
}

const MAX_NAME_LEN: usize = 255;
const MAX_LABEL_LEN: usize = 63;
/// Bounds pointer chasing; RFC 1035 permits no more than this in practice.
const MAX_POINTER_JUMPS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    #[error("message truncated at offset {0}")]
    Truncated(usize),
    #[error("compression pointer loop at offset {0}")]
    PointerLoop(usize),
    #[error("name exceeds {MAX_NAME_LEN} bytes")]
    NameTooLong,
    #[error("label exceeds {MAX_LABEL_LEN} bytes")]
    LabelTooLong,
}

pub type Result<T> = std::result::Result<T, DnsError>;

/// A decoded resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub data: RecordData,
}

/// Record payloads, decoded for the types the scanner uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ptr(String),
    /// TXT strings, each already split on its length prefix.
    Txt(Vec<String>),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// Any type we do not decode, kept as raw bytes.
    Other(Vec<u8>),
}

impl RecordData {
    /// The address in an A or AAAA record.
    pub fn as_ip(&self) -> Option<IpAddr> {
        match self {
            RecordData::A(a) => Some(IpAddr::V4(*a)),
            RecordData::Aaaa(a) => Some(IpAddr::V6(*a)),
            _ => None,
        }
    }
}

/// A decoded DNS message.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

impl Message {
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    /// Every record in the message, regardless of section.
    ///
    /// mDNS responders scatter useful records across the answer and additional
    /// sections inconsistently, so callers almost always want all of them.
    pub fn all_records(&self) -> impl Iterator<Item = &ResourceRecord> {
        self.answers
            .iter()
            .chain(self.authorities.iter())
            .chain(self.additionals.iter())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// Encodes a domain name as length-prefixed labels.
///
/// No compression is emitted: queries are small and compressing them buys
/// nothing, while getting it wrong breaks every responder.
pub fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<()> {
    let trimmed = name.trim_end_matches('.');
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            if label.len() > MAX_LABEL_LEN {
                return Err(DnsError::LabelTooLong);
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0); // root label
    Ok(())
}

/// Decodes a name starting at `offset`, following compression pointers.
///
/// Returns the name and the offset just past the name *in the original record*,
/// which is not where decoding finished if a pointer was followed.
pub fn decode_name(buf: &[u8], offset: usize) -> Result<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = offset;
    let mut jumps = 0usize;
    // Set at the first pointer: everything after it belongs to the pointed-to
    // data, so the caller's cursor must stop just past the pointer itself.
    let mut end_of_record: Option<usize> = None;
    let mut total_len = 0usize;

    loop {
        let len_byte = *buf.get(pos).ok_or(DnsError::Truncated(pos))? as usize;

        // Top two bits set marks a 14-bit pointer to an earlier offset.
        if len_byte & 0xc0 == 0xc0 {
            let b2 = *buf.get(pos + 1).ok_or(DnsError::Truncated(pos + 1))? as usize;
            let target = ((len_byte & 0x3f) << 8) | b2;

            if end_of_record.is_none() {
                end_of_record = Some(pos + 2);
            }

            jumps += 1;
            if jumps > MAX_POINTER_JUMPS {
                return Err(DnsError::PointerLoop(pos));
            }
            // A pointer must move strictly backwards. Forward or self pointers
            // are the shape every decompression-loop bug takes.
            if target >= pos {
                return Err(DnsError::PointerLoop(pos));
            }
            pos = target;
            continue;
        }

        // A length byte with either high bit set alone is reserved.
        if len_byte & 0xc0 != 0 {
            return Err(DnsError::Truncated(pos));
        }

        if len_byte == 0 {
            pos += 1;
            break;
        }

        if len_byte > MAX_LABEL_LEN {
            return Err(DnsError::LabelTooLong);
        }
        total_len += len_byte + 1;
        if total_len > MAX_NAME_LEN {
            return Err(DnsError::NameTooLong);
        }

        let start = pos + 1;
        let end = start + len_byte;
        let label = buf.get(start..end).ok_or(DnsError::Truncated(start))?;
        // Names are not required to be UTF-8; mDNS instance names often carry
        // arbitrary bytes. Lossy conversion keeps them readable.
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos = end;
    }

    Ok((labels.join("."), end_of_record.unwrap_or(pos)))
}

fn u16_at(buf: &[u8], off: usize) -> Result<u16> {
    buf.get(off..off + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or(DnsError::Truncated(off))
}

fn u32_at(buf: &[u8], off: usize) -> Result<u32> {
    buf.get(off..off + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(DnsError::Truncated(off))
}

/// Parses a complete DNS message.
pub fn parse_message(buf: &[u8]) -> Result<Message> {
    if buf.len() < 12 {
        return Err(DnsError::Truncated(0));
    }
    let id = u16_at(buf, 0)?;
    let flags = u16_at(buf, 2)?;
    let qd = u16_at(buf, 4)? as usize;
    let an = u16_at(buf, 6)? as usize;
    let ns = u16_at(buf, 8)? as usize;
    let ar = u16_at(buf, 10)? as usize;

    let mut pos = 12usize;
    let mut questions = Vec::with_capacity(qd.min(16));
    for _ in 0..qd {
        let (name, next) = decode_name(buf, pos)?;
        pos = next;
        let qtype = u16_at(buf, pos)?;
        let qclass = u16_at(buf, pos + 2)?;
        pos += 4;
        questions.push(Question {
            name,
            qtype,
            qclass,
        });
    }

    let read_section = |count: usize, pos: &mut usize| -> Result<Vec<ResourceRecord>> {
        let mut out = Vec::with_capacity(count.min(32));
        for _ in 0..count {
            out.push(parse_record(buf, pos)?);
        }
        Ok(out)
    };

    let answers = read_section(an, &mut pos)?;
    let authorities = read_section(ns, &mut pos)?;
    let additionals = read_section(ar, &mut pos)?;

    Ok(Message {
        id,
        flags,
        questions,
        answers,
        authorities,
        additionals,
    })
}

fn parse_record(buf: &[u8], pos: &mut usize) -> Result<ResourceRecord> {
    let (name, next) = decode_name(buf, *pos)?;
    *pos = next;

    let rtype = u16_at(buf, *pos)?;
    let rclass = u16_at(buf, *pos + 2)?;
    let ttl = u32_at(buf, *pos + 4)?;
    let rdlen = u16_at(buf, *pos + 8)? as usize;
    *pos += 10;

    let rdata_start = *pos;
    let rdata = buf
        .get(rdata_start..rdata_start + rdlen)
        .ok_or(DnsError::Truncated(rdata_start))?;
    *pos += rdlen;

    let data = match rtype {
        rtype::A if rdlen == 4 => {
            RecordData::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))
        }
        rtype::AAAA if rdlen == 16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(rdata);
            RecordData::Aaaa(Ipv6Addr::from(o))
        }
        // PTR and SRV targets are decoded against the whole message, since they
        // may compress against names appearing earlier in it.
        rtype::PTR => RecordData::Ptr(decode_name(buf, rdata_start)?.0),
        rtype::SRV if rdlen >= 7 => RecordData::Srv {
            priority: u16::from_be_bytes([rdata[0], rdata[1]]),
            weight: u16::from_be_bytes([rdata[2], rdata[3]]),
            port: u16::from_be_bytes([rdata[4], rdata[5]]),
            target: decode_name(buf, rdata_start + 6)?.0,
        },
        rtype::TXT => RecordData::Txt(parse_txt(rdata)),
        _ => RecordData::Other(rdata.to_vec()),
    };

    Ok(ResourceRecord {
        name,
        rtype,
        rclass,
        ttl,
        data,
    })
}

/// Splits TXT rdata into its length-prefixed strings.
fn parse_txt(mut data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    while let Some((&len, rest)) = data.split_first() {
        let len = len as usize;
        if rest.len() < len {
            break;
        }
        out.push(String::from_utf8_lossy(&rest[..len]).into_owned());
        data = &rest[len..];
    }
    out
}

/// Builds a query message.
pub fn build_query(id: u16, name: &str, qtype: u16, qclass: u16) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes()); // flags: standard query
    buf.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    buf.extend_from_slice(&0u16.to_be_bytes()); // ancount
    buf.extend_from_slice(&0u16.to_be_bytes()); // nscount
    buf.extend_from_slice(&0u16.to_be_bytes()); // arcount
    encode_name(name, &mut buf)?;
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&qclass.to_be_bytes());
    Ok(buf)
}

/// The `in-addr.arpa` / `ip6.arpa` name for a reverse lookup.
pub fn reverse_name(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(a) => {
            // Each nibble, least significant first, dot-separated.
            let mut s = String::with_capacity(72);
            for byte in a.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", byte & 0x0f, byte >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- name encoding -----------------------------------------------------

    #[test]
    fn encodes_names_as_length_prefixed_labels() {
        let mut b = Vec::new();
        encode_name("www.example.com", &mut b).unwrap();
        assert_eq!(
            b,
            b"\x03www\x07example\x03com\x00".to_vec(),
            "unexpected encoding"
        );
    }

    #[test]
    fn a_trailing_dot_does_not_produce_an_empty_label() {
        let mut with = Vec::new();
        let mut without = Vec::new();
        encode_name("example.com.", &mut with).unwrap();
        encode_name("example.com", &mut without).unwrap();
        assert_eq!(with, without);
    }

    #[test]
    fn the_root_name_is_a_single_zero_byte() {
        let mut b = Vec::new();
        encode_name("", &mut b).unwrap();
        assert_eq!(b, vec![0]);
    }

    #[test]
    fn over_long_labels_are_rejected() {
        let mut b = Vec::new();
        let long = "a".repeat(64);
        assert!(matches!(
            encode_name(&long, &mut b),
            Err(DnsError::LabelTooLong)
        ));
    }

    #[test]
    fn encoding_round_trips_through_decoding() {
        for name in [
            "example.com",
            "a.b.c.d.e.f",
            "_services._dns-sd._udp.local",
            "1.0.0.10.in-addr.arpa",
        ] {
            let mut b = Vec::new();
            encode_name(name, &mut b).unwrap();
            let (decoded, end) = decode_name(&b, 0).unwrap();
            assert_eq!(decoded, name, "round trip failed for {name}");
            assert_eq!(end, b.len());
        }
    }

    // ---- name decompression ------------------------------------------------

    #[test]
    fn follows_a_compression_pointer() {
        // "example.com" at offset 0, then a name that is just a pointer to it.
        let mut buf = Vec::new();
        encode_name("example.com", &mut buf).unwrap();
        let ptr_at = buf.len();
        buf.extend_from_slice(&[0xc0, 0x00]);

        let (name, end) = decode_name(&buf, ptr_at).unwrap();
        assert_eq!(name, "example.com");
        // The cursor stops after the 2-byte pointer, not after the target.
        assert_eq!(end, ptr_at + 2);
    }

    #[test]
    fn follows_a_pointer_after_literal_labels() {
        // "www" followed by a pointer to "example.com".
        let mut buf = Vec::new();
        encode_name("example.com", &mut buf).unwrap();
        let start = buf.len();
        buf.push(3);
        buf.extend_from_slice(b"www");
        buf.extend_from_slice(&[0xc0, 0x00]);

        let (name, end) = decode_name(&buf, start).unwrap();
        assert_eq!(name, "www.example.com");
        assert_eq!(end, buf.len());
    }

    #[test]
    fn a_self_referential_pointer_is_rejected_not_looped_on() {
        // 0xc000 at offset 0 points at itself.
        let buf = vec![0xc0, 0x00];
        assert!(matches!(
            decode_name(&buf, 0),
            Err(DnsError::PointerLoop(_))
        ));
    }

    #[test]
    fn mutually_referential_pointers_are_rejected() {
        // Offset 0 points to 2, offset 2 points to 0.
        let buf = vec![0xc0, 0x02, 0xc0, 0x00];
        assert!(matches!(
            decode_name(&buf, 0),
            Err(DnsError::PointerLoop(_))
        ));
        assert!(matches!(
            decode_name(&buf, 2),
            Err(DnsError::PointerLoop(_))
        ));
    }

    #[test]
    fn forward_pointers_are_rejected() {
        // A pointer must move strictly backwards; a forward one can be chased
        // into an unbounded chain.
        let mut buf = vec![0u8; 8];
        buf[0] = 0xc0;
        buf[1] = 0x04;
        assert!(matches!(
            decode_name(&buf, 0),
            Err(DnsError::PointerLoop(_))
        ));
    }

    #[test]
    fn a_long_backward_pointer_chain_is_bounded() {
        // Each pointer moves back by two, so the chain is legal but long.
        // The jump limit must stop it well before it becomes a denial of service.
        let mut buf = vec![0u8; 256];
        for i in (2..256).step_by(2) {
            buf[i] = 0xc0;
            buf[i + 1] = (i - 2) as u8;
        }
        assert!(matches!(
            decode_name(&buf, 254),
            Err(DnsError::PointerLoop(_))
        ));
    }

    #[test]
    fn truncated_names_are_rejected() {
        // Label claims 5 bytes but only 2 follow.
        assert!(decode_name(&[5, b'a', b'b'], 0).is_err());
        // Pointer with no second byte.
        assert!(decode_name(&[0xc0], 0).is_err());
        assert!(decode_name(&[], 0).is_err());
    }

    #[test]
    fn over_long_names_are_rejected() {
        // Many maximal labels, chained, exceed the 255-byte name limit.
        let mut buf = Vec::new();
        for _ in 0..8 {
            buf.push(63);
            buf.extend_from_slice(&[b'a'; 63]);
        }
        buf.push(0);
        assert!(matches!(decode_name(&buf, 0), Err(DnsError::NameTooLong)));
    }

    #[test]
    fn arbitrary_byte_soup_never_panics_or_hangs() {
        let mut seed = 0xcafeu32;
        for _ in 0..4000 {
            let len = (seed % 96) as usize;
            let buf: Vec<u8> = (0..len)
                .map(|i| {
                    seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                    (seed >> ((i % 4) * 8)) as u8
                })
                .collect();
            let _ = decode_name(&buf, 0);
            let _ = parse_message(&buf);
        }
    }

    // ---- message parsing ---------------------------------------------------

    /// Assembles a message from a header and pre-encoded sections.
    fn message(flags: u16, counts: [u16; 4], body: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&0x1234u16.to_be_bytes());
        m.extend_from_slice(&flags.to_be_bytes());
        for c in counts {
            m.extend_from_slice(&c.to_be_bytes());
        }
        m.extend_from_slice(body);
        m
    }

    fn record_bytes(name: &str, rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        encode_name(name, &mut r).unwrap();
        r.extend_from_slice(&rtype.to_be_bytes());
        r.extend_from_slice(&rclass::IN.to_be_bytes());
        r.extend_from_slice(&120u32.to_be_bytes());
        r.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        r.extend_from_slice(rdata);
        r
    }

    #[test]
    fn parses_a_query_built_by_build_query() {
        let q = build_query(0x1234, "example.com", rtype::A, rclass::IN).unwrap();
        let m = parse_message(&q).unwrap();
        assert_eq!(m.id, 0x1234);
        assert!(!m.is_response());
        assert_eq!(m.questions.len(), 1);
        assert_eq!(m.questions[0].name, "example.com");
        assert_eq!(m.questions[0].qtype, rtype::A);
    }

    #[test]
    fn parses_a_and_aaaa_records() {
        let body = [
            record_bytes("host.local", rtype::A, &[192, 168, 1, 10]),
            record_bytes("host.local", rtype::AAAA, &[0x20, 0x01, 0x0d, 0xb8]
                .iter().copied().chain(std::iter::repeat(0).take(11)).chain([1u8])
                .collect::<Vec<u8>>().as_slice()),
        ]
        .concat();
        let m = parse_message(&message(0x8400, [0, 2, 0, 0], &body)).unwrap();
        assert!(m.is_response());
        assert_eq!(
            m.answers[0].data,
            RecordData::A(Ipv4Addr::new(192, 168, 1, 10))
        );
        assert_eq!(
            m.answers[1].data.as_ip(),
            Some("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn a_records_with_the_wrong_rdata_length_fall_back_to_raw() {
        // A 5-byte A record is malformed; it must not be read as an address.
        let body = record_bytes("h.local", rtype::A, &[1, 2, 3, 4, 5]);
        let m = parse_message(&message(0x8400, [0, 1, 0, 0], &body)).unwrap();
        assert!(matches!(m.answers[0].data, RecordData::Other(_)));
        assert_eq!(m.answers[0].data.as_ip(), None);
    }

    #[test]
    fn parses_ptr_records_including_compressed_targets() {
        let mut body = Vec::new();
        // An A record first, so its name is available to compress against.
        body.extend(record_bytes("printer.local", rtype::A, &[10, 0, 0, 5]));
        // A PTR whose rdata is a pointer back to offset 12 ("printer.local").
        let mut ptr = Vec::new();
        encode_name("_ipp._tcp.local", &mut ptr).unwrap();
        ptr.extend_from_slice(&rtype::PTR.to_be_bytes());
        ptr.extend_from_slice(&rclass::IN.to_be_bytes());
        ptr.extend_from_slice(&120u32.to_be_bytes());
        ptr.extend_from_slice(&2u16.to_be_bytes());
        ptr.extend_from_slice(&[0xc0, 12]);
        body.extend(ptr);

        let m = parse_message(&message(0x8400, [0, 2, 0, 0], &body)).unwrap();
        assert_eq!(
            m.answers[1].data,
            RecordData::Ptr("printer.local".to_string())
        );
    }

    #[test]
    fn parses_srv_records() {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&10u16.to_be_bytes()); // priority
        rdata.extend_from_slice(&5u16.to_be_bytes()); // weight
        rdata.extend_from_slice(&631u16.to_be_bytes()); // port
        encode_name("printer.local", &mut rdata).unwrap();
        let body = record_bytes("_ipp._tcp.local", rtype::SRV, &rdata);

        let m = parse_message(&message(0x8400, [0, 1, 0, 0], &body)).unwrap();
        assert_eq!(
            m.answers[0].data,
            RecordData::Srv {
                priority: 10,
                weight: 5,
                port: 631,
                target: "printer.local".to_string(),
            }
        );
    }

    #[test]
    fn parses_multi_string_txt_records() {
        // TXT rdata is a sequence of length-prefixed strings, not one blob.
        let rdata = b"\x09model=J42\x0bvendor=Acme".to_vec();
        let body = record_bytes("d.local", rtype::TXT, &rdata);
        let m = parse_message(&message(0x8400, [0, 1, 0, 0], &body)).unwrap();
        assert_eq!(
            m.answers[0].data,
            RecordData::Txt(vec!["model=J42".to_string(), "vendor=Acme".to_string()])
        );
    }

    #[test]
    fn a_truncated_txt_string_stops_parsing_without_panicking() {
        // Length prefix claims 9 bytes but only 3 follow.
        assert_eq!(parse_txt(b"\x09abc"), Vec::<String>::new());
        assert_eq!(parse_txt(b""), Vec::<String>::new());
    }

    #[test]
    fn records_are_read_from_every_section() {
        let body = [
            record_bytes("a.local", rtype::A, &[10, 0, 0, 1]),
            record_bytes("b.local", rtype::A, &[10, 0, 0, 2]),
            record_bytes("c.local", rtype::A, &[10, 0, 0, 3]),
        ]
        .concat();
        let m = parse_message(&message(0x8400, [0, 1, 1, 1], &body)).unwrap();
        assert_eq!(m.answers.len(), 1);
        assert_eq!(m.authorities.len(), 1);
        assert_eq!(m.additionals.len(), 1);
        // mDNS responders scatter records across sections, so callers want all.
        assert_eq!(m.all_records().count(), 3);
    }

    #[test]
    fn a_record_count_larger_than_the_body_is_an_error_not_a_panic() {
        // Claims 10 answers but supplies one.
        let body = record_bytes("a.local", rtype::A, &[10, 0, 0, 1]);
        assert!(parse_message(&message(0x8400, [0, 10, 0, 0], &body)).is_err());
    }

    #[test]
    fn short_headers_are_rejected() {
        for len in 0..12 {
            assert!(parse_message(&vec![0u8; len]).is_err(), "len {len}");
        }
    }

    // ---- reverse names -----------------------------------------------------

    #[test]
    fn builds_ipv4_reverse_names_in_octet_reverse_order() {
        assert_eq!(
            reverse_name("192.168.1.10".parse().unwrap()),
            "10.1.168.192.in-addr.arpa"
        );
        assert_eq!(
            reverse_name("10.0.0.1".parse().unwrap()),
            "1.0.0.10.in-addr.arpa"
        );
    }

    #[test]
    fn builds_ipv6_reverse_names_as_reversed_nibbles() {
        // ::1 expands to 31 zero nibbles then 1, reversed.
        let n = reverse_name("::1".parse().unwrap());
        assert!(n.starts_with("1.0.0.0."), "got {n}");
        assert!(n.ends_with(".ip6.arpa"));
        // 32 nibbles each followed by a dot, plus the dot inside "ip6.arpa".
        assert_eq!(n.matches('.').count(), 33);
        assert_eq!(n.split('.').count(), 34);
    }

    #[test]
    fn reverse_names_encode_and_decode_cleanly() {
        let n = reverse_name("192.168.1.10".parse().unwrap());
        let mut b = Vec::new();
        encode_name(&n, &mut b).unwrap();
        assert_eq!(decode_name(&b, 0).unwrap().0, n);
    }
}
