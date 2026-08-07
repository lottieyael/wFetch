//! BER encoding, the subset SNMP uses.
//!
//! Hand-rolled rather than pulled from a dependency, because SNMP needs only a
//! handful of types and the encoding has two details that are easy to get
//! subtly wrong and impossible to notice without tests:
//!
//! * **Length is variable-width.** Under 128 bytes it is one byte; at or above,
//!   it is a count byte with the high bit set followed by that many big-endian
//!   length bytes. A codec that only handles the short form works perfectly
//!   until a device returns a `sysDescr` longer than 127 characters, which most
//!   of them do.
//! * **OID arcs are base-128 varints, and the first two arcs are merged** into
//!   a single byte as `40 * first + second`.

/// BER tag numbers used by SNMP.
pub mod tag {
    pub const INTEGER: u8 = 0x02;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OID: u8 = 0x06;
    pub const SEQUENCE: u8 = 0x30;

    // Application-class types from RFC 2578.
    pub const IP_ADDRESS: u8 = 0x40;
    pub const COUNTER32: u8 = 0x41;
    pub const GAUGE32: u8 = 0x42;
    pub const TIMETICKS: u8 = 0x43;
    pub const OPAQUE: u8 = 0x44;
    pub const COUNTER64: u8 = 0x46;

    // Context-specific PDU types.
    pub const GET_REQUEST: u8 = 0xa0;
    pub const GET_NEXT_REQUEST: u8 = 0xa1;
    pub const GET_RESPONSE: u8 = 0xa2;

    // Exception markers a v2c agent returns instead of a value.
    pub const NO_SUCH_OBJECT: u8 = 0x80;
    pub const NO_SUCH_INSTANCE: u8 = 0x81;
    pub const END_OF_MIB_VIEW: u8 = 0x82;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BerError {
    #[error("truncated at offset {0}")]
    Truncated(usize),
    #[error("expected tag {expected:#04x}, found {found:#04x}")]
    UnexpectedTag { expected: u8, found: u8 },
    #[error("length {0} is too large")]
    LengthTooLarge(usize),
    #[error("malformed {0}")]
    Malformed(&'static str),
}

pub type Result<T> = std::result::Result<T, BerError>;

/// Encodes a length in the short or long form as required.
pub fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    // Long form: 0x80 | byte count, then the length, big-endian, minimally.
    let bytes = len.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len() - 1);
    let significant = &bytes[first..];
    out.push(0x80 | significant.len() as u8);
    out.extend_from_slice(significant);
}

/// Decodes a length, returning it and the offset just past it.
pub fn decode_length(buf: &[u8], offset: usize) -> Result<(usize, usize)> {
    let first = *buf.get(offset).ok_or(BerError::Truncated(offset))?;
    if first & 0x80 == 0 {
        return Ok((first as usize, offset + 1));
    }
    let count = (first & 0x7f) as usize;
    // The indefinite form (count 0) is not permitted in SNMP, and more than
    // eight bytes cannot fit a usize.
    if count == 0 || count > 8 {
        return Err(BerError::Malformed("length header"));
    }
    let bytes = buf
        .get(offset + 1..offset + 1 + count)
        .ok_or(BerError::Truncated(offset + 1))?;
    let mut len = 0usize;
    for b in bytes {
        len = (len << 8) | *b as usize;
    }
    Ok((len, offset + 1 + count))
}

/// Writes a tag, a length and a body.
pub fn encode_tlv(tag: u8, body: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    encode_length(body.len(), out);
    out.extend_from_slice(body);
}

/// Encodes a signed integer in the minimal two's-complement form BER requires.
pub fn encode_integer(value: i64, out: &mut Vec<u8>) {
    let mut body = Vec::with_capacity(8);
    let bytes = value.to_be_bytes();

    // Strip leading bytes that carry no information, but keep one that
    // preserves the sign: dropping it would flip 0x00_80 into a negative 0x80.
    let mut start = 0;
    while start < 7 {
        let redundant = (bytes[start] == 0x00 && bytes[start + 1] & 0x80 == 0)
            || (bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0);
        if !redundant {
            break;
        }
        start += 1;
    }
    body.extend_from_slice(&bytes[start..]);
    encode_tlv(tag::INTEGER, &body, out);
}

/// Decodes a signed integer body.
pub fn decode_integer(body: &[u8]) -> Result<i64> {
    if body.is_empty() || body.len() > 8 {
        return Err(BerError::Malformed("integer"));
    }
    // Sign-extend from the top bit of the first byte.
    let mut value: i64 = if body[0] & 0x80 != 0 { -1 } else { 0 };
    for b in body {
        value = (value << 8) | *b as i64;
    }
    Ok(value)
}

/// Encodes an object identifier.
pub fn encode_oid(arcs: &[u32], out: &mut Vec<u8>) -> Result<()> {
    if arcs.len() < 2 {
        return Err(BerError::Malformed("OID needs at least two arcs"));
    }
    let mut body = Vec::with_capacity(arcs.len() + 4);
    // The first two arcs are merged into a single subidentifier. That
    // subidentifier is itself a base-128 varint, not a byte: under the
    // joint-iso-itu-t root (arc 0 == 2) the second arc may exceed 39, so
    // 40 * 2 + 999 does not fit in eight bits.
    let merged = arcs[0]
        .checked_mul(40)
        .and_then(|v| v.checked_add(arcs[1]))
        .ok_or(BerError::Malformed("OID root arcs overflow"))?;
    encode_base128(merged, &mut body);
    for arc in &arcs[2..] {
        encode_base128(*arc, &mut body);
    }
    encode_tlv(tag::OID, &body, out);
    Ok(())
}

/// Writes an unsigned value as a base-128 varint, most significant group first.
fn encode_base128(mut value: u32, out: &mut Vec<u8>) {
    let mut group = [0u8; 5];
    let mut n = 0;
    loop {
        group[n] = (value & 0x7f) as u8;
        n += 1;
        value >>= 7;
        if value == 0 {
            break;
        }
    }
    // Emit most significant first, with the continuation bit on all but the last.
    for i in (0..n).rev() {
        let last = i == 0;
        out.push(if last { group[i] } else { group[i] | 0x80 });
    }
}

/// Decodes an object identifier body into its arcs.
pub fn decode_oid(body: &[u8]) -> Result<Vec<u32>> {
    if body.is_empty() {
        return Err(BerError::Malformed("empty OID"));
    }
    let mut arcs = Vec::with_capacity(body.len() + 1);

    // Read the merged first subidentifier as a varint, then split it. X.690
    // caps the first arc at 2, so values of 80 and above all belong to the
    // joint-iso-itu-t root with an arbitrarily large second arc — dividing by
    // 40 unconditionally would turn 2.999 into 24.39.
    let mut merged: u32 = 0;
    let mut consumed = 0usize;
    let mut complete = false;
    for b in body {
        merged = merged
            .checked_mul(128)
            .and_then(|v| v.checked_add((*b & 0x7f) as u32))
            .ok_or(BerError::Malformed("OID arc overflow"))?;
        consumed += 1;
        if b & 0x80 == 0 {
            complete = true;
            break;
        }
    }
    if !complete {
        return Err(BerError::Malformed("truncated OID arc"));
    }
    let first = if merged < 80 { merged / 40 } else { 2 };
    arcs.push(first);
    arcs.push(merged - first * 40);

    let mut value: u32 = 0;
    let mut in_progress = false;
    for b in &body[consumed..] {
        // Guard against an arc wider than 32 bits.
        value = value
            .checked_mul(128)
            .and_then(|v| v.checked_add((*b & 0x7f) as u32))
            .ok_or(BerError::Malformed("OID arc overflow"))?;
        if b & 0x80 == 0 {
            arcs.push(value);
            value = 0;
            in_progress = false;
        } else {
            in_progress = true;
        }
    }
    if in_progress {
        return Err(BerError::Malformed("truncated OID arc"));
    }
    Ok(arcs)
}

/// Formats arcs in dotted notation.
pub fn oid_to_string(arcs: &[u32]) -> String {
    arcs.iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// Parses dotted notation into arcs.
pub fn parse_oid(s: &str) -> Result<Vec<u32>> {
    let arcs: std::result::Result<Vec<u32>, _> = s
        .trim()
        .trim_start_matches('.')
        .split('.')
        .map(|p| p.parse::<u32>())
        .collect();
    let arcs = arcs.map_err(|_| BerError::Malformed("OID text"))?;
    if arcs.len() < 2 {
        return Err(BerError::Malformed("OID needs at least two arcs"));
    }
    Ok(arcs)
}

/// A tag, its body and where the next element starts.
pub struct Element<'a> {
    pub tag: u8,
    pub body: &'a [u8],
    pub next: usize,
}

/// Reads one tag-length-value element.
pub fn read_element(buf: &[u8], offset: usize) -> Result<Element<'_>> {
    let tag = *buf.get(offset).ok_or(BerError::Truncated(offset))?;
    let (len, body_start) = decode_length(buf, offset + 1)?;
    let body = buf
        .get(body_start..body_start + len)
        .ok_or(BerError::Truncated(body_start))?;
    Ok(Element {
        tag,
        body,
        next: body_start + len,
    })
}

/// Reads an element and checks its tag.
pub fn expect_element(buf: &[u8], offset: usize, expected: u8) -> Result<Element<'_>> {
    let e = read_element(buf, offset)?;
    if e.tag != expected {
        return Err(BerError::UnexpectedTag {
            expected,
            found: e.tag,
        });
    }
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- length ------------------------------------------------------------

    #[test]
    fn short_form_lengths_are_a_single_byte() {
        for len in [0usize, 1, 127] {
            let mut out = Vec::new();
            encode_length(len, &mut out);
            assert_eq!(out, vec![len as u8], "length {len}");
            assert_eq!(decode_length(&out, 0).unwrap(), (len, 1));
        }
    }

    #[test]
    fn long_form_kicks_in_at_128() {
        // The boundary a short-form-only codec gets wrong. Most devices return
        // a sysDescr longer than this.
        let mut out = Vec::new();
        encode_length(128, &mut out);
        assert_eq!(out, vec![0x81, 0x80]);
        assert_eq!(decode_length(&out, 0).unwrap(), (128, 2));

        let mut out = Vec::new();
        encode_length(300, &mut out);
        assert_eq!(out, vec![0x82, 0x01, 0x2c]);
        assert_eq!(decode_length(&out, 0).unwrap(), (300, 3));
    }

    #[test]
    fn lengths_round_trip_across_the_whole_useful_range() {
        for len in [0usize, 1, 126, 127, 128, 129, 255, 256, 65535, 65536, 1 << 20] {
            let mut out = Vec::new();
            encode_length(len, &mut out);
            assert_eq!(decode_length(&out, 0).unwrap().0, len, "length {len}");
        }
    }

    #[test]
    fn malformed_length_headers_are_rejected() {
        // Indefinite form is not permitted in SNMP.
        assert!(decode_length(&[0x80], 0).is_err());
        // More bytes than a usize can hold.
        assert!(decode_length(&[0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0).is_err());
        // Truncated.
        assert!(decode_length(&[0x82, 0x01], 0).is_err());
        assert!(decode_length(&[], 0).is_err());
    }

    // ---- integer -----------------------------------------------------------

    #[test]
    fn integers_encode_in_minimal_twos_complement_form() {
        let cases: &[(i64, &[u8])] = &[
            (0, &[0x02, 0x01, 0x00]),
            (1, &[0x02, 0x01, 0x01]),
            (127, &[0x02, 0x01, 0x7f]),
            // 128 needs a leading zero or it would read as -128.
            (128, &[0x02, 0x02, 0x00, 0x80]),
            (256, &[0x02, 0x02, 0x01, 0x00]),
            (-1, &[0x02, 0x01, 0xff]),
            (-128, &[0x02, 0x01, 0x80]),
            (-129, &[0x02, 0x02, 0xff, 0x7f]),
        ];
        for (value, expected) in cases {
            let mut out = Vec::new();
            encode_integer(*value, &mut out);
            assert_eq!(out, *expected, "encoding {value}");
        }
    }

    #[test]
    fn integers_round_trip_including_sign_boundaries() {
        for v in [
            0i64, 1, -1, 127, 128, -128, -129, 255, 256, 32767, 32768, -32768,
            65535, 1 << 30, -(1 << 30), i32::MAX as i64, i32::MIN as i64,
        ] {
            let mut out = Vec::new();
            encode_integer(v, &mut out);
            let e = read_element(&out, 0).unwrap();
            assert_eq!(decode_integer(e.body).unwrap(), v, "value {v}");
        }
    }

    #[test]
    fn malformed_integers_are_rejected() {
        assert!(decode_integer(&[]).is_err());
        assert!(decode_integer(&[0; 9]).is_err());
    }

    // ---- OID ---------------------------------------------------------------

    #[test]
    fn encodes_the_standard_sysdescr_oid() {
        // 1.3.6.1.2.1.1.1.0: the first two arcs pack into 0x2b (43 = 40*1+3).
        let mut out = Vec::new();
        encode_oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0], &mut out).unwrap();
        assert_eq!(
            out,
            vec![0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]
        );
    }

    #[test]
    fn arcs_above_127_use_base128_continuation() {
        // 1.3.6.1.4.1.9 has a small arc; 1.3.6.1.4.1.2011 needs two groups.
        let mut out = Vec::new();
        encode_oid(&[1, 3, 6, 1, 4, 1, 2011], &mut out).unwrap();
        let e = read_element(&out, 0).unwrap();
        // 2011 = 0x7db -> groups 0x0f, 0x5b with the continuation bit on the first.
        assert_eq!(&e.body[e.body.len() - 2..], &[0x8f, 0x5b]);
        assert_eq!(decode_oid(e.body).unwrap(), vec![1, 3, 6, 1, 4, 1, 2011]);
    }

    #[test]
    fn oids_round_trip_including_large_arcs() {
        let cases: &[&[u32]] = &[
            &[1, 3, 6, 1, 2, 1, 1, 5, 0],
            &[1, 3, 6, 1, 4, 1, 8072, 3, 2, 10],
            &[0, 0],
            &[2, 999, 1],
            &[1, 3, 6, 1, 4, 1, u32::MAX],
        ];
        for arcs in cases {
            let mut out = Vec::new();
            encode_oid(arcs, &mut out).unwrap();
            let e = read_element(&out, 0).unwrap();
            assert_eq!(decode_oid(e.body).unwrap(), arcs.to_vec(), "OID {arcs:?}");
        }
    }

    #[test]
    fn the_first_two_arcs_share_one_subidentifier() {
        let mut out = Vec::new();
        encode_oid(&[1, 3], &mut out).unwrap();
        let e = read_element(&out, 0).unwrap();
        assert_eq!(e.body, &[43]);
        assert_eq!(decode_oid(&[43]).unwrap(), vec![1, 3]);
    }

    #[test]
    fn a_second_arc_above_39_still_encodes_under_the_joint_root() {
        // X.690 caps the first arc at 2, and only there may the second arc
        // exceed 39. 40 * 2 + 999 = 1079 does not fit in a byte, so the merged
        // subidentifier has to be a varint like any other.
        let mut out = Vec::new();
        encode_oid(&[2, 999, 1], &mut out).unwrap();
        let e = read_element(&out, 0).unwrap();
        assert_eq!(decode_oid(e.body).unwrap(), vec![2, 999, 1]);

        // And the classic boundary values decode to the right split.
        for (merged, expected) in [
            (0u32, vec![0u32, 0]),
            (39, vec![0, 39]),
            (40, vec![1, 0]),
            (79, vec![1, 39]),
            (80, vec![2, 0]),
            (1079, vec![2, 999]),
        ] {
            let mut body = Vec::new();
            encode_base128(merged, &mut body);
            assert_eq!(decode_oid(&body).unwrap(), expected, "merged {merged}");
        }
    }

    #[test]
    fn malformed_oids_are_rejected() {
        assert!(encode_oid(&[1], &mut Vec::new()).is_err());
        assert!(decode_oid(&[]).is_err());
        // A trailing byte with the continuation bit set has no terminator.
        assert!(decode_oid(&[0x2b, 0x8f]).is_err());
        // An arc wider than 32 bits.
        assert!(decode_oid(&[0x2b, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]).is_err());
    }

    #[test]
    fn dotted_notation_round_trips() {
        let arcs = parse_oid("1.3.6.1.2.1.1.1.0").unwrap();
        assert_eq!(arcs, vec![1, 3, 6, 1, 2, 1, 1, 1, 0]);
        assert_eq!(oid_to_string(&arcs), "1.3.6.1.2.1.1.1.0");
        // A leading dot is accepted.
        assert_eq!(parse_oid(".1.3.6").unwrap(), vec![1, 3, 6]);
    }

    #[test]
    fn malformed_dotted_notation_is_rejected() {
        for bad in ["", "1", "1.a.3", "1.3.-1", "..", "1..3"] {
            assert!(parse_oid(bad).is_err(), "should reject {bad:?}");
        }
    }

    // ---- elements ----------------------------------------------------------

    #[test]
    fn reads_a_tlv_and_reports_the_next_offset() {
        let mut buf = Vec::new();
        encode_tlv(tag::OCTET_STRING, b"hello", &mut buf);
        encode_integer(42, &mut buf);

        let first = read_element(&buf, 0).unwrap();
        assert_eq!(first.tag, tag::OCTET_STRING);
        assert_eq!(first.body, b"hello");

        let second = read_element(&buf, first.next).unwrap();
        assert_eq!(second.tag, tag::INTEGER);
        assert_eq!(decode_integer(second.body).unwrap(), 42);
        assert_eq!(second.next, buf.len());
    }

    #[test]
    fn a_long_body_is_read_correctly() {
        // Crosses the short/long length boundary.
        let payload = vec![b'x'; 500];
        let mut buf = Vec::new();
        encode_tlv(tag::OCTET_STRING, &payload, &mut buf);
        let e = read_element(&buf, 0).unwrap();
        assert_eq!(e.body.len(), 500);
        assert_eq!(e.next, buf.len());
    }

    #[test]
    fn tag_mismatches_are_reported() {
        let mut buf = Vec::new();
        encode_integer(1, &mut buf);
        assert!(matches!(
            expect_element(&buf, 0, tag::OCTET_STRING),
            Err(BerError::UnexpectedTag { .. })
        ));
        assert!(expect_element(&buf, 0, tag::INTEGER).is_ok());
    }

    #[test]
    fn a_body_longer_than_the_buffer_is_rejected() {
        // Claims 200 bytes, supplies two.
        assert!(read_element(&[0x04, 0x81, 0xc8, 0x01, 0x02], 0).is_err());
        assert!(read_element(&[], 0).is_err());
    }

    #[test]
    fn arbitrary_byte_soup_never_panics() {
        let mut seed = 0xa5a5u32;
        for _ in 0..4000 {
            let len = (seed % 64) as usize;
            let buf: Vec<u8> = (0..len)
                .map(|i| {
                    seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                    (seed >> ((i % 4) * 8)) as u8
                })
                .collect();
            let _ = read_element(&buf, 0);
            let _ = decode_length(&buf, 0);
            let _ = decode_oid(&buf);
            let _ = decode_integer(&buf);
        }
    }
}
