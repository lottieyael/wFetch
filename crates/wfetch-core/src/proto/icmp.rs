//! ICMP and ICMPv6 echo.
//!
//! Packet construction and parsing are pure functions over byte slices; the
//! socket work lives in [`crate::probe`]. Keeping them apart means the wire
//! format — in particular the RFC 1071 checksum, which is the part that silently
//! makes every probe fail if it is wrong — is testable without `CAP_NET_RAW`.

use std::net::Ipv4Addr;

pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACHABLE: u8 = 3;
pub const ICMP_TIME_EXCEEDED: u8 = 11;

pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;

/// Minimum ICMP header size: type, code, checksum, identifier, sequence.
pub const ICMP_HEADER_LEN: usize = 8;

/// The RFC 1071 internet checksum.
///
/// Sixteen-bit one's-complement sum of the data, then complemented. Two details
/// matter and are both covered by tests: carries must be folded back in rather
/// than truncated, and an odd-length buffer pads with a trailing zero byte
/// without that zero becoming a high-order byte.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    let mut chunks = data.chunks_exact(2);
    for c in chunks.by_ref() {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    // A trailing odd byte is the high-order half of the final word.
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }

    // Fold carries until none remain. Two folds suffice for any input that
    // fits in a u32, but the loop makes that independent of input length.
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

/// Builds an ICMPv4 echo request with the checksum already filled in.
pub fn build_echo_request_v4(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(ICMP_HEADER_LEN + payload.len());
    pkt.push(ICMP_ECHO_REQUEST);
    pkt.push(0); // code
    pkt.extend_from_slice(&[0, 0]); // checksum placeholder
    pkt.extend_from_slice(&identifier.to_be_bytes());
    pkt.extend_from_slice(&sequence.to_be_bytes());
    pkt.extend_from_slice(payload);

    let sum = checksum(&pkt);
    pkt[2..4].copy_from_slice(&sum.to_be_bytes());
    pkt
}

/// Builds an ICMPv6 echo request.
///
/// The checksum is left zero: ICMPv6 checksums cover an IPv6 pseudo-header that
/// includes the source address, which the kernel selects. Linux, macOS and
/// Windows all compute it on the caller's behalf for `IPPROTO_ICMPV6` sockets.
pub fn build_echo_request_v6(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(ICMP_HEADER_LEN + payload.len());
    pkt.push(ICMPV6_ECHO_REQUEST);
    pkt.push(0);
    pkt.extend_from_slice(&[0, 0]);
    pkt.extend_from_slice(&identifier.to_be_bytes());
    pkt.extend_from_slice(&sequence.to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

/// A parsed ICMP echo reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoReply {
    pub identifier: u16,
    pub sequence: u16,
    pub payload: Vec<u8>,
}

/// What an ICMP message means for host liveness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IcmpMessage {
    /// The host answered: it exists.
    EchoReply(EchoReply),
    /// Something reported the destination unreachable. The host itself did not
    /// answer, and the reply usually comes from a router rather than the target.
    Unreachable { code: u8 },
    TimeExceeded,
    /// Anything else, including our own echoed request on a shared raw socket.
    Other { icmp_type: u8, code: u8 },
}

/// Parses an ICMPv4 message body, i.e. with the IP header already stripped.
pub fn parse_icmp_v4(data: &[u8]) -> Option<IcmpMessage> {
    parse_icmp(data, ICMP_ECHO_REPLY)
}

/// Parses an ICMPv6 message body.
pub fn parse_icmp_v6(data: &[u8]) -> Option<IcmpMessage> {
    parse_icmp(data, ICMPV6_ECHO_REPLY)
}

fn parse_icmp(data: &[u8], echo_reply_type: u8) -> Option<IcmpMessage> {
    if data.len() < ICMP_HEADER_LEN {
        return None;
    }
    let icmp_type = data[0];
    let code = data[1];

    if icmp_type == echo_reply_type {
        return Some(IcmpMessage::EchoReply(EchoReply {
            identifier: u16::from_be_bytes([data[4], data[5]]),
            sequence: u16::from_be_bytes([data[6], data[7]]),
            payload: data[ICMP_HEADER_LEN..].to_vec(),
        }));
    }

    // Only the v4 numbering is checked here; v6 uses different values and its
    // unreachable messages are not currently acted on.
    if echo_reply_type == ICMP_ECHO_REPLY {
        match icmp_type {
            ICMP_DEST_UNREACHABLE => return Some(IcmpMessage::Unreachable { code }),
            ICMP_TIME_EXCEEDED => return Some(IcmpMessage::TimeExceeded),
            _ => {}
        }
    }

    Some(IcmpMessage::Other { icmp_type, code })
}

/// A minimally parsed IPv4 header, enough to find the ICMP payload and read TTL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub ttl: u8,
    pub protocol: u8,
    /// Offset at which the payload begins.
    pub header_len: usize,
}

/// Parses an IPv4 header.
///
/// Raw `SOCK_RAW` reads on IPv4 include the IP header, and its length is
/// variable (the IHL field counts 32-bit words), so the ICMP body cannot be
/// assumed to start at a fixed offset. Getting this wrong is the classic way a
/// hand-rolled pinger silently fails against hosts that emit IP options.
pub fn parse_ipv4_header(data: &[u8]) -> Option<Ipv4Header> {
    if data.len() < 20 {
        return None;
    }
    let version = data[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (data[0] & 0x0f) as usize * 4;
    // A header shorter than the minimum, or longer than the datagram, is invalid.
    if ihl < 20 || ihl > data.len() {
        return None;
    }
    Some(Ipv4Header {
        src: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
        dst: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        ttl: data[8],
        protocol: data[9],
        header_len: ihl,
    })
}

/// Infers an OS family from an observed IP TTL.
///
/// Stacks use characteristic initial TTLs, and each hop decrements by one. The
/// observed value is rounded up to the nearest common initial TTL, which stays
/// correct for a handful of hops. This is a weak signal on its own and is only
/// ever used as one input to [`crate::fingerprint`].
pub fn ttl_os_hint(ttl: u8) -> Option<TtlHint> {
    match ttl {
        // 64 is by far the most common: Linux, Android, macOS, iOS, most BSDs.
        33..=64 => Some(TtlHint::UnixLike),
        // Windows has used 128 since 2000.
        65..=128 => Some(TtlHint::Windows),
        // 255 is typical of routers, switches and other network equipment.
        129..=255 => Some(TtlHint::NetworkDevice),
        // Below 33 the hop count is too uncertain to guess from.
        _ => None,
    }
}

/// A coarse OS family inferred from TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TtlHint {
    UnixLike,
    Windows,
    NetworkDevice,
}

/// Estimated hops traversed, given an observed TTL.
pub fn ttl_hop_count(ttl: u8) -> Option<u8> {
    let initial: u8 = match ttl {
        33..=64 => 64,
        65..=128 => 128,
        129..=255 => 255,
        _ => return None,
    };
    Some(initial - ttl)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- checksum ----------------------------------------------------------

    #[test]
    fn checksum_of_the_rfc1071_worked_example() {
        // The example from RFC 1071 section 3: the sum of these octets is
        // 0xddf2, so the checksum is its complement, 0x220d.
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&data), 0x220d);
    }

    #[test]
    fn checksum_folds_carries_rather_than_truncating() {
        // Two words that sum past 0xffff: 0xffff + 0xffff = 0x1fffe, which folds
        // to 0xffff, complementing to 0. Truncating instead would give 0x0001.
        assert_eq!(checksum(&[0xff, 0xff, 0xff, 0xff]), 0x0000);
    }

    #[test]
    fn checksum_pads_an_odd_trailing_byte_into_the_high_half() {
        // The lone 0xff is the high-order byte of the last word, so the sum is
        // 0xff00, not 0x00ff.
        assert_eq!(checksum(&[0xff]), !0xff00u16);
        assert_ne!(checksum(&[0xff]), !0x00ffu16);
    }

    #[test]
    fn checksum_of_empty_data_is_all_ones() {
        assert_eq!(checksum(&[]), 0xffff);
    }

    #[test]
    fn checksum_verifies_to_zero_over_the_whole_packet() {
        // The defining property: summing a packet that already carries its own
        // checksum yields zero. This is exactly what a receiver checks.
        for payload_len in [0usize, 1, 7, 8, 32, 56, 1000] {
            let payload: Vec<u8> = (0..payload_len).map(|i| (i * 7 + 3) as u8).collect();
            let pkt = build_echo_request_v4(0x1234, 1, &payload);
            assert_eq!(
                checksum(&pkt),
                0,
                "packet with {payload_len}-byte payload fails verification"
            );
        }
    }

    #[test]
    fn checksum_is_endianness_stable_for_byte_swapped_input() {
        // Swapping every 16-bit word's bytes swaps the checksum's bytes too;
        // this catches a native-endian read slipping in.
        let data = [0x12u8, 0x34, 0x56, 0x78];
        let swapped = [0x34u8, 0x12, 0x78, 0x56];
        assert_eq!(checksum(&data).swap_bytes(), checksum(&swapped));
    }

    // ---- echo request construction ----------------------------------------

    #[test]
    fn echo_request_has_the_documented_layout() {
        let pkt = build_echo_request_v4(0xabcd, 7, b"wfetch");
        assert_eq!(pkt[0], ICMP_ECHO_REQUEST);
        assert_eq!(pkt[1], 0, "code must be zero");
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 0xabcd);
        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]), 7);
        assert_eq!(&pkt[8..], b"wfetch");
        assert_eq!(pkt.len(), ICMP_HEADER_LEN + 6);
    }

    #[test]
    fn identifier_and_sequence_are_big_endian_on_the_wire() {
        // A native-endian write would put 0xcd first on x86 and break matching
        // of replies against outstanding probes.
        let pkt = build_echo_request_v4(0xabcd, 0x0102, &[]);
        assert_eq!(&pkt[4..6], &[0xab, 0xcd]);
        assert_eq!(&pkt[6..8], &[0x01, 0x02]);
    }

    #[test]
    fn v6_echo_request_leaves_the_checksum_to_the_kernel() {
        // ICMPv6 checksums cover a pseudo-header containing the source address,
        // which we do not choose; the kernel fills it in.
        let pkt = build_echo_request_v6(1, 1, b"x");
        assert_eq!(pkt[0], ICMPV6_ECHO_REQUEST);
        assert_eq!(&pkt[2..4], &[0, 0]);
    }

    // ---- reply parsing -----------------------------------------------------

    #[test]
    fn an_echo_reply_round_trips_through_build_and_parse() {
        let mut pkt = build_echo_request_v4(0x4321, 9, b"payload");
        pkt[0] = ICMP_ECHO_REPLY; // as the target would send it back
        match parse_icmp_v4(&pkt).unwrap() {
            IcmpMessage::EchoReply(r) => {
                assert_eq!(r.identifier, 0x4321);
                assert_eq!(r.sequence, 9);
                assert_eq!(r.payload, b"payload");
            }
            other => panic!("expected EchoReply, got {other:?}"),
        }
    }

    #[test]
    fn unreachable_and_time_exceeded_are_distinguished_from_replies() {
        // These come from a router, not the target, and must not count as a
        // live host.
        let mut m = vec![0u8; ICMP_HEADER_LEN];
        m[0] = ICMP_DEST_UNREACHABLE;
        m[1] = 1; // host unreachable
        assert_eq!(
            parse_icmp_v4(&m).unwrap(),
            IcmpMessage::Unreachable { code: 1 }
        );

        m[0] = ICMP_TIME_EXCEEDED;
        m[1] = 0;
        assert_eq!(parse_icmp_v4(&m).unwrap(), IcmpMessage::TimeExceeded);
    }

    #[test]
    fn our_own_echo_request_is_not_mistaken_for_a_reply() {
        // A shared raw socket sees outgoing requests too.
        let pkt = build_echo_request_v4(1, 1, &[]);
        assert!(matches!(
            parse_icmp_v4(&pkt).unwrap(),
            IcmpMessage::Other {
                icmp_type: ICMP_ECHO_REQUEST,
                ..
            }
        ));
    }

    #[test]
    fn truncated_messages_are_rejected() {
        for len in 0..ICMP_HEADER_LEN {
            assert!(parse_icmp_v4(&vec![0u8; len]).is_none(), "len {len}");
        }
        assert!(parse_icmp_v4(&vec![0u8; ICMP_HEADER_LEN]).is_some());
    }

    #[test]
    fn v6_echo_reply_uses_the_v6_type_number() {
        let mut pkt = build_echo_request_v6(5, 6, b"z");
        pkt[0] = ICMPV6_ECHO_REPLY;
        match parse_icmp_v6(&pkt).unwrap() {
            IcmpMessage::EchoReply(r) => {
                assert_eq!(r.identifier, 5);
                assert_eq!(r.sequence, 6);
            }
            other => panic!("expected EchoReply, got {other:?}"),
        }
        // The v4 parser must not accept a v6 reply type as an echo reply.
        assert!(matches!(
            parse_icmp_v4(&pkt).unwrap(),
            IcmpMessage::Other { .. }
        ));
    }

    // ---- IPv4 header -------------------------------------------------------

    fn ipv4_header(ihl_words: u8, ttl: u8) -> Vec<u8> {
        let mut h = vec![0u8; ihl_words as usize * 4];
        h[0] = 0x40 | ihl_words; // version 4
        h[8] = ttl;
        h[9] = 1; // ICMP
        h[12..16].copy_from_slice(&[10, 0, 0, 1]);
        h[16..20].copy_from_slice(&[10, 0, 0, 2]);
        h
    }

    #[test]
    fn parses_a_minimal_ipv4_header() {
        let h = parse_ipv4_header(&ipv4_header(5, 64)).unwrap();
        assert_eq!(h.header_len, 20);
        assert_eq!(h.ttl, 64);
        assert_eq!(h.protocol, 1);
        assert_eq!(h.src, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(h.dst, Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn header_length_follows_the_ihl_field_not_a_fixed_offset() {
        // With IP options the header is longer than 20 bytes; assuming 20 would
        // read option bytes as the ICMP type and drop every such reply.
        for words in 5..=15u8 {
            let h = parse_ipv4_header(&ipv4_header(words, 64)).unwrap();
            assert_eq!(h.header_len, words as usize * 4, "ihl={words}");
        }
    }

    #[test]
    fn rejects_wrong_version_short_and_inconsistent_headers() {
        let mut h = ipv4_header(5, 64);
        h[0] = 0x60 | 5; // version 6
        assert!(parse_ipv4_header(&h).is_none());

        // IHL below the 5-word minimum.
        let mut h = ipv4_header(5, 64);
        h[0] = 0x40 | 4;
        assert!(parse_ipv4_header(&h).is_none());

        // IHL claiming more bytes than the datagram holds.
        let mut h = ipv4_header(5, 64);
        h[0] = 0x40 | 15;
        assert!(parse_ipv4_header(&h).is_none());

        assert!(parse_ipv4_header(&[]).is_none());
        assert!(parse_ipv4_header(&[0u8; 19]).is_none());
    }

    // ---- TTL inference -----------------------------------------------------

    #[test]
    fn ttl_maps_to_the_expected_os_families() {
        // Directly observed initial values.
        assert_eq!(ttl_os_hint(64), Some(TtlHint::UnixLike));
        assert_eq!(ttl_os_hint(128), Some(TtlHint::Windows));
        assert_eq!(ttl_os_hint(255), Some(TtlHint::NetworkDevice));
        // A few hops away.
        assert_eq!(ttl_os_hint(60), Some(TtlHint::UnixLike));
        assert_eq!(ttl_os_hint(120), Some(TtlHint::Windows));
        assert_eq!(ttl_os_hint(250), Some(TtlHint::NetworkDevice));
        // Too far to attribute.
        assert_eq!(ttl_os_hint(20), None);
        assert_eq!(ttl_os_hint(0), None);
    }

    #[test]
    fn ttl_boundaries_do_not_overlap() {
        // Each observed TTL yields at most one family, with no gaps in 33..=255.
        for ttl in 33..=255u8 {
            assert!(ttl_os_hint(ttl).is_some(), "ttl {ttl} unclassified");
        }
        assert_eq!(ttl_os_hint(65), Some(TtlHint::Windows));
        assert_eq!(ttl_os_hint(64), Some(TtlHint::UnixLike));
        assert_eq!(ttl_os_hint(129), Some(TtlHint::NetworkDevice));
        assert_eq!(ttl_os_hint(128), Some(TtlHint::Windows));
    }

    #[test]
    fn hop_count_is_the_distance_from_the_initial_ttl() {
        assert_eq!(ttl_hop_count(64), Some(0));
        assert_eq!(ttl_hop_count(63), Some(1));
        assert_eq!(ttl_hop_count(128), Some(0));
        assert_eq!(ttl_hop_count(125), Some(3));
        assert_eq!(ttl_hop_count(255), Some(0));
        assert_eq!(ttl_hop_count(10), None);
    }
}
