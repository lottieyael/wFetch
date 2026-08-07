//! Linux backend.
//!
//! The neighbour table is read over netlink (`RTM_GETNEIGH`), which is the same
//! interface `ip neigh` uses. Netlink is preferred over `/proc/net/arp` because
//! `/proc` covers IPv4 only, omits the NUD state in a usable form, and is
//! truncated on hosts with large tables. `/proc/net/arp` is kept as a fallback
//! for kernels and sandboxes where netlink sockets are unavailable.
//!
//! Message parsing is a pure function over a byte slice ([`netlink::parse_neigh_dump`])
//! so the wire format can be tested against handcrafted buffers, including the
//! malformed ones a fuzzer or a hostile kernel module could produce.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{
    unix_common, Capabilities, HostPlatform, Interface, NeighborEntry, NeighborState,
    PlatformError, Result,
};

pub struct LinuxPlatform;

impl LinuxPlatform {
    pub fn new() -> Self {
        LinuxPlatform
    }
}

impl Default for LinuxPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl HostPlatform for LinuxPlatform {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn interfaces(&self) -> Result<Vec<Interface>> {
        unix_common::interfaces()
    }

    fn neighbors(&self) -> Result<Vec<NeighborEntry>> {
        let mut entries = match netlink::dump_neighbors() {
            Ok(e) => e,
            // Netlink can be blocked by seccomp in containers; /proc still works.
            Err(netlink_err) => match proc_net_arp::read() {
                Ok(e) => e,
                Err(_) => return Err(netlink_err),
            },
        };

        // Attach interface names so output is readable without a second lookup.
        if let Ok(ifaces) = self.interfaces() {
            for e in entries.iter_mut() {
                e.if_name = ifaces
                    .iter()
                    .find(|i| i.index == e.if_index)
                    .map(|i| i.name.clone());
            }
        }
        Ok(entries)
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            neighbor_table: netlink::probe_available() || proc_net_arp::available(),
            raw_sockets: can_open_raw_socket(),
            icmp_echo: can_open_raw_socket() || can_open_icmp_dgram_socket(),
            multicast: true,
            broadcast: true,
        }
    }
}

/// Whether `SOCK_RAW` can be opened, i.e. we hold `CAP_NET_RAW`.
fn can_open_raw_socket() -> bool {
    // SAFETY: socket(2) with constant arguments; the fd is closed immediately.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP);
        if fd < 0 {
            return false;
        }
        libc::close(fd);
        true
    }
}

/// Whether unprivileged ICMP datagram sockets are permitted.
///
/// Linux allows these when the caller's GID is inside `net.ipv4.ping_group_range`,
/// which is how an unprivileged `ping` works on modern distributions. It gives
/// us echo without `CAP_NET_RAW`.
fn can_open_icmp_dgram_socket() -> bool {
    // SAFETY: socket(2) with constant arguments; the fd is closed immediately.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP);
        if fd < 0 {
            return false;
        }
        libc::close(fd);
        true
    }
}

/// Netlink route socket access to the kernel neighbour table.
pub(crate) mod netlink {
    use super::*;

    // Message types and flags from <linux/netlink.h> and <linux/rtnetlink.h>.
    const NETLINK_ROUTE: i32 = 0;
    const NLM_F_REQUEST: u16 = 0x001;
    const NLM_F_ROOT: u16 = 0x100;
    const NLM_F_MATCH: u16 = 0x200;
    const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
    const NLMSG_ERROR: u16 = 2;
    const NLMSG_DONE: u16 = 3;
    const RTM_NEWNEIGH: u16 = 28;
    const RTM_GETNEIGH: u16 = 30;

    const NDA_DST: u16 = 1;
    const NDA_LLADDR: u16 = 2;

    const NLMSG_HDR_LEN: usize = 16;
    const NDMSG_LEN: usize = 12;
    const RTA_HDR_LEN: usize = 4;

    // NUD_* states from <linux/neighbour.h>.
    const NUD_INCOMPLETE: u16 = 0x01;
    const NUD_REACHABLE: u16 = 0x02;
    const NUD_STALE: u16 = 0x04;
    const NUD_DELAY: u16 = 0x08;
    const NUD_PROBE: u16 = 0x10;
    const NUD_FAILED: u16 = 0x20;
    const NUD_NOARP: u16 = 0x40;
    const NUD_PERMANENT: u16 = 0x80;

    /// Netlink rounds every length up to a 4-byte boundary.
    const fn align4(len: usize) -> usize {
        (len + 3) & !3
    }

    fn state_from_nud(nud: u16) -> NeighborState {
        // Checked most-specific first: a kernel entry can carry several bits.
        if nud & NUD_PERMANENT != 0 {
            NeighborState::Permanent
        } else if nud & NUD_REACHABLE != 0 {
            NeighborState::Reachable
        } else if nud & NUD_STALE != 0 {
            NeighborState::Stale
        } else if nud & NUD_DELAY != 0 {
            NeighborState::Delay
        } else if nud & NUD_PROBE != 0 {
            NeighborState::Probe
        } else if nud & NUD_FAILED != 0 {
            NeighborState::Failed
        } else if nud & NUD_INCOMPLETE != 0 {
            NeighborState::Incomplete
        } else if nud & NUD_NOARP != 0 {
            NeighborState::NoArp
        } else {
            NeighborState::Unknown
        }
    }

    fn u16_at(b: &[u8], off: usize) -> Option<u16> {
        b.get(off..off + 2)
            .map(|s| u16::from_ne_bytes([s[0], s[1]]))
    }

    fn u32_at(b: &[u8], off: usize) -> Option<u32> {
        b.get(off..off + 4)
            .map(|s| u32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// Parses a complete `RTM_GETNEIGH` dump response.
    ///
    /// Pure over the byte buffer, so the wire format is testable without a
    /// socket. Malformed or truncated messages terminate parsing rather than
    /// panicking: every length is validated against the remaining buffer.
    pub fn parse_neigh_dump(buf: &[u8]) -> Result<Vec<NeighborEntry>> {
        let mut out = Vec::new();
        let mut off = 0usize;

        while off + NLMSG_HDR_LEN <= buf.len() {
            let len = u32_at(buf, off).unwrap_or(0) as usize;
            let msg_type = u16_at(buf, off + 4).unwrap_or(0);

            // A header shorter than the header itself, or longer than what is
            // left, means the stream is corrupt; stop rather than loop forever.
            if len < NLMSG_HDR_LEN || off + len > buf.len() {
                break;
            }

            match msg_type {
                NLMSG_DONE => break,
                NLMSG_ERROR => {
                    // Payload starts with a negative errno as i32.
                    let code = u32_at(buf, off + NLMSG_HDR_LEN).unwrap_or(0) as i32;
                    if code != 0 {
                        return Err(PlatformError::syscall(
                            "netlink RTM_GETNEIGH",
                            std::io::Error::from_raw_os_error(-code),
                        ));
                    }
                    break;
                }
                RTM_NEWNEIGH => {
                    let payload = &buf[off + NLMSG_HDR_LEN..off + len];
                    if let Some(e) = parse_neigh_message(payload) {
                        out.push(e);
                    }
                }
                // Ignore anything else the kernel multiplexes onto the socket.
                _ => {}
            }

            off += align4(len);
        }

        Ok(out)
    }

    /// Parses one `ndmsg` payload plus its attributes.
    fn parse_neigh_message(payload: &[u8]) -> Option<NeighborEntry> {
        if payload.len() < NDMSG_LEN {
            return None;
        }
        let family = payload[0] as i32;
        let if_index = u32_at(payload, 4)?;
        let state = state_from_nud(u16_at(payload, 8)?);

        let mut ip: Option<IpAddr> = None;
        let mut mac = None;

        let mut off = NDMSG_LEN;
        while off + RTA_HDR_LEN <= payload.len() {
            let rta_len = u16_at(payload, off)? as usize;
            let rta_type = u16_at(payload, off + 2)?;
            if rta_len < RTA_HDR_LEN || off + rta_len > payload.len() {
                break;
            }
            let data = &payload[off + RTA_HDR_LEN..off + rta_len];

            match rta_type {
                NDA_DST => {
                    ip = match (family, data.len()) {
                        (libc::AF_INET, 4) => {
                            Some(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])))
                        }
                        (libc::AF_INET6, 16) => {
                            let mut o = [0u8; 16];
                            o.copy_from_slice(data);
                            Some(IpAddr::V6(Ipv6Addr::from(o)))
                        }
                        // Length not matching the family means a malformed or
                        // unsupported entry; drop it rather than guess.
                        _ => None,
                    };
                }
                NDA_LLADDR => {
                    // Only EUI-48. Loopback (0) and Infiniband (20) are skipped.
                    if data.len() == 6 {
                        let mut m = [0u8; 6];
                        m.copy_from_slice(data);
                        let m = crate::mac::MacAddr::new(m);
                        // An all-zero MAC is a placeholder, not an address.
                        if !m.is_zero() {
                            mac = Some(m);
                        }
                    }
                }
                _ => {}
            }

            off += align4(rta_len);
        }

        // The kernel reports synthetic NOARP entries for loopback and some
        // tunnels with an unspecified destination. They describe no host, and
        // `ip neigh` hides them; drop them rather than report 0.0.0.0 as alive.
        let ip = ip?;
        if ip.is_unspecified() {
            return None;
        }

        Some(NeighborEntry {
            ip,
            mac,
            state,
            if_index,
            if_name: None,
        })
    }

    /// Whether a netlink route socket can be opened at all.
    pub fn probe_available() -> bool {
        // SAFETY: socket(2) with constant arguments; the fd is closed immediately.
        unsafe {
            let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE);
            if fd < 0 {
                return false;
            }
            libc::close(fd);
            true
        }
    }

    /// Builds the `RTM_GETNEIGH` dump request for an address family.
    fn build_request(family: u8, seq: u32) -> Vec<u8> {
        let total = NLMSG_HDR_LEN + NDMSG_LEN;
        let mut req = vec![0u8; total];
        req[0..4].copy_from_slice(&(total as u32).to_ne_bytes());
        req[4..6].copy_from_slice(&RTM_GETNEIGH.to_ne_bytes());
        req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        req[8..12].copy_from_slice(&seq.to_ne_bytes());
        // pid 0: let the kernel address replies to us.
        req[NLMSG_HDR_LEN] = family;
        req
    }

    /// Dumps IPv4 and IPv6 neighbours from the kernel.
    pub fn dump_neighbors() -> Result<Vec<NeighborEntry>> {
        let mut all = Vec::new();
        // AF_UNSPEC would dump both families in one go on modern kernels, but
        // asking per-family is portable back to older ones.
        for (i, family) in [libc::AF_INET as u8, libc::AF_INET6 as u8]
            .into_iter()
            .enumerate()
        {
            match dump_family(family, i as u32 + 1) {
                Ok(mut e) => all.append(&mut e),
                // A missing IPv6 stack must not fail the whole dump.
                Err(e) if family == libc::AF_INET6 as u8 => {
                    let _ = e;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(all)
    }

    fn dump_family(family: u8, seq: u32) -> Result<Vec<NeighborEntry>> {
        // SAFETY: the socket fd is owned for the duration and closed on every
        // path; all buffers passed to the kernel are sized by `len`.
        unsafe {
            let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE);
            if fd < 0 {
                return Err(PlatformError::syscall(
                    "socket(AF_NETLINK)",
                    std::io::Error::last_os_error(),
                ));
            }
            let guard = FdGuard(fd);

            // Without a receive timeout a lost dump would hang the scan forever.
            let tv = libc::timeval {
                tv_sec: 3,
                tv_usec: 0,
            };
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );

            let req = build_request(family, seq);
            let sent = libc::send(fd, req.as_ptr() as *const libc::c_void, req.len(), 0);
            if sent < 0 {
                return Err(PlatformError::syscall(
                    "send(netlink)",
                    std::io::Error::last_os_error(),
                ));
            }

            // A dump arrives as several datagrams; concatenate until NLMSG_DONE.
            let mut acc: Vec<u8> = Vec::new();
            let mut chunk = vec![0u8; 32 * 1024];
            loop {
                let n = libc::recv(fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len(), 0);
                if n < 0 {
                    return Err(PlatformError::syscall(
                        "recv(netlink)",
                        std::io::Error::last_os_error(),
                    ));
                }
                if n == 0 {
                    break;
                }
                let n = n as usize;
                acc.extend_from_slice(&chunk[..n]);
                if contains_done(&chunk[..n]) {
                    break;
                }
            }

            drop(guard);
            parse_neigh_dump(&acc)
        }
    }

    /// Whether a received datagram ends the dump.
    fn contains_done(buf: &[u8]) -> bool {
        let mut off = 0usize;
        while off + NLMSG_HDR_LEN <= buf.len() {
            let len = u32_at(buf, off).unwrap_or(0) as usize;
            let t = u16_at(buf, off + 4).unwrap_or(0);
            if len < NLMSG_HDR_LEN || off + len > buf.len() {
                return false;
            }
            if t == NLMSG_DONE || t == NLMSG_ERROR {
                return true;
            }
            off += align4(len);
        }
        false
    }

    /// Closes a file descriptor on scope exit, including on early return.
    struct FdGuard(libc::c_int);
    impl Drop for FdGuard {
        fn drop(&mut self) {
            // SAFETY: we own this fd and close it exactly once.
            unsafe {
                libc::close(self.0);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::mac::MacAddr;

        /// Builds a netlink message with the given type and payload.
        fn msg(msg_type: u16, payload: &[u8]) -> Vec<u8> {
            let len = NLMSG_HDR_LEN + payload.len();
            let mut m = vec![0u8; NLMSG_HDR_LEN];
            m[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
            m[4..6].copy_from_slice(&msg_type.to_ne_bytes());
            m.extend_from_slice(payload);
            // Pad to the netlink alignment boundary.
            m.resize(align4(len), 0);
            m
        }

        /// Builds an `ndmsg` payload with attributes.
        fn ndmsg(family: u8, if_index: u32, nud: u16, attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
            let mut p = vec![0u8; NDMSG_LEN];
            p[0] = family;
            p[4..8].copy_from_slice(&if_index.to_ne_bytes());
            p[8..10].copy_from_slice(&nud.to_ne_bytes());
            for (t, data) in attrs {
                let rta_len = RTA_HDR_LEN + data.len();
                let start = p.len();
                p.extend_from_slice(&(rta_len as u16).to_ne_bytes());
                p.extend_from_slice(&t.to_ne_bytes());
                p.extend_from_slice(data);
                p.resize(start + align4(rta_len), 0);
            }
            p
        }

        fn v4_entry(ip: [u8; 4], mac: [u8; 6], nud: u16, idx: u32) -> Vec<u8> {
            msg(
                RTM_NEWNEIGH,
                &ndmsg(
                    libc::AF_INET as u8,
                    idx,
                    nud,
                    &[(NDA_DST, ip.to_vec()), (NDA_LLADDR, mac.to_vec())],
                ),
            )
        }

        #[test]
        fn alignment_rounds_up_to_four_bytes() {
            assert_eq!(align4(0), 0);
            assert_eq!(align4(1), 4);
            assert_eq!(align4(4), 4);
            assert_eq!(align4(5), 8);
            assert_eq!(align4(16), 16);
            assert_eq!(align4(17), 20);
        }

        #[test]
        fn parses_a_single_ipv4_neighbour() {
            let buf = v4_entry([192, 168, 1, 5], [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                               NUD_REACHABLE, 2);
            let out = parse_neigh_dump(&buf).unwrap();
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].ip, "192.168.1.5".parse::<IpAddr>().unwrap());
            assert_eq!(
                out[0].mac,
                Some(MacAddr::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]))
            );
            assert_eq!(out[0].state, NeighborState::Reachable);
            assert_eq!(out[0].if_index, 2);
        }

        #[test]
        fn parses_a_multi_entry_dump_terminated_by_done() {
            let mut buf = Vec::new();
            buf.extend(v4_entry([10, 0, 0, 1], [1, 2, 3, 4, 5, 6], NUD_REACHABLE, 2));
            buf.extend(v4_entry([10, 0, 0, 2], [1, 2, 3, 4, 5, 7], NUD_STALE, 2));
            buf.extend(v4_entry([10, 0, 0, 3], [1, 2, 3, 4, 5, 8], NUD_PERMANENT, 3));
            buf.extend(msg(NLMSG_DONE, &[]));

            let out = parse_neigh_dump(&buf).unwrap();
            assert_eq!(out.len(), 3);
            assert_eq!(out[0].state, NeighborState::Reachable);
            assert_eq!(out[1].state, NeighborState::Stale);
            assert_eq!(out[2].state, NeighborState::Permanent);
            assert_eq!(out[2].if_index, 3);
        }

        #[test]
        fn stops_at_nlmsg_done_and_ignores_trailing_data() {
            let mut buf = Vec::new();
            buf.extend(v4_entry([10, 0, 0, 1], [1, 2, 3, 4, 5, 6], NUD_REACHABLE, 2));
            buf.extend(msg(NLMSG_DONE, &[]));
            buf.extend(v4_entry([10, 0, 0, 99], [9, 9, 9, 9, 9, 9], NUD_REACHABLE, 2));

            let out = parse_neigh_dump(&buf).unwrap();
            assert_eq!(out.len(), 1, "entries after NLMSG_DONE must be ignored");
        }

        #[test]
        fn parses_ipv6_neighbours() {
            let ip: Ipv6Addr = "fe80::1234".parse().unwrap();
            let buf = msg(
                RTM_NEWNEIGH,
                &ndmsg(
                    libc::AF_INET6 as u8,
                    2,
                    NUD_REACHABLE,
                    &[
                        (NDA_DST, ip.octets().to_vec()),
                        (NDA_LLADDR, vec![1, 2, 3, 4, 5, 6]),
                    ],
                ),
            );
            let out = parse_neigh_dump(&buf).unwrap();
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].ip, IpAddr::V6(ip));
        }

        #[test]
        fn maps_every_nud_state() {
            let cases = [
                (NUD_INCOMPLETE, NeighborState::Incomplete),
                (NUD_REACHABLE, NeighborState::Reachable),
                (NUD_STALE, NeighborState::Stale),
                (NUD_DELAY, NeighborState::Delay),
                (NUD_PROBE, NeighborState::Probe),
                (NUD_FAILED, NeighborState::Failed),
                (NUD_NOARP, NeighborState::NoArp),
                (NUD_PERMANENT, NeighborState::Permanent),
                (0, NeighborState::Unknown),
            ];
            for (nud, expected) in cases {
                assert_eq!(state_from_nud(nud), expected, "nud={nud:#x}");
            }
        }

        #[test]
        fn permanent_wins_when_several_state_bits_are_set() {
            // The kernel can report NUD_PERMANENT|NUD_REACHABLE together.
            assert_eq!(
                state_from_nud(NUD_PERMANENT | NUD_REACHABLE),
                NeighborState::Permanent
            );
        }

        #[test]
        fn incomplete_entries_parse_without_a_mac() {
            // An unresolved entry carries NDA_DST but no NDA_LLADDR.
            let buf = msg(
                RTM_NEWNEIGH,
                &ndmsg(
                    libc::AF_INET as u8,
                    2,
                    NUD_INCOMPLETE,
                    &[(NDA_DST, vec![10, 0, 0, 9])],
                ),
            );
            let out = parse_neigh_dump(&buf).unwrap();
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].mac, None);
            assert_eq!(out[0].state, NeighborState::Incomplete);
            // And it must not be treated as a live host.
            assert!(!out[0].state.implies_host_present());
        }

        #[test]
        fn entries_without_a_destination_are_dropped() {
            let buf = msg(
                RTM_NEWNEIGH,
                &ndmsg(libc::AF_INET as u8, 2, NUD_REACHABLE,
                       &[(NDA_LLADDR, vec![1, 2, 3, 4, 5, 6])]),
            );
            assert!(parse_neigh_dump(&buf).unwrap().is_empty());
        }

        #[test]
        fn address_length_must_match_the_family() {
            // A 16-byte address on an AF_INET entry is malformed.
            let buf = msg(
                RTM_NEWNEIGH,
                &ndmsg(libc::AF_INET as u8, 2, NUD_REACHABLE,
                       &[(NDA_DST, vec![0u8; 16])]),
            );
            assert!(parse_neigh_dump(&buf).unwrap().is_empty());
        }

        #[test]
        fn synthetic_loopback_placeholder_entries_are_dropped() {
            // Linux emits a NOARP entry on lo with an unspecified destination
            // and an all-zero MAC. It describes no host, and `ip neigh` hides
            // it; reporting it would put 0.0.0.0 in every scan result.
            let buf = msg(
                RTM_NEWNEIGH,
                &ndmsg(
                    libc::AF_INET as u8,
                    1,
                    NUD_NOARP,
                    &[(NDA_DST, vec![0, 0, 0, 0]), (NDA_LLADDR, vec![0u8; 6])],
                ),
            );
            assert!(parse_neigh_dump(&buf).unwrap().is_empty());
        }

        #[test]
        fn all_zero_link_addresses_are_reported_as_absent() {
            let buf = msg(
                RTM_NEWNEIGH,
                &ndmsg(
                    libc::AF_INET as u8,
                    2,
                    NUD_REACHABLE,
                    &[(NDA_DST, vec![10, 0, 0, 1]), (NDA_LLADDR, vec![0u8; 6])],
                ),
            );
            let out = parse_neigh_dump(&buf).unwrap();
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].mac, None);
        }

        #[test]
        fn unspecified_ipv6_destinations_are_dropped_too() {
            let buf = msg(
                RTM_NEWNEIGH,
                &ndmsg(libc::AF_INET6 as u8, 1, NUD_NOARP,
                       &[(NDA_DST, vec![0u8; 16])]),
            );
            assert!(parse_neigh_dump(&buf).unwrap().is_empty());
        }

        #[test]
        fn non_eui48_link_addresses_are_ignored() {
            // Infiniband link addresses are 20 bytes and must not be truncated
            // into a bogus MAC.
            let buf = msg(
                RTM_NEWNEIGH,
                &ndmsg(
                    libc::AF_INET as u8,
                    2,
                    NUD_REACHABLE,
                    &[(NDA_DST, vec![10, 0, 0, 1]), (NDA_LLADDR, vec![0xab; 20])],
                ),
            );
            let out = parse_neigh_dump(&buf).unwrap();
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].mac, None);
        }

        #[test]
        fn netlink_errors_are_surfaced() {
            // NLMSG_ERROR payload begins with a negative errno.
            let payload = (-(libc::EPERM as i32)).to_ne_bytes().to_vec();
            let buf = msg(NLMSG_ERROR, &payload);
            assert!(parse_neigh_dump(&buf).is_err());
        }

        #[test]
        fn a_zero_error_code_is_an_ack_not_a_failure() {
            let buf = msg(NLMSG_ERROR, &0i32.to_ne_bytes());
            assert!(parse_neigh_dump(&buf).unwrap().is_empty());
        }

        #[test]
        fn malformed_buffers_terminate_instead_of_looping_or_panicking() {
            // A zero length would advance the cursor by zero forever.
            let mut zero_len = vec![0u8; NLMSG_HDR_LEN];
            zero_len[4..6].copy_from_slice(&RTM_NEWNEIGH.to_ne_bytes());
            assert!(parse_neigh_dump(&zero_len).unwrap().is_empty());

            // A length longer than the buffer must not read out of bounds.
            let mut too_long = vec![0u8; NLMSG_HDR_LEN];
            too_long[0..4].copy_from_slice(&9999u32.to_ne_bytes());
            too_long[4..6].copy_from_slice(&RTM_NEWNEIGH.to_ne_bytes());
            assert!(parse_neigh_dump(&too_long).unwrap().is_empty());

            // Truncated and empty inputs.
            assert!(parse_neigh_dump(&[]).unwrap().is_empty());
            assert!(parse_neigh_dump(&[0u8; 3]).unwrap().is_empty());
            assert!(parse_neigh_dump(&[0xff; 8]).unwrap().is_empty());
        }

        #[test]
        fn truncated_attributes_do_not_panic() {
            // rta_len claims more bytes than the payload holds.
            let mut p = vec![0u8; NDMSG_LEN];
            p[0] = libc::AF_INET as u8;
            p[8..10].copy_from_slice(&NUD_REACHABLE.to_ne_bytes());
            p.extend_from_slice(&99u16.to_ne_bytes()); // rta_len = 99
            p.extend_from_slice(&NDA_DST.to_ne_bytes());
            p.extend_from_slice(&[10, 0]);
            let buf = msg(RTM_NEWNEIGH, &p);
            assert!(parse_neigh_dump(&buf).unwrap().is_empty());
        }

        #[test]
        fn arbitrary_byte_soup_never_panics() {
            // Cheap deterministic fuzz over the parser's length handling.
            let mut seed = 0x12345678u32;
            for _ in 0..2000 {
                let len = (seed % 128) as usize;
                let buf: Vec<u8> = (0..len)
                    .map(|i| {
                        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                        (seed >> ((i % 4) * 8)) as u8
                    })
                    .collect();
                let _ = parse_neigh_dump(&buf);
            }
        }

        #[test]
        fn request_is_well_formed() {
            let req = build_request(libc::AF_INET as u8, 1);
            assert_eq!(req.len(), NLMSG_HDR_LEN + NDMSG_LEN);
            assert_eq!(u32_at(&req, 0).unwrap() as usize, req.len());
            assert_eq!(u16_at(&req, 4).unwrap(), RTM_GETNEIGH);
            assert_eq!(u16_at(&req, 6).unwrap(), NLM_F_REQUEST | NLM_F_DUMP);
            assert_eq!(req[NLMSG_HDR_LEN], libc::AF_INET as u8);
        }

        #[test]
        fn done_detection_finds_the_terminator_after_data() {
            let mut buf = Vec::new();
            buf.extend(v4_entry([10, 0, 0, 1], [1, 2, 3, 4, 5, 6], NUD_REACHABLE, 2));
            assert!(!contains_done(&buf));
            buf.extend(msg(NLMSG_DONE, &[]));
            assert!(contains_done(&buf));
        }
    }
}

/// `/proc/net/arp` fallback for environments where netlink is blocked.
///
/// IPv4 only, and it reports no NUD state beyond a flags bitmask, so entries
/// are mapped conservatively.
pub(crate) mod proc_net_arp {
    use super::*;

    const PATH: &str = "/proc/net/arp";
    /// `ATF_COM`: the entry is complete, i.e. the MAC is valid.
    const ATF_COM: u32 = 0x02;
    /// `ATF_PERM`: statically configured.
    const ATF_PERM: u32 = 0x04;

    pub fn available() -> bool {
        std::path::Path::new(PATH).exists()
    }

    pub fn read() -> Result<Vec<NeighborEntry>> {
        let text = std::fs::read_to_string(PATH)
            .map_err(|e| PlatformError::syscall("read /proc/net/arp", e))?;
        Ok(parse(&text))
    }

    /// Parses the table. Pure over the text so it is testable without `/proc`.
    ///
    /// Columns: IP address, HW type, Flags, HW address, Mask, Device.
    pub fn parse(text: &str) -> Vec<NeighborEntry> {
        let mut out = Vec::new();
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 6 {
                continue;
            }
            let Ok(ip) = f[0].parse::<Ipv4Addr>() else {
                continue;
            };
            let flags = f[2]
                .strip_prefix("0x")
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .unwrap_or(0);
            let mac = f[3].parse::<crate::mac::MacAddr>().ok().filter(|m| !m.is_zero());

            let state = if flags & ATF_PERM != 0 {
                NeighborState::Permanent
            } else if flags & ATF_COM != 0 {
                NeighborState::Stale
            } else {
                // Incomplete entries are recorded with flags 0x0 and a zero MAC.
                NeighborState::Incomplete
            };

            out.push(NeighborEntry {
                ip: IpAddr::V4(ip),
                mac,
                state,
                // /proc gives a device name, not an index; resolve it lazily.
                if_index: unsafe {
                    std::ffi::CString::new(f[5])
                        .map(|c| libc::if_nametoindex(c.as_ptr()))
                        .unwrap_or(0)
                },
                if_name: Some(f[5].to_string()),
            });
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const SAMPLE: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.50     0x1         0x6         11:22:33:44:55:66     *        eth0
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0
";

        #[test]
        fn parses_the_documented_column_layout() {
            let e = parse(SAMPLE);
            assert_eq!(e.len(), 3);
            assert_eq!(e[0].ip, "192.168.1.1".parse::<IpAddr>().unwrap());
            assert_eq!(e[0].state, NeighborState::Stale);
            assert_eq!(e[0].if_name.as_deref(), Some("eth0"));
        }

        #[test]
        fn the_permanent_flag_is_honoured() {
            // 0x6 = ATF_COM | ATF_PERM.
            assert_eq!(parse(SAMPLE)[1].state, NeighborState::Permanent);
        }

        #[test]
        fn incomplete_entries_have_no_mac_and_imply_no_host() {
            let e = &parse(SAMPLE)[2];
            assert_eq!(e.mac, None, "all-zero MAC must not be reported");
            assert_eq!(e.state, NeighborState::Incomplete);
            assert!(!e.state.implies_host_present());
        }

        #[test]
        fn header_only_and_empty_tables_yield_nothing() {
            assert!(parse("IP address       HW type     Flags\n").is_empty());
            assert!(parse("").is_empty());
        }

        #[test]
        fn malformed_lines_are_skipped_not_fatal() {
            let text = "header\ngarbage\n1.2.3\nnot an ip 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n";
            assert!(parse(text).is_empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_a_neighbour_table_on_a_normal_linux_host() {
        let p = LinuxPlatform::new();
        assert!(
            p.capabilities().neighbor_table,
            "netlink or /proc/net/arp should be reachable"
        );
    }

    #[test]
    fn neighbour_dump_succeeds_and_is_internally_consistent() {
        let p = LinuxPlatform::new();
        let entries = p.neighbors().expect("neighbour dump should succeed");
        for e in &entries {
            // A resolved entry always carries a MAC; an unresolved one never does.
            if e.state == NeighborState::Incomplete || e.state == NeighborState::Failed {
                continue;
            }
            if let Some(m) = e.mac {
                assert!(!m.is_zero(), "{} has an all-zero MAC", e.ip);
            }
        }
    }

    #[test]
    fn interfaces_are_enumerable() {
        let p = LinuxPlatform::new();
        let ifaces = p.interfaces().unwrap();
        assert!(ifaces.iter().any(|i| i.is_loopback));
    }
}
