//! macOS backend.
//!
//! macOS has no netlink. The ARP table is retrieved with a `sysctl` over the
//! routing socket (`CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO`),
//! which is exactly what `arp -a` does. The result is a packed sequence of
//! variable-length records: an `rt_msghdr` followed by whichever `sockaddr`s
//! the `rtm_addrs` bitmask says are present, each padded to a 4-byte boundary.
//!
//! Struct layouts are declared as `#[repr(C)]` with the same field types as
//! `<net/route.h>` and `<net/if_dl.h>` rather than as hardcoded byte offsets,
//! so the compiler computes padding and the code stays correct on both x86_64
//! and arm64. Record walking is a pure function over a byte slice and is
//! covered by tests that build synthetic tables.

use std::net::{IpAddr, Ipv4Addr};

use super::{
    unix_common, Capabilities, HostPlatform, Interface, NeighborEntry, NeighborState,
    PlatformError, Result,
};
use crate::mac::MacAddr;

const CTL_NET: libc::c_int = 4;
const PF_ROUTE: libc::c_int = 17;
const NET_RT_FLAGS: libc::c_int = 2;
/// `RTF_LLINFO`: the route carries link-layer information, i.e. it is an ARP entry.
const RTF_LLINFO: libc::c_int = 0x400;
/// `RTF_STATIC`: manually configured, the macOS equivalent of a permanent entry.
const RTF_STATIC: i32 = 0x800;

const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;

/// `struct rt_metrics` from `<net/route.h>`.
#[repr(C)]
#[derive(Clone, Copy)]
struct RtMetrics {
    rmx_locks: u32,
    rmx_mtu: u32,
    rmx_hopcount: u32,
    rmx_expire: i32,
    rmx_recvpipe: u32,
    rmx_sendpipe: u32,
    rmx_ssthresh: u32,
    rmx_rtt: u32,
    rmx_rttvar: u32,
    rmx_pksent: u32,
    rmx_state: u32,
    rmx_filler: [u32; 3],
}

/// `struct rt_msghdr` from `<net/route.h>`.
#[repr(C)]
#[derive(Clone, Copy)]
struct RtMsghdr {
    rtm_msglen: u16,
    rtm_version: u8,
    rtm_type: u8,
    rtm_index: u16,
    rtm_flags: i32,
    rtm_addrs: i32,
    rtm_pid: i32,
    rtm_seq: i32,
    rtm_errno: i32,
    rtm_use: i32,
    rtm_inits: u32,
    rtm_rmx: RtMetrics,
}

const RT_MSGHDR_LEN: usize = std::mem::size_of::<RtMsghdr>();

/// BSD sockaddrs in routing messages are padded up to 4-byte boundaries, and a
/// zero-length sockaddr still occupies one slot.
const fn roundup(len: usize) -> usize {
    if len == 0 {
        4
    } else {
        (len + 3) & !3
    }
}

pub struct MacosPlatform;

impl MacosPlatform {
    pub fn new() -> Self {
        MacosPlatform
    }
}

impl Default for MacosPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl HostPlatform for MacosPlatform {
    fn name(&self) -> &'static str {
        "macos"
    }

    fn interfaces(&self) -> Result<Vec<Interface>> {
        unix_common::interfaces()
    }

    fn neighbors(&self) -> Result<Vec<NeighborEntry>> {
        let raw = sysctl_arp_table()?;
        let mut entries = parse_arp_table(&raw);
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
            neighbor_table: true,
            raw_sockets: can_open_raw_socket(),
            // macOS has no unprivileged ICMP datagram socket equivalent to the
            // Linux ping group range, so echo needs root.
            icmp_echo: can_open_raw_socket(),
            multicast: true,
            broadcast: true,
        }
    }
}

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

/// Retrieves the raw ARP table via the routing sysctl.
fn sysctl_arp_table() -> Result<Vec<u8>> {
    let mut mib: [libc::c_int; 6] = [
        CTL_NET,
        PF_ROUTE,
        0,
        libc::AF_INET,
        NET_RT_FLAGS,
        RTF_LLINFO,
    ];

    // SAFETY: sysctl is called first with a null buffer to size the result, then
    // with a buffer of exactly that size. `needed` bounds every later read.
    unsafe {
        let mut needed: libc::size_t = 0;
        if libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        ) < 0
        {
            return Err(PlatformError::syscall(
                "sysctl(NET_RT_FLAGS)",
                std::io::Error::last_os_error(),
            ));
        }
        if needed == 0 {
            return Ok(Vec::new());
        }

        // The table can grow between the sizing call and the fetch; ask for a
        // little slack so a concurrent ARP insert does not cause ENOMEM.
        let mut buf = vec![0u8; needed + 1024];
        let mut have: libc::size_t = buf.len();
        if libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut have,
            std::ptr::null_mut(),
            0,
        ) < 0
        {
            return Err(PlatformError::syscall(
                "sysctl(NET_RT_FLAGS)",
                std::io::Error::last_os_error(),
            ));
        }
        buf.truncate(have);
        Ok(buf)
    }
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_ne_bytes([s[0], s[1]]))
}

fn i32_at(b: &[u8], off: usize) -> Option<i32> {
    b.get(off..off + 4)
        .map(|s| i32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
}

/// Walks the packed routing-message table and extracts ARP entries.
///
/// Pure over the byte buffer so it can be tested without macOS. Truncated or
/// inconsistent records terminate the walk instead of panicking.
pub fn parse_arp_table(buf: &[u8]) -> Vec<NeighborEntry> {
    let mut out = Vec::new();
    let mut off = 0usize;

    while off + RT_MSGHDR_LEN <= buf.len() {
        let msglen = u16_at(buf, off).unwrap_or(0) as usize;
        // A record shorter than its own header, or overrunning the buffer,
        // means the table is corrupt; stop rather than loop on a zero length.
        if msglen < RT_MSGHDR_LEN || off + msglen > buf.len() {
            break;
        }

        let rtm_index = u16_at(buf, off + 4).unwrap_or(0) as u32;
        let rtm_flags = i32_at(buf, off + 8).unwrap_or(0);
        let rtm_addrs = i32_at(buf, off + 12).unwrap_or(0);

        let mut sa_off = off + RT_MSGHDR_LEN;
        let end = off + msglen;
        let mut ip: Option<IpAddr> = None;
        let mut mac: Option<MacAddr> = None;

        // Sockaddrs appear in ascending bit order; only the bits set in
        // rtm_addrs are present, so absent ones must not shift the others.
        for bit in [RTA_DST, RTA_GATEWAY] {
            if rtm_addrs & bit == 0 {
                continue;
            }
            if sa_off >= end {
                break;
            }
            // BSD sockaddrs carry their own length in the first byte.
            let sa_len = buf[sa_off] as usize;
            let slot = roundup(sa_len);
            if sa_off + slot > end {
                break;
            }
            let sa = &buf[sa_off..sa_off + slot.min(end - sa_off)];

            match bit {
                RTA_DST => ip = parse_sockaddr_in(sa),
                RTA_GATEWAY => mac = parse_sockaddr_dl(sa),
                _ => {}
            }
            sa_off += slot;
        }

        if let Some(ip) = ip {
            if !ip.is_unspecified() {
                out.push(NeighborEntry {
                    ip,
                    mac: mac.filter(|m| !m.is_zero()),
                    // macOS does not expose NUD states. A resolved entry is
                    // reported as Stale (present but unconfirmed), which is the
                    // honest mapping; only RTF_STATIC is definitively permanent.
                    state: if rtm_flags & RTF_STATIC != 0 {
                        NeighborState::Permanent
                    } else if mac.is_some() {
                        NeighborState::Stale
                    } else {
                        NeighborState::Incomplete
                    },
                    if_index: rtm_index,
                    if_name: None,
                });
            }
        }

        off += msglen;
    }

    out
}

/// Extracts the IPv4 address from a `sockaddr_in`/`sockaddr_inarp`.
fn parse_sockaddr_in(sa: &[u8]) -> Option<IpAddr> {
    // sa_len, sa_family, sin_port(2), sin_addr(4).
    if sa.len() < 8 || sa[1] as i32 != libc::AF_INET {
        return None;
    }
    Some(IpAddr::V4(Ipv4Addr::new(sa[4], sa[5], sa[6], sa[7])))
}

/// Extracts the hardware address from a `sockaddr_dl`.
fn parse_sockaddr_dl(sa: &[u8]) -> Option<MacAddr> {
    // sdl_len, sdl_family, sdl_index(2), sdl_type, sdl_nlen, sdl_alen, sdl_slen,
    // then sdl_data holding the name followed by the address.
    if sa.len() < 8 || sa[1] as i32 != libc::AF_LINK {
        return None;
    }
    let nlen = sa[5] as usize;
    let alen = sa[6] as usize;
    if alen != 6 {
        return None;
    }
    let start = 8 + nlen;
    let bytes = sa.get(start..start + 6)?;
    let mut m = [0u8; 6];
    m.copy_from_slice(bytes);
    Some(MacAddr::new(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a `sockaddr_in` slot.
    fn sockaddr_in(ip: [u8; 4]) -> Vec<u8> {
        let mut sa = vec![0u8; 16];
        sa[0] = 16; // sa_len
        sa[1] = libc::AF_INET as u8;
        sa[4..8].copy_from_slice(&ip);
        sa
    }

    /// Builds a `sockaddr_dl` slot carrying an interface name and a MAC.
    fn sockaddr_dl(name: &str, mac: [u8; 6]) -> Vec<u8> {
        let nlen = name.len();
        let total = 8 + nlen + 6;
        let mut sa = vec![0u8; total];
        sa[0] = total as u8; // sdl_len
        sa[1] = libc::AF_LINK as u8;
        sa[5] = nlen as u8; // sdl_nlen
        sa[6] = 6; // sdl_alen
        sa[8..8 + nlen].copy_from_slice(name.as_bytes());
        sa[8 + nlen..8 + nlen + 6].copy_from_slice(&mac);
        sa
    }

    /// Builds a complete routing record.
    fn record(index: u16, flags: i32, sockaddrs: &[Vec<u8>], addrs_mask: i32) -> Vec<u8> {
        let mut payload = Vec::new();
        for sa in sockaddrs {
            let start = payload.len();
            payload.extend_from_slice(sa);
            payload.resize(start + roundup(sa.len()), 0);
        }
        let msglen = RT_MSGHDR_LEN + payload.len();

        let mut rec = vec![0u8; RT_MSGHDR_LEN];
        rec[0..2].copy_from_slice(&(msglen as u16).to_ne_bytes());
        rec[2] = 5; // rtm_version
        rec[3] = 4; // rtm_type (RTM_GET)
        rec[4..6].copy_from_slice(&index.to_ne_bytes());
        rec[8..12].copy_from_slice(&flags.to_ne_bytes());
        rec[12..16].copy_from_slice(&addrs_mask.to_ne_bytes());
        rec.extend_from_slice(&payload);
        rec
    }

    fn arp_record(ip: [u8; 4], mac: [u8; 6], index: u16, flags: i32) -> Vec<u8> {
        record(
            index,
            flags | RTF_LLINFO,
            &[sockaddr_in(ip), sockaddr_dl("en0", mac)],
            RTA_DST | RTA_GATEWAY,
        )
    }

    #[test]
    fn header_layout_matches_the_documented_offsets() {
        // The parser reads rtm_index, rtm_flags and rtm_addrs by offset, so the
        // compiler-computed layout must agree with <net/route.h>.
        assert_eq!(std::mem::size_of::<RtMetrics>(), 56);
        assert_eq!(RT_MSGHDR_LEN, 92);
    }

    #[test]
    fn sockaddr_padding_rounds_up_to_four_with_a_minimum_slot() {
        assert_eq!(roundup(0), 4, "a zero-length sockaddr still takes a slot");
        assert_eq!(roundup(1), 4);
        assert_eq!(roundup(4), 4);
        assert_eq!(roundup(5), 8);
        assert_eq!(roundup(16), 16);
        assert_eq!(roundup(17), 20);
    }

    #[test]
    fn parses_a_single_arp_entry() {
        let buf = arp_record([192, 168, 1, 20], [0xa4, 0x83, 0xe7, 1, 2, 3], 4, 0);
        let out = parse_arp_table(&buf);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ip, "192.168.1.20".parse::<IpAddr>().unwrap());
        assert_eq!(out[0].mac, Some(MacAddr::new([0xa4, 0x83, 0xe7, 1, 2, 3])));
        assert_eq!(out[0].if_index, 4);
        assert_eq!(out[0].state, NeighborState::Stale);
    }

    #[test]
    fn parses_a_multi_entry_table() {
        let mut buf = Vec::new();
        buf.extend(arp_record([10, 0, 0, 1], [1, 2, 3, 4, 5, 6], 4, 0));
        buf.extend(arp_record([10, 0, 0, 2], [1, 2, 3, 4, 5, 7], 4, 0));
        buf.extend(arp_record([10, 0, 0, 3], [1, 2, 3, 4, 5, 8], 5, RTF_STATIC));
        let out = parse_arp_table(&buf);
        assert_eq!(out.len(), 3);
        assert_eq!(out[2].state, NeighborState::Permanent);
        assert_eq!(out[2].if_index, 5);
    }

    #[test]
    fn variable_length_interface_names_do_not_shift_the_mac() {
        // sdl_data holds the name before the address, so the MAC offset depends
        // on sdl_nlen. Getting this wrong yields a plausible but wrong MAC.
        for name in ["", "en0", "bridge100", "utun4"] {
            let sa = sockaddr_dl(name, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
            assert_eq!(
                parse_sockaddr_dl(&sa),
                Some(MacAddr::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])),
                "interface name {name:?}"
            );
        }
    }

    #[test]
    fn an_absent_gateway_does_not_shift_the_destination() {
        // Only RTA_DST is set; the parser must not read the next record's bytes
        // as a gateway sockaddr.
        let buf = record(4, RTF_LLINFO, &[sockaddr_in([10, 0, 0, 9])], RTA_DST);
        let out = parse_arp_table(&buf);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ip, "10.0.0.9".parse::<IpAddr>().unwrap());
        assert_eq!(out[0].mac, None);
        assert_eq!(out[0].state, NeighborState::Incomplete);
    }

    #[test]
    fn incomplete_entries_do_not_imply_a_host() {
        let buf = record(4, RTF_LLINFO, &[sockaddr_in([10, 0, 0, 9])], RTA_DST);
        assert!(!parse_arp_table(&buf)[0].state.implies_host_present());
    }

    #[test]
    fn non_eui48_link_addresses_are_ignored() {
        let mut sa = sockaddr_dl("en0", [0; 6]);
        sa[6] = 20; // sdl_alen for Infiniband
        assert_eq!(parse_sockaddr_dl(&sa), None);
    }

    #[test]
    fn all_zero_macs_are_reported_as_absent() {
        let buf = arp_record([10, 0, 0, 1], [0; 6], 4, 0);
        assert_eq!(parse_arp_table(&buf)[0].mac, None);
    }

    #[test]
    fn unspecified_destinations_are_dropped() {
        let buf = arp_record([0, 0, 0, 0], [1, 2, 3, 4, 5, 6], 4, 0);
        assert!(parse_arp_table(&buf).is_empty());
    }

    #[test]
    fn malformed_tables_terminate_instead_of_looping_or_panicking() {
        // Zero msglen would never advance the cursor.
        let zero = vec![0u8; RT_MSGHDR_LEN];
        assert!(parse_arp_table(&zero).is_empty());

        // msglen longer than the buffer must not read out of bounds.
        let mut too_long = vec![0u8; RT_MSGHDR_LEN];
        too_long[0..2].copy_from_slice(&9999u16.to_ne_bytes());
        assert!(parse_arp_table(&too_long).is_empty());

        assert!(parse_arp_table(&[]).is_empty());
        assert!(parse_arp_table(&[0u8; 10]).is_empty());
    }

    #[test]
    fn a_truncated_trailing_record_is_dropped_without_losing_earlier_ones() {
        let mut buf = arp_record([10, 0, 0, 1], [1, 2, 3, 4, 5, 6], 4, 0);
        buf.extend_from_slice(&[0xff; 20]); // partial record
        let out = parse_arp_table(&buf);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn arbitrary_byte_soup_never_panics() {
        let mut seed = 0xdeadbeefu32;
        for _ in 0..2000 {
            let len = (seed % 400) as usize;
            let buf: Vec<u8> = (0..len)
                .map(|i| {
                    seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                    (seed >> ((i % 4) * 8)) as u8
                })
                .collect();
            let _ = parse_arp_table(&buf);
        }
    }
}
