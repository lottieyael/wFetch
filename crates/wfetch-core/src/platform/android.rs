//! Android backend.
//!
//! Android is Linux, but the parts of Linux this scanner depends on are exactly
//! the parts Android removes from unprivileged processes. This backend reports
//! what is genuinely available rather than reusing the Linux one and returning
//! silently empty results.
//!
//! # What does not work, and why
//!
//! * **Neighbour table.** Since Android 10 (API 29), `/proc/net/arp` returns a
//!   header row and nothing else to unprivileged callers, and `RTM_GETNEIGH`
//!   netlink dumps are filtered by SELinux policy. This was deliberate: the ARP
//!   table let apps fingerprint the surrounding network and was used for
//!   cross-app device tracking. There is no permission that restores it.
//! * **Raw sockets.** `SOCK_RAW` needs `CAP_NET_RAW`, which no app process
//!   holds. That rules out ARP injection, TCP SYN scanning and classic ICMP.
//! * **ICMP echo.** Android does not open `net.ipv4.ping_group_range` to app
//!   GIDs, so the unprivileged ICMP datagram socket that works on desktop Linux
//!   is unavailable too.
//!
//! # What does work
//!
//! `getifaddrs(3)` is permitted, so the local interface list and its addresses
//! and prefix lengths are readable — enough to derive the local subnet and plan
//! a scan. On top of that, all unprivileged probes remain available: TCP
//! connect, UDP, mDNS/DNS-SD, SSDP and NetBIOS name queries. A scan from
//! Android finds fewer hosts than one from a desktop, and finds them by service
//! response rather than by link-layer presence.
//!
//! Rooted devices are not special-cased. If this backend is ever run with
//! `CAP_NET_RAW`, the capability probes below report it and the engine will use
//! the extra techniques, but nothing here assumes it.

use super::{
    unix_common, Capabilities, HostPlatform, Interface, NeighborEntry, PlatformError, Result,
};

pub struct AndroidPlatform;

impl AndroidPlatform {
    pub fn new() -> Self {
        AndroidPlatform
    }
}

impl Default for AndroidPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl HostPlatform for AndroidPlatform {
    fn name(&self) -> &'static str {
        "android"
    }

    fn interfaces(&self) -> Result<Vec<Interface>> {
        unix_common::interfaces()
    }

    fn neighbors(&self) -> Result<Vec<NeighborEntry>> {
        // Returning Err rather than Ok(vec![]) matters: an empty table is
        // indistinguishable from a quiet network, and the caller would report a
        // clean scan of a LAN it never actually inspected.
        Err(PlatformError::Unsupported(
            "neighbour table (restricted by Android since API 29)",
        ))
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            neighbor_table: false,
            // Probed rather than hardcoded so a rooted device is used properly.
            raw_sockets: can_open_raw_socket(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interfaces_are_still_enumerable() {
        let ifaces = AndroidPlatform::new()
            .interfaces()
            .expect("getifaddrs is permitted on Android");
        assert!(!ifaces.is_empty());
    }

    #[test]
    fn neighbour_table_reports_unsupported_rather_than_empty() {
        // An empty Ok would look like a scan of a network with no hosts.
        let err = AndroidPlatform::new().neighbors().unwrap_err();
        assert!(matches!(err, PlatformError::Unsupported(_)));
    }

    #[test]
    fn unprivileged_discovery_is_still_possible() {
        let c = AndroidPlatform::new().capabilities();
        assert!(!c.neighbor_table);
        assert!(
            c.can_probe_actively(),
            "multicast and broadcast probes remain available"
        );
    }
}
