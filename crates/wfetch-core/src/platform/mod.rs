//! The OS boundary.
//!
//! Everything that touches a platform network API lives under this module. The
//! rest of the crate talks to [`HostPlatform`], so the scan engine has no
//! `#[cfg]` in it and can be driven by a fake platform in tests.
//!
//! # Platform support
//!
//! | Platform | Interfaces        | Neighbour table                  | Raw sockets |
//! |----------|-------------------|----------------------------------|-------------|
//! | Linux    | `getifaddrs(3)`   | netlink `RTM_GETNEIGH`, `/proc`  | CAP_NET_RAW |
//! | macOS    | `getifaddrs(3)`   | `sysctl` `NET_RT_FLAGS`          | root        |
//! | Windows  | `GetAdaptersAddresses` | `GetIpNetTable2`            | admin       |
//! | Android  | `getifaddrs(3)`   | unavailable (see below)          | never       |
//!
//! Android deserves the footnote. Since Android 10 the neighbour table is not
//! readable by unprivileged apps: `/proc/net/arp` returns an empty table by
//! SELinux policy, and `RTM_GETNEIGH` dumps are filtered. Raw sockets require
//! `CAP_NET_RAW`, which is not available without root. So the Android backend
//! reports no neighbour table and no raw-socket capability, and the scan engine
//! degrades to unprivileged techniques rather than silently returning nothing.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::mac::MacAddr;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
mod unix_common;

pub mod fake;

/// Errors from platform network queries.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlatformError {
    #[error("{operation} failed: {source_msg}")]
    Syscall {
        operation: &'static str,
        source_msg: String,
    },
    #[error("{0} is not available on this platform")]
    Unsupported(&'static str),
    #[error("{operation} requires elevated privileges ({needed})")]
    PermissionDenied {
        operation: &'static str,
        needed: &'static str,
    },
    #[error("failed to parse {what}: {detail}")]
    Parse { what: &'static str, detail: String },
}

impl PlatformError {
    pub(crate) fn syscall(operation: &'static str, e: std::io::Error) -> Self {
        PlatformError::Syscall {
            operation,
            source_msg: e.to_string(),
        }
    }
}

pub type Result<T> = std::result::Result<T, PlatformError>;

/// An address assigned to a local interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceAddr {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

/// A local network interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    /// Kernel interface index, where the platform exposes one.
    pub index: u32,
    pub mac: Option<MacAddr>,
    pub addrs: Vec<InterfaceAddr>,
    pub is_up: bool,
    pub is_loopback: bool,
    /// Point-to-point links (VPN tunnels, PPP) have no broadcast domain, so
    /// ARP-based and broadcast-based discovery does not apply to them.
    pub is_point_to_point: bool,
    pub supports_multicast: bool,
}

impl Interface {
    /// Whether this interface is a sensible default for a LAN scan.
    pub fn is_scannable(&self) -> bool {
        self.is_up && !self.is_loopback && !self.addrs.is_empty()
    }

    /// IPv4 addresses assigned to this interface.
    pub fn ipv4_addrs(&self) -> impl Iterator<Item = &InterfaceAddr> {
        self.addrs.iter().filter(|a| a.addr.is_ipv4())
    }
}

/// Reachability state of a neighbour table entry.
///
/// These mirror the Linux NUD states, which macOS and Windows entries are
/// mapped onto so that callers see one vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NeighborState {
    /// Address resolution is in progress; no MAC yet.
    Incomplete,
    /// Confirmed reachable recently.
    Reachable,
    /// Was reachable; not confirmed recently.
    Stale,
    Delay,
    Probe,
    /// Resolution failed; the host did not answer ARP/NDP.
    Failed,
    /// Statically configured.
    Permanent,
    /// Interface does not use address resolution.
    NoArp,
    Unknown,
}

impl NeighborState {
    /// Whether the entry is evidence that a host actually exists.
    ///
    /// `Incomplete` and `Failed` are the important exclusions: they are records
    /// of a *failed* resolution, so treating them as hosts would report every
    /// address the local machine has ever tried to reach as alive.
    pub fn implies_host_present(&self) -> bool {
        matches!(
            self,
            NeighborState::Reachable
                | NeighborState::Stale
                | NeighborState::Delay
                | NeighborState::Probe
                | NeighborState::Permanent
        )
    }
}

/// An entry in the kernel's ARP (IPv4) or neighbour discovery (IPv6) cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborEntry {
    pub ip: IpAddr,
    pub mac: Option<MacAddr>,
    pub state: NeighborState,
    /// Interface index the entry was learned on.
    pub if_index: u32,
    pub if_name: Option<String>,
}

/// What a platform backend can actually do on this host, right now.
///
/// Capabilities are runtime facts, not compile-time ones: the same Linux binary
/// has `raw_sockets` when run as root and not when run as a normal user, and
/// the engine picks its probe mix accordingly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// The kernel neighbour/ARP cache can be read.
    pub neighbor_table: bool,
    /// `SOCK_RAW` is available (needed for TCP SYN scans and ARP injection).
    pub raw_sockets: bool,
    /// ICMP echo can be sent, whether by raw socket or unprivileged datagram.
    pub icmp_echo: bool,
    /// Multicast can be sent and received (mDNS, SSDP).
    pub multicast: bool,
    /// UDP broadcast can be sent (NetBIOS name service).
    pub broadcast: bool,
}

impl Capabilities {
    /// The capability set of a fully privileged host.
    pub const fn full() -> Self {
        Self {
            neighbor_table: true,
            raw_sockets: true,
            icmp_echo: true,
            multicast: true,
            broadcast: true,
        }
    }

    /// What an unprivileged process can rely on everywhere, including Android.
    pub const fn unprivileged() -> Self {
        Self {
            neighbor_table: false,
            raw_sockets: false,
            icmp_echo: false,
            multicast: true,
            broadcast: true,
        }
    }

    /// Whether any active discovery technique is available at all.
    pub fn can_probe_actively(&self) -> bool {
        self.icmp_echo || self.multicast || self.broadcast
    }
}

/// Read-only access to the host's network configuration.
pub trait HostPlatform: Send + Sync {
    /// A short identifier for the backend, e.g. `"linux"`.
    fn name(&self) -> &'static str;

    /// All local interfaces, including down and loopback ones.
    fn interfaces(&self) -> Result<Vec<Interface>>;

    /// The kernel neighbour cache.
    ///
    /// Returns [`PlatformError::Unsupported`] where no readable table exists.
    fn neighbors(&self) -> Result<Vec<NeighborEntry>>;

    /// What this backend can do on this host right now.
    fn capabilities(&self) -> Capabilities;

    /// Interfaces worth scanning by default: up, non-loopback, addressed.
    fn scannable_interfaces(&self) -> Result<Vec<Interface>> {
        Ok(self
            .interfaces()?
            .into_iter()
            .filter(Interface::is_scannable)
            .collect())
    }

    /// The interface that a LAN scan should default to.
    ///
    /// Prefers a non-point-to-point interface carrying a private IPv4 address,
    /// which is the ordinary "my LAN" case. A VPN tunnel is deliberately ranked
    /// below physical LAN interfaces so that `wfetch scan` on a laptop with a
    /// corporate VPN up still scans the local network by default.
    fn default_scan_interface(&self) -> Result<Option<Interface>> {
        let mut candidates = self.scannable_interfaces()?;
        candidates.sort_by_key(|i| {
            let has_private_v4 = i
                .ipv4_addrs()
                .any(|a| crate::addr::classify(a.addr) == crate::addr::AddrClass::Private);
            // Lower sorts first.
            (
                !has_private_v4,
                i.is_point_to_point,
                !i.supports_multicast,
                i.index,
            )
        });
        Ok(candidates.into_iter().next())
    }
}

/// Returns the platform backend for the host this binary is running on.
pub fn host_platform() -> Box<dyn HostPlatform> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxPlatform::new())
    }
    #[cfg(target_os = "android")]
    {
        Box::new(android::AndroidPlatform::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacosPlatform::new())
    }
    #[cfg(windows)]
    {
        Box::new(windows::WindowsPlatform::new())
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        windows
    )))]
    {
        Box::new(UnsupportedPlatform)
    }
}

/// Fallback backend for platforms with no dedicated implementation.
///
/// Reports no capabilities rather than pretending, so the engine reports an
/// honest "nothing available here" instead of an empty scan that looks clean.
#[allow(dead_code)]
pub struct UnsupportedPlatform;

impl HostPlatform for UnsupportedPlatform {
    fn name(&self) -> &'static str {
        "unsupported"
    }
    fn interfaces(&self) -> Result<Vec<Interface>> {
        Err(PlatformError::Unsupported("interface enumeration"))
    }
    fn neighbors(&self) -> Result<Vec<NeighborEntry>> {
        Err(PlatformError::Unsupported("neighbour table"))
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            neighbor_table: false,
            raw_sockets: false,
            icmp_echo: false,
            multicast: false,
            broadcast: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::fake::FakePlatform;

    fn iface(name: &str, index: u32, addr: &str, prefix: u8) -> Interface {
        Interface {
            name: name.to_string(),
            index,
            mac: Some(MacAddr::new([0, 1, 2, 3, 4, index as u8])),
            addrs: vec![InterfaceAddr {
                addr: addr.parse().unwrap(),
                prefix_len: prefix,
            }],
            is_up: true,
            is_loopback: false,
            is_point_to_point: false,
            supports_multicast: true,
        }
    }

    #[test]
    fn neighbor_states_that_imply_a_host_are_exactly_the_resolved_ones() {
        // Incomplete and Failed are records of failed resolution: counting them
        // as hosts would report every address we ever tried to reach as alive.
        for s in [
            NeighborState::Reachable,
            NeighborState::Stale,
            NeighborState::Delay,
            NeighborState::Probe,
            NeighborState::Permanent,
        ] {
            assert!(s.implies_host_present(), "{s:?} should imply a host");
        }
        for s in [
            NeighborState::Incomplete,
            NeighborState::Failed,
            NeighborState::NoArp,
            NeighborState::Unknown,
        ] {
            assert!(!s.implies_host_present(), "{s:?} must not imply a host");
        }
    }

    #[test]
    fn scannable_excludes_loopback_down_and_unaddressed_interfaces() {
        let mut lo = iface("lo", 1, "127.0.0.1", 8);
        lo.is_loopback = true;
        let mut down = iface("eth1", 3, "10.0.1.1", 24);
        down.is_up = false;
        let mut bare = iface("eth2", 4, "10.0.2.1", 24);
        bare.addrs.clear();
        let up = iface("eth0", 2, "10.0.0.1", 24);

        assert!(!lo.is_scannable());
        assert!(!down.is_scannable());
        assert!(!bare.is_scannable());
        assert!(up.is_scannable());

        let p = FakePlatform::new(vec![lo, up.clone(), down, bare], vec![]);
        let s = p.scannable_interfaces().unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].name, "eth0");
    }

    #[test]
    fn default_interface_prefers_private_lan_over_vpn_tunnel() {
        // A laptop with a corporate VPN up must still scan its own LAN.
        let mut tun = iface("tun0", 1, "10.8.0.2", 24);
        tun.is_point_to_point = true;
        tun.supports_multicast = false;
        let lan = iface("eth0", 2, "192.168.1.50", 24);

        let p = FakePlatform::new(vec![tun, lan], vec![]);
        let chosen = p.default_scan_interface().unwrap().unwrap();
        assert_eq!(chosen.name, "eth0");
    }

    #[test]
    fn default_interface_prefers_private_addresses_over_global_ones() {
        let public = iface("eth0", 1, "203.0.113.9", 24);
        let private = iface("eth1", 2, "192.168.1.50", 24);
        let p = FakePlatform::new(vec![public, private], vec![]);
        assert_eq!(p.default_scan_interface().unwrap().unwrap().name, "eth1");
    }

    #[test]
    fn default_interface_is_none_when_nothing_is_scannable() {
        let mut lo = iface("lo", 1, "127.0.0.1", 8);
        lo.is_loopback = true;
        let p = FakePlatform::new(vec![lo], vec![]);
        assert!(p.default_scan_interface().unwrap().is_none());
    }

    #[test]
    fn default_interface_selection_is_deterministic_for_equal_candidates() {
        // Ties break on interface index, so repeated runs agree.
        let a = iface("eth1", 7, "192.168.1.2", 24);
        let b = iface("eth0", 3, "192.168.1.3", 24);
        let p = FakePlatform::new(vec![a, b], vec![]);
        assert_eq!(p.default_scan_interface().unwrap().unwrap().index, 3);
    }

    #[test]
    fn unsupported_platform_reports_no_capabilities_rather_than_empty_results() {
        // An empty Ok(vec![]) would look like a clean scan of an empty network.
        let p = UnsupportedPlatform;
        assert!(p.interfaces().is_err());
        assert!(p.neighbors().is_err());
        assert!(!p.capabilities().can_probe_actively());
    }

    #[test]
    fn unprivileged_capabilities_exclude_raw_sockets_and_neighbour_table() {
        let c = Capabilities::unprivileged();
        assert!(!c.raw_sockets);
        assert!(!c.neighbor_table);
        assert!(!c.icmp_echo);
        // But discovery is still possible via multicast and broadcast.
        assert!(c.can_probe_actively());
    }

    #[test]
    fn ipv4_addrs_filters_out_v6() {
        let mut i = iface("eth0", 1, "10.0.0.1", 24);
        i.addrs.push(InterfaceAddr {
            addr: "fe80::1".parse().unwrap(),
            prefix_len: 64,
        });
        assert_eq!(i.ipv4_addrs().count(), 1);
    }
}
