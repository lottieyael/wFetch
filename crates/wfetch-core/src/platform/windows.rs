//! Windows backend.
//!
//! This replaces the previous implementation, which built a PowerShell script
//! as a string and shelled out to `powershell.exe` to run `Get-NetNeighbor`.
//! That approach cost a process spawn per scan, depended on the execution
//! policy and on PowerShell being present, returned data that had to be parsed
//! back out of JSON, and had no equivalent on any other platform.
//!
//! Here the same information comes from the IP Helper API directly:
//!
//! * `GetIpNetTable2` — the neighbour cache, for both IPv4 and IPv6, with the
//!   `NL_NEIGHBOR_STATE` values that `Get-NetNeighbor` surfaces as its `State`
//!   column.
//! * `GetAdaptersAddresses` — interfaces, their unicast addresses and on-link
//!   prefix lengths.
//!
//! Both are the APIs the PowerShell cmdlets call underneath, so the results are
//! identical without the interpreter in the middle.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetAdaptersAddresses, GetIpNetTable2, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    MIB_IPNET_TABLE2,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
};

use super::{
    Capabilities, HostPlatform, Interface, InterfaceAddr, NeighborEntry, NeighborState,
    PlatformError, Result,
};
use crate::mac::MacAddr;

/// `IF_TYPE_SOFTWARE_LOOPBACK` from `<ipifcons.h>`.
const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
/// `IF_TYPE_PPP` and `IF_TYPE_TUNNEL`: point-to-point links with no broadcast domain.
const IF_TYPE_PPP: u32 = 23;
const IF_TYPE_TUNNEL: u32 = 131;

/// `NL_NEIGHBOR_STATE` values from `<nldef.h>`.
mod nl_state {
    pub const UNREACHABLE: i32 = 0;
    pub const INCOMPLETE: i32 = 1;
    pub const PROBE: i32 = 2;
    pub const DELAY: i32 = 3;
    pub const STALE: i32 = 4;
    pub const REACHABLE: i32 = 5;
    pub const PERMANENT: i32 = 6;
}

pub struct WindowsPlatform;

impl WindowsPlatform {
    pub fn new() -> Self {
        WindowsPlatform
    }
}

impl Default for WindowsPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl HostPlatform for WindowsPlatform {
    fn name(&self) -> &'static str {
        "windows"
    }

    fn interfaces(&self) -> Result<Vec<Interface>> {
        adapters()
    }

    fn neighbors(&self) -> Result<Vec<NeighborEntry>> {
        let mut entries = ip_net_table()?;
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
            // IcmpSendEcho2 works without administrator rights, so echo is
            // always available even when raw sockets are not.
            icmp_echo: true,
            multicast: true,
            broadcast: true,
        }
    }
}

/// Whether `SOCK_RAW` can be opened, which on Windows requires administrator.
fn can_open_raw_socket() -> bool {
    use windows::Win32::Networking::WinSock::{
        closesocket, socket, INVALID_SOCKET, IPPROTO_ICMP, SOCK_RAW,
    };
    // SAFETY: socket/closesocket with constant arguments; the socket is closed
    // immediately and never used.
    unsafe {
        let s = socket(AF_INET.0 as i32, SOCK_RAW, IPPROTO_ICMP.0);
        match s {
            Ok(sock) if sock != INVALID_SOCKET => {
                let _ = closesocket(sock);
                true
            }
            _ => false,
        }
    }
}

fn map_state(state: i32) -> NeighborState {
    match state {
        nl_state::UNREACHABLE => NeighborState::Failed,
        nl_state::INCOMPLETE => NeighborState::Incomplete,
        nl_state::PROBE => NeighborState::Probe,
        nl_state::DELAY => NeighborState::Delay,
        nl_state::STALE => NeighborState::Stale,
        nl_state::REACHABLE => NeighborState::Reachable,
        nl_state::PERMANENT => NeighborState::Permanent,
        _ => NeighborState::Unknown,
    }
}

/// Reads the neighbour cache via `GetIpNetTable2`.
fn ip_net_table() -> Result<Vec<NeighborEntry>> {
    let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();

    // SAFETY: GetIpNetTable2 allocates the table; FreeMibTable releases it on
    // every path. Rows are read only within the reported NumEntries count.
    unsafe {
        let err = GetIpNetTable2(AF_UNSPEC, &mut table);
        if err != NO_ERROR {
            return Err(PlatformError::syscall(
                "GetIpNetTable2",
                std::io::Error::from_raw_os_error(err.0 as i32),
            ));
        }
        if table.is_null() {
            return Ok(Vec::new());
        }

        let count = (*table).NumEntries as usize;
        // The table is a header followed by a variable-length row array; the
        // declared Table field is a 1-element placeholder.
        let rows = (*table).Table.as_ptr();
        let mut out = Vec::with_capacity(count);

        for i in 0..count {
            let row = &*rows.add(i);

            let family = row.Address.si_family;
            let ip = if family == AF_INET {
                let sin: &SOCKADDR_IN = &row.Address.Ipv4;
                IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.S_un.S_addr)))
            } else if family == AF_INET6 {
                let sin6: &SOCKADDR_IN6 = &row.Address.Ipv6;
                IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.u.Byte))
            } else {
                continue;
            };

            // Kernel placeholder rows carry an unspecified address.
            if ip.is_unspecified() {
                continue;
            }

            // PhysicalAddress is a fixed 32-byte buffer; only the first
            // PhysicalAddressLength bytes are meaningful, and only EUI-48
            // link layers give a MAC.
            let mac = if row.PhysicalAddressLength == 6 {
                let mut m = [0u8; 6];
                m.copy_from_slice(&row.PhysicalAddress[..6]);
                let m = MacAddr::new(m);
                if m.is_zero() {
                    None
                } else {
                    Some(m)
                }
            } else {
                None
            };

            out.push(NeighborEntry {
                ip,
                mac,
                state: map_state(row.State.0),
                if_index: row.InterfaceIndex,
                if_name: None,
            });
        }

        FreeMibTable(table as *const _);
        Ok(out)
    }
}

/// Enumerates interfaces via `GetAdaptersAddresses`.
fn adapters() -> Result<Vec<Interface>> {
    // SAFETY: the buffer is sized by the API's own overflow report before the
    // list is walked; every pointer is null-checked before dereference.
    unsafe {
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        let mut size: u32 = 16 * 1024;
        let mut buf: Vec<u8> = Vec::new();

        // Retry on overflow: the adapter list can grow between calls.
        let mut attempts = 0;
        loop {
            buf.resize(size as usize, 0);
            let ret = GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                flags,
                None,
                Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            );
            if ret == NO_ERROR.0 {
                break;
            }
            attempts += 1;
            if ret != ERROR_BUFFER_OVERFLOW.0 || attempts > 3 {
                return Err(PlatformError::syscall(
                    "GetAdaptersAddresses",
                    std::io::Error::from_raw_os_error(ret as i32),
                ));
            }
        }

        let mut out = Vec::new();
        let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !p.is_null() {
            let a = &*p;

            let name = if a.FriendlyName.is_null() {
                String::new()
            } else {
                a.FriendlyName.to_string().unwrap_or_default()
            };

            let mac = if a.PhysicalAddressLength == 6 {
                let mut m = [0u8; 6];
                m.copy_from_slice(&a.PhysicalAddress[..6]);
                let m = MacAddr::new(m);
                if m.is_zero() {
                    None
                } else {
                    Some(m)
                }
            } else {
                None
            };

            let mut addrs = Vec::new();
            let mut ua = a.FirstUnicastAddress;
            while !ua.is_null() {
                let u = &*ua;
                if !u.Address.lpSockaddr.is_null() {
                    let sa = &*u.Address.lpSockaddr;
                    let family = windows::Win32::Networking::WinSock::ADDRESS_FAMILY(sa.sa_family.0);
                    if family == AF_INET {
                        let sin = &*(u.Address.lpSockaddr as *const SOCKADDR_IN);
                        addrs.push(InterfaceAddr {
                            addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.S_un.S_addr))),
                            prefix_len: u.OnLinkPrefixLength,
                        });
                    } else if family == AF_INET6 {
                        let sin6 = &*(u.Address.lpSockaddr as *const SOCKADDR_IN6);
                        addrs.push(InterfaceAddr {
                            addr: IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.u.Byte)),
                            prefix_len: u.OnLinkPrefixLength,
                        });
                    }
                }
                ua = u.Next;
            }

            // IfType distinguishes loopback and point-to-point links; the
            // IP_ADAPTER_ADDRESSES flags do not carry that information.
            let if_type = a.IfType;
            out.push(Interface {
                name,
                index: a.Anonymous1.Anonymous.IfIndex,
                mac,
                addrs,
                is_up: a.OperStatus == IfOperStatusUp,
                is_loopback: if_type == IF_TYPE_SOFTWARE_LOOPBACK,
                is_point_to_point: if_type == IF_TYPE_PPP || if_type == IF_TYPE_TUNNEL,
                // NoMulticast is a negative flag in the API.
                supports_multicast: a.Anonymous2.Flags & 0x10 == 0,
            });

            p = a.Next;
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_documented_neighbor_state() {
        let cases = [
            (nl_state::UNREACHABLE, NeighborState::Failed),
            (nl_state::INCOMPLETE, NeighborState::Incomplete),
            (nl_state::PROBE, NeighborState::Probe),
            (nl_state::DELAY, NeighborState::Delay),
            (nl_state::STALE, NeighborState::Stale),
            (nl_state::REACHABLE, NeighborState::Reachable),
            (nl_state::PERMANENT, NeighborState::Permanent),
            (99, NeighborState::Unknown),
        ];
        for (raw, expected) in cases {
            assert_eq!(map_state(raw), expected, "state {raw}");
        }
    }

    #[test]
    fn unreachable_and_incomplete_states_do_not_imply_a_host() {
        // Get-NetNeighbor reports these rows too; counting them as hosts would
        // report every address Windows has ever failed to reach as alive.
        assert!(!map_state(nl_state::UNREACHABLE).implies_host_present());
        assert!(!map_state(nl_state::INCOMPLETE).implies_host_present());
        assert!(map_state(nl_state::REACHABLE).implies_host_present());
        assert!(map_state(nl_state::STALE).implies_host_present());
    }

    #[test]
    fn interfaces_are_enumerable_on_this_host() {
        let p = WindowsPlatform::new();
        let ifaces = p.interfaces().expect("GetAdaptersAddresses should succeed");
        assert!(!ifaces.is_empty());
        assert!(
            ifaces.iter().any(|i| i.is_loopback),
            "Windows always has a loopback pseudo-interface"
        );
    }

    #[test]
    fn neighbour_table_is_readable_and_internally_consistent() {
        let p = WindowsPlatform::new();
        let entries = p.neighbors().expect("GetIpNetTable2 should succeed");
        for e in &entries {
            assert!(!e.ip.is_unspecified());
            if let Some(m) = e.mac {
                assert!(!m.is_zero());
            }
        }
    }

    #[test]
    fn prefix_lengths_are_within_family_bounds() {
        for i in WindowsPlatform::new().interfaces().unwrap() {
            for a in &i.addrs {
                let max = if a.addr.is_ipv4() { 32 } else { 128 };
                assert!(a.prefix_len <= max, "{}: /{}", i.name, a.prefix_len);
            }
        }
    }
}
