//! Interface enumeration shared by the Unix backends.
//!
//! `getifaddrs(3)` is available and behaves consistently on Linux, macOS and
//! Android, so all three share this code. Only the link-layer address differs:
//! Linux and Android carry it in an `AF_PACKET` entry, the BSDs and macOS in an
//! `AF_LINK` entry with a completely different layout.

use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{Interface, InterfaceAddr, PlatformError, Result};
use crate::mac::MacAddr;

/// Walks the `getifaddrs` list and assembles one [`Interface`] per name.
pub fn interfaces() -> Result<Vec<Interface>> {
    // SAFETY: getifaddrs allocates a list we own; every pointer is null-checked
    // before dereference, and freeifaddrs is called on every return path.
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return Err(PlatformError::syscall(
                "getifaddrs",
                std::io::Error::last_os_error(),
            ));
        }
        if head.is_null() {
            return Ok(Vec::new());
        }

        // Preserve first-seen order so output is stable between runs.
        let mut order: Vec<String> = Vec::new();
        let mut by_name: std::collections::HashMap<String, Interface> =
            std::collections::HashMap::new();

        let mut cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            cur = ifa.ifa_next;

            if ifa.ifa_name.is_null() {
                continue;
            }
            let name = match CStr::from_ptr(ifa.ifa_name).to_str() {
                Ok(n) => n.to_string(),
                Err(_) => continue,
            };

            let flags = ifa.ifa_flags as u32;
            let entry = by_name.entry(name.clone()).or_insert_with(|| {
                order.push(name.clone());
                Interface {
                    name: name.clone(),
                    // Filled in below; if_nametoindex needs a NUL-terminated name.
                    index: 0,
                    mac: None,
                    addrs: Vec::new(),
                    is_up: flags & (libc::IFF_UP as u32) != 0,
                    is_loopback: flags & (libc::IFF_LOOPBACK as u32) != 0,
                    is_point_to_point: flags & (libc::IFF_POINTOPOINT as u32) != 0,
                    supports_multicast: flags & (libc::IFF_MULTICAST as u32) != 0,
                }
            });

            if ifa.ifa_addr.is_null() {
                continue;
            }

            match (*ifa.ifa_addr).sa_family as i32 {
                libc::AF_INET => {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    let prefix_len = if ifa.ifa_netmask.is_null() {
                        32
                    } else {
                        let m = &*(ifa.ifa_netmask as *const libc::sockaddr_in);
                        u32::from_be(m.sin_addr.s_addr).count_ones() as u8
                    };
                    entry.addrs.push(InterfaceAddr {
                        addr: IpAddr::V4(ip),
                        prefix_len,
                    });
                }
                libc::AF_INET6 => {
                    let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    let prefix_len = if ifa.ifa_netmask.is_null() {
                        128
                    } else {
                        let m = &*(ifa.ifa_netmask as *const libc::sockaddr_in6);
                        m.sin6_addr
                            .s6_addr
                            .iter()
                            .map(|b| b.count_ones())
                            .sum::<u32>() as u8
                    };
                    entry.addrs.push(InterfaceAddr {
                        addr: IpAddr::V6(ip),
                        prefix_len,
                    });
                }
                _ => {
                    if let Some(mac) = link_layer_addr(ifa) {
                        // Ignore all-zero MACs, which tunnels and some virtual
                        // interfaces report.
                        if !mac.is_zero() {
                            entry.mac = Some(mac);
                        }
                    }
                }
            }
        }

        libc::freeifaddrs(head);

        let mut out: Vec<Interface> = order
            .into_iter()
            .filter_map(|n| by_name.remove(&n))
            .collect();

        // Resolve kernel indices now that names are known.
        for i in out.iter_mut() {
            if let Ok(cname) = std::ffi::CString::new(i.name.as_str()) {
                i.index = libc::if_nametoindex(cname.as_ptr());
            }
        }

        Ok(out)
    }
}

/// Extracts the MAC from an `AF_PACKET` entry (Linux, Android).
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn link_layer_addr(ifa: &libc::ifaddrs) -> Option<MacAddr> {
    if (*ifa.ifa_addr).sa_family as i32 != libc::AF_PACKET {
        return None;
    }
    let sll = &*(ifa.ifa_addr as *const libc::sockaddr_ll);
    // Only EUI-48 link layers; skip loopback (halen 0) and Infiniband (halen 20).
    if sll.sll_halen != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&sll.sll_addr[..6]);
    Some(MacAddr::new(mac))
}

/// Extracts the MAC from an `AF_LINK` entry (macOS, BSD).
///
/// `sockaddr_dl` packs the interface name and the hardware address into one
/// variable-length trailing buffer: the address starts `sdl_nlen` bytes in.
#[cfg(target_os = "macos")]
unsafe fn link_layer_addr(ifa: &libc::ifaddrs) -> Option<MacAddr> {
    if (*ifa.ifa_addr).sa_family as i32 != libc::AF_LINK {
        return None;
    }
    let sdl = &*(ifa.ifa_addr as *const libc::sockaddr_dl);
    if sdl.sdl_alen != 6 {
        return None;
    }
    let start = sdl.sdl_nlen as usize;
    let data = &sdl.sdl_data;
    if start + 6 > data.len() {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        *b = data[start + i] as u8;
    }
    Some(MacAddr::new(mac))
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
unsafe fn link_layer_addr(_ifa: &libc::ifaddrs) -> Option<MacAddr> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerates_real_interfaces_on_this_host() {
        let ifaces = interfaces().expect("getifaddrs should succeed");
        assert!(!ifaces.is_empty(), "a host always has at least loopback");

        let lo = ifaces
            .iter()
            .find(|i| i.is_loopback)
            .expect("loopback interface must be present");
        assert!(lo.is_up);
        assert!(
            lo.addrs.iter().any(|a| a.addr.is_loopback()),
            "loopback must carry a loopback address"
        );
    }

    #[test]
    fn every_interface_has_a_resolvable_kernel_index() {
        for i in interfaces().unwrap() {
            assert_ne!(i.index, 0, "interface {} has no index", i.name);
        }
    }

    #[test]
    fn interface_names_are_unique() {
        // One Interface per name, with all its addresses merged in.
        let ifaces = interfaces().unwrap();
        let mut names: Vec<&str> = ifaces.iter().map(|i| i.name.as_str()).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "duplicate interface entries");
    }

    #[test]
    fn prefix_lengths_are_within_family_bounds() {
        for i in interfaces().unwrap() {
            for a in &i.addrs {
                let max = if a.addr.is_ipv4() { 32 } else { 128 };
                assert!(
                    a.prefix_len <= max,
                    "{}: prefix /{} out of range for {}",
                    i.name,
                    a.prefix_len,
                    a.addr
                );
            }
        }
    }

    #[test]
    fn reported_macs_are_never_all_zero() {
        for i in interfaces().unwrap() {
            if let Some(m) = i.mac {
                assert!(!m.is_zero(), "{} reported an all-zero MAC", i.name);
            }
        }
    }
}
