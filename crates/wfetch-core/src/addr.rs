//! Address arithmetic: CIDR blocks, host enumeration and address classification.
//!
//! This module is deliberately free of I/O. Everything here is pure arithmetic so
//! that it can be exhaustively tested without a network, and so that the scan
//! planner can reason about target sets before a single packet is sent.
//!
//! Two edge cases drive most of the complexity and are handled explicitly rather
//! than by the usual `2^(32-n) - 2` shortcut:
//!
//! * **RFC 3021 /31 links.** A /31 has no network or broadcast address; both
//!   addresses are usable hosts. The naive formula yields 0 hosts, which would
//!   silently skip every point-to-point link in a routed network.
//! * **/32 host routes.** A single address is its own host.
//!
//! IPv6 has no broadcast address at all, so the "subtract 2" rule never applies;
//! only the subnet-router anycast address (the all-zeros host part) is reserved,
//! and we keep it enumerable because hosts do answer on it in practice.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Errors produced when parsing address specifications.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddrError {
    #[error("invalid IP address: {0}")]
    InvalidIp(String),
    #[error("invalid prefix length {len} for IPv{family}")]
    InvalidPrefix { len: u32, family: u8 },
    #[error("invalid netmask: {0}")]
    InvalidNetmask(String),
    #[error("invalid CIDR block: {0}")]
    InvalidCidr(String),
    #[error("invalid address range: {0}")]
    InvalidRange(String),
    #[error("range endpoints are of different address families: {0}")]
    MixedFamily(String),
    #[error("range start {start} is greater than end {end}")]
    ReversedRange { start: IpAddr, end: IpAddr },
}

/// An IPv4 CIDR block, normalised to its network address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ipv4Cidr {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Cidr {
    /// Builds a block, masking `addr` down to the network address.
    pub fn new(addr: Ipv4Addr, prefix_len: u8) -> Result<Self, AddrError> {
        if prefix_len > 32 {
            return Err(AddrError::InvalidPrefix {
                len: prefix_len as u32,
                family: 4,
            });
        }
        let mask = v4_mask(prefix_len);
        Ok(Self {
            network: Ipv4Addr::from(u32::from(addr) & mask),
            prefix_len,
        })
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn network(&self) -> Ipv4Addr {
        self.network
    }

    pub fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::from(v4_mask(self.prefix_len))
    }

    /// The all-ones address in the block. For /31 and /32 this is not a
    /// broadcast address in the RFC 919 sense, merely the highest address.
    pub fn last_address(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network) | !v4_mask(self.prefix_len))
    }

    /// The directed broadcast address, or `None` for /31 and /32 which have none.
    pub fn broadcast(&self) -> Option<Ipv4Addr> {
        if self.prefix_len >= 31 {
            None
        } else {
            Some(self.last_address())
        }
    }

    /// Total addresses in the block, including network and broadcast.
    pub fn address_count(&self) -> u64 {
        1u64 << (32 - self.prefix_len as u32)
    }

    /// Addresses that can be assigned to a host and are worth probing.
    ///
    /// Follows RFC 3021 for /31 (2 hosts) and treats /32 as a single host.
    pub fn host_count(&self) -> u64 {
        match self.prefix_len {
            32 => 1,
            31 => 2,
            _ => self.address_count() - 2,
        }
    }

    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        let mask = v4_mask(self.prefix_len);
        u32::from(addr) & mask == u32::from(self.network)
    }

    /// Iterates every probeable host address in the block, low to high.
    pub fn hosts(&self) -> Ipv4HostIter {
        let (start, end) = match self.prefix_len {
            // Single host route: the address itself.
            32 => (u32::from(self.network), u32::from(self.network)),
            // RFC 3021: both addresses are usable.
            31 => (u32::from(self.network), u32::from(self.last_address())),
            // Skip the network and broadcast addresses.
            _ => (
                u32::from(self.network) + 1,
                u32::from(self.last_address()) - 1,
            ),
        };
        Ipv4HostIter {
            next: Some(start),
            end,
        }
    }

    /// Splits the block into `2^(new_prefix - prefix)` sub-blocks.
    ///
    /// Returns an error if `new_prefix` is shorter than the current prefix.
    pub fn split_to(&self, new_prefix: u8) -> Result<Vec<Ipv4Cidr>, AddrError> {
        if new_prefix > 32 {
            return Err(AddrError::InvalidPrefix {
                len: new_prefix as u32,
                family: 4,
            });
        }
        if new_prefix < self.prefix_len {
            return Err(AddrError::InvalidCidr(format!(
                "cannot split /{} into a shorter /{}",
                self.prefix_len, new_prefix
            )));
        }
        let step = 1u64 << (32 - new_prefix as u32);
        let count = 1u64 << (new_prefix as u32 - self.prefix_len as u32);
        let base = u32::from(self.network) as u64;
        Ok((0..count)
            .map(|i| Ipv4Cidr {
                network: Ipv4Addr::from((base + i * step) as u32),
                prefix_len: new_prefix,
            })
            .collect())
    }

    /// The immediately enclosing block, or `None` for /0.
    pub fn supernet(&self) -> Option<Ipv4Cidr> {
        if self.prefix_len == 0 {
            return None;
        }
        Ipv4Cidr::new(self.network, self.prefix_len - 1).ok()
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

/// Iterator over IPv4 host addresses that cannot overflow at 255.255.255.255.
#[derive(Debug, Clone)]
pub struct Ipv4HostIter {
    /// `None` once the iterator is exhausted. Using an Option rather than a
    /// bare cursor keeps `end == u32::MAX` (a /0 or /1 scan) from wrapping.
    next: Option<u32>,
    end: u32,
}

impl Iterator for Ipv4HostIter {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Ipv4Addr> {
        let cur = self.next?;
        if cur > self.end {
            self.next = None;
            return None;
        }
        self.next = if cur == self.end { None } else { Some(cur + 1) };
        Some(Ipv4Addr::from(cur))
    }
}

/// An IPv6 CIDR block, normalised to its network address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ipv6Cidr {
    network: Ipv6Addr,
    prefix_len: u8,
}

impl Ipv6Cidr {
    pub fn new(addr: Ipv6Addr, prefix_len: u8) -> Result<Self, AddrError> {
        if prefix_len > 128 {
            return Err(AddrError::InvalidPrefix {
                len: prefix_len as u32,
                family: 6,
            });
        }
        let mask = v6_mask(prefix_len);
        Ok(Self {
            network: Ipv6Addr::from(u128::from(addr) & mask),
            prefix_len,
        })
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn network(&self) -> Ipv6Addr {
        self.network
    }

    pub fn last_address(&self) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(self.network) | !v6_mask(self.prefix_len))
    }

    /// Total addresses in the block. Saturates for prefixes shorter than /64,
    /// which cannot be represented in a u128 count and are never enumerated.
    pub fn address_count(&self) -> u128 {
        if self.prefix_len == 0 {
            u128::MAX
        } else {
            1u128 << (128 - self.prefix_len as u32)
        }
    }

    pub fn contains(&self, addr: Ipv6Addr) -> bool {
        let mask = v6_mask(self.prefix_len);
        u128::from(addr) & mask == u128::from(self.network)
    }

    /// Iterates addresses in the block, low to high.
    ///
    /// IPv6 has no broadcast address, so every address in the block is
    /// enumerable. Callers are responsible for bounding this: a /64 contains
    /// 2^64 addresses and must never be swept exhaustively.
    pub fn hosts(&self) -> Ipv6HostIter {
        Ipv6HostIter {
            next: Some(u128::from(self.network)),
            end: u128::from(self.last_address()),
        }
    }
}

impl fmt::Display for Ipv6Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

#[derive(Debug, Clone)]
pub struct Ipv6HostIter {
    next: Option<u128>,
    end: u128,
}

impl Iterator for Ipv6HostIter {
    type Item = Ipv6Addr;

    fn next(&mut self) -> Option<Ipv6Addr> {
        let cur = self.next?;
        if cur > self.end {
            self.next = None;
            return None;
        }
        self.next = if cur == self.end { None } else { Some(cur + 1) };
        Some(Ipv6Addr::from(cur))
    }
}

/// A CIDR block of either address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IpCidr {
    V4(Ipv4Cidr),
    V6(Ipv6Cidr),
}

impl IpCidr {
    pub fn network(&self) -> IpAddr {
        match self {
            IpCidr::V4(c) => IpAddr::V4(c.network()),
            IpCidr::V6(c) => IpAddr::V6(c.network()),
        }
    }

    pub fn prefix_len(&self) -> u8 {
        match self {
            IpCidr::V4(c) => c.prefix_len(),
            IpCidr::V6(c) => c.prefix_len(),
        }
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self, addr) {
            (IpCidr::V4(c), IpAddr::V4(a)) => c.contains(a),
            (IpCidr::V6(c), IpAddr::V6(a)) => c.contains(a),
            _ => false,
        }
    }

    /// Number of probeable hosts, saturating at `u64::MAX` for huge v6 blocks.
    pub fn host_count(&self) -> u64 {
        match self {
            IpCidr::V4(c) => c.host_count(),
            IpCidr::V6(c) => c.address_count().min(u64::MAX as u128) as u64,
        }
    }

    pub fn is_ipv4(&self) -> bool {
        matches!(self, IpCidr::V4(_))
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpCidr::V4(c) => c.fmt(f),
            IpCidr::V6(c) => c.fmt(f),
        }
    }
}

impl FromStr for IpCidr {
    type Err = AddrError;

    /// Accepts `10.0.0.0/24`, `10.0.0.0/255.255.255.0`, `2001:db8::/32`,
    /// and bare addresses (treated as /32 or /128).
    fn from_str(s: &str) -> Result<Self, AddrError> {
        let s = s.trim();
        let Some((addr_part, prefix_part)) = s.split_once('/') else {
            // A bare address is a host route.
            return match IpAddr::from_str(s) {
                Ok(IpAddr::V4(a)) => Ok(IpCidr::V4(Ipv4Cidr::new(a, 32)?)),
                Ok(IpAddr::V6(a)) => Ok(IpCidr::V6(Ipv6Cidr::new(a, 128)?)),
                Err(_) => Err(AddrError::InvalidIp(s.to_string())),
            };
        };

        let addr = IpAddr::from_str(addr_part.trim())
            .map_err(|_| AddrError::InvalidIp(addr_part.trim().to_string()))?;
        let prefix_part = prefix_part.trim();

        match addr {
            IpAddr::V4(a) => {
                // Dotted-quad netmask form, e.g. 10.0.0.0/255.255.255.0.
                let prefix_len = if prefix_part.contains('.') {
                    let mask = Ipv4Addr::from_str(prefix_part)
                        .map_err(|_| AddrError::InvalidNetmask(prefix_part.to_string()))?;
                    netmask_to_prefix_len(mask)?
                } else {
                    prefix_part
                        .parse::<u32>()
                        .map_err(|_| AddrError::InvalidCidr(s.to_string()))
                        .and_then(|len| {
                            if len > 32 {
                                Err(AddrError::InvalidPrefix { len, family: 4 })
                            } else {
                                Ok(len as u8)
                            }
                        })?
                };
                Ok(IpCidr::V4(Ipv4Cidr::new(a, prefix_len)?))
            }
            IpAddr::V6(a) => {
                let len = prefix_part
                    .parse::<u32>()
                    .map_err(|_| AddrError::InvalidCidr(s.to_string()))?;
                if len > 128 {
                    return Err(AddrError::InvalidPrefix { len, family: 6 });
                }
                Ok(IpCidr::V6(Ipv6Cidr::new(a, len as u8)?))
            }
        }
    }
}

/// Converts a dotted-quad netmask to a prefix length.
///
/// Rejects non-contiguous masks such as 255.0.255.0, which some tools silently
/// accept and then interpret inconsistently.
pub fn netmask_to_prefix_len(mask: Ipv4Addr) -> Result<u8, AddrError> {
    let bits = u32::from(mask);
    let ones = bits.leading_ones();
    // A valid mask is a run of ones followed only by zeros.
    if ones < 32 && bits << ones != 0 {
        return Err(AddrError::InvalidNetmask(format!(
            "{mask} is not contiguous"
        )));
    }
    Ok(ones as u8)
}

/// Builds the IPv4 mask for a prefix length, avoiding the undefined `<< 32`.
fn v4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len as u32)
    }
}

/// Builds the IPv6 mask for a prefix length, avoiding the undefined `<< 128`.
fn v6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len as u32)
    }
}

/// How an address should be treated by the scan planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddrClass {
    /// RFC 1918 / RFC 4193 private space: the normal scan target.
    Private,
    /// RFC 6598 carrier-grade NAT space.
    CarrierGrade,
    /// RFC 3927 / RFC 4291 link-local.
    LinkLocal,
    Loopback,
    Multicast,
    /// The all-ones IPv4 address, or a subnet broadcast.
    Broadcast,
    /// RFC 5737 / RFC 3849 documentation ranges.
    Documentation,
    Unspecified,
    /// Globally routable. Scanning this is legitimate but is never implied by
    /// a local-network scan, so the planner requires it to be explicit.
    Global,
}

impl AddrClass {
    /// Whether an address of this class is worth probing during a LAN sweep.
    pub fn is_probeable(&self) -> bool {
        matches!(
            self,
            AddrClass::Private | AddrClass::CarrierGrade | AddrClass::Global
        )
    }
}

/// Classifies an address for scan planning.
pub fn classify(addr: IpAddr) -> AddrClass {
    match addr {
        IpAddr::V4(a) => classify_v4(a),
        IpAddr::V6(a) => classify_v6(a),
    }
}

pub fn classify_v4(a: Ipv4Addr) -> AddrClass {
    let o = a.octets();
    if a.is_unspecified() {
        return AddrClass::Unspecified;
    }
    if a.is_loopback() {
        return AddrClass::Loopback;
    }
    if a == Ipv4Addr::BROADCAST {
        return AddrClass::Broadcast;
    }
    if a.is_multicast() {
        return AddrClass::Multicast;
    }
    if a.is_link_local() {
        return AddrClass::LinkLocal;
    }
    // RFC 6598 100.64.0.0/10.
    if o[0] == 100 && (64..128).contains(&o[1]) {
        return AddrClass::CarrierGrade;
    }
    // RFC 1918.
    if o[0] == 10
        || (o[0] == 172 && (16..32).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
    {
        return AddrClass::Private;
    }
    // RFC 5737 documentation ranges.
    if (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
    {
        return AddrClass::Documentation;
    }
    AddrClass::Global
}

pub fn classify_v6(a: Ipv6Addr) -> AddrClass {
    if a.is_unspecified() {
        return AddrClass::Unspecified;
    }
    if a.is_loopback() {
        return AddrClass::Loopback;
    }
    if a.is_multicast() {
        return AddrClass::Multicast;
    }
    let seg = a.segments();
    // fe80::/10 link-local.
    if seg[0] & 0xffc0 == 0xfe80 {
        return AddrClass::LinkLocal;
    }
    // fc00::/7 unique local.
    if seg[0] & 0xfe00 == 0xfc00 {
        return AddrClass::Private;
    }
    // RFC 3849 2001:db8::/32 documentation.
    if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        return AddrClass::Documentation;
    }
    AddrClass::Global
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn cidr(s: &str) -> IpCidr {
        s.parse().unwrap()
    }

    // ---- mask construction -------------------------------------------------

    #[test]
    fn v4_mask_covers_both_shift_boundaries() {
        // /0 and /32 are the two cases a naive `<< (32 - n)` gets wrong.
        assert_eq!(v4_mask(0), 0);
        assert_eq!(v4_mask(32), u32::MAX);
        assert_eq!(v4_mask(24), 0xffff_ff00);
        assert_eq!(v4_mask(1), 0x8000_0000);
    }

    #[test]
    fn v6_mask_covers_both_shift_boundaries() {
        assert_eq!(v6_mask(0), 0);
        assert_eq!(v6_mask(128), u128::MAX);
        assert_eq!(v6_mask(64), u128::MAX << 64);
    }

    #[test]
    fn every_v4_prefix_length_has_a_contiguous_mask() {
        for len in 0..=32u8 {
            let m = v4_mask(len);
            assert_eq!(m.leading_ones(), len as u32, "prefix /{len}");
            assert_eq!(m.count_ones(), len as u32, "prefix /{len} not contiguous");
        }
    }

    // ---- block normalisation ----------------------------------------------

    #[test]
    fn constructor_masks_host_bits_to_the_network_address() {
        let c = Ipv4Cidr::new(v4("192.168.1.77"), 24).unwrap();
        assert_eq!(c.network(), v4("192.168.1.0"));
        assert_eq!(c.last_address(), v4("192.168.1.255"));
    }

    #[test]
    fn rejects_out_of_range_prefix_lengths() {
        assert!(Ipv4Cidr::new(v4("10.0.0.0"), 33).is_err());
        assert!(Ipv6Cidr::new(Ipv6Addr::UNSPECIFIED, 129).is_err());
    }

    // ---- host counting -----------------------------------------------------

    #[test]
    fn host_count_matches_the_standard_formula_for_ordinary_blocks() {
        for len in 0..=30u8 {
            let c = Ipv4Cidr::new(v4("10.0.0.0"), len).unwrap();
            let expected = (1u64 << (32 - len as u32)) - 2;
            assert_eq!(c.host_count(), expected, "prefix /{len}");
        }
    }

    #[test]
    fn slash_31_has_two_hosts_per_rfc3021() {
        // The naive formula gives 0 here, which would skip every p2p link.
        let c = Ipv4Cidr::new(v4("10.0.0.4"), 31).unwrap();
        assert_eq!(c.address_count(), 2);
        assert_eq!(c.host_count(), 2);
        assert_eq!(c.broadcast(), None);
        let hosts: Vec<_> = c.hosts().collect();
        assert_eq!(hosts, vec![v4("10.0.0.4"), v4("10.0.0.5")]);
    }

    #[test]
    fn slash_32_is_a_single_host_route() {
        let c = Ipv4Cidr::new(v4("10.1.2.3"), 32).unwrap();
        assert_eq!(c.address_count(), 1);
        assert_eq!(c.host_count(), 1);
        assert_eq!(c.broadcast(), None);
        let hosts: Vec<_> = c.hosts().collect();
        assert_eq!(hosts, vec![v4("10.1.2.3")]);
    }

    #[test]
    fn host_iteration_count_always_equals_host_count() {
        // Ties the iterator and the arithmetic together for every size we can
        // afford to enumerate exhaustively.
        for len in 20..=32u8 {
            let c = Ipv4Cidr::new(v4("172.16.0.0"), len).unwrap();
            assert_eq!(
                c.hosts().count() as u64,
                c.host_count(),
                "prefix /{len}"
            );
        }
    }

    #[test]
    fn hosts_exclude_network_and_broadcast_for_ordinary_blocks() {
        let c = Ipv4Cidr::new(v4("192.168.1.0"), 24).unwrap();
        let hosts: Vec<_> = c.hosts().collect();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], v4("192.168.1.1"));
        assert_eq!(hosts[253], v4("192.168.1.254"));
        assert!(!hosts.contains(&v4("192.168.1.0")));
        assert!(!hosts.contains(&v4("192.168.1.255")));
    }

    #[test]
    fn host_iterator_terminates_at_the_top_of_the_address_space() {
        // 255.255.255.254/31 ends exactly at u32::MAX; a cursor-based iterator
        // would wrap to 0 and loop forever here.
        let c = Ipv4Cidr::new(v4("255.255.255.254"), 31).unwrap();
        let hosts: Vec<_> = c.hosts().collect();
        assert_eq!(hosts, vec![v4("255.255.255.254"), v4("255.255.255.255")]);

        let c = Ipv4Cidr::new(v4("255.255.255.255"), 32).unwrap();
        assert_eq!(c.hosts().collect::<Vec<_>>(), vec![v4("255.255.255.255")]);
    }

    #[test]
    fn v6_host_iterator_terminates_at_the_top_of_the_address_space() {
        let all_ones = Ipv6Addr::from(u128::MAX);
        let c = Ipv6Cidr::new(all_ones, 127).unwrap();
        assert_eq!(c.hosts().count(), 2);
        let c = Ipv6Cidr::new(all_ones, 128).unwrap();
        assert_eq!(c.hosts().collect::<Vec<_>>(), vec![all_ones]);
    }

    // ---- containment -------------------------------------------------------

    #[test]
    fn containment_respects_prefix_boundaries() {
        let c = Ipv4Cidr::new(v4("192.168.1.0"), 24).unwrap();
        assert!(c.contains(v4("192.168.1.0")));
        assert!(c.contains(v4("192.168.1.255")));
        assert!(!c.contains(v4("192.168.2.0")));
        assert!(!c.contains(v4("192.168.0.255")));
    }

    #[test]
    fn slash_zero_contains_every_v4_address() {
        let c = Ipv4Cidr::new(v4("0.0.0.0"), 0).unwrap();
        for a in ["0.0.0.0", "8.8.8.8", "255.255.255.255", "10.0.0.1"] {
            assert!(c.contains(v4(a)), "{a}");
        }
        assert_eq!(c.address_count(), 1u64 << 32);
    }

    #[test]
    fn containment_is_consistent_with_host_enumeration() {
        let c = Ipv4Cidr::new(v4("10.9.8.0"), 28).unwrap();
        for h in c.hosts() {
            assert!(c.contains(h), "{h} enumerated but not contained");
        }
    }

    // ---- splitting and supernetting ---------------------------------------

    #[test]
    fn splitting_partitions_the_block_exactly() {
        let c = Ipv4Cidr::new(v4("10.0.0.0"), 24).unwrap();
        let subs = c.split_to(26).unwrap();
        assert_eq!(subs.len(), 4);
        assert_eq!(subs[0].network(), v4("10.0.0.0"));
        assert_eq!(subs[1].network(), v4("10.0.0.64"));
        assert_eq!(subs[2].network(), v4("10.0.0.128"));
        assert_eq!(subs[3].network(), v4("10.0.0.192"));
        // The parts must tile the whole without gaps or overlap.
        let total: u64 = subs.iter().map(|s| s.address_count()).sum();
        assert_eq!(total, c.address_count());
        assert_eq!(subs.last().unwrap().last_address(), c.last_address());
    }

    #[test]
    fn splitting_to_the_same_prefix_is_the_identity() {
        let c = Ipv4Cidr::new(v4("10.0.0.0"), 24).unwrap();
        assert_eq!(c.split_to(24).unwrap(), vec![c]);
    }

    #[test]
    fn splitting_to_a_shorter_prefix_is_rejected() {
        let c = Ipv4Cidr::new(v4("10.0.0.0"), 24).unwrap();
        assert!(c.split_to(23).is_err());
        assert!(c.split_to(33).is_err());
    }

    #[test]
    fn supernet_walks_up_to_slash_zero_and_stops() {
        let mut c = Ipv4Cidr::new(v4("192.168.1.0"), 24).unwrap();
        let mut steps = 0;
        while let Some(parent) = c.supernet() {
            assert!(parent.contains(c.network()));
            assert_eq!(parent.prefix_len(), c.prefix_len() - 1);
            c = parent;
            steps += 1;
        }
        assert_eq!(c.prefix_len(), 0);
        assert_eq!(steps, 24);
    }

    // ---- parsing -----------------------------------------------------------

    #[test]
    fn parses_prefix_and_netmask_forms_identically() {
        assert_eq!(cidr("10.0.0.0/24"), cidr("10.0.0.0/255.255.255.0"));
        assert_eq!(cidr("10.0.0.0/8"), cidr("10.0.0.0/255.0.0.0"));
        assert_eq!(cidr("10.0.0.1/32"), cidr("10.0.0.1/255.255.255.255"));
    }

    #[test]
    fn parses_bare_addresses_as_host_routes() {
        assert_eq!(cidr("192.168.1.5").prefix_len(), 32);
        assert_eq!(cidr("2001:db8::1").prefix_len(), 128);
    }

    #[test]
    fn parsing_normalises_host_bits_away() {
        assert_eq!(cidr("192.168.1.77/24"), cidr("192.168.1.0/24"));
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in [
            "",
            "not-an-ip",
            "10.0.0.0/33",
            "10.0.0.0/-1",
            "10.0.0.0/abc",
            "2001:db8::/129",
            "999.1.1.1/24",
            "10.0.0.0/255.0.255.0", // non-contiguous mask
        ] {
            assert!(bad.parse::<IpCidr>().is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn non_contiguous_netmasks_are_rejected() {
        assert!(netmask_to_prefix_len(v4("255.0.255.0")).is_err());
        assert!(netmask_to_prefix_len(v4("255.255.255.1")).is_err());
        assert_eq!(netmask_to_prefix_len(v4("0.0.0.0")).unwrap(), 0);
        assert_eq!(netmask_to_prefix_len(v4("255.255.255.255")).unwrap(), 32);
    }

    #[test]
    fn netmask_conversion_round_trips_for_every_prefix_length() {
        for len in 0..=32u8 {
            let c = Ipv4Cidr::new(v4("10.0.0.0"), len).unwrap();
            assert_eq!(netmask_to_prefix_len(c.netmask()).unwrap(), len);
        }
    }

    #[test]
    fn display_round_trips_through_parsing() {
        for s in ["10.0.0.0/8", "192.168.1.0/24", "0.0.0.0/0", "10.1.2.3/32"] {
            let c = cidr(s);
            assert_eq!(c.to_string(), s);
            assert_eq!(c.to_string().parse::<IpCidr>().unwrap(), c);
        }
    }

    // ---- IPv6 --------------------------------------------------------------

    #[test]
    fn v6_blocks_normalise_and_size_correctly() {
        let c = Ipv6Cidr::new("2001:db8::1234".parse().unwrap(), 64).unwrap();
        assert_eq!(c.network(), "2001:db8::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(c.address_count(), 1u128 << 64);
        assert!(c.contains("2001:db8::ffff".parse().unwrap()));
        assert!(!c.contains("2001:db8:0:1::1".parse().unwrap()));
    }

    #[test]
    fn v6_slash_zero_count_saturates_instead_of_overflowing() {
        let c = Ipv6Cidr::new(Ipv6Addr::UNSPECIFIED, 0).unwrap();
        assert_eq!(c.address_count(), u128::MAX);
    }

    #[test]
    fn mixed_family_containment_is_always_false() {
        let v4c = cidr("0.0.0.0/0");
        let v6c = cidr("::/0");
        assert!(!v4c.contains("2001:db8::1".parse().unwrap()));
        assert!(!v6c.contains("10.0.0.1".parse().unwrap()));
    }

    // ---- classification ----------------------------------------------------

    #[test]
    fn classifies_v4_special_ranges() {
        let cases = [
            ("10.0.0.1", AddrClass::Private),
            ("172.16.0.1", AddrClass::Private),
            ("172.31.255.254", AddrClass::Private),
            ("192.168.1.1", AddrClass::Private),
            ("100.64.0.1", AddrClass::CarrierGrade),
            ("100.127.255.254", AddrClass::CarrierGrade),
            ("169.254.1.1", AddrClass::LinkLocal),
            ("127.0.0.1", AddrClass::Loopback),
            ("224.0.0.251", AddrClass::Multicast),
            ("239.255.255.250", AddrClass::Multicast),
            ("255.255.255.255", AddrClass::Broadcast),
            ("0.0.0.0", AddrClass::Unspecified),
            ("192.0.2.1", AddrClass::Documentation),
            ("8.8.8.8", AddrClass::Global),
        ];
        for (addr, expected) in cases {
            assert_eq!(classify_v4(v4(addr)), expected, "{addr}");
        }
    }

    #[test]
    fn private_range_boundaries_are_exact() {
        // The octet just outside each RFC 1918 block must not be private.
        assert_eq!(classify_v4(v4("172.15.255.255")), AddrClass::Global);
        assert_eq!(classify_v4(v4("172.32.0.0")), AddrClass::Global);
        assert_eq!(classify_v4(v4("192.167.255.255")), AddrClass::Global);
        assert_eq!(classify_v4(v4("192.169.0.0")), AddrClass::Global);
        assert_eq!(classify_v4(v4("11.0.0.0")), AddrClass::Global);
        // RFC 6598 boundaries.
        assert_eq!(classify_v4(v4("100.63.255.255")), AddrClass::Global);
        assert_eq!(classify_v4(v4("100.128.0.0")), AddrClass::Global);
    }

    #[test]
    fn classifies_v6_special_ranges() {
        let cases = [
            ("::", AddrClass::Unspecified),
            ("::1", AddrClass::Loopback),
            ("fe80::1", AddrClass::LinkLocal),
            ("febf::1", AddrClass::LinkLocal),
            ("fd00::1", AddrClass::Private),
            ("fc00::1", AddrClass::Private),
            ("ff02::fb", AddrClass::Multicast),
            ("2001:db8::1", AddrClass::Documentation),
            ("2606:4700::1", AddrClass::Global),
        ];
        for (addr, expected) in cases {
            assert_eq!(classify_v6(addr.parse().unwrap()), expected, "{addr}");
        }
    }

    #[test]
    fn only_routable_classes_are_probeable() {
        assert!(AddrClass::Private.is_probeable());
        assert!(AddrClass::Global.is_probeable());
        assert!(AddrClass::CarrierGrade.is_probeable());
        for c in [
            AddrClass::Loopback,
            AddrClass::Multicast,
            AddrClass::Broadcast,
            AddrClass::LinkLocal,
            AddrClass::Unspecified,
            AddrClass::Documentation,
        ] {
            assert!(!c.is_probeable(), "{c:?} must not be probed");
        }
    }
}
