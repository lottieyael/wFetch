//! Scan target planning.
//!
//! Turns user-supplied target specifications into a bounded, deduplicated,
//! deterministically ordered list of addresses to probe.
//!
//! The planner is the safety boundary of the scanner. It exists so that a
//! mistyped prefix cannot turn into a 16-million-address sweep: the plan's size
//! is computed arithmetically *before* any address is materialised, and a plan
//! that exceeds its budget is rejected rather than truncated silently.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::addr::{self, AddrClass, AddrError, IpCidr};

/// Default ceiling on plan size. A /16 sweep (65 534 hosts) fits; a /8 does not.
pub const DEFAULT_MAX_HOSTS: u64 = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetError {
    #[error(transparent)]
    Addr(#[from] AddrError),
    #[error("empty target specification")]
    Empty,
    #[error("target range is malformed: {0}")]
    MalformedRange(String),
    #[error("range endpoints must be the same address family: {start} and {end}")]
    MixedFamily { start: IpAddr, end: IpAddr },
    #[error("range start {start} is greater than end {end}")]
    ReversedRange { start: IpAddr, end: IpAddr },
    #[error(
        "plan covers {requested} addresses, which exceeds the limit of {limit}; \
         narrow the target or raise the limit explicitly"
    )]
    TooLarge { requested: u64, limit: u64 },
}

/// A single user-supplied target specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TargetSpec {
    /// A CIDR block. Enumerates probeable hosts only.
    Cidr(IpCidr),
    /// An inclusive address range.
    Range { start: IpAddr, end: IpAddr },
    /// A single address.
    Single(IpAddr),
}

impl TargetSpec {
    /// Number of addresses this spec contributes, before deduplication.
    pub fn size(&self) -> u64 {
        match self {
            TargetSpec::Single(_) => 1,
            TargetSpec::Cidr(c) => c.host_count(),
            TargetSpec::Range { start, end } => match (start, end) {
                (IpAddr::V4(s), IpAddr::V4(e)) => {
                    (u32::from(*e) as u64) - (u32::from(*s) as u64) + 1
                }
                (IpAddr::V6(s), IpAddr::V6(e)) => {
                    let span = u128::from(*e) - u128::from(*s);
                    span.saturating_add(1).min(u64::MAX as u128) as u64
                }
                // Mixed-family ranges are rejected at construction time.
                _ => 0,
            },
        }
    }

    /// Expands the spec, appending to `out`.
    fn expand_into(&self, out: &mut Vec<IpAddr>) {
        match self {
            TargetSpec::Single(a) => out.push(*a),
            TargetSpec::Cidr(IpCidr::V4(c)) => out.extend(c.hosts().map(IpAddr::V4)),
            TargetSpec::Cidr(IpCidr::V6(c)) => out.extend(c.hosts().map(IpAddr::V6)),
            TargetSpec::Range { start, end } => match (start, end) {
                (IpAddr::V4(s), IpAddr::V4(e)) => {
                    let (s, e) = (u32::from(*s), u32::from(*e));
                    // Inclusive walk that cannot wrap at u32::MAX.
                    let mut cur = s;
                    loop {
                        out.push(IpAddr::V4(Ipv4Addr::from(cur)));
                        if cur == e {
                            break;
                        }
                        cur += 1;
                    }
                }
                (IpAddr::V6(s), IpAddr::V6(e)) => {
                    let (s, e) = (u128::from(*s), u128::from(*e));
                    let mut cur = s;
                    loop {
                        out.push(IpAddr::V6(Ipv6Addr::from(cur)));
                        if cur == e {
                            break;
                        }
                        cur += 1;
                    }
                }
                _ => {}
            },
        }
    }
}

impl FromStr for TargetSpec {
    type Err = TargetError;

    /// Accepts:
    /// * `10.0.0.0/24`, `10.0.0.0/255.255.255.0`, `2001:db8::/64` — CIDR
    /// * `10.0.0.1-10.0.0.50` — explicit range
    /// * `10.0.0.1-50` — last-octet shorthand range
    /// * `10.0.0.1` — single address
    fn from_str(s: &str) -> Result<Self, TargetError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(TargetError::Empty);
        }

        if s.contains('/') {
            return Ok(TargetSpec::Cidr(s.parse::<IpCidr>()?));
        }

        // A '-' means a range, but only for IPv4-looking input: bare IPv6
        // addresses never contain '-', so this stays unambiguous.
        if let Some((lhs, rhs)) = s.split_once('-') {
            let (lhs, rhs) = (lhs.trim(), rhs.trim());
            let start = IpAddr::from_str(lhs)
                .map_err(|_| TargetError::Addr(AddrError::InvalidIp(lhs.to_string())))?;

            let end = if let Ok(end) = IpAddr::from_str(rhs) {
                end
            } else if let (IpAddr::V4(s4), Ok(last)) = (start, rhs.parse::<u8>()) {
                // Last-octet shorthand: 10.0.0.1-50 => 10.0.0.1 .. 10.0.0.50.
                let mut o = s4.octets();
                o[3] = last;
                IpAddr::V4(Ipv4Addr::from(o))
            } else {
                return Err(TargetError::MalformedRange(s.to_string()));
            };

            return build_range(start, end);
        }

        let addr = IpAddr::from_str(s)
            .map_err(|_| TargetError::Addr(AddrError::InvalidIp(s.to_string())))?;
        Ok(TargetSpec::Single(addr))
    }
}

fn build_range(start: IpAddr, end: IpAddr) -> Result<TargetSpec, TargetError> {
    match (start, end) {
        (IpAddr::V4(s), IpAddr::V4(e)) => {
            if u32::from(s) > u32::from(e) {
                return Err(TargetError::ReversedRange { start, end });
            }
        }
        (IpAddr::V6(s), IpAddr::V6(e)) => {
            if u128::from(s) > u128::from(e) {
                return Err(TargetError::ReversedRange { start, end });
            }
        }
        _ => return Err(TargetError::MixedFamily { start, end }),
    }
    Ok(TargetSpec::Range { start, end })
}

/// Builds a [`TargetPlan`] from specs, exclusions and limits.
#[derive(Debug, Clone)]
pub struct TargetPlanBuilder {
    specs: Vec<TargetSpec>,
    exclusions: Vec<TargetSpec>,
    max_hosts: u64,
    allow_non_probeable: bool,
}

impl Default for TargetPlanBuilder {
    fn default() -> Self {
        Self {
            specs: Vec::new(),
            exclusions: Vec::new(),
            max_hosts: DEFAULT_MAX_HOSTS,
            allow_non_probeable: false,
        }
    }
}

impl TargetPlanBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn include(mut self, spec: TargetSpec) -> Self {
        self.specs.push(spec);
        self
    }

    pub fn exclude(mut self, spec: TargetSpec) -> Self {
        self.exclusions.push(spec);
        self
    }

    /// Raises or lowers the ceiling on plan size.
    pub fn max_hosts(mut self, max: u64) -> Self {
        self.max_hosts = max;
        self
    }

    /// Permits loopback, link-local, multicast and broadcast addresses in the
    /// plan. Off by default; the test harness turns it on to scan 127.0.0.0/8.
    pub fn allow_non_probeable(mut self, allow: bool) -> Self {
        self.allow_non_probeable = allow;
        self
    }

    /// Upper bound on the plan size before deduplication.
    ///
    /// Computed arithmetically, so this is safe to call on specs far too large
    /// to enumerate.
    pub fn upper_bound(&self) -> u64 {
        self.specs
            .iter()
            .fold(0u64, |acc, s| acc.saturating_add(s.size()))
    }

    /// Materialises the plan, rejecting it if it exceeds the host limit.
    pub fn build(self) -> Result<TargetPlan, TargetError> {
        if self.specs.is_empty() {
            return Err(TargetError::Empty);
        }

        // Check the arithmetic bound before allocating anything. This is what
        // stops `wfetch scan 10.0.0.0/8` from trying to build a 16M-entry Vec.
        let bound = self.upper_bound();
        if bound > self.max_hosts {
            return Err(TargetError::TooLarge {
                requested: bound,
                limit: self.max_hosts,
            });
        }

        let mut raw = Vec::with_capacity(bound as usize);
        for spec in &self.specs {
            spec.expand_into(&mut raw);
        }

        // Exclusions are matched by containment rather than by expansion, so
        // excluding a /8 from a /24 scan costs nothing.
        let excluded: Vec<&TargetSpec> = self.exclusions.iter().collect();
        let allow_non_probeable = self.allow_non_probeable;

        // BTreeSet gives dedup and a deterministic (numeric, v4-before-v6) order
        // in one pass, which keeps scan output stable across runs.
        let addresses: BTreeSet<IpAddr> = raw
            .into_iter()
            .filter(|a| allow_non_probeable || addr::classify(*a).is_probeable())
            .filter(|a| !excluded.iter().any(|e| spec_contains(e, *a)))
            .collect();

        Ok(TargetPlan {
            addresses: addresses.into_iter().collect(),
            specs: self.specs,
        })
    }
}

/// Whether a spec covers an address, without expanding it.
fn spec_contains(spec: &TargetSpec, addr: IpAddr) -> bool {
    match spec {
        TargetSpec::Single(a) => *a == addr,
        TargetSpec::Cidr(c) => c.contains(addr),
        TargetSpec::Range { start, end } => match (start, end, addr) {
            (IpAddr::V4(s), IpAddr::V4(e), IpAddr::V4(a)) => {
                (u32::from(*s)..=u32::from(*e)).contains(&u32::from(a))
            }
            (IpAddr::V6(s), IpAddr::V6(e), IpAddr::V6(a)) => {
                (u128::from(*s)..=u128::from(*e)).contains(&u128::from(a))
            }
            _ => false,
        },
    }
}

/// A bounded, deduplicated, ordered set of addresses to probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetPlan {
    addresses: Vec<IpAddr>,
    specs: Vec<TargetSpec>,
}

impl TargetPlan {
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// The specs this plan was built from, for reporting.
    pub fn specs(&self) -> &[TargetSpec] {
        &self.specs
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        self.addresses.binary_search(&addr).is_ok()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, IpAddr> {
        self.addresses.iter()
    }

    /// Splits the plan into `n` roughly equal chunks for parallel workers.
    ///
    /// Chunks are strided rather than contiguous so that each worker's traffic
    /// is spread across the address space instead of hammering one /24 at a
    /// time, which is gentler on switch ARP tables.
    pub fn stripe(&self, n: usize) -> Vec<Vec<IpAddr>> {
        if n == 0 {
            return vec![];
        }
        let mut out = vec![Vec::new(); n];
        for (i, a) in self.addresses.iter().enumerate() {
            out[i % n].push(*a);
        }
        out
    }
}

impl<'a> IntoIterator for &'a TargetPlan {
    type Item = &'a IpAddr;
    type IntoIter = std::slice::Iter<'a, IpAddr>;
    fn into_iter(self) -> Self::IntoIter {
        self.addresses.iter()
    }
}

/// Classifies an address the same way the planner does, for reporting.
pub fn class_of(addr: IpAddr) -> AddrClass {
    addr::classify(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(s: &str) -> TargetSpec {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn plan(specs: &[&str]) -> TargetPlan {
        let mut b = TargetPlanBuilder::new();
        for s in specs {
            b = b.include(spec(s));
        }
        b.build().unwrap()
    }

    // ---- spec parsing ------------------------------------------------------

    #[test]
    fn parses_each_spec_form() {
        assert!(matches!(spec("10.0.0.0/24"), TargetSpec::Cidr(_)));
        assert!(matches!(spec("10.0.0.0/255.255.255.0"), TargetSpec::Cidr(_)));
        assert!(matches!(spec("2001:db8::/64"), TargetSpec::Cidr(_)));
        assert!(matches!(spec("10.0.0.1"), TargetSpec::Single(_)));
        assert!(matches!(spec("10.0.0.1-10.0.0.9"), TargetSpec::Range { .. }));
    }

    #[test]
    fn last_octet_shorthand_expands_against_the_start_address() {
        assert_eq!(
            spec("10.0.0.5-9"),
            TargetSpec::Range {
                start: ip("10.0.0.5"),
                end: ip("10.0.0.9"),
            }
        );
        // The shorthand must not leak into the upper octets.
        assert_eq!(
            spec("192.168.7.10-20"),
            TargetSpec::Range {
                start: ip("192.168.7.10"),
                end: ip("192.168.7.20"),
            }
        );
    }

    #[test]
    fn rejects_malformed_specs() {
        for bad in [
            "",
            "   ",
            "nonsense",
            "10.0.0.0/33",
            "10.0.0.5-1",              // reversed
            "10.0.0.1-2001:db8::1",    // mixed family
            "10.0.0.1-999",            // shorthand out of octet range
            "-10.0.0.1",               // no start
        ] {
            assert!(bad.parse::<TargetSpec>().is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn reversed_and_mixed_ranges_report_distinct_errors() {
        assert!(matches!(
            "10.0.0.5-10.0.0.1".parse::<TargetSpec>(),
            Err(TargetError::ReversedRange { .. })
        ));
        assert!(matches!(
            "10.0.0.1-2001:db8::5".parse::<TargetSpec>(),
            Err(TargetError::MixedFamily { .. })
        ));
    }

    // ---- size arithmetic ---------------------------------------------------

    #[test]
    fn spec_size_matches_actual_expansion() {
        for s in [
            "10.0.0.0/24",
            "10.0.0.0/30",
            "10.0.0.0/31",
            "10.0.0.1/32",
            "10.0.0.1",
            "10.0.0.1-10.0.0.50",
            "10.0.0.7-7",
        ] {
            let sp = spec(s);
            let mut out = Vec::new();
            sp.expand_into(&mut out);
            assert_eq!(out.len() as u64, sp.size(), "size mismatch for {s}");
        }
    }

    #[test]
    fn single_element_range_yields_exactly_one_address() {
        let sp = spec("10.0.0.7-10.0.0.7");
        assert_eq!(sp.size(), 1);
        let mut out = Vec::new();
        sp.expand_into(&mut out);
        assert_eq!(out, vec![ip("10.0.0.7")]);
    }

    #[test]
    fn range_expansion_does_not_wrap_at_the_top_of_the_space() {
        let sp = build_range(ip("255.255.255.254"), ip("255.255.255.255")).unwrap();
        let mut out = Vec::new();
        sp.expand_into(&mut out);
        assert_eq!(out, vec![ip("255.255.255.254"), ip("255.255.255.255")]);
    }

    #[test]
    fn upper_bound_is_computed_without_expansion() {
        // A /8 is far too large to materialise; the bound must still be exact.
        let b = TargetPlanBuilder::new().include(spec("10.0.0.0/8"));
        assert_eq!(b.upper_bound(), (1u64 << 24) - 2);
    }

    // ---- plan limits -------------------------------------------------------

    #[test]
    fn oversized_plans_are_rejected_rather_than_truncated() {
        let err = TargetPlanBuilder::new()
            .include(spec("10.0.0.0/8"))
            .build()
            .unwrap_err();
        match err {
            TargetError::TooLarge { requested, limit } => {
                assert_eq!(requested, (1u64 << 24) - 2);
                assert_eq!(limit, DEFAULT_MAX_HOSTS);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn the_limit_can_be_raised_explicitly() {
        let p = TargetPlanBuilder::new()
            .include(spec("10.0.0.0/16"))
            .max_hosts(100_000)
            .build()
            .unwrap();
        assert_eq!(p.len(), 65_534);
    }

    #[test]
    fn a_16_bit_sweep_fits_under_the_default_limit() {
        assert!(TargetPlanBuilder::new()
            .include(spec("10.0.0.0/16"))
            .build()
            .is_ok());
    }

    #[test]
    fn empty_plans_are_rejected() {
        assert!(matches!(
            TargetPlanBuilder::new().build(),
            Err(TargetError::Empty)
        ));
    }

    // ---- deduplication, ordering, filtering --------------------------------

    #[test]
    fn overlapping_specs_are_deduplicated() {
        let p = plan(&["10.0.0.0/24", "10.0.0.0/25", "10.0.0.5"]);
        // The /25 and the single address are wholly inside the /24's host set.
        assert_eq!(p.len(), 254);
        assert_eq!(
            p.addresses().iter().collect::<BTreeSet<_>>().len(),
            p.len(),
            "plan contains duplicates"
        );
    }

    #[test]
    fn addresses_are_returned_in_ascending_numeric_order() {
        let p = plan(&["10.0.0.20-10.0.0.22", "10.0.0.1-10.0.0.3"]);
        assert_eq!(
            p.addresses(),
            &[
                ip("10.0.0.1"),
                ip("10.0.0.2"),
                ip("10.0.0.3"),
                ip("10.0.0.20"),
                ip("10.0.0.21"),
                ip("10.0.0.22"),
            ]
        );
    }

    #[test]
    fn ordering_is_numeric_not_lexicographic() {
        // "10.0.0.9" sorts after "10.0.0.10" as a string but before it as an
        // address; getting this wrong makes scan output non-monotonic.
        let p = plan(&["10.0.0.9-10.0.0.11"]);
        assert_eq!(
            p.addresses(),
            &[ip("10.0.0.9"), ip("10.0.0.10"), ip("10.0.0.11")]
        );
    }

    #[test]
    fn plan_construction_is_deterministic() {
        let a = plan(&["10.0.0.0/28", "10.0.0.5", "10.0.0.1-10.0.0.3"]);
        let b = plan(&["10.0.0.1-10.0.0.3", "10.0.0.5", "10.0.0.0/28"]);
        assert_eq!(a.addresses(), b.addresses());
    }

    #[test]
    fn non_probeable_addresses_are_filtered_out_by_default() {
        let p = TargetPlanBuilder::new()
            .include(spec("127.0.0.1"))
            .include(spec("169.254.0.1"))
            .include(spec("224.0.0.251"))
            .include(spec("255.255.255.255"))
            .include(spec("10.0.0.1"))
            .build()
            .unwrap();
        assert_eq!(p.addresses(), &[ip("10.0.0.1")]);
    }

    #[test]
    fn non_probeable_addresses_can_be_opted_into() {
        let p = TargetPlanBuilder::new()
            .include(spec("127.0.0.1-127.0.0.3"))
            .allow_non_probeable(true)
            .build()
            .unwrap();
        assert_eq!(p.len(), 3);
    }

    #[test]
    fn cidr_expansion_already_omits_network_and_broadcast() {
        let p = plan(&["192.168.1.0/24"]);
        assert!(!p.contains(ip("192.168.1.0")));
        assert!(!p.contains(ip("192.168.1.255")));
        assert!(p.contains(ip("192.168.1.1")));
        assert!(p.contains(ip("192.168.1.254")));
    }

    // ---- exclusions --------------------------------------------------------

    #[test]
    fn exclusions_remove_addresses_from_the_plan() {
        let p = TargetPlanBuilder::new()
            .include(spec("10.0.0.0/24"))
            .exclude(spec("10.0.0.100-10.0.0.199"))
            .build()
            .unwrap();
        assert_eq!(p.len(), 154);
        assert!(!p.contains(ip("10.0.0.150")));
        assert!(p.contains(ip("10.0.0.99")));
        assert!(p.contains(ip("10.0.0.200")));
    }

    #[test]
    fn exclusions_are_matched_by_containment_not_expansion() {
        // Excluding a /8 must not cost 16M operations.
        let p = TargetPlanBuilder::new()
            .include(spec("10.0.0.0/24"))
            .exclude(spec("10.0.0.0/8"))
            .build()
            .unwrap();
        assert!(p.is_empty());
    }

    #[test]
    fn excluding_a_single_address_leaves_the_rest_intact() {
        let p = TargetPlanBuilder::new()
            .include(spec("10.0.0.0/29"))
            .exclude(spec("10.0.0.3"))
            .build()
            .unwrap();
        assert!(!p.contains(ip("10.0.0.3")));
        assert_eq!(p.len(), 5); // 6 hosts in a /29, minus one excluded
    }

    // ---- striping ----------------------------------------------------------

    #[test]
    fn striping_partitions_the_plan_without_loss_or_duplication() {
        let p = plan(&["10.0.0.0/24"]);
        for n in [1usize, 2, 3, 7, 16, 254, 255, 1000] {
            let stripes = p.stripe(n);
            assert_eq!(stripes.len(), n, "stripe count for n={n}");
            let total: usize = stripes.iter().map(|s| s.len()).sum();
            assert_eq!(total, p.len(), "address lost or duplicated for n={n}");
            let flat: BTreeSet<IpAddr> = stripes.iter().flatten().copied().collect();
            assert_eq!(flat.len(), p.len(), "duplicate across stripes for n={n}");
        }
    }

    #[test]
    fn stripes_are_balanced_to_within_one_address() {
        let p = plan(&["10.0.0.0/24"]);
        let stripes = p.stripe(7);
        let min = stripes.iter().map(|s| s.len()).min().unwrap();
        let max = stripes.iter().map(|s| s.len()).max().unwrap();
        assert!(max - min <= 1, "unbalanced stripes: {min}..{max}");
    }

    #[test]
    fn striping_by_zero_is_not_a_panic() {
        assert!(plan(&["10.0.0.0/30"]).stripe(0).is_empty());
    }

    // ---- lookup ------------------------------------------------------------

    #[test]
    fn contains_agrees_with_the_address_list() {
        let p = plan(&["10.0.0.0/25"]);
        for a in p.addresses() {
            assert!(p.contains(*a));
        }
        assert!(!p.contains(ip("10.0.0.200")));
        assert!(!p.contains(ip("2001:db8::1")));
    }

    // ---- IPv6 --------------------------------------------------------------

    #[test]
    fn small_v6_blocks_plan_correctly() {
        let p = TargetPlanBuilder::new()
            .include(spec("fd00::/125"))
            .build()
            .unwrap();
        // No broadcast concept in v6: all 8 addresses are enumerated.
        assert_eq!(p.len(), 8);
        assert!(p.contains(ip("fd00::")));
        assert!(p.contains(ip("fd00::7")));
    }

    #[test]
    fn a_v6_slash_64_is_refused_as_too_large() {
        let err = TargetPlanBuilder::new()
            .include(spec("2001:db8::/64"))
            .max_hosts(1_000_000)
            .build()
            .unwrap_err();
        assert!(matches!(err, TargetError::TooLarge { .. }));
    }

    #[test]
    fn mixed_family_plans_order_v4_before_v6() {
        let p = TargetPlanBuilder::new()
            .include(spec("10.0.0.1"))
            .include(spec("fd00::1"))
            .build()
            .unwrap();
        assert_eq!(p.addresses(), &[ip("10.0.0.1"), ip("fd00::1")]);
    }
}
