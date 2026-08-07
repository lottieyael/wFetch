//! What a scan found, and why it believes it.
//!
//! Every conclusion carries the evidence that produced it. A scanner that
//! reports "host up" with no reason is impossible to debug on someone else's
//! network, and impossible for an agent consuming the JSON to reason about: a
//! host found only in a stale ARP entry deserves less trust than one that
//! completed a TCP handshake, and the output has to say which happened.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::mac::MacAddr;
use crate::platform::NeighborState;
use crate::proto::mdns::MdnsInfo;
use crate::proto::netbios::NodeStatus;
use crate::proto::ssdp::SsdpResponse;

/// A single observation supporting the conclusion that a host exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    /// The host appears in the local kernel's neighbour cache.
    NeighborTable { state: NeighborState },
    /// The host answered an ICMP echo request.
    IcmpEchoReply { rtt_micros: u64, ttl: Option<u8> },
    /// A TCP handshake completed: the port is open.
    TcpOpen { port: u16, rtt_micros: u64 },
    /// The host sent a RST. The port is closed, but the host exists — this is
    /// as strong a liveness proof as an open port, and it is the only signal
    /// available on hosts that drop ICMP and run no services.
    TcpClosed { port: u16 },
    /// The host answered an mDNS query.
    Mdns,
    /// The host answered an SSDP M-SEARCH.
    Ssdp,
    /// The host answered a NetBIOS node status query.
    NetbiosNodeStatus,
    /// A reverse DNS record resolved for the address. Weak on its own: the
    /// record can outlive the host by months.
    ReverseDns { name: String },
}

impl Evidence {
    /// How strongly this observation implies a host is present right now.
    ///
    /// The weights are ordinal, used only to rank confidence and to pick a
    /// winner when signals disagree.
    pub fn weight(&self) -> u32 {
        match self {
            // A completed handshake or an ICMP reply is proof of life.
            Evidence::TcpOpen { .. } => 100,
            Evidence::IcmpEchoReply { .. } => 95,
            // A RST is equally conclusive: something answered.
            Evidence::TcpClosed { .. } => 90,
            // Service responses are proof too, and far more informative.
            Evidence::Mdns => 85,
            Evidence::Ssdp => 85,
            Evidence::NetbiosNodeStatus => 85,
            // A neighbour entry proves recent link-layer presence, but a stale
            // one can survive the host being unplugged.
            Evidence::NeighborTable { state } => match state {
                NeighborState::Reachable | NeighborState::Permanent => 80,
                NeighborState::Stale | NeighborState::Delay | NeighborState::Probe => 55,
                _ => 0,
            },
            // A DNS record proves only that someone once wrote one down.
            Evidence::ReverseDns { .. } => 20,
        }
    }

    /// Whether this observation alone justifies reporting the host as up.
    pub fn is_conclusive(&self) -> bool {
        self.weight() >= 80
    }

    /// A short label for table output.
    pub fn label(&self) -> &'static str {
        match self {
            Evidence::NeighborTable { .. } => "arp",
            Evidence::IcmpEchoReply { .. } => "icmp",
            Evidence::TcpOpen { .. } => "tcp",
            Evidence::TcpClosed { .. } => "rst",
            Evidence::Mdns => "mdns",
            Evidence::Ssdp => "ssdp",
            Evidence::NetbiosNodeStatus => "netbios",
            Evidence::ReverseDns { .. } => "dns",
        }
    }
}

/// How confident the scan is that a host exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Something answered us directly.
    Confirmed,
    /// Indirect evidence only, such as a stale neighbour entry.
    Probable,
    /// Weak evidence only, such as a DNS record.
    Possible,
}

/// One host found by a scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Host {
    pub ip: IpAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub confidence: Confidence,
    /// Everything observed about this host, in discovery order.
    pub evidence: Vec<Evidence>,
    /// Ports found open, ascending.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_ports: Vec<u16>,
    /// Best round-trip time observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_micros: Option<u64>,
    /// IP TTL of a reply, which hints at the OS family.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mdns: Option<MdnsInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssdp: Vec<SsdpResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netbios: Option<NodeStatus>,
    /// What the fingerprinter concluded, filled in after discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<crate::fingerprint::DeviceIdentity>,
}

impl Host {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            mac: None,
            hostname: None,
            confidence: Confidence::Possible,
            evidence: Vec::new(),
            open_ports: Vec::new(),
            rtt_micros: None,
            ttl: None,
            mdns: None,
            ssdp: Vec::new(),
            netbios: None,
            identity: None,
        }
    }

    /// Records an observation and updates the derived fields.
    pub fn add_evidence(&mut self, e: Evidence) {
        match &e {
            Evidence::TcpOpen { port, rtt_micros } => {
                if !self.open_ports.contains(port) {
                    self.open_ports.push(*port);
                    self.open_ports.sort_unstable();
                }
                self.observe_rtt(*rtt_micros);
            }
            Evidence::IcmpEchoReply { rtt_micros, ttl } => {
                self.observe_rtt(*rtt_micros);
                if self.ttl.is_none() {
                    self.ttl = *ttl;
                }
            }
            Evidence::ReverseDns { name } => {
                if self.hostname.is_none() {
                    self.hostname = Some(name.clone());
                }
            }
            _ => {}
        }

        // Duplicate observations add nothing; the same port probed twice on
        // retry should not appear twice in the evidence list.
        if !self.evidence.contains(&e) {
            self.evidence.push(e);
        }
        self.recompute_confidence();
    }

    /// Keeps the fastest round trip seen, which is the best estimate of the
    /// true path latency.
    fn observe_rtt(&mut self, micros: u64) {
        self.rtt_micros = Some(match self.rtt_micros {
            Some(existing) => existing.min(micros),
            None => micros,
        });
    }

    fn recompute_confidence(&mut self) {
        let best = self.evidence.iter().map(Evidence::weight).max().unwrap_or(0);
        self.confidence = if best >= 80 {
            Confidence::Confirmed
        } else if best >= 50 {
            Confidence::Probable
        } else {
            Confidence::Possible
        };
    }

    /// The strongest evidence weight backing this host.
    pub fn evidence_weight(&self) -> u32 {
        self.evidence.iter().map(Evidence::weight).max().unwrap_or(0)
    }

    /// Whether any observation justifies reporting this host at all.
    ///
    /// Filters out neighbour entries in `Failed` or `Incomplete` state, which
    /// are records of an ARP attempt that got no answer.
    pub fn is_reportable(&self) -> bool {
        self.evidence.iter().any(|e| e.weight() > 0)
    }

    pub fn rtt(&self) -> Option<Duration> {
        self.rtt_micros.map(Duration::from_micros)
    }

    /// Merges another observation of the same address into this one.
    pub fn merge(&mut self, other: Host) {
        debug_assert_eq!(self.ip, other.ip);

        if self.mac.is_none() {
            self.mac = other.mac;
        }
        if self.hostname.is_none() {
            self.hostname = other.hostname;
        }
        if self.ttl.is_none() {
            self.ttl = other.ttl;
        }
        if let Some(rtt) = other.rtt_micros {
            self.observe_rtt(rtt);
        }
        if self.mdns.is_none() {
            self.mdns = other.mdns;
        }
        if self.netbios.is_none() {
            self.netbios = other.netbios;
        }
        for s in other.ssdp {
            if !self.ssdp.contains(&s) {
                self.ssdp.push(s);
            }
        }
        for p in other.open_ports {
            if !self.open_ports.contains(&p) {
                self.open_ports.push(p);
            }
        }
        self.open_ports.sort_unstable();
        for e in other.evidence {
            if !self.evidence.contains(&e) {
                self.evidence.push(e);
            }
        }
        self.recompute_confidence();
    }
}

/// The complete result of a scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    /// Hosts found, ordered by address.
    pub hosts: Vec<Host>,
    /// How many addresses were probed.
    pub addresses_probed: usize,
    pub duration_micros: u64,
    /// Techniques that actually ran, after capability filtering.
    pub techniques_used: Vec<String>,
    /// Techniques that were requested but unavailable, with the reason. This is
    /// what stops an Android scan from looking like a clean sweep of an empty
    /// network when it simply could not use half its probes.
    pub techniques_skipped: BTreeMap<String, String>,
}

impl ScanReport {
    pub fn duration(&self) -> Duration {
        Duration::from_micros(self.duration_micros)
    }

    /// Hosts the scan is confident about.
    pub fn confirmed(&self) -> impl Iterator<Item = &Host> {
        self.hosts
            .iter()
            .filter(|h| h.confidence == Confidence::Confirmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // ---- evidence weighting ------------------------------------------------

    #[test]
    fn a_tcp_reset_is_as_conclusive_as_an_open_port() {
        // A RST proves something answered. On a host that drops ICMP and runs
        // no services it is the only liveness signal available, so treating it
        // as weak would make such hosts invisible.
        assert!(Evidence::TcpClosed { port: 80 }.is_conclusive());
        assert!(Evidence::TcpOpen {
            port: 80,
            rtt_micros: 1
        }
        .is_conclusive());
    }

    #[test]
    fn failed_neighbour_entries_carry_no_weight() {
        // These record an ARP attempt that got no answer; counting them would
        // report every address the host ever tried to reach as alive.
        for state in [
            NeighborState::Incomplete,
            NeighborState::Failed,
            NeighborState::NoArp,
            NeighborState::Unknown,
        ] {
            assert_eq!(
                Evidence::NeighborTable { state }.weight(),
                0,
                "{state:?} must carry no weight"
            );
        }
    }

    #[test]
    fn a_stale_neighbour_entry_is_weaker_than_a_reachable_one() {
        let stale = Evidence::NeighborTable {
            state: NeighborState::Stale,
        };
        let reachable = Evidence::NeighborTable {
            state: NeighborState::Reachable,
        };
        assert!(stale.weight() < reachable.weight());
        assert!(!stale.is_conclusive(), "a stale entry can outlive the host");
        assert!(reachable.is_conclusive());
    }

    #[test]
    fn reverse_dns_alone_is_never_conclusive() {
        // A PTR record can outlive the host it names by months.
        let e = Evidence::ReverseDns {
            name: "gone.local".to_string(),
        };
        assert!(!e.is_conclusive());
        assert!(e.weight() > 0, "but it is still worth reporting");
    }

    // ---- confidence derivation ---------------------------------------------

    #[test]
    fn confidence_follows_the_strongest_evidence() {
        let mut h = Host::new(ip("10.0.0.1"));
        h.add_evidence(Evidence::ReverseDns {
            name: "x".to_string(),
        });
        assert_eq!(h.confidence, Confidence::Possible);

        h.add_evidence(Evidence::NeighborTable {
            state: NeighborState::Stale,
        });
        assert_eq!(h.confidence, Confidence::Probable);

        h.add_evidence(Evidence::IcmpEchoReply {
            rtt_micros: 500,
            ttl: Some(64),
        });
        assert_eq!(h.confidence, Confidence::Confirmed);
    }

    #[test]
    fn weak_evidence_never_downgrades_an_already_confirmed_host() {
        let mut h = Host::new(ip("10.0.0.1"));
        h.add_evidence(Evidence::TcpOpen {
            port: 22,
            rtt_micros: 100,
        });
        assert_eq!(h.confidence, Confidence::Confirmed);
        h.add_evidence(Evidence::ReverseDns {
            name: "x".to_string(),
        });
        assert_eq!(h.confidence, Confidence::Confirmed);
    }

    #[test]
    fn a_host_with_only_failed_arp_evidence_is_not_reportable() {
        let mut h = Host::new(ip("10.0.0.99"));
        h.add_evidence(Evidence::NeighborTable {
            state: NeighborState::Incomplete,
        });
        assert!(!h.is_reportable());
    }

    // ---- derived fields ----------------------------------------------------

    #[test]
    fn open_ports_accumulate_sorted_and_deduplicated() {
        let mut h = Host::new(ip("10.0.0.1"));
        for p in [443u16, 22, 80, 22] {
            h.add_evidence(Evidence::TcpOpen {
                port: p,
                rtt_micros: 1000,
            });
        }
        assert_eq!(h.open_ports, vec![22, 80, 443]);
    }

    #[test]
    fn duplicate_evidence_is_not_recorded_twice() {
        // Retries re-probe the same port; the evidence list must not grow.
        let mut h = Host::new(ip("10.0.0.1"));
        let e = Evidence::TcpOpen {
            port: 22,
            rtt_micros: 100,
        };
        h.add_evidence(e.clone());
        h.add_evidence(e.clone());
        h.add_evidence(e);
        assert_eq!(h.evidence.len(), 1);
    }

    #[test]
    fn the_fastest_round_trip_is_kept() {
        let mut h = Host::new(ip("10.0.0.1"));
        h.add_evidence(Evidence::TcpOpen {
            port: 80,
            rtt_micros: 5000,
        });
        h.add_evidence(Evidence::TcpOpen {
            port: 443,
            rtt_micros: 900,
        });
        h.add_evidence(Evidence::TcpOpen {
            port: 22,
            rtt_micros: 3000,
        });
        assert_eq!(h.rtt_micros, Some(900));
        assert_eq!(h.rtt(), Some(Duration::from_micros(900)));
    }

    #[test]
    fn reverse_dns_supplies_a_hostname_when_none_is_known() {
        let mut h = Host::new(ip("10.0.0.1"));
        h.add_evidence(Evidence::ReverseDns {
            name: "nas.lan".to_string(),
        });
        assert_eq!(h.hostname.as_deref(), Some("nas.lan"));
    }

    // ---- merging -----------------------------------------------------------

    #[test]
    fn merging_combines_evidence_ports_and_identity_fields() {
        let mut a = Host::new(ip("10.0.0.1"));
        a.add_evidence(Evidence::TcpOpen {
            port: 22,
            rtt_micros: 2000,
        });

        let mut b = Host::new(ip("10.0.0.1"));
        b.mac = Some("aa:bb:cc:dd:ee:ff".parse().unwrap());
        b.hostname = Some("host.lan".to_string());
        b.ttl = Some(64);
        b.add_evidence(Evidence::TcpOpen {
            port: 443,
            rtt_micros: 500,
        });

        a.merge(b);
        assert_eq!(a.open_ports, vec![22, 443]);
        assert_eq!(a.evidence.len(), 2);
        assert_eq!(a.mac, Some("aa:bb:cc:dd:ee:ff".parse().unwrap()));
        assert_eq!(a.hostname.as_deref(), Some("host.lan"));
        assert_eq!(a.ttl, Some(64));
        assert_eq!(a.rtt_micros, Some(500), "should keep the faster RTT");
    }

    #[test]
    fn merging_does_not_overwrite_information_already_present() {
        let mut a = Host::new(ip("10.0.0.1"));
        a.hostname = Some("first".to_string());
        a.mac = Some("11:22:33:44:55:66".parse().unwrap());

        let mut b = Host::new(ip("10.0.0.1"));
        b.hostname = Some("second".to_string());
        b.mac = Some("aa:bb:cc:dd:ee:ff".parse().unwrap());

        a.merge(b);
        assert_eq!(a.hostname.as_deref(), Some("first"));
        assert_eq!(a.mac, Some("11:22:33:44:55:66".parse().unwrap()));
    }

    #[test]
    fn merging_recomputes_confidence_from_the_combined_evidence() {
        let mut a = Host::new(ip("10.0.0.1"));
        a.add_evidence(Evidence::ReverseDns {
            name: "x".to_string(),
        });
        assert_eq!(a.confidence, Confidence::Possible);

        let mut b = Host::new(ip("10.0.0.1"));
        b.add_evidence(Evidence::Mdns);

        a.merge(b);
        assert_eq!(a.confidence, Confidence::Confirmed);
    }

    #[test]
    fn merging_is_idempotent() {
        let mut a = Host::new(ip("10.0.0.1"));
        a.add_evidence(Evidence::TcpOpen {
            port: 80,
            rtt_micros: 100,
        });
        let snapshot = a.clone();
        a.merge(snapshot.clone());
        assert_eq!(a.evidence.len(), 1);
        assert_eq!(a.open_ports, vec![80]);
        assert_eq!(a, snapshot);
    }

    // ---- serialisation -----------------------------------------------------

    #[test]
    fn empty_optional_fields_are_omitted_from_json() {
        // Agents parse this output; absent fields should not appear as nulls.
        let h = Host::new(ip("10.0.0.1"));
        let j = serde_json::to_value(&h).unwrap();
        assert!(j.get("mac").is_none());
        assert!(j.get("hostname").is_none());
        assert!(j.get("open_ports").is_none());
        assert!(j.get("ip").is_some());
        assert!(j.get("confidence").is_some());
    }

    #[test]
    fn evidence_serialises_with_a_discriminating_tag() {
        let e = Evidence::TcpOpen {
            port: 22,
            rtt_micros: 500,
        };
        let j = serde_json::to_value(&e).unwrap();
        assert_eq!(j["kind"], "tcp_open");
        assert_eq!(j["port"], 22);
        // And it round-trips.
        assert_eq!(serde_json::from_value::<Evidence>(j).unwrap(), e);
    }

    #[test]
    fn a_host_round_trips_through_json() {
        let mut h = Host::new(ip("192.168.1.5"));
        h.mac = Some("aa:bb:cc:dd:ee:ff".parse().unwrap());
        h.add_evidence(Evidence::TcpOpen {
            port: 445,
            rtt_micros: 1200,
        });
        h.add_evidence(Evidence::NetbiosNodeStatus);
        let j = serde_json::to_string(&h).unwrap();
        assert_eq!(serde_json::from_str::<Host>(&j).unwrap(), h);
    }
}
