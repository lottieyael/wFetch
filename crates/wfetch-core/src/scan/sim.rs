//! A simulated network for testing the engine.
//!
//! The engine's scheduling, retry, merging and confidence logic needs to be
//! tested against situations that are awkward or impossible to build for real:
//! a host that answers only every third probe, a firewall that drops SYNs
//! silently, a responder that claims an address it does not own. This transport
//! provides exactly those, deterministically.
//!
//! It complements rather than replaces the real-network tests: the namespace
//! harness in `tests/` proves the probes work against a real kernel, and this
//! proves the engine reasons correctly about what they return.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use crate::proto::{mdns, netbios, ssdp};

use super::transport::{EchoOutcome, MulticastReply, TcpOutcome, Transport};

/// How a simulated host behaves.
#[derive(Debug, Clone, Default)]
pub struct SimHost {
    /// Ports that complete a handshake.
    pub open_ports: Vec<u16>,
    /// Whether the host answers ICMP echo.
    pub answers_icmp: bool,
    /// Round-trip time to report.
    pub rtt: Duration,
    /// IP TTL to report on echo replies.
    pub ttl: Option<u8>,
    /// When true, unopened ports time out instead of sending a RST — a
    /// firewalled host rather than a bare one.
    pub drops_closed_ports: bool,
    pub mdns: Option<mdns::MdnsInfo>,
    pub ssdp: Vec<ssdp::SsdpResponse>,
    pub netbios: Option<netbios::NodeStatus>,
    pub reverse_dns: Option<String>,
    /// Answer only one probe in every `n`; 1 means always. Models a host under
    /// load or a network dropping packets.
    pub answer_every: u32,
}

impl SimHost {
    /// A host that answers everything on the given ports.
    pub fn responsive(ports: &[u16]) -> Self {
        Self {
            open_ports: ports.to_vec(),
            answers_icmp: true,
            rtt: Duration::from_millis(1),
            ttl: Some(64),
            answer_every: 1,
            ..Default::default()
        }
    }

    /// A host that exists but drops everything: no ICMP, no RSTs, no services.
    /// Nothing can find it, which is a case the engine must report honestly.
    pub fn silent() -> Self {
        Self {
            answers_icmp: false,
            drops_closed_ports: true,
            answer_every: 1,
            ..Default::default()
        }
    }

    pub fn with_icmp(mut self, answers: bool) -> Self {
        self.answers_icmp = answers;
        self
    }

    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    pub fn firewalled(mut self) -> Self {
        self.drops_closed_ports = true;
        self
    }

    pub fn with_mdns(mut self, info: mdns::MdnsInfo) -> Self {
        self.mdns = Some(info);
        self
    }

    pub fn with_netbios(mut self, status: netbios::NodeStatus) -> Self {
        self.netbios = Some(status);
        self
    }

    pub fn with_reverse_dns(mut self, name: &str) -> Self {
        self.reverse_dns = Some(name.to_string());
        self
    }

    /// Answers only one probe in every `n`.
    pub fn flaky(mut self, answer_every: u32) -> Self {
        self.answer_every = answer_every.max(1);
        self
    }
}

/// A deterministic fake network.
pub struct SimTransport {
    hosts: HashMap<IpAddr, SimHost>,
    /// Per-address probe counters, driving the flakiness model.
    counters: Mutex<HashMap<IpAddr, u32>>,
    /// Total probes issued, so tests can assert on scan cost.
    probe_count: AtomicU64,
    /// When set, every capability-gated probe reports this error.
    icmp_error: Option<io::ErrorKind>,
    multicast_error: Option<io::ErrorKind>,
}

impl SimTransport {
    pub fn new() -> Self {
        Self {
            hosts: HashMap::new(),
            counters: Mutex::new(HashMap::new()),
            probe_count: AtomicU64::new(0),
            icmp_error: None,
            multicast_error: None,
        }
    }

    pub fn with_host(mut self, addr: &str, host: SimHost) -> Self {
        self.hosts.insert(addr.parse().unwrap(), host);
        self
    }

    /// Makes ICMP unavailable, as on an unprivileged host.
    pub fn without_icmp(mut self) -> Self {
        self.icmp_error = Some(io::ErrorKind::PermissionDenied);
        self
    }

    /// Makes multicast unavailable, as on a segment that blocks it.
    pub fn without_multicast(mut self) -> Self {
        self.multicast_error = Some(io::ErrorKind::PermissionDenied);
        self
    }

    /// How many probes have been issued.
    pub fn probes_issued(&self) -> u64 {
        self.probe_count.load(Ordering::Relaxed)
    }

    /// Whether this probe should be answered, given the host's flakiness.
    fn should_answer(&self, addr: IpAddr, host: &SimHost) -> bool {
        if host.answer_every <= 1 {
            return true;
        }
        let mut counters = self.counters.lock().unwrap();
        let c = counters.entry(addr).or_insert(0);
        *c += 1;
        *c % host.answer_every == 0
    }
}

impl Default for SimTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for SimTransport {
    fn tcp_probe(&self, addr: SocketAddr, _timeout: Duration) -> TcpOutcome {
        self.probe_count.fetch_add(1, Ordering::Relaxed);
        let Some(host) = self.hosts.get(&addr.ip()) else {
            // No host at this address: silence, exactly as on a real network.
            return TcpOutcome::Filtered;
        };
        if !self.should_answer(addr.ip(), host) {
            return TcpOutcome::Filtered;
        }
        if host.open_ports.contains(&addr.port()) {
            TcpOutcome::Open { rtt: host.rtt }
        } else if host.drops_closed_ports {
            TcpOutcome::Filtered
        } else {
            TcpOutcome::Closed { rtt: host.rtt }
        }
    }

    fn icmp_echo(
        &self,
        addr: IpAddr,
        _timeout: Duration,
        _identifier: u16,
        _sequence: u16,
    ) -> io::Result<Option<EchoOutcome>> {
        if let Some(kind) = self.icmp_error {
            return Err(io::Error::new(kind, "ICMP unavailable in simulation"));
        }
        self.probe_count.fetch_add(1, Ordering::Relaxed);
        let Some(host) = self.hosts.get(&addr) else {
            return Ok(None);
        };
        if !host.answers_icmp || !self.should_answer(addr, host) {
            return Ok(None);
        }
        Ok(Some(EchoOutcome {
            rtt: host.rtt,
            ttl: host.ttl,
        }))
    }

    fn mdns_sweep(&self, _timeout: Duration) -> io::Result<Vec<MulticastReply<mdns::MdnsInfo>>> {
        if let Some(kind) = self.multicast_error {
            return Err(io::Error::new(kind, "multicast unavailable in simulation"));
        }
        self.probe_count.fetch_add(1, Ordering::Relaxed);
        let mut out: Vec<_> = self
            .hosts
            .iter()
            .filter_map(|(ip, h)| {
                h.mdns.clone().map(|payload| MulticastReply {
                    from: *ip,
                    payload,
                })
            })
            .collect();
        // HashMap iteration order is not stable; sort so scans are reproducible.
        out.sort_by_key(|r| r.from);
        Ok(out)
    }

    fn ssdp_sweep(&self, _timeout: Duration) -> io::Result<Vec<MulticastReply<ssdp::SsdpResponse>>> {
        if let Some(kind) = self.multicast_error {
            return Err(io::Error::new(kind, "multicast unavailable in simulation"));
        }
        self.probe_count.fetch_add(1, Ordering::Relaxed);
        let mut out: Vec<_> = self
            .hosts
            .iter()
            .flat_map(|(ip, h)| {
                h.ssdp.iter().map(move |r| MulticastReply {
                    from: *ip,
                    payload: r.clone(),
                })
            })
            .collect();
        out.sort_by_key(|r| r.from);
        Ok(out)
    }

    fn netbios_probe(
        &self,
        addr: IpAddr,
        _timeout: Duration,
    ) -> io::Result<Option<netbios::NodeStatus>> {
        self.probe_count.fetch_add(1, Ordering::Relaxed);
        Ok(self.hosts.get(&addr).and_then(|h| h.netbios.clone()))
    }

    fn reverse_dns(&self, addr: IpAddr) -> Option<String> {
        self.hosts.get(&addr).and_then(|h| h.reverse_dns.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sock(s: &str, port: u16) -> SocketAddr {
        SocketAddr::new(s.parse().unwrap(), port)
    }

    #[test]
    fn an_absent_address_is_silent() {
        let t = SimTransport::new();
        assert_eq!(
            t.tcp_probe(sock("10.0.0.99", 80), Duration::ZERO),
            TcpOutcome::Filtered
        );
        assert_eq!(
            t.icmp_echo("10.0.0.99".parse().unwrap(), Duration::ZERO, 1, 1)
                .unwrap(),
            None
        );
    }

    #[test]
    fn a_bare_host_rsts_closed_ports_but_a_firewalled_one_drops_them() {
        let t = SimTransport::new()
            .with_host("10.0.0.1", SimHost::responsive(&[22]))
            .with_host("10.0.0.2", SimHost::responsive(&[22]).firewalled());

        assert!(matches!(
            t.tcp_probe(sock("10.0.0.1", 9999), Duration::ZERO),
            TcpOutcome::Closed { .. }
        ));
        assert_eq!(
            t.tcp_probe(sock("10.0.0.2", 9999), Duration::ZERO),
            TcpOutcome::Filtered
        );
        // Both still answer on their open port.
        assert!(matches!(
            t.tcp_probe(sock("10.0.0.2", 22), Duration::ZERO),
            TcpOutcome::Open { .. }
        ));
    }

    #[test]
    fn a_flaky_host_answers_at_the_configured_rate() {
        let t = SimTransport::new().with_host("10.0.0.1", SimHost::responsive(&[22]).flaky(3));
        let outcomes: Vec<bool> = (0..9)
            .map(|_| t.tcp_probe(sock("10.0.0.1", 22), Duration::ZERO).proves_host())
            .collect();
        // One in three: probes 3, 6 and 9.
        assert_eq!(outcomes.iter().filter(|x| **x).count(), 3);
    }

    #[test]
    fn a_silent_host_is_undetectable() {
        // It exists, but nothing the scanner can send will reveal it. The
        // engine must report this honestly rather than inventing a host.
        let t = SimTransport::new().with_host("10.0.0.5", SimHost::silent());
        assert_eq!(
            t.tcp_probe(sock("10.0.0.5", 80), Duration::ZERO),
            TcpOutcome::Filtered
        );
        assert_eq!(
            t.icmp_echo("10.0.0.5".parse().unwrap(), Duration::ZERO, 1, 1)
                .unwrap(),
            None
        );
    }

    #[test]
    fn capability_failures_are_errors_not_empty_results() {
        let t = SimTransport::new()
            .with_host("10.0.0.1", SimHost::responsive(&[22]))
            .without_icmp()
            .without_multicast();
        assert!(t
            .icmp_echo("10.0.0.1".parse().unwrap(), Duration::ZERO, 1, 1)
            .is_err());
        assert!(t.mdns_sweep(Duration::ZERO).is_err());
        assert!(t.ssdp_sweep(Duration::ZERO).is_err());
    }

    #[test]
    fn multicast_sweeps_are_ordered_deterministically() {
        // HashMap iteration order varies per run; scans must not.
        let info = mdns::MdnsInfo {
            hostname: Some("h".into()),
            ..Default::default()
        };
        let t = SimTransport::new()
            .with_host("10.0.0.3", SimHost::responsive(&[]).with_mdns(info.clone()))
            .with_host("10.0.0.1", SimHost::responsive(&[]).with_mdns(info.clone()))
            .with_host("10.0.0.2", SimHost::responsive(&[]).with_mdns(info));

        let first: Vec<IpAddr> = t
            .mdns_sweep(Duration::ZERO)
            .unwrap()
            .iter()
            .map(|r| r.from)
            .collect();
        assert_eq!(
            first,
            vec![
                "10.0.0.1".parse::<IpAddr>().unwrap(),
                "10.0.0.2".parse().unwrap(),
                "10.0.0.3".parse().unwrap()
            ]
        );
    }

    #[test]
    fn probe_counting_tracks_scan_cost() {
        let t = SimTransport::new().with_host("10.0.0.1", SimHost::responsive(&[22]));
        assert_eq!(t.probes_issued(), 0);
        t.tcp_probe(sock("10.0.0.1", 22), Duration::ZERO);
        t.tcp_probe(sock("10.0.0.1", 80), Duration::ZERO);
        t.icmp_echo("10.0.0.1".parse().unwrap(), Duration::ZERO, 1, 1)
            .unwrap();
        assert_eq!(t.probes_issued(), 3);
    }
}
