//! The scan engine.
//!
//! Runs a [`TargetPlan`] through a [`Transport`] and produces a [`ScanReport`].
//!
//! Three properties shape the design:
//!
//! * **Capabilities gate techniques, and gaps are reported.** A technique that
//!   cannot run is recorded in `techniques_skipped` with its reason. Silently
//!   dropping it would make an unprivileged scan look like a clean sweep of a
//!   network that simply has fewer hosts than it does.
//! * **Passive first.** The kernel's neighbour table already knows about hosts
//!   this machine has talked to, and reading it costs no packets. It runs
//!   before anything is transmitted.
//! * **Bounded concurrency, paced.** Work is spread over a fixed thread pool
//!   with a shared token bucket, so scan intensity is a property of the
//!   configuration rather than of how many addresses were requested.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::addr::AddrClass;
use crate::fingerprint::{self, oui::OuiDatabase, Signals};
use crate::platform::{Capabilities, HostPlatform};
use crate::proto::netbios;
use crate::target::TargetPlan;

use super::rate::{RttEstimator, TokenBucket};
use super::result::{Evidence, Host, ScanReport};
use super::transport::{TcpOutcome, Transport};

/// Ports probed by default.
///
/// Chosen so that each either identifies a device class or is likely to be open
/// on a host that answers nothing else. This is a discovery set, not a service
/// inventory: it is deliberately small, because every extra port multiplies the
/// packet count by the number of addresses scanned.
pub const DEFAULT_PORTS: &[u16] = &[
    22,   // SSH: any Unix-like host
    80,   // HTTP: routers, printers, cameras, embedded web UIs
    443,  // HTTPS
    445,  // SMB: Windows, and NAS boxes running Samba
    139,  // NetBIOS session
    135,  // MSRPC: with 445, a strong Windows signal
    3389, // RDP
    631,  // IPP: printers
    9100, // JetDirect: printers
    53,   // DNS: routers
    5555, // ADB: Android
    62078, // lockdownd: iOS
    161,  // SNMP over TCP, where offered
    8080, // alternate HTTP
];

/// Which techniques a scan may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Techniques {
    pub neighbor_table: bool,
    pub icmp_echo: bool,
    pub tcp_connect: bool,
    pub mdns: bool,
    pub ssdp: bool,
    pub netbios: bool,
    pub reverse_dns: bool,
}

impl Techniques {
    /// Everything the scanner knows how to do.
    pub const fn all() -> Self {
        Self {
            neighbor_table: true,
            icmp_echo: true,
            tcp_connect: true,
            mdns: true,
            ssdp: true,
            netbios: true,
            reverse_dns: true,
        }
    }

    /// Only techniques that need no elevated privileges.
    pub const fn unprivileged() -> Self {
        Self {
            neighbor_table: false,
            icmp_echo: false,
            tcp_connect: true,
            mdns: true,
            ssdp: true,
            netbios: true,
            reverse_dns: true,
        }
    }

    /// The quietest useful scan: no sweep, only what hosts volunteer.
    pub const fn passive() -> Self {
        Self {
            neighbor_table: true,
            icmp_echo: false,
            tcp_connect: false,
            mdns: true,
            ssdp: true,
            netbios: false,
            reverse_dns: true,
        }
    }
}

impl Default for Techniques {
    fn default() -> Self {
        Self::all()
    }
}

/// How a scan should run.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Worker threads issuing probes.
    pub concurrency: usize,
    /// Starting per-probe timeout. Adapts once round trips are observed.
    pub timeout: Duration,
    /// Floor for the adaptive timeout.
    pub min_timeout: Duration,
    /// Extra attempts against addresses that did not answer.
    pub retries: u32,
    /// Probes per second across all workers. `None` means unpaced.
    pub rate_limit: Option<f64>,
    pub ports: Vec<u16>,
    pub techniques: Techniques,
    /// How long to listen for multicast responses.
    pub multicast_timeout: Duration,
    /// The subnet's default gateway, if known. A strong router signal that
    /// cannot be derived from probing the host itself.
    pub default_gateway: Option<IpAddr>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            concurrency: 64,
            timeout: Duration::from_millis(1000),
            min_timeout: Duration::from_millis(50),
            retries: 1,
            rate_limit: Some(2000.0),
            ports: DEFAULT_PORTS.to_vec(),
            techniques: Techniques::all(),
            multicast_timeout: Duration::from_secs(3),
            default_gateway: None,
        }
    }
}

impl ScanConfig {
    /// A fast configuration for small, quiet networks.
    pub fn quick() -> Self {
        Self {
            timeout: Duration::from_millis(300),
            retries: 0,
            ports: vec![22, 80, 443, 445, 631],
            multicast_timeout: Duration::from_secs(2),
            ..Default::default()
        }
    }

    /// Restricts the configuration to what the host can actually do.
    ///
    /// Returns the reasons for anything removed, so the report can say why a
    /// technique did not run instead of leaving its absence unexplained.
    pub fn constrain_to(&mut self, caps: &Capabilities) -> BTreeMap<String, String> {
        let mut skipped = BTreeMap::new();

        if self.techniques.neighbor_table && !caps.neighbor_table {
            self.techniques.neighbor_table = false;
            skipped.insert(
                "neighbor_table".to_string(),
                "the kernel neighbour table is not readable on this platform".to_string(),
            );
        }
        if self.techniques.icmp_echo && !caps.icmp_echo {
            self.techniques.icmp_echo = false;
            skipped.insert(
                "icmp_echo".to_string(),
                "ICMP echo requires raw sockets or an unprivileged ICMP socket, \
                 neither of which is available"
                    .to_string(),
            );
        }
        if self.techniques.mdns && !caps.multicast {
            self.techniques.mdns = false;
            skipped.insert(
                "mdns".to_string(),
                "multicast is unavailable on this host".to_string(),
            );
        }
        if self.techniques.ssdp && !caps.multicast {
            self.techniques.ssdp = false;
            skipped.insert(
                "ssdp".to_string(),
                "multicast is unavailable on this host".to_string(),
            );
        }
        if self.techniques.netbios && !caps.broadcast {
            self.techniques.netbios = false;
            skipped.insert(
                "netbios".to_string(),
                "UDP broadcast is unavailable on this host".to_string(),
            );
        }
        skipped
    }
}

/// Runs scans.
pub struct Engine<T: Transport> {
    transport: Arc<T>,
    config: ScanConfig,
    oui: Arc<OuiDatabase>,
}

impl<T: Transport + 'static> Engine<T> {
    pub fn new(transport: T, config: ScanConfig) -> Self {
        Self {
            transport: Arc::new(transport),
            config,
            oui: Arc::new(OuiDatabase::builtin()),
        }
    }

    /// Replaces the vendor database, e.g. with the full IEEE registry loaded.
    pub fn with_oui_database(mut self, db: OuiDatabase) -> Self {
        self.oui = Arc::new(db);
        self
    }

    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    /// Scans a plan, optionally consulting a platform for passive data.
    pub fn scan(&self, plan: &TargetPlan, platform: Option<&dyn HostPlatform>) -> ScanReport {
        let started = Instant::now();
        let mut hosts: BTreeMap<IpAddr, Host> = BTreeMap::new();
        let mut used: Vec<String> = Vec::new();
        let mut skipped: BTreeMap<String, String> = BTreeMap::new();

        // ---- Passive: the neighbour table costs no packets -----------------
        if self.config.techniques.neighbor_table {
            match platform.map(|p| p.neighbors()) {
                Some(Ok(entries)) => {
                    used.push("neighbor_table".to_string());
                    for e in entries {
                        // Only entries inside the plan, so a scan of one subnet
                        // does not report the whole ARP cache.
                        if !plan.contains(e.ip) {
                            continue;
                        }
                        if !e.state.implies_host_present() {
                            continue;
                        }
                        let h = hosts.entry(e.ip).or_insert_with(|| Host::new(e.ip));
                        if h.mac.is_none() {
                            h.mac = e.mac;
                        }
                        h.add_evidence(Evidence::NeighborTable { state: e.state });
                    }
                }
                Some(Err(e)) => {
                    skipped.insert("neighbor_table".to_string(), e.to_string());
                }
                None => {
                    skipped.insert(
                        "neighbor_table".to_string(),
                        "no platform backend supplied".to_string(),
                    );
                }
            }
        }

        // ---- Multicast sweeps: one exchange covers the whole segment -------
        if self.config.techniques.mdns {
            match self.transport.mdns_sweep(self.config.multicast_timeout) {
                Ok(replies) => {
                    used.push("mdns".to_string());
                    for r in replies {
                        if !plan.contains(r.from) {
                            continue;
                        }
                        let h = hosts.entry(r.from).or_insert_with(|| Host::new(r.from));
                        if h.hostname.is_none() {
                            h.hostname = r.payload.hostname.clone();
                        }
                        h.mdns = Some(r.payload);
                        h.add_evidence(Evidence::Mdns);
                    }
                }
                Err(e) => {
                    skipped.insert("mdns".to_string(), e.to_string());
                }
            }
        }

        if self.config.techniques.ssdp {
            match self.transport.ssdp_sweep(self.config.multicast_timeout) {
                Ok(replies) => {
                    used.push("ssdp".to_string());
                    for r in replies {
                        if !plan.contains(r.from) {
                            continue;
                        }
                        let h = hosts.entry(r.from).or_insert_with(|| Host::new(r.from));
                        h.ssdp.push(r.payload);
                        h.add_evidence(Evidence::Ssdp);
                    }
                }
                Err(e) => {
                    skipped.insert("ssdp".to_string(), e.to_string());
                }
            }
        }

        // ---- Active per-address probes -------------------------------------
        let needs_active = self.config.techniques.icmp_echo
            || self.config.techniques.tcp_connect
            || self.config.techniques.netbios
            || self.config.techniques.reverse_dns;

        if needs_active && !plan.is_empty() {
            if self.config.techniques.icmp_echo {
                used.push("icmp_echo".to_string());
            }
            if self.config.techniques.tcp_connect {
                used.push("tcp_connect".to_string());
            }
            if self.config.techniques.netbios {
                used.push("netbios".to_string());
            }
            if self.config.techniques.reverse_dns {
                used.push("reverse_dns".to_string());
            }

            let probed = self.probe_all(plan, &mut skipped);
            for (ip, found) in probed {
                match hosts.get_mut(&ip) {
                    Some(existing) => existing.merge(found),
                    None => {
                        hosts.insert(ip, found);
                    }
                }
            }

            // Re-read the neighbour table now that probing has generated
            // traffic. The first read happened before a single packet was sent,
            // so on a cold ARP cache it saw nothing — and the MAC is the single
            // strongest identification signal available, since it carries the
            // vendor OUI. Without this pass a first scan reports no MACs and a
            // second scan of the same network reports them all, which looks
            // like the scanner is unreliable.
            if self.config.techniques.neighbor_table {
                if let Some(Ok(entries)) = platform.map(|p| p.neighbors()) {
                    for e in entries {
                        if !e.state.implies_host_present() {
                            continue;
                        }
                        // Only fill in hosts already found. An ARP entry alone
                        // was handled by the passive pass; adding hosts here
                        // would let traffic from an unrelated process leak
                        // addresses outside the plan into the results.
                        if let Some(h) = hosts.get_mut(&e.ip) {
                            if h.mac.is_none() {
                                h.mac = e.mac;
                            }
                        }
                    }
                }
            }
        }

        // ---- Identify ------------------------------------------------------
        let mut out: Vec<Host> = hosts
            .into_values()
            .filter(|h| h.is_reportable())
            .collect();

        for h in out.iter_mut() {
            let identity = fingerprint::identify(
                &Signals {
                    mac: h.mac,
                    open_ports: &h.open_ports,
                    ttl: h.ttl,
                    hostname: h.hostname.as_deref(),
                    mdns: h.mdns.as_ref(),
                    ssdp: &h.ssdp,
                    netbios: h.netbios.as_ref(),
                    is_default_gateway: self.config.default_gateway == Some(h.ip),
                },
                &self.oui,
            );
            h.identity = Some(identity);
        }

        used.sort_unstable();
        used.dedup();

        ScanReport {
            hosts: out,
            addresses_probed: plan.len(),
            duration_micros: started.elapsed().as_micros() as u64,
            techniques_used: used,
            techniques_skipped: skipped,
        }
    }

    /// Probes every address in the plan across the worker pool.
    fn probe_all(
        &self,
        plan: &TargetPlan,
        skipped: &mut BTreeMap<String, String>,
    ) -> Vec<(IpAddr, Host)> {
        let workers = self.config.concurrency.max(1).min(plan.len().max(1));
        let stripes = plan.stripe(workers);

        let bucket = self.config.rate_limit.map(|r| {
            Arc::new(Mutex::new(TokenBucket::per_second(r)))
        });
        let started = Instant::now();
        let results: Arc<Mutex<Vec<(IpAddr, Host)>>> = Arc::new(Mutex::new(Vec::new()));
        // Records the first transport-level failure per technique, so a missing
        // capability is reported once rather than per address.
        let failures: Arc<Mutex<BTreeMap<String, String>>> = Arc::new(Mutex::new(BTreeMap::new()));
        let seq = Arc::new(AtomicUsize::new(0));

        std::thread::scope(|scope| {
            for stripe in stripes {
                if stripe.is_empty() {
                    continue;
                }
                let transport = Arc::clone(&self.transport);
                let config = self.config.clone();
                let results = Arc::clone(&results);
                let failures = Arc::clone(&failures);
                let bucket = bucket.clone();
                let seq = Arc::clone(&seq);

                scope.spawn(move || {
                    // Each worker keeps its own RTT estimate. Sharing one would
                    // need a lock on every probe for little benefit, and paths
                    // within a stripe are alike.
                    let mut rtt = RttEstimator::new(config.min_timeout, config.timeout);
                    let mut local: Vec<(IpAddr, Host)> = Vec::new();

                    for ip in stripe {
                        if let Some(b) = &bucket {
                            wait_for_token(b, started);
                        }
                        let identifier = (std::process::id() & 0xffff) as u16;
                        let sequence = seq.fetch_add(1, Ordering::Relaxed) as u16;

                        if let Some(host) = probe_one(
                            &*transport,
                            ip,
                            &config,
                            &mut rtt,
                            identifier,
                            sequence,
                            &failures,
                            &bucket,
                            started,
                        ) {
                            local.push((ip, host));
                        }
                    }

                    results.lock().unwrap().extend(local);
                });
            }
        });

        for (k, v) in failures.lock().unwrap().iter() {
            skipped.entry(k.clone()).or_insert_with(|| v.clone());
        }

        Arc::try_unwrap(results)
            .map(|m| m.into_inner().unwrap())
            .unwrap_or_default()
    }
}

/// Blocks until the rate limiter allows another probe.
fn wait_for_token(bucket: &Arc<Mutex<TokenBucket>>, started: Instant) {
    loop {
        let wait = {
            let mut b = bucket.lock().unwrap();
            let now = started.elapsed();
            if b.try_acquire(now) {
                return;
            }
            b.time_until_available(now)
        };
        match wait {
            // Cap each sleep so a mis-set rate cannot wedge a worker for
            // minutes at a time.
            Some(d) => std::thread::sleep(d.clamp(
                Duration::from_micros(100),
                Duration::from_millis(50),
            )),
            // A zero rate would never yield a token; proceed rather than hang.
            None => return,
        }
    }
}

/// Probes one address with every enabled technique.
#[allow(clippy::too_many_arguments)]
fn probe_one(
    transport: &dyn Transport,
    ip: IpAddr,
    config: &ScanConfig,
    rtt: &mut RttEstimator,
    identifier: u16,
    sequence: u16,
    failures: &Arc<Mutex<BTreeMap<String, String>>>,
    bucket: &Option<Arc<Mutex<TokenBucket>>>,
    started: Instant,
) -> Option<Host> {
    let mut host = Host::new(ip);
    let mut found = false;

    // ---- ICMP --------------------------------------------------------------
    if config.techniques.icmp_echo {
        for attempt in 0..=config.retries {
            if attempt > 0 {
                if let Some(b) = bucket {
                    wait_for_token(b, started);
                }
            }
            match transport.icmp_echo(ip, rtt.timeout(), identifier, sequence) {
                Ok(Some(echo)) => {
                    rtt.observe(echo.rtt);
                    host.add_evidence(Evidence::IcmpEchoReply {
                        rtt_micros: echo.rtt.as_micros() as u64,
                        ttl: echo.ttl,
                    });
                    found = true;
                    break;
                }
                Ok(None) => continue,
                Err(e) => {
                    failures
                        .lock()
                        .unwrap()
                        .entry("icmp_echo".to_string())
                        .or_insert_with(|| e.to_string());
                    break;
                }
            }
        }
    }

    // ---- TCP ---------------------------------------------------------------
    if config.techniques.tcp_connect {
        for port in &config.ports {
            if let Some(b) = bucket {
                wait_for_token(b, started);
            }
            match transport.tcp_probe(SocketAddr::new(ip, *port), rtt.timeout()) {
                TcpOutcome::Open { rtt: r } => {
                    rtt.observe(r);
                    host.add_evidence(Evidence::TcpOpen {
                        port: *port,
                        rtt_micros: r.as_micros() as u64,
                    });
                    found = true;
                }
                TcpOutcome::Closed { rtt: r } => {
                    rtt.observe(r);
                    // A RST proves the host exists. Record it once: a whole
                    // scan's worth of closed ports adds no information.
                    if !found {
                        host.add_evidence(Evidence::TcpClosed { port: *port });
                        found = true;
                    }
                }
                TcpOutcome::Filtered | TcpOutcome::Unreachable => {}
            }
        }
    }

    // ---- NetBIOS -----------------------------------------------------------
    // Only worth sending to a host we already believe exists: it is a single
    // packet, but across a /16 of empty addresses that is 65 000 wasted ones.
    if config.techniques.netbios && found {
        if let Ok(Some(status)) = transport.netbios_probe(ip, rtt.timeout()) {
            if host.hostname.is_none() {
                host.hostname = status.computer_name().map(str::to_string);
            }
            if host.mac.is_none() {
                host.mac = status.mac;
            }
            host.netbios = Some(status);
            host.add_evidence(Evidence::NetbiosNodeStatus);
        }
    }

    // ---- Reverse DNS -------------------------------------------------------
    if config.techniques.reverse_dns && found {
        if let Some(name) = transport.reverse_dns(ip) {
            host.add_evidence(Evidence::ReverseDns { name });
        }
    }

    if found {
        Some(host)
    } else {
        None
    }
}

/// Whether an address is a plausible default gateway for a plan.
///
/// Convention puts the router at the first host address of a subnet, but this
/// is only a fallback for when the platform cannot report the real route.
pub fn guess_gateway(plan: &TargetPlan) -> Option<IpAddr> {
    plan.addresses()
        .iter()
        .find(|a| crate::addr::classify(**a) == AddrClass::Private)
        .copied()
}

/// Builds NetBIOS-derived hostnames into a host record.
pub fn apply_netbios(host: &mut Host, status: netbios::NodeStatus) {
    if host.hostname.is_none() {
        host.hostname = status.computer_name().map(str::to_string);
    }
    if host.mac.is_none() {
        host.mac = status.mac;
    }
    host.netbios = Some(status);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::fake::FakePlatform;
    use crate::platform::{Interface, NeighborEntry, NeighborState};
    use crate::proto::mdns::MdnsInfo;
    use crate::scan::sim::{SimHost, SimTransport};
    use crate::target::{TargetPlanBuilder, TargetSpec};

    fn plan(spec: &str) -> TargetPlan {
        TargetPlanBuilder::new()
            .include(spec.parse::<TargetSpec>().unwrap())
            .build()
            .unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// A config with multicast off and no pacing, for fast deterministic tests.
    fn test_config() -> ScanConfig {
        ScanConfig {
            concurrency: 4,
            timeout: Duration::from_millis(10),
            min_timeout: Duration::from_millis(1),
            retries: 0,
            rate_limit: None,
            ports: vec![22, 80, 445],
            techniques: Techniques {
                neighbor_table: false,
                icmp_echo: true,
                tcp_connect: true,
                mdns: false,
                ssdp: false,
                netbios: false,
                reverse_dns: false,
            },
            multicast_timeout: Duration::from_millis(1),
            default_gateway: None,
        }
    }

    // ---- discovery ---------------------------------------------------------

    #[test]
    fn finds_exactly_the_hosts_that_exist() {
        let t = SimTransport::new()
            .with_host("10.0.0.1", SimHost::responsive(&[80]))
            .with_host("10.0.0.5", SimHost::responsive(&[22]))
            .with_host("10.0.0.9", SimHost::responsive(&[445]));

        let report = Engine::new(t, test_config()).scan(&plan("10.0.0.0/28"), None);

        let found: Vec<IpAddr> = report.hosts.iter().map(|h| h.ip).collect();
        assert_eq!(found, vec![ip("10.0.0.1"), ip("10.0.0.5"), ip("10.0.0.9")]);
    }

    #[test]
    fn reports_no_hosts_on_an_empty_network() {
        let report = Engine::new(SimTransport::new(), test_config()).scan(&plan("10.0.0.0/29"), None);
        assert!(report.hosts.is_empty());
        assert_eq!(report.addresses_probed, 6);
    }

    #[test]
    fn a_silent_host_is_not_reported_rather_than_invented() {
        // It exists, but answers nothing. Claiming to have found it would be a
        // lie; the scan simply cannot see it.
        let t = SimTransport::new().with_host("10.0.0.3", SimHost::silent());
        let report = Engine::new(t, test_config()).scan(&plan("10.0.0.0/29"), None);
        assert!(report.hosts.is_empty());
    }

    #[test]
    fn a_firewalled_host_is_found_through_its_one_open_port() {
        let t = SimTransport::new()
            .with_host("10.0.0.4", SimHost::responsive(&[443]).firewalled().with_icmp(false));
        let mut cfg = test_config();
        cfg.ports = vec![22, 80, 443];
        let report = Engine::new(t, cfg).scan(&plan("10.0.0.0/29"), None);

        assert_eq!(report.hosts.len(), 1);
        assert_eq!(report.hosts[0].open_ports, vec![443]);
    }

    #[test]
    fn a_host_with_no_open_ports_is_still_found_by_its_resets() {
        // A bare host that drops ICMP still RSTs closed ports, and that RST is
        // the only thing revealing it.
        let t = SimTransport::new().with_host("10.0.0.2", SimHost::responsive(&[]).with_icmp(false));
        let report = Engine::new(t, test_config()).scan(&plan("10.0.0.0/29"), None);

        assert_eq!(report.hosts.len(), 1);
        assert!(report.hosts[0].open_ports.is_empty());
        assert!(report.hosts[0]
            .evidence
            .iter()
            .any(|e| matches!(e, Evidence::TcpClosed { .. })));
    }

    #[test]
    fn a_reset_is_recorded_once_not_per_closed_port() {
        let t = SimTransport::new().with_host("10.0.0.2", SimHost::responsive(&[]).with_icmp(false));
        let mut cfg = test_config();
        cfg.ports = vec![22, 80, 443, 445, 8080];
        let report = Engine::new(t, cfg).scan(&plan("10.0.0.0/29"), None);

        let resets = report.hosts[0]
            .evidence
            .iter()
            .filter(|e| matches!(e, Evidence::TcpClosed { .. }))
            .count();
        assert_eq!(resets, 1, "one RST is as informative as five");
    }

    // ---- retries -----------------------------------------------------------

    #[test]
    fn retries_recover_a_flaky_host() {
        // Answers one probe in three: a single attempt would miss it.
        let t = SimTransport::new()
            .with_host("10.0.0.1", SimHost::responsive(&[]).flaky(3).with_icmp(true));
        let mut cfg = test_config();
        cfg.techniques.tcp_connect = false;
        cfg.retries = 4;

        let report = Engine::new(t, cfg).scan(&plan("10.0.0.1/32"), None);
        assert_eq!(report.hosts.len(), 1, "retries should find the flaky host");
    }

    #[test]
    fn without_retries_a_flaky_host_can_be_missed() {
        let t = SimTransport::new()
            .with_host("10.0.0.1", SimHost::responsive(&[]).flaky(10).with_icmp(true));
        let mut cfg = test_config();
        cfg.techniques.tcp_connect = false;
        cfg.retries = 0;

        let report = Engine::new(t, cfg).scan(&plan("10.0.0.1/32"), None);
        assert!(report.hosts.is_empty());
    }

    // ---- passive sources ---------------------------------------------------

    #[test]
    fn the_neighbour_table_contributes_hosts_and_macs() {
        let entries = vec![
            NeighborEntry {
                ip: ip("10.0.0.7"),
                mac: Some("aa:bb:cc:dd:ee:ff".parse().unwrap()),
                state: NeighborState::Reachable,
                if_index: 2,
                if_name: Some("eth0".into()),
            },
            // A failed entry: an ARP attempt that got no answer.
            NeighborEntry {
                ip: ip("10.0.0.8"),
                mac: None,
                state: NeighborState::Failed,
                if_index: 2,
                if_name: Some("eth0".into()),
            },
        ];
        let platform = FakePlatform::new(vec![], entries);

        let mut cfg = test_config();
        cfg.techniques.neighbor_table = true;
        cfg.techniques.icmp_echo = false;
        cfg.techniques.tcp_connect = false;

        let report = Engine::new(SimTransport::new(), cfg).scan(&plan("10.0.0.0/28"), Some(&platform));

        assert_eq!(report.hosts.len(), 1, "the failed entry must not count");
        assert_eq!(report.hosts[0].ip, ip("10.0.0.7"));
        assert_eq!(report.hosts[0].mac, Some("aa:bb:cc:dd:ee:ff".parse().unwrap()));
    }

    #[test]
    fn neighbour_entries_outside_the_plan_are_ignored() {
        // Scanning one subnet must not dump the whole ARP cache.
        let entries = vec![NeighborEntry {
            ip: ip("192.168.99.1"),
            mac: None,
            state: NeighborState::Reachable,
            if_index: 2,
            if_name: None,
        }];
        let mut cfg = test_config();
        cfg.techniques.neighbor_table = true;
        cfg.techniques.icmp_echo = false;
        cfg.techniques.tcp_connect = false;

        let report = Engine::new(SimTransport::new(), cfg)
            .scan(&plan("10.0.0.0/28"), Some(&FakePlatform::new(vec![], entries)));
        assert!(report.hosts.is_empty());
    }

    #[test]
    fn an_unreadable_neighbour_table_is_reported_as_skipped() {
        // The Android case. It must not look like an empty network.
        let platform = FakePlatform::new(vec![] as Vec<Interface>, vec![]).with_unreadable_neighbors();
        let mut cfg = test_config();
        cfg.techniques.neighbor_table = true;

        let report = Engine::new(SimTransport::new(), cfg).scan(&plan("10.0.0.0/29"), Some(&platform));
        assert!(report.techniques_skipped.contains_key("neighbor_table"));
        assert!(!report.techniques_used.contains(&"neighbor_table".to_string()));
    }

    #[test]
    fn mdns_responses_supply_hostnames() {
        let info = MdnsInfo {
            hostname: Some("printer".into()),
            services: vec!["_ipp._tcp".into()],
            ..Default::default()
        };
        let t = SimTransport::new()
            .with_host("10.0.0.6", SimHost::responsive(&[631]).with_mdns(info));

        let mut cfg = test_config();
        cfg.techniques.mdns = true;
        cfg.ports = vec![631];

        let report = Engine::new(t, cfg).scan(&plan("10.0.0.0/28"), None);
        assert_eq!(report.hosts.len(), 1);
        assert_eq!(report.hosts[0].hostname.as_deref(), Some("printer"));
        assert!(report.hosts[0].mdns.is_some());
    }

    // ---- capability gating -------------------------------------------------

    #[test]
    fn unavailable_techniques_are_reported_with_a_reason() {
        let t = SimTransport::new()
            .with_host("10.0.0.1", SimHost::responsive(&[80]))
            .without_icmp();
        let report = Engine::new(t, test_config()).scan(&plan("10.0.0.0/29"), None);

        assert!(
            report.techniques_skipped.contains_key("icmp_echo"),
            "a failed technique must be explained, not silently dropped"
        );
        // And the scan still works through the techniques that remain.
        assert_eq!(report.hosts.len(), 1);
    }

    #[test]
    fn constraining_to_capabilities_removes_and_explains_techniques() {
        let mut cfg = ScanConfig::default();
        let skipped = cfg.constrain_to(&Capabilities::unprivileged());

        assert!(!cfg.techniques.icmp_echo);
        assert!(!cfg.techniques.neighbor_table);
        assert!(cfg.techniques.tcp_connect, "always available");
        assert!(cfg.techniques.mdns, "multicast is unprivileged");

        assert!(skipped.contains_key("icmp_echo"));
        assert!(skipped.contains_key("neighbor_table"));
        assert!(!skipped["icmp_echo"].is_empty());
    }

    #[test]
    fn constraining_to_full_capabilities_removes_nothing() {
        let mut cfg = ScanConfig::default();
        let skipped = cfg.constrain_to(&Capabilities::full());
        assert!(skipped.is_empty());
        assert_eq!(cfg.techniques, Techniques::all());
    }

    // ---- identification ----------------------------------------------------

    #[test]
    fn discovered_hosts_are_identified() {
        let t = SimTransport::new().with_host(
            "10.0.0.1",
            SimHost::responsive(&[631, 80]).with_ttl(64),
        );
        let mut cfg = test_config();
        cfg.ports = vec![80, 631];

        let report = Engine::new(t, cfg).scan(&plan("10.0.0.0/29"), None);
        let identity = report.hosts[0].identity.as_ref().unwrap();
        assert_eq!(identity.class, crate::fingerprint::DeviceClass::Printer);
    }

    #[test]
    fn the_configured_gateway_is_identified_as_a_router() {
        let t = SimTransport::new().with_host("10.0.0.1", SimHost::responsive(&[53, 80]));
        let mut cfg = test_config();
        cfg.ports = vec![53, 80];
        cfg.default_gateway = Some(ip("10.0.0.1"));

        let report = Engine::new(t, cfg).scan(&plan("10.0.0.0/29"), None);
        assert_eq!(
            report.hosts[0].identity.as_ref().unwrap().class,
            crate::fingerprint::DeviceClass::Router
        );
    }

    // ---- concurrency and determinism ---------------------------------------

    #[test]
    fn results_are_ordered_by_address_regardless_of_worker_count() {
        let t = SimTransport::new()
            .with_host("10.0.0.9", SimHost::responsive(&[80]))
            .with_host("10.0.0.2", SimHost::responsive(&[80]))
            .with_host("10.0.0.14", SimHost::responsive(&[80]))
            .with_host("10.0.0.5", SimHost::responsive(&[80]));

        for workers in [1usize, 2, 3, 8, 64] {
            let mut cfg = test_config();
            cfg.concurrency = workers;
            let report = Engine::new(
                SimTransport::new()
                    .with_host("10.0.0.9", SimHost::responsive(&[80]))
                    .with_host("10.0.0.2", SimHost::responsive(&[80]))
                    .with_host("10.0.0.14", SimHost::responsive(&[80]))
                    .with_host("10.0.0.5", SimHost::responsive(&[80])),
                cfg,
            )
            .scan(&plan("10.0.0.0/28"), None);

            let found: Vec<IpAddr> = report.hosts.iter().map(|h| h.ip).collect();
            assert_eq!(
                found,
                vec![ip("10.0.0.2"), ip("10.0.0.5"), ip("10.0.0.9"), ip("10.0.0.14")],
                "worker count {workers} changed the result"
            );
        }
        drop(t);
    }

    #[test]
    fn every_address_in_the_plan_is_probed_exactly_once() {
        let t = SimTransport::new();
        let mut cfg = test_config();
        cfg.techniques.icmp_echo = true;
        cfg.techniques.tcp_connect = false;
        cfg.concurrency = 4;

        let engine = Engine::new(t, cfg);
        let p = plan("10.0.0.0/28");
        let report = engine.scan(&p, None);

        assert_eq!(report.addresses_probed, 14);
        assert_eq!(
            engine.transport.probes_issued(),
            14,
            "one ICMP probe per address, no duplicates and none skipped"
        );
    }

    #[test]
    fn scanning_a_single_address_works() {
        let t = SimTransport::new().with_host("10.0.0.1", SimHost::responsive(&[80]));
        let report = Engine::new(t, test_config()).scan(&plan("10.0.0.1/32"), None);
        assert_eq!(report.hosts.len(), 1);
    }

    #[test]
    fn concurrency_above_the_plan_size_is_harmless() {
        let t = SimTransport::new().with_host("10.0.0.1", SimHost::responsive(&[80]));
        let mut cfg = test_config();
        cfg.concurrency = 1000;
        let report = Engine::new(t, cfg).scan(&plan("10.0.0.1/32"), None);
        assert_eq!(report.hosts.len(), 1);
    }

    // ---- rate limiting -----------------------------------------------------

    #[test]
    fn rate_limiting_paces_a_scan_without_losing_hosts() {
        let t = SimTransport::new()
            .with_host("10.0.0.1", SimHost::responsive(&[80]))
            .with_host("10.0.0.2", SimHost::responsive(&[80]));
        let mut cfg = test_config();
        cfg.rate_limit = Some(500.0);
        cfg.concurrency = 2;

        let report = Engine::new(t, cfg).scan(&plan("10.0.0.0/29"), None);
        assert_eq!(report.hosts.len(), 2, "pacing must not drop results");
    }

    // ---- reporting ---------------------------------------------------------

    #[test]
    fn the_report_records_which_techniques_ran() {
        let t = SimTransport::new().with_host("10.0.0.1", SimHost::responsive(&[80]));
        let report = Engine::new(t, test_config()).scan(&plan("10.0.0.0/29"), None);

        assert!(report.techniques_used.contains(&"tcp_connect".to_string()));
        assert!(report.techniques_used.contains(&"icmp_echo".to_string()));
        // The list is sorted and deduplicated.
        let mut sorted = report.techniques_used.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted, report.techniques_used);
    }

    #[test]
    fn the_report_round_trips_through_json() {
        let t = SimTransport::new().with_host("10.0.0.1", SimHost::responsive(&[80]));
        let report = Engine::new(t, test_config()).scan(&plan("10.0.0.0/29"), None);
        let j = serde_json::to_string(&report).unwrap();
        let back: ScanReport = serde_json::from_str(&j).unwrap();
        assert_eq!(back.hosts.len(), report.hosts.len());
        assert_eq!(back.addresses_probed, report.addresses_probed);
    }
}
