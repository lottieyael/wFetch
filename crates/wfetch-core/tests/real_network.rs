//! End-to-end verification against a real kernel network.
//!
//! Every test here runs the production code paths — [`SystemTransport`] on real
//! sockets, the Linux netlink backend on the real neighbour table — against a
//! bridged LAN of live network namespaces. Nothing is stubbed below the engine.
//!
//! These tests are what distinguish "the scanner's logic is consistent" from
//! "the scanner actually finds hosts". They skip with a message when the
//! environment cannot provide namespaces; see `tests/support/mod.rs`.

// Network namespaces are a Linux facility; there is no equivalent to build this
// harness on the other supported platforms. Their coverage comes from the unit
// tests and the simulated transport instead.
#![cfg(target_os = "linux")]

mod support;

use std::net::IpAddr;
use std::time::Duration;

use support::TestLan;
use wfetch_core::platform;
use wfetch_core::scan::engine::{Engine, ScanConfig, Techniques};
use wfetch_core::scan::result::Evidence;
use wfetch_core::scan::transport::{SystemTransport, TcpOutcome, Transport};
use wfetch_core::target::{TargetPlanBuilder, TargetSpec};

/// Builds a plan covering the LAN, excluding the scanner's own address.
fn plan_for(lan: &TestLan) -> wfetch_core::target::TargetPlan {
    TargetPlanBuilder::new()
        .include(lan.subnet().parse::<TargetSpec>().unwrap())
        .exclude(TargetSpec::Single(IpAddr::V4(lan.scanner_addr)))
        .build()
        .unwrap()
}

/// A configuration suited to a fast local bridge.
fn lan_config(ports: Vec<u16>, techniques: Techniques) -> ScanConfig {
    ScanConfig {
        concurrency: 32,
        timeout: Duration::from_millis(400),
        min_timeout: Duration::from_millis(20),
        retries: 1,
        rate_limit: None,
        ports,
        techniques,
        multicast_timeout: Duration::from_millis(300),
        default_gateway: None,
    }
}

/// TCP and ICMP only: the techniques that work without multicast on a bridge.
fn active_only() -> Techniques {
    Techniques {
        neighbor_table: false,
        icmp_echo: true,
        tcp_connect: true,
        mdns: false,
        ssdp: false,
        netbios: false,
        reverse_dns: false,
    }
}

#[test]
fn tcp_connect_finds_every_real_host_and_no_others() {
    let lan = require_lan!(TestLan::create(
        10,
        &[(11, vec![8080]), (12, vec![9090]), (13, vec![7070])]
    ));

    let mut techniques = active_only();
    techniques.icmp_echo = false;

    let engine = Engine::new(
        SystemTransport::new(),
        lan_config(vec![7070, 8080, 9090], techniques),
    );
    let report = engine.scan(&plan_for(&lan), None);

    let found: Vec<IpAddr> = report.hosts.iter().map(|h| h.ip).collect();
    assert_eq!(
        found,
        lan.host_addrs(),
        "scan should find exactly the hosts that exist"
    );

    // 253 addresses were probed and only the three real ones reported.
    assert_eq!(report.addresses_probed, 253);
}

#[test]
fn open_ports_are_reported_accurately_per_host() {
    let lan = require_lan!(TestLan::create(
        11,
        &[(21, vec![8080, 8081]), (22, vec![9090])]
    ));

    let mut techniques = active_only();
    techniques.icmp_echo = false;

    let engine = Engine::new(
        SystemTransport::new(),
        lan_config(vec![8080, 8081, 9090], techniques),
    );
    let report = engine.scan(&plan_for(&lan), None);

    for host in &lan.hosts {
        let found = report
            .hosts
            .iter()
            .find(|h| h.ip == host.ip())
            .unwrap_or_else(|| panic!("host {} was not found", host.addr));
        let mut expected = host.open_ports.clone();
        expected.sort_unstable();
        assert_eq!(
            found.open_ports, expected,
            "wrong ports for {}",
            host.addr
        );
    }
}

#[test]
fn a_host_with_no_listeners_is_still_found_by_its_tcp_reset() {
    // The kernel RSTs connections to unused ports. That reset is the only
    // thing revealing a host that runs no services, and it is exactly what a
    // simulated transport cannot verify.
    let lan = require_lan!(TestLan::create(12, &[(31, vec![])]));

    let mut techniques = active_only();
    techniques.icmp_echo = false;

    let engine = Engine::new(SystemTransport::new(), lan_config(vec![9, 80, 445], techniques));
    let report = engine.scan(&plan_for(&lan), None);

    assert_eq!(report.hosts.len(), 1, "the silent host should still be found");
    let host = &report.hosts[0];
    assert!(host.open_ports.is_empty());
    assert!(
        host.evidence
            .iter()
            .any(|e| matches!(e, Evidence::TcpClosed { .. })),
        "liveness should rest on the RST, evidence was {:?}",
        host.evidence
    );
    assert_eq!(host.confidence, wfetch_core::scan::result::Confidence::Confirmed);
}

#[test]
fn tcp_probes_distinguish_open_closed_and_absent() {
    let lan = require_lan!(TestLan::create(13, &[(41, vec![8080])]));
    let t = SystemTransport::new();
    let timeout = Duration::from_millis(500);
    let host = lan.hosts[0].ip();

    // A listening port: handshake completes.
    assert!(
        matches!(
            t.tcp_probe(std::net::SocketAddr::new(host, 8080), timeout),
            TcpOutcome::Open { .. }
        ),
        "listening port should be Open"
    );

    // An unused port on a live host: the kernel sends a RST.
    assert!(
        matches!(
            t.tcp_probe(std::net::SocketAddr::new(host, 9999), timeout),
            TcpOutcome::Closed { .. }
        ),
        "unused port on a live host should be Closed"
    );

    // An address with no host: nothing comes back at all.
    let absent: IpAddr = "10.42.13.200".parse().unwrap();
    assert_eq!(
        t.tcp_probe(std::net::SocketAddr::new(absent, 8080), timeout),
        TcpOutcome::Filtered,
        "an absent address should be Filtered"
    );
}

#[test]
fn icmp_echo_reaches_real_hosts_and_measures_a_round_trip() {
    // Exercises the hand-rolled RFC 1071 checksum, the variable-length IPv4
    // header walk and the reply matching, against the kernel's ICMP stack.
    let lan = require_lan!(TestLan::create(14, &[(51, vec![]), (52, vec![])]));
    let t = SystemTransport::new();

    for (i, host) in lan.hosts.iter().enumerate() {
        match t.icmp_echo(host.ip(), Duration::from_secs(2), 0x4242, i as u16) {
            Ok(Some(echo)) => {
                assert!(
                    echo.rtt < Duration::from_secs(2),
                    "round trip {:?} is implausible on a local bridge",
                    echo.rtt
                );
                if let Some(ttl) = echo.ttl {
                    assert_eq!(ttl, 64, "Linux replies with an initial TTL of 64");
                }
            }
            Ok(None) => panic!("host {} did not answer ICMP echo", host.addr),
            Err(e) => {
                eprintln!("SKIP: ICMP unavailable in this environment: {e}");
                return;
            }
        }
    }

    // And an address with no host must not answer.
    let absent: IpAddr = "10.42.14.200".parse().unwrap();
    assert_eq!(
        t.icmp_echo(absent, Duration::from_millis(500), 0x4242, 99)
            .unwrap(),
        None,
        "an absent address must not produce an echo reply"
    );
}

#[test]
fn icmp_only_scan_finds_hosts_that_expose_no_ports() {
    let lan = require_lan!(TestLan::create(15, &[(61, vec![]), (62, vec![])]));

    let mut techniques = active_only();
    techniques.tcp_connect = false;

    let engine = Engine::new(SystemTransport::new(), lan_config(vec![], techniques));
    let report = engine.scan(&plan_for(&lan), None);

    if report.techniques_skipped.contains_key("icmp_echo") {
        eprintln!("SKIP: ICMP unavailable in this environment");
        return;
    }

    assert_eq!(report.hosts.len(), 2);
    for host in &report.hosts {
        assert!(
            host.evidence
                .iter()
                .any(|e| matches!(e, Evidence::IcmpEchoReply { .. })),
            "expected ICMP evidence for {}",
            host.ip
        );
        // The reply's TTL should be recorded, since raw sockets expose it.
        assert!(host.rtt_micros.is_some());
    }
}

#[test]
fn the_neighbour_table_reflects_real_arp_resolution() {
    // Reads the real kernel neighbour table over netlink, after real ARP.
    let lan = require_lan!(TestLan::create(16, &[(71, vec![8080]), (72, vec![8080])]));
    lan.warm_neighbour_table();

    let p = platform::host_platform();
    let neighbors = p.neighbors().expect("neighbour dump should succeed");

    for host in &lan.hosts {
        let entry = neighbors
            .iter()
            .find(|n| n.ip == host.ip())
            .unwrap_or_else(|| panic!("{} missing from the neighbour table", host.addr));

        let mac = entry
            .mac
            .unwrap_or_else(|| panic!("{} has no MAC in the neighbour table", host.addr));
        assert!(!mac.is_zero(), "resolved entry must carry a real MAC");
        assert!(
            entry.state.implies_host_present(),
            "{} is in state {:?}",
            host.addr,
            entry.state
        );
    }

    // Every host has a distinct MAC, as on real hardware.
    let macs: Vec<_> = lan
        .hosts
        .iter()
        .filter_map(|h| neighbors.iter().find(|n| n.ip == h.ip()))
        .filter_map(|n| n.mac)
        .collect();
    let mut unique = macs.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), macs.len(), "MACs should be distinct per host");
}

#[test]
fn a_passive_neighbour_table_scan_finds_hosts_without_sending_probes() {
    let lan = require_lan!(TestLan::create(17, &[(81, vec![8080]), (82, vec![8080])]));
    lan.warm_neighbour_table();

    let techniques = Techniques {
        neighbor_table: true,
        icmp_echo: false,
        tcp_connect: false,
        mdns: false,
        ssdp: false,
        netbios: false,
        reverse_dns: false,
    };

    let platform = platform::host_platform();
    let engine = Engine::new(SystemTransport::new(), lan_config(vec![], techniques));
    let report = engine.scan(&plan_for(&lan), Some(platform.as_ref()));

    let found: Vec<IpAddr> = report.hosts.iter().map(|h| h.ip).collect();
    for host in &lan.hosts {
        assert!(
            found.contains(&host.ip()),
            "{} should be found passively",
            host.addr
        );
    }
    // Passive discovery yields MACs, which active probing alone does not.
    for h in &report.hosts {
        assert!(h.mac.is_some(), "{} should carry a MAC", h.ip);
    }
}

#[test]
fn combined_techniques_agree_on_the_same_host_set() {
    // Each technique should find the same hosts; disagreement means one of them
    // is producing false positives or negatives.
    let lan = require_lan!(TestLan::create(
        18,
        &[(91, vec![8080]), (92, vec![8080]), (93, vec![8080])]
    ));
    lan.warm_neighbour_table();

    let expected = lan.host_addrs();
    let platform = platform::host_platform();

    let tcp_only = Techniques {
        neighbor_table: false,
        icmp_echo: false,
        tcp_connect: true,
        mdns: false,
        ssdp: false,
        netbios: false,
        reverse_dns: false,
    };
    let arp_only = Techniques {
        neighbor_table: true,
        tcp_connect: false,
        ..tcp_only
    };

    for (name, techniques) in [("tcp", tcp_only), ("neighbour table", arp_only)] {
        let engine = Engine::new(SystemTransport::new(), lan_config(vec![8080], techniques));
        let report = engine.scan(&plan_for(&lan), Some(platform.as_ref()));
        let found: Vec<IpAddr> = report.hosts.iter().map(|h| h.ip).collect();
        assert_eq!(found, expected, "{name} disagreed on the host set");
    }
}

#[test]
fn a_scan_of_an_empty_subnet_reports_nothing() {
    // The most important false-positive check: a subnet with no hosts must
    // produce an empty result, not phantom entries from stale state.
    let lan = require_lan!(TestLan::create(19, &[(101, vec![8080])]));

    // Scan a different subnet entirely, one with nothing on it.
    let plan = TargetPlanBuilder::new()
        .include("10.42.99.0/28".parse::<TargetSpec>().unwrap())
        .build()
        .unwrap();

    let engine = Engine::new(SystemTransport::new(), lan_config(vec![8080], active_only()));
    let report = engine.scan(&plan, None);

    assert!(
        report.hosts.is_empty(),
        "empty subnet produced {:?}",
        report.hosts
    );
    drop(lan);
}

#[test]
fn scan_results_are_stable_across_repeated_runs() {
    // A scanner that returns different answers each run is not usable for
    // change detection, which is most of what an administrator wants it for.
    let lan = require_lan!(TestLan::create(20, &[(111, vec![8080]), (112, vec![9090])]));

    let mut techniques = active_only();
    techniques.icmp_echo = false;

    let mut runs = Vec::new();
    for _ in 0..3 {
        let engine = Engine::new(
            SystemTransport::new(),
            lan_config(vec![8080, 9090], techniques),
        );
        let report = engine.scan(&plan_for(&lan), None);
        runs.push(
            report
                .hosts
                .iter()
                .map(|h| (h.ip, h.open_ports.clone()))
                .collect::<Vec<_>>(),
        );
    }

    assert_eq!(runs[0], runs[1], "run 1 and 2 disagreed");
    assert_eq!(runs[1], runs[2], "run 2 and 3 disagreed");
    assert_eq!(runs[0].len(), 2);
}

#[test]
fn discovered_hosts_are_identified_from_real_evidence() {
    // 9100 is JetDirect; a host answering there should be read as a printer.
    let lan = require_lan!(TestLan::create(21, &[(121, vec![9100, 631])]));

    let mut techniques = active_only();
    techniques.icmp_echo = false;

    let engine = Engine::new(
        SystemTransport::new(),
        lan_config(vec![631, 9100], techniques),
    );
    let report = engine.scan(&plan_for(&lan), None);

    assert_eq!(report.hosts.len(), 1);
    let identity = report.hosts[0]
        .identity
        .as_ref()
        .expect("every reported host should be identified");
    assert_eq!(identity.class, wfetch_core::fingerprint::DeviceClass::Printer);
    assert!(!identity.reasons.is_empty());
}

#[test]
fn interface_enumeration_sees_the_test_bridge() {
    let lan = require_lan!(TestLan::create(22, &[(131, vec![])]));

    let p = platform::host_platform();
    let interfaces = p.interfaces().expect("interface enumeration should succeed");

    let bridge = interfaces
        .iter()
        .find(|i| {
            i.addrs
                .iter()
                .any(|a| a.addr == IpAddr::V4(lan.scanner_addr))
        })
        .expect("the test bridge should appear in the interface list");

    assert!(bridge.is_up);
    assert!(!bridge.is_loopback);
    assert!(bridge.is_scannable());
    assert_eq!(
        bridge
            .addrs
            .iter()
            .find(|a| a.addr == IpAddr::V4(lan.scanner_addr))
            .unwrap()
            .prefix_len,
        24,
        "the prefix length should be read from the kernel, not assumed"
    );
}
