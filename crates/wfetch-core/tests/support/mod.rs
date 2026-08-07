//! A real-network test harness built from Linux network namespaces.
//!
//! Simulated transports prove the engine reasons correctly about probe results.
//! They cannot prove the probes themselves work, because a bug in the ICMP
//! checksum, the IPv4 header walk or the TCP outcome mapping is invisible to a
//! fake that never touches a socket.
//!
//! This harness builds an actual layer-2 network instead. Each simulated host
//! is a real network namespace holding one end of a real veth pair; the other
//! ends are bridged together in the namespace the test process runs in. Traffic
//! across it is handled by the kernel exactly as on physical hardware:
//!
//! * ARP resolution is performed by the kernel and populates the real neighbour
//!   table, which the Linux backend then reads over netlink.
//! * Every simulated host has a distinct, kernel-assigned MAC address.
//! * Closed ports produce genuine TCP RSTs, and open ones complete a genuine
//!   three-way handshake.
//! * ICMP echo requests are answered by the kernel's own ICMP stack.
//!
//! # Requirements
//!
//! Root (or `CAP_NET_ADMIN` plus `CAP_NET_RAW`), the `ip` command from
//! iproute2, and `python3` for the listener processes. When any of these is
//! missing [`TestLan::create`] returns `None` and the tests skip rather than
//! fail, so the suite still runs unprivileged.

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// One simulated host: a network namespace with an address and some listeners.
pub struct TestHost {
    pub addr: Ipv4Addr,
    pub netns: String,
    pub open_ports: Vec<u16>,
    listeners: Vec<Child>,
}

impl TestHost {
    pub fn ip(&self) -> IpAddr {
        IpAddr::V4(self.addr)
    }
}

/// A real bridged LAN, torn down when dropped.
pub struct TestLan {
    /// Unique suffix so concurrent test binaries do not collide.
    id: String,
    bridge: String,
    /// The address the test process itself holds on the bridge.
    pub scanner_addr: Ipv4Addr,
    pub hosts: Vec<TestHost>,
}

/// Whether the environment can build a real test LAN.
pub fn can_build_lan() -> bool {
    is_root() && has_command("ip") && has_command("python3")
}

fn is_root() -> bool {
    // SAFETY: geteuid cannot fail and touches no memory.
    unsafe { libc::geteuid() == 0 }
}

fn has_command(name: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {name}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run(args: &[&str]) -> bool {
    Command::new(args[0])
        .args(&args[1..])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

impl TestLan {
    /// Builds a bridged LAN with one namespace per host specification.
    ///
    /// `specs` gives each host's final address octet and the ports it listens
    /// on. Returns `None` when the environment cannot support it.
    pub fn create(subnet_third_octet: u8, specs: &[(u8, Vec<u16>)]) -> Option<TestLan> {
        if !can_build_lan() {
            return None;
        }

        // A per-process suffix keeps parallel test binaries from colliding on
        // interface names, which are limited to 15 characters.
        let id = format!("{:x}", std::process::id() & 0xffff);
        let bridge = format!("wfbr{id}");
        let scanner_addr = Ipv4Addr::new(10, 42, subnet_third_octet, 1);

        let mut lan = TestLan {
            id: id.clone(),
            bridge: bridge.clone(),
            scanner_addr,
            hosts: Vec::new(),
        };

        // Clean up anything a previous crashed run left behind.
        lan.teardown();

        if !run(&["ip", "link", "add", &bridge, "type", "bridge"]) {
            return None;
        }
        if !run(&["ip", "link", "set", &bridge, "up"]) {
            lan.teardown();
            return None;
        }
        if !run(&[
            "ip",
            "addr",
            "add",
            &format!("{scanner_addr}/24"),
            "dev",
            &bridge,
        ]) {
            lan.teardown();
            return None;
        }

        for (index, (octet, ports)) in specs.iter().enumerate() {
            let netns = format!("wfns{id}n{index}");
            let veth = format!("wfv{id}n{index}");
            let peer = format!("wfp{id}n{index}");
            let addr = Ipv4Addr::new(10, 42, subnet_third_octet, *octet);

            let ok = run(&["ip", "netns", "add", &netns])
                && run(&["ip", "link", "add", &veth, "type", "veth", "peer", "name", &peer])
                && run(&["ip", "link", "set", &veth, "master", &bridge])
                && run(&["ip", "link", "set", &veth, "up"])
                && run(&["ip", "link", "set", &peer, "netns", &netns])
                && run(&["ip", "netns", "exec", &netns, "ip", "link", "set", "lo", "up"])
                && run(&[
                    "ip", "netns", "exec", &netns, "ip", "addr", "add",
                    &format!("{addr}/24"), "dev", &peer,
                ])
                && run(&["ip", "netns", "exec", &netns, "ip", "link", "set", &peer, "up"]);

            if !ok {
                lan.teardown();
                return None;
            }

            let mut host = TestHost {
                addr,
                netns: netns.clone(),
                open_ports: ports.clone(),
                listeners: Vec::new(),
            };

            // One real listener process per port, inside the host's namespace.
            for port in ports {
                let script = format!(
                    "import socket,time\n\
                     s=socket.socket()\n\
                     s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n\
                     s.bind(('{addr}',{port}))\n\
                     s.listen(64)\n\
                     while True:\n\
                     \x20   try:\n\
                     \x20       c,_=s.accept(); c.close()\n\
                     \x20   except Exception:\n\
                     \x20       time.sleep(0.01)\n"
                );
                if let Ok(child) = Command::new("ip")
                    .args(["netns", "exec", &netns, "python3", "-c", &script])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                {
                    host.listeners.push(child);
                }
            }

            lan.hosts.push(host);
        }

        // Listeners take a moment to bind; without this the first scan races
        // them and reports ports as filtered.
        if !lan.wait_until_ready(Duration::from_secs(10)) {
            lan.teardown();
            return None;
        }

        Some(lan)
    }

    /// Blocks until every declared port accepts a connection.
    fn wait_until_ready(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let all_up = self.hosts.iter().all(|h| {
                h.open_ports.iter().all(|p| {
                    std::net::TcpStream::connect_timeout(
                        &std::net::SocketAddr::new(h.ip(), *p),
                        Duration::from_millis(200),
                    )
                    .is_ok()
                })
            });
            if all_up {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Addresses of every host on the LAN.
    pub fn host_addrs(&self) -> Vec<IpAddr> {
        self.hosts.iter().map(|h| h.ip()).collect()
    }

    /// The CIDR covering the LAN.
    pub fn subnet(&self) -> String {
        let o = self.scanner_addr.octets();
        format!("{}.{}.{}.0/24", o[0], o[1], o[2])
    }

    /// Forces ARP resolution for every host by opening a connection to each.
    ///
    /// The neighbour table is populated by traffic, so a test that reads it has
    /// to generate some first.
    pub fn warm_neighbour_table(&self) {
        for h in &self.hosts {
            let port = h.open_ports.first().copied().unwrap_or(9);
            let _ = std::net::TcpStream::connect_timeout(
                &std::net::SocketAddr::new(h.ip(), port),
                Duration::from_millis(300),
            );
        }
        // The kernel updates the table asynchronously.
        std::thread::sleep(Duration::from_millis(200));
    }

    fn teardown(&mut self) {
        for host in self.hosts.iter_mut() {
            for child in host.listeners.iter_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        // Deleting a namespace takes its veth peer with it.
        for index in 0..16 {
            let netns = format!("wfns{}n{}", self.id, index);
            run(&["ip", "netns", "del", &netns]);
        }
        run(&["ip", "link", "del", &self.bridge]);
        self.hosts.clear();
    }
}

impl Drop for TestLan {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Unwraps a test LAN, or skips the test when the environment cannot build one.
///
/// Skipping rather than failing keeps the suite runnable unprivileged; the
/// real-network coverage is simply reported as absent.
#[macro_export]
macro_rules! require_lan {
    ($lan:expr) => {
        match $lan {
            Some(l) => l,
            None => {
                eprintln!(
                    "SKIP: needs root, iproute2 and python3 to build a real test LAN"
                );
                return;
            }
        }
    };
}
