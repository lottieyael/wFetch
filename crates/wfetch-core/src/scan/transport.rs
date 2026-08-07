//! The probe transport.
//!
//! The engine issues every probe through [`Transport`], so the scheduling,
//! merging and confidence logic can be driven by a simulated network in tests
//! while the real implementation talks to sockets. [`SystemTransport`] is the
//! real one; [`crate::scan::sim::SimTransport`] is the deterministic fake.

use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::proto::{mdns, netbios, ssdp};

/// What a TCP connect attempt found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOutcome {
    /// The handshake completed.
    Open { rtt: Duration },
    /// The host sent a RST. The port is shut, but the host answered — which is
    /// as good a liveness proof as an open port.
    Closed { rtt: Duration },
    /// Nothing came back before the timeout: either no host, or a firewall
    /// dropping the packet silently. These two are genuinely indistinguishable
    /// from a connect probe, so they are not distinguished here.
    Filtered,
    /// The probe could not be sent at all (no route, address family unsupported).
    Unreachable,
}

impl TcpOutcome {
    /// Whether this outcome proves a host is present.
    pub fn proves_host(&self) -> bool {
        matches!(self, TcpOutcome::Open { .. } | TcpOutcome::Closed { .. })
    }
}

/// A successful ICMP echo exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoOutcome {
    pub rtt: Duration,
    /// The IP TTL of the reply, where the socket type exposes it.
    pub ttl: Option<u8>,
}

/// A response gathered from a multicast or broadcast sweep.
#[derive(Debug, Clone, PartialEq)]
pub struct MulticastReply<T> {
    pub from: IpAddr,
    pub payload: T,
}

/// How the engine reaches the network.
pub trait Transport: Send + Sync {
    /// Attempts a TCP connection.
    fn tcp_probe(&self, addr: SocketAddr, timeout: Duration) -> TcpOutcome;

    /// Sends one ICMP echo request and waits for its reply.
    ///
    /// Returns `Ok(None)` when the probe was sent but nothing answered, and
    /// `Err` when it could not be sent at all — the caller must not record a
    /// missing capability as a silent absence of hosts.
    fn icmp_echo(
        &self,
        addr: IpAddr,
        timeout: Duration,
        identifier: u16,
        sequence: u16,
    ) -> io::Result<Option<EchoOutcome>>;

    /// Issues mDNS queries and collects every response within `timeout`.
    fn mdns_sweep(&self, timeout: Duration) -> io::Result<Vec<MulticastReply<mdns::MdnsInfo>>>;

    /// Issues SSDP M-SEARCH requests and collects responses.
    fn ssdp_sweep(&self, timeout: Duration) -> io::Result<Vec<MulticastReply<ssdp::SsdpResponse>>>;

    /// Sends a NetBIOS node status query to one address.
    fn netbios_probe(
        &self,
        addr: IpAddr,
        timeout: Duration,
    ) -> io::Result<Option<netbios::NodeStatus>>;

    /// Resolves an address to a name via reverse DNS.
    fn reverse_dns(&self, addr: IpAddr) -> Option<String>;
}

/// The real transport, backed by operating system sockets.
pub struct SystemTransport {
    /// Source address to bind probes to, for hosts with several interfaces.
    bind_addr: Option<IpAddr>,
}

impl SystemTransport {
    pub fn new() -> Self {
        Self { bind_addr: None }
    }

    /// Binds outgoing probes to a specific local address.
    pub fn bound_to(addr: IpAddr) -> Self {
        Self {
            bind_addr: Some(addr),
        }
    }
}

impl Default for SystemTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for SystemTransport {
    fn tcp_probe(&self, addr: SocketAddr, timeout: Duration) -> TcpOutcome {
        let start = Instant::now();
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => {
                let rtt = start.elapsed();
                // Close immediately: the handshake is all we needed, and
                // lingering sockets exhaust the local port range on a big sweep.
                drop(stream);
                TcpOutcome::Open { rtt }
            }
            Err(e) => match e.kind() {
                // A RST. The host is there and said no.
                io::ErrorKind::ConnectionRefused => TcpOutcome::Closed {
                    rtt: start.elapsed(),
                },
                // Silence. No host, or a firewall dropping the SYN.
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => TcpOutcome::Filtered,
                _ => {
                    // ICMP unreachable surfaces here on some platforms, as does
                    // a missing route. Neither proves a host.
                    TcpOutcome::Unreachable
                }
            },
        }
    }

    fn icmp_echo(
        &self,
        addr: IpAddr,
        timeout: Duration,
        identifier: u16,
        sequence: u16,
    ) -> io::Result<Option<EchoOutcome>> {
        icmp_impl::echo(addr, timeout, identifier, sequence, self.bind_addr)
    }

    fn mdns_sweep(&self, timeout: Duration) -> io::Result<Vec<MulticastReply<mdns::MdnsInfo>>> {
        let socket = self.bind_udp(0)?;
        socket.set_read_timeout(Some(timeout))?;
        socket.set_multicast_loop_v4(false).ok();

        let group = SocketAddr::new(IpAddr::V4(mdns::MDNS_IPV4_GROUP), mdns::MDNS_PORT);

        // The service enumeration meta-query first, then the specific types.
        // Responders that ignore the meta-query still answer the direct ones.
        if let Ok(q) = mdns::build_service_enumeration_query() {
            socket.send_to(&q, group).ok();
        }
        for service in mdns::INTERESTING_SERVICES {
            if let Ok(q) = mdns::build_query(service, crate::proto::dns::rtype::PTR, true) {
                socket.send_to(&q, group).ok();
            }
        }

        let mut out: Vec<MulticastReply<mdns::MdnsInfo>> = Vec::new();
        let deadline = Instant::now() + timeout;
        let mut buf = vec![0u8; 8192];

        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            socket.set_read_timeout(Some(remaining)).ok();
            match socket.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let Ok(msg) = crate::proto::dns::parse_message(&buf[..n]) else {
                        continue;
                    };
                    if !msg.is_response() {
                        continue;
                    }
                    let info = mdns::extract(&msg);
                    if info.is_empty() {
                        continue;
                    }
                    // Several queries produce several responses per host; fold
                    // them together rather than reporting the host repeatedly.
                    match out.iter_mut().find(|r| r.from == from.ip()) {
                        Some(existing) => merge_mdns(&mut existing.payload, info),
                        None => out.push(MulticastReply {
                            from: from.ip(),
                            payload: info,
                        }),
                    }
                }
                Err(e) if is_timeout(&e) => break,
                Err(_) => break,
            }
        }
        Ok(out)
    }

    fn ssdp_sweep(&self, timeout: Duration) -> io::Result<Vec<MulticastReply<ssdp::SsdpResponse>>> {
        let socket = self.bind_udp(0)?;
        socket.set_multicast_loop_v4(false).ok();

        let group = SocketAddr::new(IpAddr::V4(ssdp::SSDP_IPV4_GROUP), ssdp::SSDP_PORT);
        // MX must be shorter than our own timeout or responders will still be
        // waiting to reply when we stop listening.
        let mx = timeout.min(Duration::from_secs(3));
        for target in ssdp::SEARCH_TARGETS {
            let req = ssdp::build_msearch(target, mx);
            socket.send_to(req.as_bytes(), group).ok();
        }

        let mut out: Vec<MulticastReply<ssdp::SsdpResponse>> = Vec::new();
        let deadline = Instant::now() + timeout;
        let mut buf = vec![0u8; 8192];

        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            socket.set_read_timeout(Some(remaining)).ok();
            match socket.recv_from(&mut buf) {
                Ok((n, from)) => {
                    if let Some(r) = ssdp::parse_response(&buf[..n]) {
                        // A device answers each search target separately.
                        let dup = out
                            .iter()
                            .any(|e| e.from == from.ip() && e.payload.usn == r.usn);
                        if !dup {
                            out.push(MulticastReply {
                                from: from.ip(),
                                payload: r,
                            });
                        }
                    }
                }
                Err(e) if is_timeout(&e) => break,
                Err(_) => break,
            }
        }
        Ok(out)
    }

    fn netbios_probe(
        &self,
        addr: IpAddr,
        timeout: Duration,
    ) -> io::Result<Option<netbios::NodeStatus>> {
        // NetBIOS name service is IPv4 only.
        if !addr.is_ipv4() {
            return Ok(None);
        }
        let socket = self.bind_udp(0)?;
        socket.set_read_timeout(Some(timeout))?;

        let req = netbios::build_node_status_request(0x4242);
        socket.send_to(&req, SocketAddr::new(addr, netbios::NETBIOS_NS_PORT))?;

        let mut buf = vec![0u8; 4096];
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                // Ignore anything from an address we did not probe.
                if from.ip() != addr {
                    return Ok(None);
                }
                Ok(netbios::parse_node_status(&buf[..n]))
            }
            Err(e) if is_timeout(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn reverse_dns(&self, addr: IpAddr) -> Option<String> {
        reverse_dns_impl::lookup(addr)
    }
}

impl SystemTransport {
    fn bind_udp(&self, port: u16) -> io::Result<UdpSocket> {
        let bind_ip = self
            .bind_addr
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, port))?;
        socket.set_broadcast(true).ok();
        Ok(socket)
    }
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

/// Folds a second mDNS response for the same host into the first.
fn merge_mdns(into: &mut mdns::MdnsInfo, other: mdns::MdnsInfo) {
    if into.hostname.is_none() {
        into.hostname = other.hostname;
    }
    for a in other.addresses {
        if !into.addresses.contains(&a) {
            into.addresses.push(a);
        }
    }
    for s in other.services {
        if !into.services.contains(&s) {
            into.services.push(s);
        }
    }
    for n in other.instance_names {
        if !into.instance_names.contains(&n) {
            into.instance_names.push(n);
        }
    }
    for (k, v) in other.txt {
        if !into.txt.iter().any(|(ek, _)| *ek == k) {
            into.txt.push((k, v));
        }
    }
}

/// ICMP echo over raw or unprivileged datagram sockets.
#[cfg(unix)]
mod icmp_impl {
    use super::*;
    use crate::proto::icmp;

    /// Sends an echo request and waits for the matching reply.
    ///
    /// Two socket types are tried. `SOCK_DGRAM` with `IPPROTO_ICMP` is
    /// unprivileged where the kernel permits it (Linux with the caller's GID
    /// inside `net.ipv4.ping_group_range`, and macOS for the root group), and
    /// the kernel rewrites the identifier field to the socket's port — so
    /// replies are matched on sequence rather than identifier. `SOCK_RAW` needs
    /// `CAP_NET_RAW` or root and delivers the IP header along with the reply.
    pub fn echo(
        addr: IpAddr,
        timeout: Duration,
        identifier: u16,
        sequence: u16,
        bind_addr: Option<IpAddr>,
    ) -> io::Result<Option<EchoOutcome>> {
        let is_v6 = addr.is_ipv6();
        let (domain, proto) = if is_v6 {
            (libc::AF_INET6, libc::IPPROTO_ICMPV6)
        } else {
            (libc::AF_INET, libc::IPPROTO_ICMP)
        };

        // SAFETY: socket(2) with validated constants; the fd is owned by
        // FdGuard and closed on every path.
        let (fd, is_raw) = unsafe {
            let dgram = libc::socket(domain, libc::SOCK_DGRAM, proto);
            if dgram >= 0 {
                (dgram, false)
            } else {
                let raw = libc::socket(domain, libc::SOCK_RAW, proto);
                if raw < 0 {
                    return Err(io::Error::last_os_error());
                }
                (raw, true)
            }
        };
        let _guard = FdGuard(fd);

        // SAFETY: setsockopt with a correctly sized timeval.
        unsafe {
            let tv = libc::timeval {
                tv_sec: timeout.as_secs() as libc::time_t,
                tv_usec: timeout.subsec_micros() as libc::suseconds_t,
            };
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        if let Some(bind) = bind_addr {
            if bind.is_ipv4() == addr.is_ipv4() {
                bind_socket(fd, bind)?;
            }
        }

        let packet = if is_v6 {
            icmp::build_echo_request_v6(identifier, sequence, b"wfetch")
        } else {
            icmp::build_echo_request_v4(identifier, sequence, b"wfetch")
        };

        let (sa, sa_len) = sockaddr_for(addr);
        let start = Instant::now();

        // SAFETY: sendto with a buffer and sockaddr both sized by their lengths.
        let sent = unsafe {
            libc::sendto(
                fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &sa as *const _ as *const libc::sockaddr,
                sa_len,
            )
        };
        if sent < 0 {
            let e = io::Error::last_os_error();
            // No route to the target is not a transport failure; it just means
            // nothing is there.
            return match e.raw_os_error() {
                Some(libc::EHOSTUNREACH) | Some(libc::ENETUNREACH) => Ok(None),
                _ => Err(e),
            };
        }

        // Replies from other hosts can arrive on the same socket, so read until
        // one matches or the deadline passes.
        let deadline = start + timeout;
        let mut buf = vec![0u8; 1500];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            // SAFETY: setsockopt with a correctly sized timeval.
            unsafe {
                let tv = libc::timeval {
                    tv_sec: remaining.as_secs() as libc::time_t,
                    tv_usec: remaining.subsec_micros() as libc::suseconds_t,
                };
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &tv as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                );
            }

            // SAFETY: recv into a buffer sized by its own length.
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                let e = io::Error::last_os_error();
                return match e.raw_os_error() {
                    // EWOULDBLOCK is the same value as EAGAIN on Linux, so
                    // matching both is rejected as an unreachable pattern.
                    Some(libc::EAGAIN) | Some(libc::EINTR) => Ok(None),
                    _ => Err(e),
                };
            }
            let data = &buf[..n as usize];
            let rtt = start.elapsed();

            // A raw IPv4 socket delivers the IP header; a datagram one does not.
            // The header length is variable, so it cannot be skipped blindly.
            let (body, ttl) = if is_raw && !is_v6 {
                match icmp::parse_ipv4_header(data) {
                    Some(h) => (&data[h.header_len..], Some(h.ttl)),
                    None => continue,
                }
            } else {
                (data, None)
            };

            let parsed = if is_v6 {
                icmp::parse_icmp_v6(body)
            } else {
                icmp::parse_icmp_v4(body)
            };

            match parsed {
                Some(icmp::IcmpMessage::EchoReply(reply)) => {
                    // On a datagram socket the kernel rewrites the identifier to
                    // the socket's port, so only the sequence is ours to match.
                    let matches = if is_raw {
                        reply.identifier == identifier && reply.sequence == sequence
                    } else {
                        reply.sequence == sequence
                    };
                    if matches {
                        return Ok(Some(EchoOutcome { rtt, ttl }));
                    }
                }
                // Unreachable and time-exceeded come from a router, not the
                // target; keep waiting for a real reply.
                _ => continue,
            }
        }
    }

    fn bind_socket(fd: libc::c_int, addr: IpAddr) -> io::Result<()> {
        let (sa, len) = sockaddr_for(addr);
        // SAFETY: bind with a sockaddr sized by `len`.
        let rc = unsafe { libc::bind(fd, &sa as *const _ as *const libc::sockaddr, len) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Builds a sockaddr storage for either family.
    fn sockaddr_for(addr: IpAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
        // SAFETY: sockaddr_storage is a plain byte buffer; the correct variant
        // is written before use and the returned length matches it.
        unsafe {
            let mut storage: libc::sockaddr_storage = std::mem::zeroed();
            match addr {
                IpAddr::V4(v4) => {
                    let sin = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in);
                    sin.sin_family = libc::AF_INET as libc::sa_family_t;
                    sin.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
                    (
                        storage,
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                }
                IpAddr::V6(v6) => {
                    let sin6 = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6);
                    sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                    sin6.sin6_addr.s6_addr = v6.octets();
                    (
                        storage,
                        std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    )
                }
            }
        }
    }

    struct FdGuard(libc::c_int);
    impl Drop for FdGuard {
        fn drop(&mut self) {
            // SAFETY: we own this fd and close it exactly once.
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

/// ICMP echo on Windows, via the IP Helper echo API.
#[cfg(windows)]
mod icmp_impl {
    use super::*;

    /// Windows exposes `IcmpSendEcho2`, which works without administrator
    /// rights — unlike raw sockets, which need elevation. This is why the
    /// Windows backend reports `icmp_echo` as always available.
    pub fn echo(
        addr: IpAddr,
        timeout: Duration,
        _identifier: u16,
        _sequence: u16,
        _bind_addr: Option<IpAddr>,
    ) -> io::Result<Option<EchoOutcome>> {
        use windows::Win32::NetworkManagement::IpHelper::{
            IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY,
        };

        let IpAddr::V4(v4) = addr else {
            // IcmpSendEcho is IPv4 only; Icmp6SendEcho2 requires a bound source
            // address, which the scanner does not currently track per target.
            return Ok(None);
        };

        // SAFETY: the handle is closed on every path, and the reply buffer is
        // sized to hold the documented reply structure plus the payload.
        unsafe {
            let handle = IcmpCreateFile().map_err(|e| io::Error::other(e.to_string()))?;

            let payload = b"wfetch";
            let reply_size = std::mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 8;
            let mut reply = vec![0u8; reply_size];

            let dest = u32::from_ne_bytes(v4.octets());
            let start = Instant::now();
            let n = IcmpSendEcho(
                handle,
                dest,
                payload.as_ptr() as *const _,
                payload.len() as u16,
                None,
                reply.as_mut_ptr() as *mut _,
                reply_size as u32,
                timeout.as_millis().min(u32::MAX as u128) as u32,
            );

            let out = if n > 0 {
                let r = &*(reply.as_ptr() as *const ICMP_ECHO_REPLY);
                Some(EchoOutcome {
                    // The API reports its own round-trip time in milliseconds,
                    // which is coarser than our clock for a LAN; prefer ours.
                    rtt: start.elapsed(),
                    ttl: Some(r.Options.Ttl),
                })
            } else {
                None
            };

            let _ = IcmpCloseHandle(handle);
            Ok(out)
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod icmp_impl {
    use super::*;
    pub fn echo(
        _addr: IpAddr,
        _timeout: Duration,
        _identifier: u16,
        _sequence: u16,
        _bind_addr: Option<IpAddr>,
    ) -> io::Result<Option<EchoOutcome>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ICMP echo is not implemented on this platform",
        ))
    }
}

/// Reverse DNS via the platform resolver.
#[cfg(unix)]
mod reverse_dns_impl {
    use super::*;
    use std::ffi::CStr;

    /// Resolves an address to a name with `getnameinfo(3)`.
    ///
    /// Uses the system resolver rather than querying a nameserver directly, so
    /// it honours `/etc/hosts`, mDNS via nsswitch, and any search domains the
    /// host is configured with.
    pub fn lookup(addr: IpAddr) -> Option<String> {
        // SAFETY: getnameinfo writes at most `host.len()` bytes into the
        // buffer, and the sockaddr passed is sized by its matching length.
        unsafe {
            let (sa, len) = sockaddr_for(addr);
            let mut host = [0 as libc::c_char; 256];
            let rc = libc::getnameinfo(
                &sa as *const _ as *const libc::sockaddr,
                len,
                host.as_mut_ptr(),
                host.len() as _,
                std::ptr::null_mut(),
                0,
                // Fail rather than fall back to the numeric form, so a missing
                // record is not reported as a hostname.
                libc::NI_NAMEREQD,
            );
            if rc != 0 {
                return None;
            }
            let name = CStr::from_ptr(host.as_ptr()).to_str().ok()?.to_string();
            if name.is_empty() {
                None
            } else {
                Some(name)
            }
        }
    }

    fn sockaddr_for(addr: IpAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
        // SAFETY: as in icmp_impl; the correct variant is written before use.
        unsafe {
            let mut storage: libc::sockaddr_storage = std::mem::zeroed();
            match addr {
                IpAddr::V4(v4) => {
                    let sin = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in);
                    sin.sin_family = libc::AF_INET as libc::sa_family_t;
                    sin.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
                    (
                        storage,
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                }
                IpAddr::V6(v6) => {
                    let sin6 = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6);
                    sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                    sin6.sin6_addr.s6_addr = v6.octets();
                    (
                        storage,
                        std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    )
                }
            }
        }
    }
}

#[cfg(not(unix))]
mod reverse_dns_impl {
    use super::*;
    /// Not yet implemented off Unix. Reverse DNS is the weakest evidence the
    /// scanner collects, so its absence costs a hostname, never a host.
    pub fn lookup(_addr: IpAddr) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn a_real_listener_is_reported_open() {
        // A genuine socket on loopback: real handshake, real kernel.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let t = SystemTransport::new();
        match t.tcp_probe(addr, Duration::from_secs(2)) {
            TcpOutcome::Open { .. } => {}
            other => panic!("expected Open, got {other:?}"),
        }
    }

    #[test]
    fn a_closed_port_is_reported_closed_not_filtered() {
        // Bind then drop, so the port is certainly unused and the kernel RSTs.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let t = SystemTransport::new();
        let outcome = t.tcp_probe(addr, Duration::from_secs(2));
        assert_eq!(
            outcome,
            TcpOutcome::Closed {
                rtt: match outcome {
                    TcpOutcome::Closed { rtt } => rtt,
                    _ => panic!("expected Closed, got {outcome:?}"),
                }
            }
        );
        // And a RST still proves the host exists.
        assert!(outcome.proves_host());
    }

    #[test]
    fn open_and_closed_both_prove_a_host_but_filtered_does_not() {
        assert!(TcpOutcome::Open {
            rtt: Duration::ZERO
        }
        .proves_host());
        assert!(TcpOutcome::Closed {
            rtt: Duration::ZERO
        }
        .proves_host());
        assert!(!TcpOutcome::Filtered.proves_host());
        assert!(!TcpOutcome::Unreachable.proves_host());
    }

    #[test]
    fn reverse_dns_resolves_loopback_or_reports_nothing() {
        // Hosts vary in whether 127.0.0.1 has a PTR record; both are valid.
        // What must not happen is the numeric form being returned as a name.
        let t = SystemTransport::new();
        if let Some(name) = t.reverse_dns("127.0.0.1".parse().unwrap()) {
            assert_ne!(name, "127.0.0.1", "NI_NAMEREQD should prevent this");
            assert!(!name.is_empty());
        }
    }

    #[test]
    fn reverse_dns_of_an_unassigned_address_yields_nothing() {
        let t = SystemTransport::new();
        // A documentation-range address that should have no PTR record.
        assert_eq!(t.reverse_dns("203.0.113.201".parse().unwrap()), None);
    }

    #[test]
    fn mdns_merging_folds_repeat_responses_from_one_host() {
        let mut a = mdns::MdnsInfo {
            hostname: Some("host".into()),
            services: vec!["_ipp._tcp".into()],
            txt: vec![("ty".into(), "Printer".into())],
            ..Default::default()
        };
        let b = mdns::MdnsInfo {
            hostname: Some("other".into()),
            services: vec!["_ipp._tcp".into(), "_http._tcp".into()],
            txt: vec![("ty".into(), "Ignored".into()), ("rp".into(), "ipp".into())],
            ..Default::default()
        };
        merge_mdns(&mut a, b);

        assert_eq!(a.hostname.as_deref(), Some("host"), "first name wins");
        assert_eq!(a.services, vec!["_ipp._tcp", "_http._tcp"]);
        assert_eq!(a.txt_value("ty"), Some("Printer"), "first value wins");
        assert_eq!(a.txt_value("rp"), Some("ipp"));
    }
}
