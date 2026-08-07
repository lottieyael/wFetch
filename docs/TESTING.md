# Testing

```console
$ cargo test              # unit tests; no privileges required
$ sudo cargo test         # adds the real-network suite
```

## Three substrates

Each one catches a class of bug the others cannot see.

| Substrate | Verifies | Needs |
|---|---|---|
| Unit tests over pure functions | arithmetic and wire formats | nothing |
| `SimTransport`, a deterministic fake network | engine reasoning | nothing |
| Network namespaces, a real kernel LAN | that probes actually work | root, Linux |

### 1. Pure unit tests

Address arithmetic, wire formats and device identification perform no I/O, so
they are tested directly and exhaustively.

This is where the bugs that silently break a scanner live. A wrong ICMP
checksum makes every probe fail with no error anywhere. A `/31` reported as
having zero usable hosts skips every point-to-point link in a routed network.
Neither is visible from the outside; both are trivially visible here.

Cases are chosen for the boundaries that actually break implementations:

- **CIDR:** `/0`, `/31` (RFC 3021 — two hosts, not zero), `/32`, and iterators
  terminating at `255.255.255.255` without wrapping.
- **ICMP:** the RFC 1071 worked example, carry folding, odd-length padding, and
  the defining property that a packet carrying its own checksum sums to zero.
- **DNS:** name decompression with self-referential and mutually-referential
  pointers, which loop forever in a naive decoder.
- **BER:** the short/long length boundary at 128 bytes, which every device
  crosses with its `sysDescr`, and OIDs under the joint root where the merged
  first arc exceeds one byte.
- **NetBIOS:** the level-1 name encoding in both directions, and the wildcard
  name's NUL padding as distinct from ordinary space padding.

Several parsers additionally take a deterministic pseudo-random byte stream and
assert only that they neither panic nor hang.

### 2. Simulated network

`SimTransport` implements `Transport` over a table of scripted hosts. It models
situations that are awkward to build for real:

- a host that answers one probe in three, so retry logic can be tested;
- a firewalled host that drops SYNs instead of sending resets;
- a host that exists but answers nothing at all, which the engine must decline
  to report rather than invent;
- a transport whose ICMP or multicast fails, so capability degradation can be
  tested without dropping privileges.

It proves the engine reasons correctly about probe results. It cannot prove the
probes work, because it never touches a socket.

### 3. Real networks

This is what verifies the scans work.

`tests/support/mod.rs` builds an actual layer-2 network out of Linux network
namespaces. Each simulated host is a real namespace holding one end of a real
veth pair; the other ends are bridged together in the test process's own
namespace:

```
   test process
   (the scanner)
        │
   ┌────┴─────┐  10.42.x.1/24
   │  bridge  │
   └─┬──┬───┬─┘
     │  │   │        veth pairs
   ┌─┴┐┌┴─┐┌┴─┐
   │h1││h2││h3│      one netns per host, each with
   └──┘└──┘└──┘      its own address and listeners
```

Everything across it is handled by the kernel exactly as on physical hardware:

- ARP resolution is performed by the kernel and populates the real neighbour
  table, which the netlink backend then reads;
- every host has a distinct, kernel-assigned MAC address;
- closed ports produce genuine TCP resets and open ones a genuine handshake;
- ICMP echo requests are answered by the kernel's own ICMP stack, which is what
  validates the hand-rolled checksum and the variable-length IPv4 header walk.

Listeners inside each namespace are real processes bound to real ports.

#### What the real-network suite asserts

| Test | What would otherwise go unnoticed |
|---|---|
| Finds exactly the hosts that exist across a 253-address sweep | false positives and negatives at scale |
| Per-host open ports are accurate | results attributed to the wrong host |
| A host with no listeners is found via its TCP reset | hosts running no services being invisible |
| Open, closed and absent are distinguished | a firewall being reported as an absent host |
| ICMP round-trips against the kernel | a wrong checksum, or a wrong header offset |
| The neighbour table shows real ARP with distinct MACs | netlink parsing errors |
| A passive scan finds hosts without transmitting | passive mode not actually being passive |
| A cold-cache scan still reports MACs | the ARP table being read only before probing |
| The post-probe pass adds no out-of-plan hosts | unrelated traffic leaking into results |
| Separate techniques agree on the same host set | one technique lying |
| An empty subnet reports nothing | phantom hosts from stale state |
| Repeated runs agree exactly | output that cannot be diffed |

The last one matters more than it looks: change detection is most of what an
administrator wants a scanner for, and a tool whose output reorders between
runs cannot support it.

#### Requirements and skipping

The harness needs root (or `CAP_NET_ADMIN` and `CAP_NET_RAW`), `iproute2` and
`python3`. When any is missing the tests print `SKIP` and pass, so the suite
still runs unprivileged — the real-network coverage is simply reported as
absent rather than faked.

Namespaces and interfaces are named with a per-process suffix so parallel test
binaries do not collide, and are torn down on `Drop`, including on panic. A
crashed run's leftovers are cleaned up by the next one.

The suite takes around 75 seconds, mostly waiting out timeouts on the empty
addresses of `/24` sweeps. That wait is the point: it exercises the same
scheduling and timeout paths a real scan uses.

## Cross-platform verification

```console
$ for t in aarch64-linux-android aarch64-apple-darwin x86_64-pc-windows-msvc; do
    cargo check --tests --target $t
  done
```

All four backends type-check for their own targets, tests included. This
catches the ordinary portability mistakes — `getnameinfo` taking `size_t` on
Bionic where glibc takes `socklen_t`, Windows API signatures drifting between
crate versions — without needing four machines.

It is compilation, not execution. The macOS `PF_ROUTE` and Windows
`GetIpNetTable2` backends are covered at runtime only by their pure parsers,
which are tested against synthetic buffers built to the documented struct
layouts. Running the real-network suite on those platforms would require a
different harness on each; that gap is real and is recorded here rather than
papered over.

## Coverage summary

| Suite | Count | Requires |
|---|---:|---|
| `wfetch-core` unit tests | 405 | nothing |
| `wfetch-cli` unit tests | 28 | nothing |
| Real-network integration | 15 | root, Linux |
