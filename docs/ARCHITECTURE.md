# Architecture

## Layout

```
crates/
  wfetch-core/     library: everything except argument parsing and rendering
  wfetch-cli/      the `wfetch` binary
```

The split exists so the scanner can be used as a library, and so the engine has
no opinion about how results are displayed.

## Layers

```
                    ┌─────────────────┐
                    │   wfetch-cli    │  parsing, rendering, exit codes
                    └────────┬────────┘
                             │
 ┌───────────────────────────┴───────────────────────────┐
 │                      wfetch-core                      │
 │                                                       │
 │   addr ──────► target ──────► scan::engine            │
 │   (pure math)  (planning)     (scheduling, merging)   │
 │                                    │                  │
 │                       ┌────────────┴────────────┐     │
 │                       ▼                         ▼     │
 │                 scan::transport            platform   │
 │                 (sockets)                  (OS APIs)  │
 │                       │                               │
 │                       ▼                               │
 │                     proto                             │
 │                (wire formats, pure)                   │
 │                                                       │
 │   fingerprint ◄──────────────── results               │
 │   inventory   (credentialed, post-discovery)          │
 └───────────────────────────────────────────────────────┘
```

Modules, bottom to top:

| Module | Responsibility | I/O? |
|---|---|---|
| `addr` | CIDR arithmetic, host enumeration, address classification | no |
| `mac` | EUI-48 addresses, OUI extraction | no |
| `proto` | ICMP, DNS, mDNS, SSDP, NetBIOS wire formats | no |
| `target` | turns user specs into a bounded, ordered scan plan | no |
| `platform` | interfaces and neighbour tables, per OS | yes |
| `scan::transport` | sockets: TCP, ICMP, UDP, multicast | yes |
| `scan::engine` | scheduling, pacing, retries, merging | via traits |
| `fingerprint` | device identification from accumulated evidence | no |
| `inventory` | credentialed inspection over SNMP and SSH | yes |

## Design decisions

### Everything above the platform boundary is pure

Address arithmetic, wire formats and device identification perform no I/O. They
are ordinary functions over values, which is why they can be exhaustively
tested without a network, without privileges and without waiting.

This is not decoration. The bugs that make a scanner silently useless live
exactly here — an ICMP checksum that is subtly wrong makes every probe fail, a
`/31` reported as having zero hosts skips every point-to-point link — and none
of them are visible from the outside. They are visible from a unit test.

### Two abstraction seams

Only two traits separate the engine from the outside world:

- **`HostPlatform`** — interfaces and the neighbour table.
- **`Transport`** — probes.

Everything else is concrete. Two seams are enough to test the engine against a
fake network and a fake host, and few enough that the code is still readable as
a straight line.

There is no `#[cfg]` anywhere above `platform`. All four operating systems are
handled behind that one trait.

### Capabilities are runtime facts

The same binary has different capabilities as root and as a normal user, so
capabilities are probed at runtime rather than assumed from the target triple.

A technique that cannot run is recorded in `techniques_skipped` with a reason.
This matters more than it sounds: a scan that silently drops half its probes
produces a shorter host list that looks exactly like a network with fewer hosts
on it. The report distinguishes the two.

### Evidence, not verdicts

The engine records *observations*, and confidence is derived from them:

| Evidence | Weight | Why |
|---|---:|---|
| TCP handshake completed | 100 | The host answered. |
| ICMP echo reply | 95 | The host answered. |
| TCP reset | 90 | The host answered, and said no. |
| mDNS / SSDP / NetBIOS response | 85 | The host answered, informatively. |
| Neighbour entry, reachable | 80 | Confirmed at the link layer, recently. |
| Neighbour entry, stale | 55 | Can outlive the host being unplugged. |
| Reverse DNS record | 20 | Proves only that someone wrote one down. |
| Neighbour entry, failed/incomplete | 0 | A record of a resolution that *failed*. |

That last row is the one that matters most in practice: an `INCOMPLETE` ARP
entry means the kernel asked and got no answer. Counting those as hosts would
report every address the machine has ever tried to reach as alive.

### The planner is the safety boundary

Plan size is computed arithmetically before a single address is materialised,
so `wfetch scan 10.0.0.0/8` is *rejected* rather than expanded into a
sixteen-million-entry allocation. Exclusions are matched by containment rather
than expansion, so excluding a `/8` from a `/24` scan costs nothing.

### Passive before active

The kernel's neighbour table already knows about hosts this machine has talked
to, and reading it costs no packets, so it runs before anything is transmitted.

It is then read a *second* time after probing. The first read happens on a
possibly cold ARP cache and can see nothing; probing populates it. Without the
second pass a first scan reports no MAC addresses and an immediate re-scan
reports them all — which looks like an unreliable scanner, and loses the vendor
OUI, the strongest identification signal available.

The second pass only fills in hosts already found. Adding hosts there would let
traffic from unrelated processes leak addresses outside the plan into results.

### Concurrency

A fixed pool of worker threads, with the plan striped across them, and a shared
token bucket pacing the whole pool. Threads rather than an async runtime: the
work is a bounded number of blocking socket calls with timeouts, which threads
express directly and which would need an entire executor otherwise.

Stripes are interleaved rather than contiguous, so each worker's traffic is
spread across the address space instead of hammering one `/24` at a time.

Results are keyed by address in a `BTreeMap`, so output ordering does not depend
on worker scheduling. A scanner whose output reorders between runs cannot be
diffed, and diffing is most of what change detection is.

### Timeouts adapt

A fixed probe timeout is wrong in both directions: too short and a busy host is
recorded as down, too long and sweeping a quiet `/24` is nearly all waiting. The
engine tracks smoothed RTT and its variation per worker (RFC 6298) and derives
the timeout from both.

## Adding a platform

1. Implement `HostPlatform` in `platform/<os>.rs`.
2. Add the `#[cfg]` arm in `platform/mod.rs::host_platform()`.
3. Report capabilities honestly — return `Err(Unsupported)` rather than
   `Ok(vec![])` for anything the platform cannot do, because an empty result is
   indistinguishable from a network with no hosts on it.
4. Split any wire-format parsing into a pure function over `&[u8]` so it can be
   tested from a synthetic buffer, as the netlink and `PF_ROUTE` backends do.

## Adding a probe

1. Put the wire format in `proto/`, as pure encode and decode functions.
2. Add the method to `Transport`, implement it in `SystemTransport`, and model
   it in `SimTransport`.
3. Add an `Evidence` variant and give it a weight relative to the table above.
4. Gate it on a capability in `ScanConfig::constrain_to`.
