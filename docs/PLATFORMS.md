# Platform support

Supported: **Linux**, **macOS**, **Windows**, **Android**.
Not supported: **iOS** — see the last section for why.

## Summary

| | Linux | macOS | Windows | Android |
|---|---|---|---|---|
| Interface enumeration | `getifaddrs` | `getifaddrs` | `GetAdaptersAddresses` | `getifaddrs` |
| Neighbour table | netlink `RTM_GETNEIGH` | `PF_ROUTE` sysctl | `GetIpNetTable2` | **unavailable** |
| ICMP echo | raw or `SOCK_DGRAM` | raw (root) | `IcmpSendEcho` | **unavailable** |
| Raw sockets | `CAP_NET_RAW` | root | administrator | **never** |
| TCP connect | yes | yes | yes | yes |
| mDNS / SSDP | yes | yes | yes | yes |
| NetBIOS | yes | yes | yes | yes |
| Reverse DNS | `getnameinfo` | `getnameinfo` | not implemented | `getnameinfo` |

`wfetch capabilities` reports the real answer for the machine you are on.
Capabilities are probed at runtime, not inferred from the build target, because
the same binary has different capabilities as root and as a normal user.

## Linux

Fully supported.

The neighbour table is read over netlink (`RTM_GETNEIGH`), the same interface
`ip neigh` uses. Netlink is preferred over `/proc/net/arp` because `/proc`
covers IPv4 only, does not expose NUD state usefully, and truncates on hosts
with large tables. `/proc/net/arp` remains as a fallback for sandboxes where
netlink sockets are blocked by seccomp.

ICMP works two ways. `SOCK_DGRAM` with `IPPROTO_ICMP` needs no privileges when
the caller's GID falls inside `net.ipv4.ping_group_range` — the mechanism an
unprivileged `ping` uses on modern distributions. Otherwise a raw socket is
tried, which needs `CAP_NET_RAW`.

On a datagram ICMP socket the kernel rewrites the identifier field to the
socket's port, so replies are matched on sequence number rather than identifier.

To grant the capability without running as root:

```console
$ sudo setcap cap_net_raw+ep ./target/release/wfetch
```

## macOS

Fully supported.

There is no netlink. The ARP table comes from a `sysctl` over the routing
socket (`CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO`) — what
`arp -a` does. The result is a packed sequence of variable-length records, each
an `rt_msghdr` followed by whichever `sockaddr`s the `rtm_addrs` bitmask
declares, every one padded to a four-byte boundary.

Struct layouts are declared with matching field types rather than hardcoded
byte offsets, so the compiler computes padding and the code is correct on both
Intel and Apple Silicon.

macOS has no equivalent of the Linux unprivileged ICMP socket, so ICMP echo
requires root. Everything else works unprivileged.

macOS does not report NUD states, so resolved entries are reported as `stale`
(present, unconfirmed) and only `RTF_STATIC` entries as `permanent`. This is
deliberately conservative: claiming `reachable` would overstate what the
platform actually told us.

## Windows

Fully supported.

The neighbour table comes from `GetIpNetTable2` and interfaces from
`GetAdaptersAddresses` — the IP Helper APIs that `Get-NetNeighbor` and
`Get-NetAdapter` call underneath.

The previous version of this project ran discovery by building a PowerShell
script as a string and shelling out to `powershell.exe`. That is gone. It cost
a process spawn per scan, depended on the execution policy and on PowerShell
being present, round-tripped every result through JSON, and had no equivalent
on any other platform.

ICMP uses `IcmpSendEcho`, which works **without** administrator rights — unlike
raw sockets, which need elevation. So ICMP sweeps work for ordinary users on
Windows, which is not true anywhere else.

Reverse DNS is not yet implemented on Windows. It is the weakest evidence the
scanner collects, so its absence costs a hostname, never a host.

## Android

**Supported, but genuinely reduced.** Not a limitation of this implementation —
a limitation of the platform.

### What does not work

**The neighbour table.** Since Android 10 (API 29), `/proc/net/arp` returns a
header row and nothing else to unprivileged callers, and `RTM_GETNEIGH` netlink
dumps are filtered by SELinux policy. This was deliberate on Google's part: the
ARP table let apps fingerprint the surrounding network and was used for
cross-app device tracking. There is no permission that restores it.

**Raw sockets.** `SOCK_RAW` requires `CAP_NET_RAW`, which no app process holds.
That rules out ARP injection and TCP SYN scanning.

**ICMP echo.** Android does not open `net.ipv4.ping_group_range` to app GIDs,
so the unprivileged ICMP socket that works on desktop Linux is unavailable too.

### What does work

`getifaddrs` is permitted, so interfaces, their addresses and prefix lengths
are readable — enough to derive the local subnet and plan a scan. On top of
that, every unprivileged probe remains available: TCP connect, UDP, mDNS/DNS-SD,
SSDP and NetBIOS name queries.

### What that means in practice

A scan from Android finds hosts **by service response** rather than by
link-layer presence. It will find a printer, a router, a NAS, a Chromecast and
any host with an open TCP port. It will not find a host that runs no services
and answers no discovery protocol, because the two techniques that would have
found it — ARP and ICMP — are both unavailable.

The Android backend returns `Unsupported` for the neighbour table rather than
an empty list, so this shows up in `techniques_skipped` instead of looking like
a network with fewer hosts on it.

### Running it

`wfetch` is a CLI, so on Android it runs under a terminal environment such as
Termux:

```console
$ cargo build --release --target aarch64-linux-android
```

Rooted devices are not special-cased. The capability probes report whatever is
actually available, so a rooted device automatically gets the extra techniques.

## iOS — not supported

iOS is not a target, and this is a platform judgement rather than a backlog
item:

- **There is no user-runnable CLI.** Stock iOS has no shell and no way to
  execute an arbitrary binary. A command-line tool has nowhere to run.
- **Raw sockets are prohibited.** The sandbox denies `SOCK_RAW` outright, so
  ICMP and ARP are impossible.
- **The ARP table is inaccessible.** There is no public API, and the `sysctl`
  route macOS uses is blocked.
- **App Store policy** restricts network scanning functionality, so packaging
  the engine as an app is not a route around any of the above.

What remains — TCP connect and multicast discovery behind the Local Network
permission prompt — would be a different product with a different interface, not
this one. Building it would mean shipping an iOS target that could not do most
of what the tool claims to do.

The platform layer is a trait, so an iOS backend could be added later without
disturbing anything above it. Nothing in the codebase assumes it exists.

## Cross-compiling

```console
$ rustup target add x86_64-pc-windows-msvc aarch64-apple-darwin aarch64-linux-android
$ cargo check --target aarch64-linux-android
```

All four backends are type-checked for their own targets in CI. Note that
`cargo check` verifies compilation only; linking Windows and macOS binaries
needs the respective toolchains.
