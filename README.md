# wFetch

A cross-platform network scanner for the command line, for administrators and
for agents.

`wfetch` discovers the hosts on a network, works out what each one is, and can
inventory them over SNMP or SSH. It runs on Linux, macOS, Windows and Android,
has no GUI, and emits either an aligned table or stable JSON.

```console
$ wfetch scan 192.168.1.0/24
ADDRESS        MAC                HOSTNAME     DEVICE                    PORTS         EVIDENCE
192.168.1.1    c8:0e:14:11:22:33  fritz.box    router / Linux / AVM      53,80,443     arp,icmp,ssdp,tcp
192.168.1.20   00:80:77:aa:bb:cc  BRW8077      printer / Brother         80,631,9100   arp,mdns,tcp
192.168.1.34   a4:83:e7:0d:9f:11  Simons-iPad  tablet / iOS / Apple      62078         arp,mdns,tcp
192.168.1.50   00:0c:29:de:ad:01  web-01       VM / Linux / VMware       22,80,443     arp,icmp,tcp
192.168.1.77   b8:27:eb:01:02:03  pi-hole      SBC / Linux / Raspberry…  22,53,80      arp,icmp,tcp

5 hosts found from 254 addresses in 4.2s.
```

## Status

This is a developer-facing tool. It is a ground-up rewrite: the project was
previously a Windows-only Tauri desktop application, and none of that remains.

## Why this exists

Most scanners tell you an address is "up" and leave you to work out what that
means. `wfetch` records *why* it believes each host exists and how strongly:

- A completed TCP handshake or an ICMP reply is proof.
- A TCP reset is equally conclusive — something answered — and is often the
  only signal a host with no services and no ICMP will ever give you.
- A stale ARP entry is weaker: it can outlive the host being unplugged.
- A reverse DNS record is weakest of all: it proves only that someone once
  wrote one down.

Every host carries its evidence in the output, so a surprising result can be
argued with instead of guessed at.

## Installing

Requires Rust 1.80 or later.

```console
$ cargo build --release
$ ./target/release/wfetch --help
```

The binary is self-contained. It has no runtime dependency on `ping`,
`arp`, PowerShell or any other external command; the one exception is the
optional SSH inventory path, which drives the host's own `ssh` client
deliberately (see [docs/INVENTORY.md](docs/INVENTORY.md)).

## Quick start

```console
# Scan the local subnet, derived from the default interface
$ wfetch scan

# Scan a specific network, skipping the gateway
$ wfetch scan 10.0.0.0/24 --exclude 10.0.0.1

# Ranges and single addresses work too
$ wfetch scan 10.0.0.1-50 192.168.1.10

# Send nothing at all: report only what this machine already knows
$ wfetch scan --passive

# Machine-readable output for scripts and agents
$ wfetch scan -o json | jq '.hosts[] | select(.identity.class == "printer")'

# What can this host actually do?
$ wfetch capabilities
```

## Privileges

`wfetch` works unprivileged and reports what it had to skip. Running it with
elevated privileges adds techniques rather than being a requirement:

| Technique | Unprivileged | Privileged |
|---|---|---|
| TCP connect | yes | yes |
| mDNS / SSDP / NetBIOS | yes | yes |
| Reverse DNS | yes | yes |
| Neighbour (ARP/NDP) table | platform-dependent | yes |
| ICMP echo | platform-dependent | yes |

`wfetch capabilities` reports the answer for the machine you are on. When a
technique is unavailable, the scan says so explicitly rather than quietly
returning fewer hosts:

```console
$ wfetch scan 10.0.0.0/24
wfetch: skipping icmp_echo: ICMP echo requires raw sockets or an unprivileged
        ICMP socket, neither of which is available
```

## Platform support

| Platform | Discovery | Neighbour table | ICMP | Notes |
|---|---|---|---|---|
| Linux | full | netlink `RTM_GETNEIGH` | raw or unprivileged | |
| macOS | full | `PF_ROUTE` sysctl | raw (needs root) | |
| Windows | full | `GetIpNetTable2` | `IcmpSendEcho` | no elevation needed for ICMP |
| Android | reduced | **unavailable** | **unavailable** | unprivileged techniques only |

Android is genuinely limited, not merely untested: since API 29 the neighbour
table is not readable by unprivileged processes and `CAP_NET_RAW` is not
available, so ARP-based and ICMP-based discovery cannot work. Hosts are found
by service response instead. iOS is **not** a target — there is no user-runnable
CLI on a stock device, raw sockets are prohibited, and the ARP table is
inaccessible.

[docs/PLATFORMS.md](docs/PLATFORMS.md) explains each of these in detail.

## Documentation

| Document | Contents |
|---|---|
| [docs/CLI.md](docs/CLI.md) | Every command and flag |
| [docs/JSON.md](docs/JSON.md) | Output schema for scripts and agents |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How the crate is put together |
| [docs/PLATFORMS.md](docs/PLATFORMS.md) | Per-platform capabilities and limits |
| [docs/IDENTIFICATION.md](docs/IDENTIFICATION.md) | How devices are identified |
| [docs/INVENTORY.md](docs/INVENTORY.md) | SNMP and SSH inventory |
| [docs/TESTING.md](docs/TESTING.md) | The test strategy, including the real-network harness |

## Testing

```console
$ cargo test                 # unit tests, no privileges needed
$ sudo cargo test            # adds the real-network suite
```

Beyond unit tests, the suite builds **real** networks out of Linux network
namespaces — veth pairs bridged together, real kernel ARP, real MAC addresses,
real TCP resets — and runs the production socket code against them. That is
what verifies the scans actually work, rather than only that the logic is
self-consistent. See [docs/TESTING.md](docs/TESTING.md).

## Legitimate use

Scanning a network generates traffic that intrusion detection systems are
built to notice, and on many networks doing so without authorisation is a
disciplinary or legal matter regardless of intent. Scan networks you are
responsible for, or have been asked to look at.

The default rate limit is there for a practical reason as well as a polite one:
an unpaced sweep can overflow a switch's ARP table, and many access points
treat a burst of ARP requests as an attack and begin dropping them — so an
unpaced scan often finds *fewer* hosts than a paced one.

## License

MIT.
