# Command reference

```
wfetch [OPTIONS] <COMMAND>
```

Results go to **stdout**; progress notes and warnings go to **stderr**. So
`wfetch scan -o json | jq` works without diagnostics corrupting the stream.

## Global options

| Option | Default | Meaning |
|---|---|---|
| `-o`, `--output <FORMAT>` | `human` | `human`, `json` or `ndjson` |
| `-q`, `--quiet` | off | Suppress progress notes on stderr |
| `-h`, `--help` | | Help; `--help` is longer than `-h` |
| `-V`, `--version` | | Version |

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | The command ran |
| 1 | It could not run — unreadable platform data, an unusable target |
| 2 | Usage error — an unknown flag or an unparseable argument |
| 3 | It ran cleanly and found nothing (`scan --fail-if-empty`, or `inventory` with no data) |

Finding no hosts is not an error by default: an empty network is a valid
answer. `--fail-if-empty` makes it exit 3 for scripts that need the
distinction.

"No hosts" is 3 rather than 2 because 2 is what the argument parser returns on
a usage error, and a script that cannot tell "you typed the command wrong" from
"the network is empty" will eventually act on the wrong one.

---

## `wfetch scan`

```
wfetch scan [OPTIONS] [TARGET]...
```

With no target, scans the subnet of the default interface — preferring a
physical LAN over a VPN tunnel, and excluding the scanner's own address.

### Target syntax

| Form | Example | Notes |
|---|---|---|
| CIDR | `10.0.0.0/24` | Network and broadcast addresses are excluded |
| Netmask | `10.0.0.0/255.255.255.0` | Non-contiguous masks are rejected |
| Range | `10.0.0.1-10.0.0.50` | Inclusive |
| Short range | `10.0.0.1-50` | Last-octet shorthand |
| Single | `10.0.0.5` | |
| IPv6 | `fd00::/120` | Small prefixes only; a `/64` is refused as too large |

Targets are combined, deduplicated and sorted numerically. Overlapping targets
are not scanned twice.

### Options

| Option | Default | Meaning |
|---|---|---|
| `-x`, `--exclude <TARGET>` | | Addresses to skip. Repeatable. Matched by containment, so excluding a `/8` is free |
| `-p`, `--port <PORT>` | see below | TCP ports. Repeatable or comma-separated |
| `-c`, `--concurrency <N>` | 64 | Worker threads |
| `-t`, `--timeout <MS>` | 1000 | Initial per-probe timeout; adapts to observed RTT |
| `-r`, `--retries <N>` | 1 | Extra attempts against silent addresses |
| `--rate <N>` | 2000 | Probes per second across all workers. `0` removes the limit |
| `--max-hosts <N>` | 65536 | Ceiling on plan size |
| `--passive` | off | Send nothing; report only what this host already knows |
| `--unprivileged` | off | Skip techniques needing elevation, even if available |
| `--multicast-timeout <SECS>` | 3 | How long to listen for mDNS and SSDP |
| `--gateway <ADDRESS>` | | Treat this address as the default gateway when identifying |
| `--oui-file <PATH>` | | Load the IEEE `oui.csv` for full vendor coverage |
| `--include-all-addresses` | off | Also scan loopback, link-local and multicast |
| `--fail-if-empty` | off | Exit 3 when no hosts are found |

### Default ports

`22, 80, 443, 445, 139, 135, 3389, 631, 9100, 53, 5555, 62078, 161, 8080`

A discovery set, not a service inventory. Each either identifies a device class
or is likely to be open on a host that answers nothing else. It is deliberately
short: every extra port multiplies the packet count by the number of addresses.

### Examples

```console
# The local subnet
$ wfetch scan

# A specific network, skipping the gateway
$ wfetch scan 10.0.0.0/24 -x 10.0.0.1

# Quick sweep: fewer ports, no retries, shorter timeout
$ wfetch scan 10.0.0.0/24 -p 22,80,443 -r 0 -t 300

# Gentle: 50 probes a second, for production hours
$ wfetch scan 10.0.0.0/24 --rate 50

# Passive: no packets sent to any address
$ wfetch scan --passive

# Full vendor coverage
$ curl -sO https://standards-oui.ieee.org/oui/oui.csv
$ wfetch scan 10.0.0.0/24 --oui-file oui.csv

# Just the printers
$ wfetch scan -o json -q | jq -r '.hosts[] | select(.identity.class=="printer") | .ip'
```

### On `--rate`

The default pacing is not only politeness. An unpaced sweep can overflow the
ARP table of the first switch it crosses, and many access points treat a burst
of ARP requests as an attack and start dropping them. An unpaced scan therefore
often finds *fewer* hosts than a paced one.

---

## `wfetch interfaces`

Lists local interfaces with addresses, prefix lengths, MACs and flags. The
`scannable` flag marks interfaces a scan would consider by default: up,
non-loopback and addressed.

```console
$ wfetch interfaces
NAME   INDEX  MAC                ADDRESSES              FLAGS
lo     1      -                  127.0.0.1/8, ::1/128   up,loopback
eth0   2      aa:bb:cc:dd:ee:ff  192.168.1.50/24        up,multicast,scannable
```

---

## `wfetch neighbors`

Shows the kernel neighbour (ARP/NDP) table.

States follow the Linux NUD vocabulary; macOS and Windows entries are mapped
onto it. `incomplete` and `failed` are records of a resolution that got no
answer — they are shown, but never counted as hosts.

Fails with an explanation on Android, where the table is not readable.

---

## `wfetch capabilities`

Reports what this host can actually do, probed at runtime.

```console
$ wfetch capabilities
platform:         linux
  neighbour table  available      read hosts this machine has already talked to
  raw sockets      available      TCP SYN and ARP probes
  ICMP echo        available      ping sweeps
  multicast        available      mDNS and SSDP discovery
  broadcast        available      NetBIOS name queries
```

Run this first when a scan finds less than expected.

---

## `wfetch inventory`

```
wfetch inventory [OPTIONS] <HOST>...
```

Collects detail from hosts already known to exist. Unlike `scan`, this needs
credentials and is aimed at named hosts rather than a range.

| Option | Default | Meaning |
|---|---|---|
| `--snmp-community <S>` | | SNMP v2c community string |
| `--ssh-user <USER>` | | SSH username |
| `--ssh-port <PORT>` | 22 | SSH port |
| `--ssh-key <PATH>` | | SSH private key |
| `--ssh-accept-new` | off | Record host keys not yet in `known_hosts` |
| `--no-snmp` / `--no-ssh` | | Disable a method |
| `--timeout <SECS>` | 5 | Per-method timeout |

`WFETCH_SNMP_COMMUNITY` is read when `--snmp-community` is absent, and should
be preferred: a command line is readable by every other user on the machine.

Methods are independent — a device that answers SNMP usually will not answer
SSH, so a failure of one never prevents the other. Failures are reported per
method with a reason rather than shown as an empty record.

```console
$ WFETCH_SNMP_COMMUNITY=public wfetch inventory 10.0.0.1 --no-ssh
10.0.0.1
  name:        core-sw-01
  description: Acme Networks GS724T, Firmware 6.3.1.18
  uptime:      14d 6h 56m 7s
```

See [INVENTORY.md](INVENTORY.md) for the security notes on both methods.
