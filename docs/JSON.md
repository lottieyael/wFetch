# JSON output

For scripts and agents. `-o json` emits one document; `-o ndjson` emits one
object per line.

Data goes to stdout and diagnostics to stderr, so no filtering is needed:

```console
$ wfetch scan -o json | jq '.hosts | length'
```

Use `-q` as well to silence progress notes entirely.

## Conventions

- **Absent fields are omitted, never `null`.** A host with no MAC has no `mac`
  key. Test for presence, not for null.
- **Enumerations are `snake_case` strings** — `"tcp_open"`, `"media_device"`.
- **Durations are integer microseconds**, in fields suffixed `_micros`.
- **Hosts are ordered by address**, numerically, and the order is stable across
  runs. Two scans of an unchanged network produce identical output, so results
  can be diffed.

## `wfetch scan`

```jsonc
{
  "hosts": [ /* Host objects, ordered by address */ ],
  "addresses_probed": 254,
  "duration_micros": 4213554,
  "techniques_used": ["icmp_echo", "mdns", "neighbor_table", "tcp_connect"],
  "techniques_skipped": {
    "ssdp": "multicast is unavailable on this host"
  }
}
```

`techniques_skipped` is the field to check before trusting an empty result. A
scan that could not use ICMP or the neighbour table returns a shorter host list
that looks exactly like a network with fewer hosts on it; this map is what
distinguishes the two.

### Host

```jsonc
{
  "ip": "192.168.1.20",
  "mac": "00:80:77:aa:bb:cc",        // omitted if unknown
  "hostname": "BRW8077AABBCC",       // omitted if unknown
  "confidence": "confirmed",         // confirmed | probable | possible
  "evidence": [ /* see below */ ],
  "open_ports": [80, 631, 9100],     // omitted if empty; ascending
  "rtt_micros": 412,                 // fastest round trip observed
  "ttl": 64,                         // IP TTL of a reply
  "mdns":    { /* if the host answered mDNS */ },
  "ssdp":  [ { /* one per SSDP response */ } ],
  "netbios": { /* if the host answered NetBIOS */ },
  "identity": { /* see below */ }
}
```

### Confidence

Derived from the strongest evidence, never asserted directly.

| Value | Meaning |
|---|---|
| `confirmed` | Something answered us directly |
| `probable` | Indirect evidence only, such as a stale ARP entry |
| `possible` | Weak evidence only, such as a DNS record |

### Evidence

A tagged union, discriminated by `kind`. Every conclusion the scan reached is
traceable to one of these.

```jsonc
{ "kind": "tcp_open", "port": 22, "rtt_micros": 412 }
{ "kind": "tcp_closed", "port": 80 }
{ "kind": "icmp_echo_reply", "rtt_micros": 2086, "ttl": 64 }
{ "kind": "neighbor_table", "state": "reachable" }
{ "kind": "mdns" }
{ "kind": "ssdp" }
{ "kind": "netbios_node_status" }
{ "kind": "reverse_dns", "name": "printer.lan" }
```

`tcp_closed` is a *positive* result: the host sent a reset, which proves it
exists. On a host with no services and no ICMP it is the only signal there is.

`neighbor_table.state` uses the Linux NUD vocabulary: `reachable`, `stale`,
`delay`, `probe`, `permanent`, `incomplete`, `failed`, `no_arp`, `unknown`.
Hosts backed only by `incomplete` or `failed` are never reported at all — those
record a resolution that got *no* answer.

### Identity

```jsonc
{
  "class": "printer",
  "os": "linux",
  "vendor": "Brother",              // omitted if unknown
  "model": "Brother HL-L2350DW",    // omitted if unknown
  "confidence": 85,                 // 0-100
  "reasons": ["advertises _ipp._tcp", "printing port open"]
}
```

`class` is one of: `router`, `switch`, `access_point`, `printer`, `scanner`,
`computer`, `server`, `nas`, `phone`, `tablet`, `media_device`, `game_console`,
`camera`, `iot_device`, `virtual_machine`, `single_board_computer`, `unknown`.

`os` is one of: `windows`, `linux`, `mac_os`, `ios`, `android`, `bsd`,
`network_os`, `embedded`, `unknown`.

`confidence` falls when signals contradict each other, so a device with two
equally plausible readings reports low confidence rather than picking one and
sounding certain. **Treat anything below 50 as a hint.** `reasons` is ordered
strongest first.

## `wfetch interfaces`

```jsonc
[
  {
    "name": "eth0",
    "index": 2,
    "mac": "aa:bb:cc:dd:ee:ff",
    "addrs": [{ "addr": "192.168.1.50", "prefix_len": 24 }],
    "is_up": true,
    "is_loopback": false,
    "is_point_to_point": false,
    "supports_multicast": true
  }
]
```

## `wfetch neighbors`

```jsonc
[
  {
    "ip": "192.168.1.1",
    "mac": "c8:0e:14:11:22:33",
    "state": "reachable",
    "if_index": 2,
    "if_name": "eth0"
  }
]
```

## `wfetch capabilities`

```jsonc
{
  "platform": "linux",
  "capabilities": {
    "neighbor_table": true,
    "raw_sockets": true,
    "icmp_echo": true,
    "multicast": true,
    "broadcast": true
  }
}
```

## `wfetch inventory`

```jsonc
[
  {
    "ip": "10.0.0.1",
    "snmp": {
      "descr": "Acme Networks GS724T, Firmware 6.3.1.18",
      "name": "core-sw-01",
      "uptime": "14d 6h 56m 7s"
    },
    "unix": {
      "hostname": "web-01",
      "kernel": "Linux",
      "distribution": "Debian GNU/Linux 12 (bookworm)",
      "cpu_count": 8,
      "memory_total_kb": 16316412
    },
    "errors": [
      { "method": "ssh", "reason": "connection refused" }
    ]
  }
]
```

`errors` records why a method produced nothing. A device that answers SNMP but
refuses SSH is a normal outcome, and this says which happened rather than
showing an empty record.

Credentials never appear in output. The type carrying them deliberately
implements no serialisation.

## Recipes

```console
# Addresses only
$ wfetch scan -o json -q | jq -r '.hosts[].ip'

# Everything identified as a printer
$ wfetch scan -o json -q | jq '.hosts[] | select(.identity.class=="printer")'

# Hosts with SMB exposed
$ wfetch scan -o json -q | jq -r '.hosts[] | select(.open_ports // [] | index(445)) | .ip'

# Only what the scan is certain of
$ wfetch scan -o json -q | jq '[.hosts[] | select(.confidence=="confirmed")]'

# Warn if the scan was degraded
$ wfetch scan -o json -q | jq -e '.techniques_skipped | length == 0' >/dev/null \
    || echo "warning: some techniques were unavailable"

# Stream into a pipeline, one host at a time
$ wfetch scan -o ndjson -q | while read -r h; do
    echo "$h" | jq -r '"\(.ip) \(.identity.class // "unknown")"'
  done

# Diff two scans to detect change
$ wfetch scan -o ndjson -q > today.ndjson
$ diff yesterday.ndjson today.ndjson
```

## Stability

Field names and enumeration values are part of the interface. Within a major
version, fields may be **added** but not renamed or removed, and enumerations
may gain variants — so match on the variants you know and treat unrecognised
ones as `unknown` rather than failing.
