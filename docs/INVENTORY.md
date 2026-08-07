# Inventory

Discovery says a host exists and guesses what it is. Inventory logs in and
asks.

They are separate commands on purpose: discovery needs no credentials and
touches every address in a plan, while inventory needs credentials and is only
ever aimed at hosts already known to exist.

```console
$ wfetch inventory 10.0.0.1 10.0.0.50 --snmp-community public --ssh-user admin
```

## Methods

| Method | Targets | Implementation |
|---|---|---|
| SNMP v2c | switches, routers, printers, access points, UPSs | native |
| SSH | Linux, macOS, BSD | via the host's `ssh` client |
| WMI/DCOM | Windows | **not implemented** — see below |

Methods are independent. A device that answers SNMP will usually refuse SSH and
the reverse, so a failure of one never prevents the other from running. Each
failure is reported with a reason rather than shown as an empty record.

## SNMP

The path for network equipment. A managed switch, printer or UPS will not
accept an SSH login from an inventory tool, but almost all of them answer SNMP,
and `sysDescr` alone usually names the vendor, model and firmware version.

Reads the standard system group: `sysDescr`, `sysObjectID`, `sysUpTime`,
`sysContact`, `sysName` and `sysLocation`.

```console
$ WFETCH_SNMP_COMMUNITY=public wfetch inventory 10.0.0.1 --no-ssh
10.0.0.1
  name:        core-sw-01
  description: Acme Networks GS724T, Firmware 6.3.1.18, Boot 1.0.0.9
  uptime:      14d 6h 56m 7s
  location:    Rack 3, Floor 2
```

### Security

**v2c authenticates with a community string sent in clear text, and provides no
encryption.** It is appropriate for reading inventory on a trusted management
network and nothing else. Anyone able to observe the traffic can read both the
community string and everything it returns.

Two consequences are built in:

- No SET operation is implemented at all. This module cannot write to a device.
- Prefer `WFETCH_SNMP_COMMUNITY` over `--snmp-community`: a command line is
  readable by every other user on the machine, through `ps` and `/proc`.

### Why only v2c

v1 is strictly less capable. v3 adds a user-based security model with key
derivation for authentication and privacy, which needs a cryptographic
dependency and careful implementation. A half-implemented v3 client fails in
ways that are indistinguishable from a device being down, which is worse than
not offering it — so it is a genuine gap rather than something quietly
approximated.

## SSH

Collects hostname, kernel, architecture, distribution, uptime, CPU and memory
from Unix-like hosts.

```console
$ wfetch inventory 10.0.0.50 --ssh-user admin --no-snmp
10.0.0.50
  name:        web-01
  description: Debian GNU/Linux 12 (bookworm)
  kernel:      Linux 6.1.0-18-amd64
  arch:        x86_64
  cpu:         Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz x8
  memory:      15.6 GiB
```

### Why the system client

This drives the host's own OpenSSH client rather than embedding an SSH
implementation. That is a deliberate trade, and it is *not* the same pattern as
the PowerShell shelling this project removed:

- The command is built as an **argument vector**, never a shell string. No
  value is interpolated into anything a shell parses.
- `ssh` has a stable, standardised command line. The PowerShell path depended
  on execution policy and module availability.
- It exists on Linux, macOS, the BSDs and Windows 10 and later.
- Most importantly, it honours the operator's existing configuration:
  `~/.ssh/config`, agent forwarding, jump hosts, per-host keys and
  `known_hosts`. An embedded client would need all of that reimplemented, and
  would get host-key verification wrong in the meantime.

The cost is a process spawn per host and a dependency on `ssh` being installed,
which is reported as a specific error rather than discovered at first failure.

### Host key verification

Verification is **on**, and cannot be disabled through any flag. An inventory
tool that turns off host-key checking for convenience is one that will happily
inventory a machine-in-the-middle.

`--ssh-accept-new` uses `StrictHostKeyChecking=accept-new`: it records keys not
yet in `known_hosts`, and still refuses a key that has **changed** — the case
that actually indicates interception.

Failures are classified, because each needs a different response:

| Error | Meaning | What to do |
|---|---|---|
| `HostKeyUnverified` | Unknown or changed key | Investigate before retrying |
| `AuthFailed` | Credentials rejected | Fix the user or key |
| `ConnectionFailed` | Refused, unreachable, timed out | Check the host and firewall |
| `ClientMissing` | No `ssh` on PATH | Install OpenSSH |

Other hardening applied to every connection: `BatchMode=yes` so a scan never
blocks on a password prompt, and `ForwardAgent=no` with `ForwardX11=no` so a
read-only inventory does not expose the operator's agent to every host it
touches.

## Windows: WMI is not implemented

The previous version of this project inventoried Windows hosts by shelling out
to `powershell.exe` and running remote CIM queries. That is not carried over,
for two reasons: it only worked when the scanner itself ran on Windows, and it
is exactly the pattern the discovery path was rewritten to remove.

The honest replacement is a native DCOM/WMI client. That is a substantial piece
of work — the wire protocol is MSRPC over DCOM with NTLM or Kerberos
authentication — and it cannot be verified without a Windows domain to test
against. Shipping an unverified implementation would produce failures
indistinguishable from a host being down, which is worse than not shipping it.

So it is recorded here as a gap rather than approximated.

**Windows hosts are still discovered and identified normally** — through SMB
and RPC port profiles, NetBIOS node status, SSDP and hostname patterns. For
credentialed detail they can be inventoried over SNMP where the SNMP service is
enabled, or over SSH where the OpenSSH server feature is installed (a supported
optional feature since Windows 10 1809).

## Credentials

Credentials are supplied per invocation and never persisted. `wfetch` writes no
credential store, keyring entry or cache — an inventory tool that caches secrets
becomes a target itself.

They also never appear in output: the type carrying them deliberately
implements no serialisation, so they cannot reach a JSON report.

| Source | Method |
|---|---|
| `WFETCH_SNMP_COMMUNITY` | SNMP, preferred |
| `--snmp-community` | SNMP, visible in `ps` |
| `~/.ssh/config`, agent, `--ssh-key` | SSH |
