# Device identification

## The problem

No single signal identifies a device reliably:

- A **MAC OUI** is authoritative — until the device randomises it, which every
  modern phone does by default, on every network it joins.
- **Port 445 open** means Windows — until it is a NAS running Samba.
- **TTL 64** means Unix-like — which covers Linux, macOS, iOS, Android and the
  BSDs at once.
- **A hostname** means whatever someone typed years ago.

So `wfetch` does not pick a signal. It accumulates weighted evidence from every
signal the scan collected, scores each candidate, and reports the
best-supported answer along with the reasons — and lowers its confidence when
signals disagree instead of picking one and sounding certain.

## Inputs

| Signal | Strength | What it gives |
|---|---|---|
| mDNS TXT `model=` | very strong | Exact model: `iPhone14,5`, `AppleTV6,2`, `MacBookPro18,3` |
| Default gateway role | very strong | Router. Cannot be derived from the host itself |
| mDNS service types | strong | `_ipp._tcp` → printer, `_googlecast._tcp` → media device |
| MAC OUI | strong | Vendor, and often a device class |
| Distinctive ports | strong | 62078 → iOS, 5555 → Android, 9100 → printer |
| SSDP `SERVER` / `ST` | strong | OS name and `InternetGatewayDevice` |
| NetBIOS response | strong | Windows or Samba; domain controller roles |
| Port profiles | moderate | 135 + 445 together is far more Windows-specific than 445 alone |
| Hostname patterns | weak | `DESKTOP-*` is the Windows default; `*printer*` is a hint |
| IP TTL | very weak | Only ever a tiebreaker |

## Scoring

Each signal adds weight to a device class, an OS family, or both. The winner in
each category is the highest total. Confidence combines absolute support with
the **margin** over the runner-up:

```
confidence = min(top, 100) * 0.6 + min(top - runner_up, 100) * 0.4
```

The margin term is what makes contradiction visible. A host with both RDP
(Windows) and the iOS lockdown service open cannot be both; the two scores
cancel, the margin collapses, and confidence drops. A host with only the iOS
port open has no competition and scores high.

Everything is deterministic: the same signals always produce the same verdict,
with ties broken on a stable key. There is no randomness and no learned model.

## Randomised MACs

Vendor lookup ignores locally administered addresses. Those bytes were never
assigned by the IEEE, so any table hit would be a coincidence presented as
fact. This is the common case, not an edge case — iOS, Android, Windows and
recent macOS all randomise per network by default.

One deliberate exception: a few prefixes are locally administered *by
convention* and are genuinely identifying, the important one being QEMU/KVM's
`52:54:00`. Refusing to resolve it would leave every VM on a hypervisor host
showing an unknown vendor. The distinction is self-enforcing — a table entry
whose own OUI has the local bit set is by construction a deliberate entry of
this kind.

## Vendor database

The built-in table is a **curated subset**, not the full IEEE registry, which
is roughly 35 000 entries and several megabytes. It covers what actually turns
up on a LAN: virtualisation vendors (otherwise mystifying to see), the major
router, printer, NAS, camera and media-device makers, and the device families
whose OUI alone identifies them.

`lookup` returning nothing means "not in the built-in table" — never "not a
real vendor" — and an unknown OUI is never treated as evidence of anything.

For exhaustive coverage, load the registry:

```console
$ curl -sO https://standards-oui.ieee.org/oui/oui.csv
$ wfetch scan 10.0.0.0/24 --oui-file oui.csv
```

Registry entries supply vendor names only. Built-in entries additionally carry
device-class hints, so they take precedence on conflict.

General-purpose vendors — Intel, Realtek, Broadcom — carry **no** class hint.
Their chips appear in everything, so a guess from them would be worse than no
guess.

## Reading the output

The `DEVICE` column shows class, OS family and vendor. A trailing `?` marks a
confidence below 50:

```
DEVICE
router / Linux / AVM        confident
Linux?                      a guess, most likely from TTL alone
printer / Brother           confident
```

In JSON, `identity.reasons` lists the justifications, strongest first:

```console
$ wfetch scan -o json -q | jq '.hosts[] | {ip, class: .identity.class, why: .identity.reasons}'
```

If a verdict looks wrong, that list says exactly which signal produced it.

## Limits

- **Randomised MACs remove the vendor signal entirely.** A modern phone that
  answers no discovery protocol is very hard to place.
- **Samba looks like Windows** on port evidence alone. mDNS or NetBIOS usually
  resolves it; port evidence alone will not.
- **TTL is nearly worthless on its own** and is weighted accordingly. It only
  breaks ties.
- **Identification describes what a device presents as**, which is not the same
  as what it is. A host deliberately presenting differently will be described
  as it presents.
- The classifier is a fixed rule set, not a learned model. It is auditable and
  deterministic, and it will not recognise a device nobody has taught it about.
