//! MAC (EUI-48) addresses.
//!
//! Kept separate from the platform layer because device identification reasons
//! about MACs heavily: the OUI is often the single strongest signal about what
//! a device is, and the locally-administered bit is what tells us the OUI is
//! worthless (randomised privacy MACs, which every modern phone uses).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid MAC address: {0}")]
pub struct MacParseError(pub String);

/// A 48-bit hardware address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub const ZERO: MacAddr = MacAddr([0; 6]);
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);

    pub const fn new(octets: [u8; 6]) -> Self {
        MacAddr(octets)
    }

    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// The 24-bit Organisationally Unique Identifier, as a `u32` in the low bits.
    pub fn oui(&self) -> u32 {
        u32::from_be_bytes([0, self.0[0], self.0[1], self.0[2]])
    }

    /// Group bit (LSB of the first octet): the frame is multicast/broadcast.
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Local bit (bit 1 of the first octet).
    ///
    /// When set, the address was not assigned from an IEEE OUI block, so vendor
    /// lookup is meaningless. Randomised MACs on iOS, Android, Windows and
    /// recent macOS all set this bit, as do most virtual interfaces.
    pub fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// Whether an OUI lookup on this address can be meaningful.
    pub fn has_meaningful_oui(&self) -> bool {
        !self.is_locally_administered() && !self.is_multicast() && *self != Self::ZERO
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 6]
    }

    /// Canonical lowercase colon-separated form, e.g. `a4:83:e7:1c:0d:9f`.
    pub fn to_canonical_string(&self) -> String {
        self.to_string()
    }

    /// The OUI as a colon-separated prefix, e.g. `a4:83:e7`.
    pub fn oui_string(&self) -> String {
        format!("{:02x}:{:02x}:{:02x}", self.0[0], self.0[1], self.0[2])
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl FromStr for MacAddr {
    type Err = MacParseError;

    /// Accepts colon, hyphen and dot separators, and bare hex.
    ///
    /// All four forms occur in the wild: `ip neigh` emits colons, Windows
    /// `getmac` emits hyphens, Cisco gear emits dotted triples, and some SNMP
    /// agents emit bare hex.
    fn from_str(s: &str) -> Result<Self, MacParseError> {
        let t = s.trim();
        let err = || MacParseError(s.to_string());

        // Cisco dotted-triple form: aabb.ccdd.eeff
        if t.contains('.') {
            let groups: Vec<&str> = t.split('.').collect();
            if groups.len() != 3 || groups.iter().any(|g| g.len() != 4) {
                return Err(err());
            }
            let mut out = [0u8; 6];
            for (i, g) in groups.iter().enumerate() {
                let v = u16::from_str_radix(g, 16).map_err(|_| err())?;
                out[i * 2] = (v >> 8) as u8;
                out[i * 2 + 1] = (v & 0xff) as u8;
            }
            return Ok(MacAddr(out));
        }

        let sep = if t.contains(':') {
            Some(':')
        } else if t.contains('-') {
            Some('-')
        } else {
            None
        };

        let bytes: Vec<u8> = match sep {
            Some(c) => {
                let parts: Vec<&str> = t.split(c).collect();
                if parts.len() != 6 {
                    return Err(err());
                }
                parts
                    .iter()
                    .map(|p| {
                        if p.len() > 2 || p.is_empty() {
                            return Err(err());
                        }
                        u8::from_str_radix(p, 16).map_err(|_| err())
                    })
                    .collect::<Result<_, _>>()?
            }
            None => {
                if t.len() != 12 {
                    return Err(err());
                }
                (0..6)
                    .map(|i| u8::from_str_radix(&t[i * 2..i * 2 + 2], 16).map_err(|_| err()))
                    .collect::<Result<_, _>>()?
            }
        };

        let mut out = [0u8; 6];
        out.copy_from_slice(&bytes);
        Ok(MacAddr(out))
    }
}

impl Serialize for MacAddr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(v: [u8; 6]) -> Self {
        MacAddr(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_separator_form_to_the_same_value() {
        let expected = MacAddr([0xa4, 0x83, 0xe7, 0x1c, 0x0d, 0x9f]);
        for s in [
            "a4:83:e7:1c:0d:9f",
            "A4:83:E7:1C:0D:9F",
            "a4-83-e7-1c-0d-9f",
            "a483.e71c.0d9f",
            "a483e71c0d9f",
            "  a4:83:e7:1c:0d:9f  ",
        ] {
            assert_eq!(s.parse::<MacAddr>().unwrap(), expected, "parsing {s:?}");
        }
    }

    #[test]
    fn accepts_single_digit_groups() {
        // `ip neigh` prints 0:1:2:3:4:5 rather than zero-padding on some systems.
        assert_eq!(
            "0:1:2:3:4:5".parse::<MacAddr>().unwrap(),
            MacAddr([0, 1, 2, 3, 4, 5])
        );
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in [
            "",
            "zz:83:e7:1c:0d:9f",
            "a4:83:e7:1c:0d",         // too few groups
            "a4:83:e7:1c:0d:9f:11",   // too many groups
            "a4:83:e7:1c:0d:9ff",     // group too long
            "a483e71c0d",             // bare hex too short
            "a483.e71c",              // too few dotted groups
            "a4::e7:1c:0d:9f",        // empty group
        ] {
            assert!(bad.parse::<MacAddr>().is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn display_is_canonical_lowercase_and_zero_padded() {
        assert_eq!(MacAddr([0, 1, 2, 3, 4, 5]).to_string(), "00:01:02:03:04:05");
        assert_eq!(
            MacAddr([0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa]).to_string(),
            "ff:ee:dd:cc:bb:aa"
        );
    }

    #[test]
    fn display_round_trips_through_parsing() {
        let m = MacAddr([0xa4, 0x83, 0xe7, 0x1c, 0x0d, 0x9f]);
        assert_eq!(m.to_string().parse::<MacAddr>().unwrap(), m);
    }

    #[test]
    fn extracts_the_oui() {
        let m: MacAddr = "a4:83:e7:1c:0d:9f".parse().unwrap();
        assert_eq!(m.oui(), 0xa483e7);
        assert_eq!(m.oui_string(), "a4:83:e7");
    }

    #[test]
    fn detects_the_group_and_local_bits() {
        // 02:... has the local bit set; 01:... has the group bit set.
        let local: MacAddr = "02:00:00:00:00:01".parse().unwrap();
        assert!(local.is_locally_administered());
        assert!(!local.is_multicast());

        let group: MacAddr = "01:00:5e:00:00:fb".parse().unwrap();
        assert!(group.is_multicast());
        assert!(!group.is_locally_administered());

        let global: MacAddr = "a4:83:e7:1c:0d:9f".parse().unwrap();
        assert!(!global.is_locally_administered());
        assert!(!global.is_multicast());
    }

    #[test]
    fn randomised_and_broadcast_macs_have_no_meaningful_oui() {
        // A randomised phone MAC: vendor lookup would be actively misleading.
        assert!(!"02:1a:2b:3c:4d:5e"
            .parse::<MacAddr>()
            .unwrap()
            .has_meaningful_oui());
        assert!(!MacAddr::BROADCAST.has_meaningful_oui());
        assert!(!MacAddr::ZERO.has_meaningful_oui());
        assert!("a4:83:e7:1c:0d:9f"
            .parse::<MacAddr>()
            .unwrap()
            .has_meaningful_oui());
    }

    #[test]
    fn every_locally_administered_bit_pattern_is_detected() {
        // The local bit is bit 1 of octet 0; check all 256 first-octet values.
        for b in 0u8..=255 {
            let m = MacAddr([b, 0, 0, 0, 0, 1]);
            assert_eq!(m.is_locally_administered(), b & 0x02 != 0, "octet {b:#04x}");
            assert_eq!(m.is_multicast(), b & 0x01 != 0, "octet {b:#04x}");
        }
    }

    #[test]
    fn serde_round_trips_as_a_string() {
        let m: MacAddr = "a4:83:e7:1c:0d:9f".parse().unwrap();
        let j = serde_json::to_string(&m).unwrap();
        assert_eq!(j, "\"a4:83:e7:1c:0d:9f\"");
        assert_eq!(serde_json::from_str::<MacAddr>(&j).unwrap(), m);
    }

    #[test]
    fn ordering_is_by_octet_significance() {
        let a: MacAddr = "00:00:00:00:00:01".parse().unwrap();
        let b: MacAddr = "00:00:00:00:01:00".parse().unwrap();
        let c: MacAddr = "01:00:00:00:00:00".parse().unwrap();
        assert!(a < b && b < c);
    }
}
