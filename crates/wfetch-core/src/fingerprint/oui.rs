//! MAC vendor lookup.
//!
//! The IEEE registry is roughly 35 000 entries and several megabytes, which is
//! more than belongs in a binary that is otherwise under a megabyte. So a
//! curated subset of the assignments that actually turn up on a LAN is built
//! in, and the full registry can be loaded at runtime for exhaustive coverage.
//!
//! The built-in table is deliberately a subset. `lookup` returning `None` means
//! "not in the built-in table", never "not a real vendor", and callers must not
//! treat an unknown OUI as evidence of anything.

use std::collections::HashMap;

use crate::mac::MacAddr;

/// What kind of device a vendor predominantly makes.
///
/// Only recorded where an OUI is a genuinely strong hint. A vendor that makes
/// everything, like Intel or Realtek, carries `None` rather than a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VendorHint {
    NetworkEquipment,
    Printer,
    Virtualisation,
    MediaDevice,
    Iot,
    Nas,
    Camera,
    GameConsole,
    Computer,
    Phone,
    SingleBoardComputer,
}

/// One built-in OUI assignment.
struct OuiEntry {
    /// The 24-bit OUI, high-order byte first.
    oui: u32,
    vendor: &'static str,
    hint: Option<VendorHint>,
}

/// Curated OUI assignments.
///
/// Chosen for what appears on real networks rather than for coverage: virtual
/// machine vendors (which are otherwise mystifying to see), the major router
/// and access-point makers, printers, and the handful of device families whose
/// OUI alone reliably identifies them.
const BUILTIN: &[OuiEntry] = &[
    // ---- Virtualisation. Distinctive, and confusing without a name. --------
    OuiEntry { oui: 0x000569, vendor: "VMware", hint: Some(VendorHint::Virtualisation) },
    OuiEntry { oui: 0x000c29, vendor: "VMware", hint: Some(VendorHint::Virtualisation) },
    OuiEntry { oui: 0x001c14, vendor: "VMware", hint: Some(VendorHint::Virtualisation) },
    OuiEntry { oui: 0x005056, vendor: "VMware", hint: Some(VendorHint::Virtualisation) },
    OuiEntry { oui: 0x080027, vendor: "Oracle VirtualBox", hint: Some(VendorHint::Virtualisation) },
    OuiEntry { oui: 0x00163e, vendor: "Xen", hint: Some(VendorHint::Virtualisation) },
    OuiEntry { oui: 0x00155d, vendor: "Microsoft Hyper-V", hint: Some(VendorHint::Virtualisation) },
    OuiEntry { oui: 0x525400, vendor: "QEMU/KVM", hint: Some(VendorHint::Virtualisation) },
    OuiEntry { oui: 0x001c42, vendor: "Parallels", hint: Some(VendorHint::Virtualisation) },

    // ---- Single-board computers -------------------------------------------
    OuiEntry { oui: 0xb827eb, vendor: "Raspberry Pi Foundation", hint: Some(VendorHint::SingleBoardComputer) },
    OuiEntry { oui: 0xdca632, vendor: "Raspberry Pi Trading", hint: Some(VendorHint::SingleBoardComputer) },
    OuiEntry { oui: 0xe45f01, vendor: "Raspberry Pi Trading", hint: Some(VendorHint::SingleBoardComputer) },
    OuiEntry { oui: 0x28cdc1, vendor: "Raspberry Pi Trading", hint: Some(VendorHint::SingleBoardComputer) },
    OuiEntry { oui: 0x2ccf67, vendor: "Raspberry Pi Trading", hint: Some(VendorHint::SingleBoardComputer) },
    OuiEntry { oui: 0xd83add, vendor: "Raspberry Pi Trading", hint: Some(VendorHint::SingleBoardComputer) },

    // ---- Apple -------------------------------------------------------------
    OuiEntry { oui: 0x000a27, vendor: "Apple", hint: Some(VendorHint::Computer) },
    OuiEntry { oui: 0x000a95, vendor: "Apple", hint: Some(VendorHint::Computer) },
    OuiEntry { oui: 0x001b63, vendor: "Apple", hint: Some(VendorHint::Computer) },
    OuiEntry { oui: 0x001ec2, vendor: "Apple", hint: Some(VendorHint::Computer) },
    OuiEntry { oui: 0x0023df, vendor: "Apple", hint: Some(VendorHint::Computer) },
    OuiEntry { oui: 0x3c0754, vendor: "Apple", hint: Some(VendorHint::Computer) },
    OuiEntry { oui: 0xa483e7, vendor: "Apple", hint: Some(VendorHint::Computer) },
    OuiEntry { oui: 0xacbc32, vendor: "Apple", hint: Some(VendorHint::Computer) },
    OuiEntry { oui: 0xf01898, vendor: "Apple", hint: Some(VendorHint::Computer) },
    OuiEntry { oui: 0xdca904, vendor: "Apple", hint: Some(VendorHint::Computer) },
    OuiEntry { oui: 0x8866a5, vendor: "Apple", hint: Some(VendorHint::Computer) },
    OuiEntry { oui: 0x68a86d, vendor: "Apple", hint: Some(VendorHint::Computer) },

    // ---- Network equipment -------------------------------------------------
    OuiEntry { oui: 0x00000c, vendor: "Cisco", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0x000142, vendor: "Cisco", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0x001aa1, vendor: "Cisco", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0x000b86, vendor: "Aruba Networks", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0x000c42, vendor: "MikroTik", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0x488f5a, vendor: "MikroTik", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0x000585, vendor: "Juniper Networks", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0x00156d, vendor: "Ubiquiti", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0x24a43c, vendor: "Ubiquiti", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0x788a20, vendor: "Ubiquiti", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0xdc9fdb, vendor: "Ubiquiti", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0xfcecda, vendor: "Ubiquiti", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0x00095b, vendor: "Netgear", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0x00146c, vendor: "Netgear", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0x204e7f, vendor: "Netgear", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0xa040a0, vendor: "Netgear", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0x14cc20, vendor: "TP-Link", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0x50c7bf, vendor: "TP-Link", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0xa42bb0, vendor: "TP-Link", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0x00040e, vendor: "AVM (FRITZ!Box)", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0x3810d5, vendor: "AVM (FRITZ!Box)", hint: Some(VendorHint::NetworkEquipment) },
    OuiEntry { oui: 0xc80e14, vendor: "AVM (FRITZ!Box)", hint: Some(VendorHint::NetworkEquipment) },

    // ---- Printers ----------------------------------------------------------
    OuiEntry { oui: 0x008077, vendor: "Brother", hint: Some(VendorHint::Printer) },
    OuiEntry { oui: 0x30055c, vendor: "Brother", hint: Some(VendorHint::Printer) },
    OuiEntry { oui: 0x000085, vendor: "Canon", hint: Some(VendorHint::Printer) },
    OuiEntry { oui: 0x001e8f, vendor: "Canon", hint: Some(VendorHint::Printer) },
    OuiEntry { oui: 0x000048, vendor: "Seiko Epson", hint: Some(VendorHint::Printer) },
    OuiEntry { oui: 0x0026ab, vendor: "Seiko Epson", hint: Some(VendorHint::Printer) },
    OuiEntry { oui: 0xa4ee57, vendor: "Seiko Epson", hint: Some(VendorHint::Printer) },
    OuiEntry { oui: 0x0000aa, vendor: "Xerox", hint: Some(VendorHint::Printer) },
    OuiEntry { oui: 0x9c934e, vendor: "Xerox", hint: Some(VendorHint::Printer) },

    // ---- NAS ---------------------------------------------------------------
    OuiEntry { oui: 0x001132, vendor: "Synology", hint: Some(VendorHint::Nas) },
    OuiEntry { oui: 0x00089b, vendor: "QNAP", hint: Some(VendorHint::Nas) },
    OuiEntry { oui: 0x245ebe, vendor: "QNAP", hint: Some(VendorHint::Nas) },

    // ---- Cameras -----------------------------------------------------------
    OuiEntry { oui: 0x4419b6, vendor: "Hikvision", hint: Some(VendorHint::Camera) },
    OuiEntry { oui: 0xbcad28, vendor: "Hikvision", hint: Some(VendorHint::Camera) },
    OuiEntry { oui: 0xc056e3, vendor: "Hikvision", hint: Some(VendorHint::Camera) },
    OuiEntry { oui: 0x3cef8c, vendor: "Dahua", hint: Some(VendorHint::Camera) },
    OuiEntry { oui: 0x9002a9, vendor: "Dahua", hint: Some(VendorHint::Camera) },

    // ---- Media devices -----------------------------------------------------
    OuiEntry { oui: 0x000e58, vendor: "Sonos", hint: Some(VendorHint::MediaDevice) },
    OuiEntry { oui: 0x5caafd, vendor: "Sonos", hint: Some(VendorHint::MediaDevice) },
    OuiEntry { oui: 0x7828ca, vendor: "Sonos", hint: Some(VendorHint::MediaDevice) },
    OuiEntry { oui: 0xb8e937, vendor: "Sonos", hint: Some(VendorHint::MediaDevice) },
    OuiEntry { oui: 0xb0a737, vendor: "Roku", hint: Some(VendorHint::MediaDevice) },
    OuiEntry { oui: 0xcc6da0, vendor: "Roku", hint: Some(VendorHint::MediaDevice) },
    OuiEntry { oui: 0xd83134, vendor: "Roku", hint: Some(VendorHint::MediaDevice) },
    OuiEntry { oui: 0x3c5ab4, vendor: "Google", hint: Some(VendorHint::MediaDevice) },
    OuiEntry { oui: 0xf4f5d8, vendor: "Google", hint: Some(VendorHint::MediaDevice) },
    OuiEntry { oui: 0x546009, vendor: "Google", hint: Some(VendorHint::MediaDevice) },
    OuiEntry { oui: 0x44650d, vendor: "Amazon", hint: Some(VendorHint::MediaDevice) },
    OuiEntry { oui: 0x6837e9, vendor: "Amazon", hint: Some(VendorHint::MediaDevice) },
    OuiEntry { oui: 0xfca183, vendor: "Amazon", hint: Some(VendorHint::MediaDevice) },
    OuiEntry { oui: 0x74c246, vendor: "Amazon", hint: Some(VendorHint::MediaDevice) },

    // ---- Game consoles -----------------------------------------------------
    OuiEntry { oui: 0x0009bf, vendor: "Nintendo", hint: Some(VendorHint::GameConsole) },
    OuiEntry { oui: 0x98b6e9, vendor: "Nintendo", hint: Some(VendorHint::GameConsole) },
    OuiEntry { oui: 0xfc0fe6, vendor: "Sony Interactive Entertainment", hint: Some(VendorHint::GameConsole) },

    // ---- IoT ---------------------------------------------------------------
    OuiEntry { oui: 0x240ac4, vendor: "Espressif", hint: Some(VendorHint::Iot) },
    OuiEntry { oui: 0x30aea4, vendor: "Espressif", hint: Some(VendorHint::Iot) },
    OuiEntry { oui: 0x3c71bf, vendor: "Espressif", hint: Some(VendorHint::Iot) },
    OuiEntry { oui: 0x840d8e, vendor: "Espressif", hint: Some(VendorHint::Iot) },
    OuiEntry { oui: 0xa4cf12, vendor: "Espressif", hint: Some(VendorHint::Iot) },
    OuiEntry { oui: 0xecfabc, vendor: "Espressif", hint: Some(VendorHint::Iot) },

    // ---- General-purpose vendors. No device hint: they make everything. ----
    OuiEntry { oui: 0x001b21, vendor: "Intel", hint: None },
    OuiEntry { oui: 0x001517, vendor: "Intel", hint: None },
    OuiEntry { oui: 0x3c970e, vendor: "Intel", hint: None },
    OuiEntry { oui: 0x0002b3, vendor: "Intel", hint: None },
    OuiEntry { oui: 0x00e04c, vendor: "Realtek", hint: None },
    OuiEntry { oui: 0x001018, vendor: "Broadcom", hint: None },
    OuiEntry { oui: 0x001422, vendor: "Dell", hint: Some(VendorHint::Computer) },
    OuiEntry { oui: 0x001ec9, vendor: "Dell", hint: Some(VendorHint::Computer) },
    OuiEntry { oui: 0xb82a72, vendor: "Dell", hint: Some(VendorHint::Computer) },
    OuiEntry { oui: 0x180373, vendor: "Dell", hint: Some(VendorHint::Computer) },
    OuiEntry { oui: 0x001f29, vendor: "Hewlett Packard", hint: None },
    OuiEntry { oui: 0x0025b3, vendor: "Hewlett Packard", hint: None },
    OuiEntry { oui: 0x3cd92b, vendor: "Hewlett Packard", hint: None },
    OuiEntry { oui: 0x001599, vendor: "Samsung", hint: Some(VendorHint::Phone) },
    OuiEntry { oui: 0x001d25, vendor: "Samsung", hint: Some(VendorHint::Phone) },
    OuiEntry { oui: 0x342387, vendor: "Samsung", hint: Some(VendorHint::Phone) },
    OuiEntry { oui: 0x781fdb, vendor: "Samsung", hint: Some(VendorHint::Phone) },
    OuiEntry { oui: 0x009ec8, vendor: "Xiaomi", hint: Some(VendorHint::Phone) },
    OuiEntry { oui: 0x286c07, vendor: "Xiaomi", hint: Some(VendorHint::Phone) },
    OuiEntry { oui: 0x640980, vendor: "Xiaomi", hint: Some(VendorHint::Phone) },
    OuiEntry { oui: 0x7811dc, vendor: "Xiaomi", hint: Some(VendorHint::Phone) },
    OuiEntry { oui: 0x001882, vendor: "Huawei", hint: Some(VendorHint::Phone) },
    OuiEntry { oui: 0x00e0fc, vendor: "Huawei", hint: Some(VendorHint::Phone) },
];

/// A vendor lookup table.
pub struct OuiDatabase {
    entries: HashMap<u32, (String, Option<VendorHint>)>,
}

/// What a lookup found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorInfo {
    pub name: String,
    pub hint: Option<VendorHint>,
}

impl OuiDatabase {
    /// Builds the database from the built-in curated table.
    pub fn builtin() -> Self {
        let entries = BUILTIN
            .iter()
            .map(|e| (e.oui, (e.vendor.to_string(), e.hint)))
            .collect();
        Self { entries }
    }

    /// Looks up a MAC's vendor.
    ///
    /// Multicast and all-zero addresses never resolve. Locally administered
    /// addresses resolve only if the table holds that exact prefix, which is
    /// the behaviour both cases need:
    ///
    /// * A randomised privacy MAC — what every modern phone presents — has
    ///   random bytes that the IEEE never assigned, so it misses the table and
    ///   returns `None` rather than attributing a coincidence as a fact.
    /// * A few prefixes are locally administered *by convention* and are
    ///   genuinely identifying. QEMU/KVM's `52:54:00` is the common one, and
    ///   refusing to resolve it would leave every VM on a hypervisor host
    ///   showing as an unknown vendor.
    ///
    /// The distinction is self-enforcing: a table entry whose own OUI has the
    /// local bit set is by construction a deliberate registration of this kind.
    pub fn lookup(&self, mac: MacAddr) -> Option<VendorInfo> {
        if mac.is_multicast() || mac.is_zero() {
            return None;
        }
        self.entries.get(&mac.oui()).map(|(name, hint)| VendorInfo {
            name: name.clone(),
            hint: *hint,
        })
    }

    /// Merges entries from the IEEE registry in its published `oui.csv` form.
    ///
    /// The header row and any malformed line are skipped rather than failing
    /// the load, because the published file periodically contains stray commas
    /// inside quoted organisation names.
    pub fn load_ieee_csv(&mut self, csv: &str) -> usize {
        let mut added = 0;
        for line in csv.lines().skip(1) {
            // Registry,Assignment,Organization Name,Organization Address
            let mut fields = line.splitn(4, ',');
            let Some(_registry) = fields.next() else {
                continue;
            };
            let Some(assignment) = fields.next() else {
                continue;
            };
            let Some(org) = fields.next() else {
                continue;
            };
            let assignment = assignment.trim().trim_matches('"');
            if assignment.len() != 6 {
                continue;
            }
            let Ok(oui) = u32::from_str_radix(assignment, 16) else {
                continue;
            };
            let name = org.trim().trim_matches('"').to_string();
            if name.is_empty() {
                continue;
            }
            // Built-in entries carry device hints the registry does not, so
            // they win on conflict.
            self.entries.entry(oui).or_insert((name, None));
            added += 1;
        }
        added
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for OuiDatabase {
    fn default() -> Self {
        Self::builtin()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    #[test]
    fn looks_up_a_builtin_vendor() {
        let db = OuiDatabase::builtin();
        let v = db.lookup(mac("b8:27:eb:11:22:33")).unwrap();
        assert_eq!(v.name, "Raspberry Pi Foundation");
        assert_eq!(v.hint, Some(VendorHint::SingleBoardComputer));
    }

    #[test]
    fn lookup_ignores_the_device_specific_bytes() {
        let db = OuiDatabase::builtin();
        // Only the first three octets select the vendor.
        for suffix in ["00:00:00", "ff:ff:ff", "12:34:56"] {
            let v = db.lookup(mac(&format!("00:0c:29:{suffix}"))).unwrap();
            assert_eq!(v.name, "VMware");
        }
    }

    #[test]
    fn randomised_macs_are_never_attributed_to_a_vendor() {
        // Locally administered addresses were not assigned by the IEEE, so any
        // table hit is a coincidence. Every modern phone randomises per network.
        let db = OuiDatabase::builtin();
        assert_eq!(db.lookup(mac("02:0c:29:11:22:33")), None);
        assert_eq!(db.lookup(mac("b6:27:eb:11:22:33")), None);
        // The same OUI without the local bit does resolve.
        assert!(db.lookup(mac("00:0c:29:11:22:33")).is_some());
    }

    #[test]
    fn broadcast_and_zero_macs_resolve_to_nothing() {
        let db = OuiDatabase::builtin();
        assert_eq!(db.lookup(MacAddr::BROADCAST), None);
        assert_eq!(db.lookup(MacAddr::ZERO), None);
    }

    #[test]
    fn an_unknown_oui_returns_none_rather_than_a_guess() {
        let db = OuiDatabase::builtin();
        assert_eq!(db.lookup(mac("aa:bb:cc:dd:ee:ff")), None);
    }

    #[test]
    fn general_purpose_vendors_carry_no_device_hint() {
        // Intel and Realtek chips appear in everything; a device-class guess
        // from them would be worse than no guess.
        let db = OuiDatabase::builtin();
        assert_eq!(db.lookup(mac("00:1b:21:00:00:01")).unwrap().hint, None);
        assert_eq!(db.lookup(mac("00:e0:4c:00:00:01")).unwrap().hint, None);
    }

    #[test]
    fn the_builtin_table_has_no_duplicate_ouis() {
        // A duplicate would silently shadow one entry.
        let mut seen = std::collections::HashSet::new();
        for e in BUILTIN {
            assert!(seen.insert(e.oui), "duplicate OUI {:#08x}", e.oui);
        }
        assert_eq!(OuiDatabase::builtin().len(), BUILTIN.len());
    }

    #[test]
    fn every_builtin_oui_fits_in_24_bits() {
        for e in BUILTIN {
            assert!(e.oui <= 0xff_ffff, "{:#x} exceeds 24 bits", e.oui);
        }
    }

    #[test]
    fn no_builtin_oui_is_multicast() {
        // The group bit marks a frame destination, never a vendor assignment,
        // and such an entry would be unreachable through `lookup`.
        for e in BUILTIN {
            let first = (e.oui >> 16) as u8;
            assert_eq!(first & 0x01, 0, "{} has the group bit set", e.vendor);
        }
    }

    #[test]
    fn locally_administered_builtins_are_limited_to_known_conventions() {
        // Entries with the local bit are deliberate: they are prefixes used by
        // convention rather than IEEE assignment. QEMU/KVM's 52:54:00 is the
        // canonical one. Anything else here would risk colliding with a
        // randomised privacy MAC and attributing it to a vendor.
        let laa: Vec<&str> = BUILTIN
            .iter()
            .filter(|e| ((e.oui >> 16) as u8) & 0x02 != 0)
            .map(|e| e.vendor)
            .collect();
        assert_eq!(laa, vec!["QEMU/KVM"]);
    }

    #[test]
    fn a_conventional_locally_administered_prefix_still_resolves() {
        // Every VM on a KVM host presents 52:54:00; refusing to resolve it
        // would leave them all showing as an unknown vendor.
        let db = OuiDatabase::builtin();
        let v = db.lookup(mac("52:54:00:12:34:56")).unwrap();
        assert_eq!(v.name, "QEMU/KVM");
        assert_eq!(v.hint, Some(VendorHint::Virtualisation));
    }

    #[test]
    fn loads_the_ieee_csv_format() {
        let csv = "Registry,Assignment,Organization Name,Organization Address\n\
MA-L,ACDE48,Example Corp,123 Street\n\
MA-L,001122,Another Vendor,456 Road\n";
        let mut db = OuiDatabase::builtin();
        let before = db.len();
        assert_eq!(db.load_ieee_csv(csv), 2);
        assert_eq!(db.len(), before + 2);
        assert_eq!(db.lookup(mac("ac:de:48:00:00:01")).unwrap().name, "Example Corp");
    }

    #[test]
    fn builtin_hints_survive_a_registry_load() {
        // The registry has no device hints; loading it must not erase ours.
        let csv = "Registry,Assignment,Organization Name,Address\n\
MA-L,B827EB,Raspberry Pi Foundation,UK\n";
        let mut db = OuiDatabase::builtin();
        db.load_ieee_csv(csv);
        assert_eq!(
            db.lookup(mac("b8:27:eb:00:00:01")).unwrap().hint,
            Some(VendorHint::SingleBoardComputer)
        );
    }

    #[test]
    fn malformed_csv_lines_are_skipped_not_fatal() {
        let csv = "header\n\
MA-L,TOOLONGVALUE,X,Y\n\
MA-L,ZZZZZZ,Bad Hex,Y\n\
garbage\n\
\n\
MA-L,ABCDEF,,No Name\n\
MA-L,102030,Good Vendor,Z\n";
        let mut db = OuiDatabase::builtin();
        assert_eq!(db.load_ieee_csv(csv), 1);
        assert_eq!(db.lookup(mac("10:20:30:00:00:01")).unwrap().name, "Good Vendor");
    }

    #[test]
    fn an_empty_csv_adds_nothing() {
        let mut db = OuiDatabase::builtin();
        let before = db.len();
        assert_eq!(db.load_ieee_csv(""), 0);
        assert_eq!(db.load_ieee_csv("just-a-header\n"), 0);
        assert_eq!(db.len(), before);
    }
}
