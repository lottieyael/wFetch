//! Device identification.
//!
//! No single signal identifies a device reliably. A MAC OUI is authoritative
//! until the device randomises it; an open port 445 means Windows until it is a
//! Samba box; a TTL of 64 covers Linux, macOS, Android and iOS at once. So this
//! module accumulates weighted evidence from every signal the scan collected
//! and picks the best-supported answer, keeping the reasons so the conclusion
//! can be argued with.
//!
//! Scoring is deterministic and pure: [`identify`] takes a [`Signals`] struct
//! and returns a [`DeviceIdentity`]. Every rule below is exercised by a test
//! that feeds it one signal set and asserts the verdict.

pub mod oui;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::mac::MacAddr;
use crate::proto::icmp::{ttl_os_hint, TtlHint};
use crate::proto::mdns::MdnsInfo;
use crate::proto::netbios::NodeStatus;
use crate::proto::ssdp::SsdpResponse;
use oui::{OuiDatabase, VendorHint};

/// What a device is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClass {
    Router,
    Switch,
    AccessPoint,
    Printer,
    Scanner,
    Computer,
    Server,
    Nas,
    Phone,
    Tablet,
    MediaDevice,
    GameConsole,
    Camera,
    IotDevice,
    VirtualMachine,
    SingleBoardComputer,
    Unknown,
}

/// The operating system family a device runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    Windows,
    Linux,
    MacOs,
    Ios,
    Android,
    Bsd,
    /// Router and switch firmware: IOS-XE, RouterOS, JunOS and the like.
    NetworkOs,
    /// Embedded firmware with no general-purpose OS.
    Embedded,
    Unknown,
}

/// Everything the scan learned about one host, as input to identification.
#[derive(Debug, Clone, Default)]
pub struct Signals<'a> {
    pub mac: Option<MacAddr>,
    pub open_ports: &'a [u16],
    pub ttl: Option<u8>,
    pub hostname: Option<&'a str>,
    pub mdns: Option<&'a MdnsInfo>,
    pub ssdp: &'a [SsdpResponse],
    pub netbios: Option<&'a NodeStatus>,
    /// Whether the address is its subnet's default gateway, which is the single
    /// strongest router signal available and cannot be derived from the host
    /// itself.
    pub is_default_gateway: bool,
}

/// The conclusion, with its supporting reasons.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub class: DeviceClass,
    pub os: OsFamily,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// 0–100. Derived from how much the winning answer outscored the runner-up,
    /// so a device with two equally plausible readings reports low confidence
    /// rather than picking one and sounding certain.
    pub confidence: u8,
    /// Human-readable justifications, strongest first.
    pub reasons: Vec<String>,
}

impl DeviceIdentity {
    fn unknown() -> Self {
        Self {
            class: DeviceClass::Unknown,
            os: OsFamily::Unknown,
            vendor: None,
            model: None,
            confidence: 0,
            reasons: Vec::new(),
        }
    }
}

/// Accumulates weighted votes for a category.
struct Scores<T: Ord + Copy> {
    votes: BTreeMap<T, u32>,
    reasons: Vec<(u32, String)>,
}

impl<T: Ord + Copy> Scores<T> {
    fn new() -> Self {
        Self {
            votes: BTreeMap::new(),
            reasons: Vec::new(),
        }
    }

    fn add(&mut self, key: T, weight: u32, reason: impl Into<String>) {
        *self.votes.entry(key).or_insert(0) += weight;
        self.reasons.push((weight, reason.into()));
    }

    /// The winner and a 0–100 confidence derived from its margin.
    fn best(&self) -> Option<(T, u8)> {
        let mut ranked: Vec<(&T, &u32)> = self.votes.iter().collect();
        // Sort by score descending; ties break on the key so results are stable.
        ranked.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let (&winner, &top) = ranked.first().map(|(k, v)| (*k, *v))?;
        if top == 0 {
            return None;
        }
        let runner_up = ranked.get(1).map(|(_, v)| **v).unwrap_or(0);

        // Confidence combines absolute support with the margin over the
        // runner-up: a lone weak signal and two strong contradicting ones
        // should both read as uncertain.
        let margin = top.saturating_sub(runner_up);
        let confidence = ((top.min(100) * 60 / 100) + (margin.min(100) * 40 / 100)).min(100);
        Some((winner, confidence as u8))
    }
}

/// Identifies a device from the signals a scan collected.
pub fn identify(signals: &Signals<'_>, oui_db: &OuiDatabase) -> DeviceIdentity {
    let mut class: Scores<DeviceClass> = Scores::new();
    let mut os: Scores<OsFamily> = Scores::new();
    let mut vendor: Option<String> = None;
    let mut model: Option<String> = None;

    // ---- MAC vendor --------------------------------------------------------
    if let Some(mac) = signals.mac {
        if let Some(v) = oui_db.lookup(mac) {
            vendor = Some(v.name.clone());
            match v.hint {
                Some(VendorHint::Virtualisation) => {
                    class.add(DeviceClass::VirtualMachine, 90, format!("MAC OUI belongs to {}", v.name));
                }
                Some(VendorHint::NetworkEquipment) => {
                    class.add(DeviceClass::Router, 45, format!("MAC OUI belongs to {}", v.name));
                    os.add(OsFamily::NetworkOs, 30, format!("{} network equipment", v.name));
                }
                Some(VendorHint::Printer) => {
                    class.add(DeviceClass::Printer, 70, format!("MAC OUI belongs to {}", v.name));
                    os.add(OsFamily::Embedded, 25, "printer firmware");
                }
                Some(VendorHint::Nas) => {
                    class.add(DeviceClass::Nas, 70, format!("MAC OUI belongs to {}", v.name));
                    os.add(OsFamily::Linux, 40, format!("{} appliances run Linux", v.name));
                }
                Some(VendorHint::Camera) => {
                    class.add(DeviceClass::Camera, 70, format!("MAC OUI belongs to {}", v.name));
                    os.add(OsFamily::Embedded, 30, "camera firmware");
                }
                Some(VendorHint::MediaDevice) => {
                    class.add(DeviceClass::MediaDevice, 55, format!("MAC OUI belongs to {}", v.name));
                }
                Some(VendorHint::GameConsole) => {
                    class.add(DeviceClass::GameConsole, 70, format!("MAC OUI belongs to {}", v.name));
                }
                Some(VendorHint::Iot) => {
                    class.add(DeviceClass::IotDevice, 60, format!("MAC OUI belongs to {}", v.name));
                    os.add(OsFamily::Embedded, 40, format!("{} modules run embedded firmware", v.name));
                }
                Some(VendorHint::SingleBoardComputer) => {
                    class.add(DeviceClass::SingleBoardComputer, 75, format!("MAC OUI belongs to {}", v.name));
                    os.add(OsFamily::Linux, 45, "single-board computers normally run Linux");
                }
                Some(VendorHint::Computer) => {
                    class.add(DeviceClass::Computer, 35, format!("MAC OUI belongs to {}", v.name));
                }
                Some(VendorHint::Phone) => {
                    class.add(DeviceClass::Phone, 30, format!("MAC OUI belongs to {}", v.name));
                }
                // A general-purpose vendor names the maker but implies nothing.
                None => {}
            }
        }
    }

    // ---- Gateway role ------------------------------------------------------
    if signals.is_default_gateway {
        class.add(DeviceClass::Router, 85, "address is the subnet's default gateway");
    }

    // ---- NetBIOS -----------------------------------------------------------
    if let Some(nb) = signals.netbios {
        // Only Windows and Samba answer this at all.
        os.add(OsFamily::Windows, 55, "answered a NetBIOS node status query");
        if nb.is_domain_controller() {
            class.add(DeviceClass::Server, 80, "advertises a domain controller role");
            os.add(OsFamily::Windows, 30, "domain controller");
        } else if nb.is_file_server() {
            class.add(DeviceClass::Computer, 25, "offers file and printer sharing");
        }
    }

    // ---- mDNS --------------------------------------------------------------
    if let Some(m) = signals.mdns {
        for service in &m.services {
            match service.as_str() {
                // Apple-only services.
                "_airplay._tcp" | "_raop._tcp" => {
                    class.add(DeviceClass::MediaDevice, 55, format!("advertises {service}"));
                    os.add(OsFamily::Ios, 25, format!("advertises {service}"));
                }
                "_companion-link._tcp" | "_homekit._tcp" => {
                    os.add(OsFamily::Ios, 40, format!("advertises {service}"));
                }
                "_apple-mobdev2._tcp" => {
                    class.add(DeviceClass::Phone, 65, "advertises the iOS pairing service");
                    os.add(OsFamily::Ios, 70, "advertises the iOS pairing service");
                }
                // Printing.
                "_ipp._tcp" | "_ipps._tcp" | "_printer._tcp" | "_pdl-datastream._tcp" => {
                    class.add(DeviceClass::Printer, 80, format!("advertises {service}"));
                }
                "_scanner._tcp" => {
                    class.add(DeviceClass::Scanner, 70, format!("advertises {service}"));
                }
                // Media.
                "_googlecast._tcp" => {
                    class.add(DeviceClass::MediaDevice, 80, "advertises Google Cast");
                    os.add(OsFamily::Android, 35, "Cast devices run an Android-derived OS");
                }
                "_androidtvremote2._tcp" => {
                    class.add(DeviceClass::MediaDevice, 75, "advertises the Android TV remote service");
                    os.add(OsFamily::Android, 65, "advertises the Android TV remote service");
                }
                "_sonos._tcp" | "_spotify-connect._tcp" => {
                    class.add(DeviceClass::MediaDevice, 60, format!("advertises {service}"));
                }
                // File services.
                "_afpovertcp._tcp" => {
                    os.add(OsFamily::MacOs, 45, "advertises AFP");
                    class.add(DeviceClass::Nas, 25, "advertises AFP");
                }
                "_smb._tcp" | "_nfs._tcp" => {
                    class.add(DeviceClass::Nas, 30, format!("advertises {service}"));
                }
                "_workstation._tcp" => {
                    class.add(DeviceClass::Computer, 40, "advertises the workstation service");
                }
                "_esphomelib._tcp" | "_hue._tcp" | "_miio._udp" => {
                    class.add(DeviceClass::IotDevice, 70, format!("advertises {service}"));
                    os.add(OsFamily::Embedded, 40, format!("advertises {service}"));
                }
                _ => {}
            }
        }

        // TXT records frequently name the model outright.
        if let Some(v) = m.txt_value("model") {
            model = Some(v.to_string());
            let lower = v.to_ascii_lowercase();
            if lower.starts_with("appletv") {
                class.add(DeviceClass::MediaDevice, 85, format!("mDNS model {v}"));
                os.add(OsFamily::Ios, 60, format!("mDNS model {v}"));
            } else if lower.starts_with("iphone") {
                class.add(DeviceClass::Phone, 90, format!("mDNS model {v}"));
                os.add(OsFamily::Ios, 90, format!("mDNS model {v}"));
            } else if lower.starts_with("ipad") {
                class.add(DeviceClass::Tablet, 90, format!("mDNS model {v}"));
                os.add(OsFamily::Ios, 90, format!("mDNS model {v}"));
            } else if lower.starts_with("macbook") || lower.starts_with("imac")
                || lower.starts_with("macmini") || lower.starts_with("macpro")
                || lower.starts_with("mac")
            {
                class.add(DeviceClass::Computer, 85, format!("mDNS model {v}"));
                os.add(OsFamily::MacOs, 85, format!("mDNS model {v}"));
            }
        }
        // A printer's TXT type string names the product.
        if let Some(v) = m.txt_value("ty") {
            if model.is_none() {
                model = Some(v.to_string());
            }
            class.add(DeviceClass::Printer, 40, format!("mDNS printer type {v}"));
        }
        if let Some(v) = m.txt_value("osvers") {
            os.add(OsFamily::Ios, 20, format!("reports OS version {v}"));
        }
    }

    // ---- SSDP --------------------------------------------------------------
    for r in signals.ssdp {
        if let Some(server) = &r.server {
            let lower = server.to_ascii_lowercase();
            if lower.contains("windows") {
                os.add(OsFamily::Windows, 50, format!("SSDP server string {server:?}"));
            } else if lower.contains("linux") || lower.contains("unix") {
                os.add(OsFamily::Linux, 45, format!("SSDP server string {server:?}"));
            }
            if vendor.is_none() {
                // The first token is usually the product or OS name.
                if let Some(tok) = crate::proto::ssdp::server_tokens(server).first() {
                    vendor = Some(tok.clone());
                }
            }
        }
        if let Some(st) = &r.search_target {
            if st.contains("InternetGatewayDevice") {
                class.add(DeviceClass::Router, 80, "advertises an SSDP InternetGatewayDevice");
            } else if st.contains("MediaRenderer") {
                class.add(DeviceClass::MediaDevice, 60, "advertises an SSDP MediaRenderer");
            } else if st.contains("MediaServer") {
                class.add(DeviceClass::Nas, 40, "advertises an SSDP MediaServer");
            } else if st.contains("dial-multiscreen") {
                class.add(DeviceClass::MediaDevice, 55, "advertises the DIAL screen-casting service");
            } else if st.contains("Printer") {
                class.add(DeviceClass::Printer, 65, "advertises an SSDP printer");
            }
        }
    }

    // ---- Open ports --------------------------------------------------------
    let ports = signals.open_ports;
    let has = |p: u16| ports.contains(&p);

    // SMB is the clearest Windows tell, though Samba muddies it.
    if has(445) || has(139) {
        os.add(OsFamily::Windows, 35, "SMB port open");
    }
    if has(135) && has(445) {
        // The RPC endpoint mapper alongside SMB is far more Windows-specific:
        // Samba does not normally expose 135.
        os.add(OsFamily::Windows, 45, "RPC endpoint mapper and SMB both open");
    }
    if has(3389) {
        os.add(OsFamily::Windows, 50, "RDP port open");
        class.add(DeviceClass::Computer, 25, "RDP port open");
    }
    if has(22) {
        os.add(OsFamily::Linux, 20, "SSH port open");
    }
    if has(62078) {
        // lockdownd: present on iOS devices and essentially nothing else.
        class.add(DeviceClass::Phone, 70, "iOS lockdown service port open");
        os.add(OsFamily::Ios, 80, "iOS lockdown service port open");
    }
    if has(5555) {
        class.add(DeviceClass::Phone, 40, "Android debug bridge port open");
        os.add(OsFamily::Android, 60, "Android debug bridge port open");
    }
    if has(548) {
        os.add(OsFamily::MacOs, 30, "AFP port open");
    }
    if has(631) || has(9100) {
        class.add(DeviceClass::Printer, 60, "printing port open");
    }
    if has(53) && (has(80) || has(443)) {
        // A DNS resolver with a web interface is the classic home-router shape.
        class.add(DeviceClass::Router, 35, "serves DNS and a web interface");
    }
    if has(161) {
        class.add(DeviceClass::Switch, 20, "SNMP agent present");
        os.add(OsFamily::NetworkOs, 20, "SNMP agent present");
    }
    if has(554) || has(8554) {
        class.add(DeviceClass::Camera, 45, "RTSP port open");
    }
    if has(5000) && has(5001) {
        class.add(DeviceClass::Nas, 35, "Synology management ports open");
    }
    for db_port in [3306u16, 5432, 1433, 27017] {
        if has(db_port) {
            class.add(DeviceClass::Server, 40, format!("database service on port {db_port}"));
        }
    }

    // ---- TTL ---------------------------------------------------------------
    // The weakest signal: an entire OS family shares each value. It only ever
    // breaks ties, never decides on its own.
    if let Some(ttl) = signals.ttl {
        match ttl_os_hint(ttl) {
            Some(TtlHint::Windows) => os.add(OsFamily::Windows, 15, format!("IP TTL {ttl}")),
            Some(TtlHint::UnixLike) => {
                // 64 covers Linux, macOS, Android, iOS and the BSDs equally.
                os.add(OsFamily::Linux, 10, format!("IP TTL {ttl}"));
            }
            Some(TtlHint::NetworkDevice) => {
                os.add(OsFamily::NetworkOs, 20, format!("IP TTL {ttl}"));
                class.add(DeviceClass::Router, 15, format!("IP TTL {ttl}"));
            }
            None => {}
        }
    }

    // ---- Hostname ----------------------------------------------------------
    if let Some(h) = signals.hostname {
        let lower = h.to_ascii_lowercase();
        for (needle, cls, weight) in [
            ("router", DeviceClass::Router, 30u32),
            ("gateway", DeviceClass::Router, 25),
            ("printer", DeviceClass::Printer, 35),
            ("camera", DeviceClass::Camera, 30),
            ("switch", DeviceClass::Switch, 25),
            ("nas", DeviceClass::Nas, 25),
        ] {
            if lower.contains(needle) {
                class.add(cls, weight, format!("hostname contains {needle:?}"));
            }
        }
        if lower.starts_with("desktop-") || lower.starts_with("laptop-") {
            // The Windows default naming scheme.
            class.add(DeviceClass::Computer, 40, "hostname follows the Windows default pattern");
            os.add(OsFamily::Windows, 35, "hostname follows the Windows default pattern");
        }
        if lower.contains("android") {
            os.add(OsFamily::Android, 30, "hostname mentions Android");
        }
    }

    // ---- Verdict -----------------------------------------------------------
    let (best_class, class_conf) = class.best().unwrap_or((DeviceClass::Unknown, 0));
    let (best_os, os_conf) = os.best().unwrap_or((OsFamily::Unknown, 0));

    if best_class == DeviceClass::Unknown && best_os == OsFamily::Unknown && vendor.is_none() {
        return DeviceIdentity::unknown();
    }

    // Report the reasons that fed the winning answers, strongest first.
    let mut reasons: Vec<(u32, String)> = class.reasons;
    reasons.extend(other_reasons(&os));
    reasons.sort_by(|a, b| b.0.cmp(&a.0));
    reasons.dedup_by(|a, b| a.1 == b.1);

    DeviceIdentity {
        class: best_class,
        os: best_os,
        vendor,
        model,
        // The overall figure is the weaker of the two, since a confident class
        // with an unknown OS is not a confident identification.
        confidence: class_conf.max(os_conf),
        reasons: reasons.into_iter().map(|(_, r)| r).take(8).collect(),
    }
}

fn other_reasons(os: &Scores<OsFamily>) -> Vec<(u32, String)> {
    os.reasons.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::netbios::{NameKind, NetbiosName, NodeStatus};

    fn db() -> OuiDatabase {
        OuiDatabase::builtin()
    }

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    /// Builds signals with only open ports set.
    fn from_ports(ports: &[u16]) -> DeviceIdentity {
        identify(
            &Signals {
                open_ports: ports,
                ..Default::default()
            },
            &db(),
        )
    }

    fn mdns_with(services: &[&str], txt: &[(&str, &str)]) -> MdnsInfo {
        MdnsInfo {
            hostname: None,
            addresses: vec![],
            services: services.iter().map(|s| s.to_string()).collect(),
            instance_names: vec![],
            txt: txt
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    // ---- no signal ---------------------------------------------------------

    #[test]
    fn no_signals_yields_an_honest_unknown() {
        let id = identify(&Signals::default(), &db());
        assert_eq!(id.class, DeviceClass::Unknown);
        assert_eq!(id.os, OsFamily::Unknown);
        assert_eq!(id.confidence, 0);
        assert!(id.reasons.is_empty());
    }

    #[test]
    fn a_randomised_mac_alone_yields_unknown() {
        // Privacy MACs must not produce a vendor, and therefore no class.
        let id = identify(
            &Signals {
                mac: Some(mac("02:11:22:33:44:55")),
                ..Default::default()
            },
            &db(),
        );
        assert_eq!(id.class, DeviceClass::Unknown);
        assert_eq!(id.vendor, None);
    }

    // ---- MAC-driven identification ----------------------------------------

    #[test]
    fn a_vmware_mac_identifies_a_virtual_machine() {
        let id = identify(
            &Signals {
                mac: Some(mac("00:0c:29:aa:bb:cc")),
                ..Default::default()
            },
            &db(),
        );
        assert_eq!(id.class, DeviceClass::VirtualMachine);
        assert_eq!(id.vendor.as_deref(), Some("VMware"));
        assert!(id.confidence > 50);
    }

    #[test]
    fn a_raspberry_pi_mac_identifies_a_linux_sbc() {
        let id = identify(
            &Signals {
                mac: Some(mac("b8:27:eb:01:02:03")),
                ..Default::default()
            },
            &db(),
        );
        assert_eq!(id.class, DeviceClass::SingleBoardComputer);
        assert_eq!(id.os, OsFamily::Linux);
    }

    #[test]
    fn a_general_purpose_vendor_names_the_maker_without_guessing_a_class() {
        // Intel NICs appear in everything.
        let id = identify(
            &Signals {
                mac: Some(mac("00:1b:21:00:00:01")),
                ..Default::default()
            },
            &db(),
        );
        assert_eq!(id.vendor.as_deref(), Some("Intel"));
        assert_eq!(id.class, DeviceClass::Unknown);
    }

    // ---- port-driven identification ---------------------------------------

    #[test]
    fn rpc_plus_smb_identifies_windows_more_strongly_than_smb_alone() {
        // Samba exposes 445 but not usually 135, so the pair is the better tell.
        let smb_only = from_ports(&[445]);
        let with_rpc = from_ports(&[135, 445]);
        assert_eq!(smb_only.os, OsFamily::Windows);
        assert_eq!(with_rpc.os, OsFamily::Windows);
        assert!(with_rpc.confidence > smb_only.confidence);
    }

    #[test]
    fn the_ios_lockdown_port_identifies_an_iphone() {
        let id = from_ports(&[62078]);
        assert_eq!(id.class, DeviceClass::Phone);
        assert_eq!(id.os, OsFamily::Ios);
    }

    #[test]
    fn the_adb_port_identifies_android() {
        assert_eq!(from_ports(&[5555]).os, OsFamily::Android);
    }

    #[test]
    fn printing_ports_identify_a_printer() {
        assert_eq!(from_ports(&[631]).class, DeviceClass::Printer);
        assert_eq!(from_ports(&[9100]).class, DeviceClass::Printer);
    }

    #[test]
    fn a_database_port_identifies_a_server() {
        for p in [3306u16, 5432, 1433, 27017] {
            assert_eq!(from_ports(&[p]).class, DeviceClass::Server, "port {p}");
        }
    }

    #[test]
    fn ssh_alone_is_a_weak_linux_hint_not_a_confident_verdict() {
        let id = from_ports(&[22]);
        assert_eq!(id.os, OsFamily::Linux);
        assert!(
            id.confidence < 50,
            "SSH alone should not be confident, got {}",
            id.confidence
        );
    }

    // ---- gateway -----------------------------------------------------------

    #[test]
    fn being_the_default_gateway_identifies_a_router() {
        let id = identify(
            &Signals {
                is_default_gateway: true,
                open_ports: &[53, 80],
                ..Default::default()
            },
            &db(),
        );
        assert_eq!(id.class, DeviceClass::Router);
        assert!(id.confidence > 60);
        assert!(id.reasons.iter().any(|r| r.contains("default gateway")));
    }

    // ---- mDNS --------------------------------------------------------------

    #[test]
    fn an_iphone_mdns_model_is_decisive() {
        let m = mdns_with(&["_companion-link._tcp"], &[("model", "iPhone14,5")]);
        let id = identify(
            &Signals {
                mdns: Some(&m),
                ..Default::default()
            },
            &db(),
        );
        assert_eq!(id.class, DeviceClass::Phone);
        assert_eq!(id.os, OsFamily::Ios);
        assert_eq!(id.model.as_deref(), Some("iPhone14,5"));
        assert!(id.confidence > 70);
    }

    #[test]
    fn a_macbook_mdns_model_identifies_macos() {
        let m = mdns_with(&["_ssh._tcp"], &[("model", "MacBookPro18,3")]);
        let id = identify(
            &Signals {
                mdns: Some(&m),
                open_ports: &[22],
                ..Default::default()
            },
            &db(),
        );
        assert_eq!(id.class, DeviceClass::Computer);
        assert_eq!(id.os, OsFamily::MacOs, "should outweigh the SSH Linux hint");
    }

    #[test]
    fn google_cast_identifies_a_media_device() {
        let m = mdns_with(&["_googlecast._tcp"], &[]);
        let id = identify(
            &Signals {
                mdns: Some(&m),
                ..Default::default()
            },
            &db(),
        );
        assert_eq!(id.class, DeviceClass::MediaDevice);
    }

    #[test]
    fn ipp_identifies_a_printer_and_names_the_model() {
        let m = mdns_with(&["_ipp._tcp"], &[("ty", "Acme LaserJet 400")]);
        let id = identify(
            &Signals {
                mdns: Some(&m),
                ..Default::default()
            },
            &db(),
        );
        assert_eq!(id.class, DeviceClass::Printer);
        assert_eq!(id.model.as_deref(), Some("Acme LaserJet 400"));
    }

    // ---- SSDP --------------------------------------------------------------

    #[test]
    fn an_internet_gateway_device_identifies_a_router() {
        let r = SsdpResponse {
            server: Some("Linux/4.4 UPnP/1.0 MiniUPnPd/2.1".to_string()),
            search_target: Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1".to_string()),
            ..Default::default()
        };
        let ssdp = vec![r];
        let id = identify(
            &Signals {
                ssdp: &ssdp,
                ..Default::default()
            },
            &db(),
        );
        assert_eq!(id.class, DeviceClass::Router);
        assert_eq!(id.os, OsFamily::Linux);
    }

    #[test]
    fn a_windows_ssdp_server_string_identifies_windows() {
        let ssdp = vec![SsdpResponse {
            server: Some("Microsoft-Windows/10.0 UPnP/1.0".to_string()),
            ..Default::default()
        }];
        let id = identify(
            &Signals {
                ssdp: &ssdp,
                ..Default::default()
            },
            &db(),
        );
        assert_eq!(id.os, OsFamily::Windows);
    }

    // ---- NetBIOS -----------------------------------------------------------

    fn node_status(kinds: &[(NameKind, &str)]) -> NodeStatus {
        NodeStatus {
            names: kinds
                .iter()
                .map(|(k, n)| NetbiosName {
                    name: n.to_string(),
                    suffix: 0,
                    is_group: false,
                    kind: *k,
                })
                .collect(),
            mac: None,
        }
    }

    #[test]
    fn a_netbios_response_identifies_windows() {
        let nb = node_status(&[(NameKind::Workstation, "PC1")]);
        let id = identify(
            &Signals {
                netbios: Some(&nb),
                ..Default::default()
            },
            &db(),
        );
        assert_eq!(id.os, OsFamily::Windows);
    }

    #[test]
    fn a_domain_controller_is_identified_as_a_server() {
        let nb = node_status(&[
            (NameKind::Workstation, "DC01"),
            (NameKind::DomainController, "CORP"),
        ]);
        let id = identify(
            &Signals {
                netbios: Some(&nb),
                open_ports: &[135, 445, 389],
                ..Default::default()
            },
            &db(),
        );
        assert_eq!(id.class, DeviceClass::Server);
        assert_eq!(id.os, OsFamily::Windows);
        assert!(id.confidence > 60);
    }

    // ---- TTL is a tiebreaker only -----------------------------------------

    #[test]
    fn ttl_alone_never_produces_a_confident_verdict() {
        let id = identify(
            &Signals {
                ttl: Some(128),
                ..Default::default()
            },
            &db(),
        );
        assert_eq!(id.os, OsFamily::Windows);
        assert!(
            id.confidence < 40,
            "TTL alone must stay uncertain, got {}",
            id.confidence
        );
    }

    #[test]
    fn a_strong_signal_overrides_a_contradicting_ttl() {
        // TTL 64 hints Unix-like, but the lockdown port is decisive for iOS.
        let id = identify(
            &Signals {
                ttl: Some(64),
                open_ports: &[62078],
                ..Default::default()
            },
            &db(),
        );
        assert_eq!(id.os, OsFamily::Ios);
    }

    // ---- hostname ----------------------------------------------------------

    #[test]
    fn the_windows_default_hostname_pattern_is_recognised() {
        let id = identify(
            &Signals {
                hostname: Some("DESKTOP-A1B2C3"),
                ..Default::default()
            },
            &db(),
        );
        assert_eq!(id.class, DeviceClass::Computer);
        assert_eq!(id.os, OsFamily::Windows);
    }

    #[test]
    fn descriptive_hostnames_contribute_a_class_hint() {
        for (name, expected) in [
            ("office-printer-2", DeviceClass::Printer),
            ("front-door-camera", DeviceClass::Camera),
            ("home-router", DeviceClass::Router),
        ] {
            let id = identify(
                &Signals {
                    hostname: Some(name),
                    ..Default::default()
                },
                &db(),
            );
            assert_eq!(id.class, expected, "hostname {name}");
        }
    }

    // ---- combined, realistic cases ----------------------------------------

    #[test]
    fn a_realistic_windows_workstation_is_identified() {
        let nb = node_status(&[(NameKind::Workstation, "DESKTOP-X1")]);
        let id = identify(
            &Signals {
                mac: Some(mac("00:1b:21:aa:bb:cc")),
                open_ports: &[135, 139, 445, 3389],
                ttl: Some(128),
                hostname: Some("DESKTOP-X1"),
                netbios: Some(&nb),
                ..Default::default()
            },
            &db(),
        );
        assert_eq!(id.os, OsFamily::Windows);
        assert_eq!(id.class, DeviceClass::Computer);
        assert_eq!(id.vendor.as_deref(), Some("Intel"));
        assert!(id.confidence > 70, "got {}", id.confidence);
    }

    #[test]
    fn a_realistic_home_router_is_identified() {
        let ssdp = vec![SsdpResponse {
            server: Some("Linux/4.4 UPnP/1.0 MiniUPnPd/2.1".to_string()),
            search_target: Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1".to_string()),
            ..Default::default()
        }];
        let id = identify(
            &Signals {
                mac: Some(mac("c8:0e:14:11:22:33")),
                open_ports: &[53, 80, 443],
                ttl: Some(64),
                is_default_gateway: true,
                ssdp: &ssdp,
                ..Default::default()
            },
            &db(),
        );
        assert_eq!(id.class, DeviceClass::Router);
        assert_eq!(id.vendor.as_deref(), Some("AVM (FRITZ!Box)"));
        assert!(id.confidence > 80);
    }

    #[test]
    fn a_realistic_network_printer_is_identified() {
        let m = mdns_with(&["_ipp._tcp", "_printer._tcp"], &[("ty", "Brother HL-L2350DW")]);
        let id = identify(
            &Signals {
                mac: Some(mac("00:80:77:11:22:33")),
                open_ports: &[80, 631, 9100],
                mdns: Some(&m),
                ..Default::default()
            },
            &db(),
        );
        assert_eq!(id.class, DeviceClass::Printer);
        assert_eq!(id.vendor.as_deref(), Some("Brother"));
        assert_eq!(id.model.as_deref(), Some("Brother HL-L2350DW"));
        assert!(id.confidence > 80);
    }

    // ---- determinism -------------------------------------------------------

    #[test]
    fn identification_is_deterministic() {
        let m = mdns_with(&["_ipp._tcp"], &[("ty", "X")]);
        let signals = Signals {
            mac: Some(mac("00:80:77:11:22:33")),
            open_ports: &[80, 631],
            ttl: Some(64),
            mdns: Some(&m),
            ..Default::default()
        };
        let first = identify(&signals, &db());
        for _ in 0..20 {
            assert_eq!(identify(&signals, &db()), first);
        }
    }

    #[test]
    fn contradicting_signals_lower_confidence_rather_than_picking_confidently() {
        // A Windows RDP port and an iOS lockdown port cannot both be right.
        let conflicted = from_ports(&[3389, 62078]);
        let clean = from_ports(&[62078]);
        assert!(
            conflicted.confidence < clean.confidence,
            "conflict {} should be less confident than clean {}",
            conflicted.confidence,
            clean.confidence
        );
    }

    #[test]
    fn reasons_are_reported_strongest_first_and_bounded() {
        let m = mdns_with(&["_ipp._tcp", "_printer._tcp", "_http._tcp"], &[("ty", "P")]);
        let id = identify(
            &Signals {
                mac: Some(mac("00:80:77:11:22:33")),
                open_ports: &[80, 443, 631, 9100, 161, 22, 445, 3389],
                ttl: Some(64),
                hostname: Some("office-printer"),
                mdns: Some(&m),
                ..Default::default()
            },
            &db(),
        );
        assert!(!id.reasons.is_empty());
        assert!(id.reasons.len() <= 8, "reason list should stay readable");
    }

    #[test]
    fn identity_round_trips_through_json() {
        let id = from_ports(&[62078]);
        let j = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<DeviceIdentity>(&j).unwrap(), id);
    }
}
