//! mDNS and DNS-SD (RFC 6762, RFC 6763).
//!
//! Multicast DNS is the single most informative unprivileged discovery
//! technique on a modern LAN. It needs no raw sockets, so it works on Android
//! and as a normal user everywhere, and responders volunteer their hostname,
//! their service list and often their exact hardware model.
//!
//! The service types below are the ones that identify a device rather than
//! merely prove it exists.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use super::dns::{self, Message, RecordData};

/// The IPv4 mDNS group address.
pub const MDNS_IPV4_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// The IPv6 mDNS group address, `ff02::fb`.
pub const MDNS_IPV6_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);
pub const MDNS_PORT: u16 = 5353;

/// The DNS-SD meta-query that asks a responder to list its service types.
pub const SERVICE_ENUMERATION: &str = "_services._dns-sd._udp.local";

/// Service types worth querying, chosen because each pins down a device class.
pub const INTERESTING_SERVICES: &[&str] = &[
    // Generic, but carries model/OS strings in TXT.
    "_device-info._tcp.local",
    // Apple ecosystem.
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_companion-link._tcp.local",
    "_homekit._tcp.local",
    "_apple-mobdev2._tcp.local",
    // Printers.
    "_ipp._tcp.local",
    "_ipps._tcp.local",
    "_printer._tcp.local",
    "_pdl-datastream._tcp.local",
    "_scanner._tcp.local",
    // File and remote access.
    "_smb._tcp.local",
    "_afpovertcp._tcp.local",
    "_nfs._tcp.local",
    "_ssh._tcp.local",
    "_sftp-ssh._tcp.local",
    "_rfb._tcp.local",
    // Media and smart-home devices.
    "_googlecast._tcp.local",
    "_androidtvremote2._tcp.local",
    "_spotify-connect._tcp.local",
    "_sonos._tcp.local",
    "_hue._tcp.local",
    "_miio._udp.local",
    // Infrastructure.
    "_http._tcp.local",
    "_https._tcp.local",
    "_workstation._tcp.local",
    "_esphomelib._tcp.local",
];

/// Builds an mDNS query.
///
/// The unicast-response bit is set: a scanner wants the answer addressed to it
/// rather than multicast to the whole segment, which halves the noise a scan
/// creates. Responders that ignore the bit simply multicast as usual.
pub fn build_query(name: &str, qtype: u16, unicast_response: bool) -> dns::Result<Vec<u8>> {
    let qclass = if unicast_response {
        dns::rclass::IN | dns::rclass::UNICAST_RESPONSE
    } else {
        dns::rclass::IN
    };
    // mDNS queries use transaction ID 0 (RFC 6762 §18.1).
    dns::build_query(0, name, qtype, qclass)
}

/// Builds the DNS-SD service enumeration query.
pub fn build_service_enumeration_query() -> dns::Result<Vec<u8>> {
    build_query(SERVICE_ENUMERATION, dns::rtype::PTR, true)
}

/// What an mDNS response told us about a host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdnsInfo {
    /// The `.local` hostname, with the suffix stripped.
    pub hostname: Option<String>,
    /// Addresses the responder claims.
    pub addresses: Vec<IpAddr>,
    /// Service types offered, e.g. `_airplay._tcp`.
    pub services: Vec<String>,
    /// Human-readable instance names, e.g. "Kitchen Speaker".
    pub instance_names: Vec<String>,
    /// Key/value pairs from TXT records, which is where models and OS versions
    /// appear.
    pub txt: Vec<(String, String)>,
}

impl MdnsInfo {
    pub fn is_empty(&self) -> bool {
        self.hostname.is_none()
            && self.addresses.is_empty()
            && self.services.is_empty()
            && self.txt.is_empty()
    }

    /// Looks up a TXT key case-insensitively.
    pub fn txt_value(&self, key: &str) -> Option<&str> {
        self.txt
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }
}

/// Extracts host information from an mDNS response.
pub fn extract(msg: &Message) -> MdnsInfo {
    let mut info = MdnsInfo::default();

    for rr in msg.all_records() {
        match &rr.data {
            RecordData::A(a) => {
                push_unique_addr(&mut info.addresses, IpAddr::V4(*a));
                if let Some(h) = strip_local(&rr.name) {
                    set_hostname(&mut info, h);
                }
            }
            RecordData::Aaaa(a) => {
                push_unique_addr(&mut info.addresses, IpAddr::V6(*a));
                if let Some(h) = strip_local(&rr.name) {
                    set_hostname(&mut info, h);
                }
            }
            RecordData::Ptr(target) => {
                // The service enumeration meta-query answers with service types
                // as the target; ordinary service PTRs answer with an instance.
                if rr.name == SERVICE_ENUMERATION {
                    if let Some(s) = strip_local(target) {
                        push_unique(&mut info.services, s.to_string());
                    }
                } else {
                    if let Some(s) = strip_local(&rr.name) {
                        push_unique(&mut info.services, s.to_string());
                    }
                    if let Some(instance) = instance_label(target) {
                        push_unique(&mut info.instance_names, instance);
                    }
                }
            }
            RecordData::Srv { target, .. } => {
                if let Some(h) = strip_local(target) {
                    set_hostname(&mut info, h);
                }
                if let Some(s) = service_type_of(&rr.name) {
                    push_unique(&mut info.services, s);
                }
            }
            RecordData::Txt(strings) => {
                for s in strings {
                    // TXT entries are `key=value`, or a bare flag with no value.
                    let (k, v) = match s.split_once('=') {
                        Some((k, v)) => (k.to_string(), v.to_string()),
                        None => (s.clone(), String::new()),
                    };
                    if k.is_empty() {
                        continue;
                    }
                    if !info.txt.iter().any(|(ek, _)| *ek == k) {
                        info.txt.push((k, v));
                    }
                }
                if let Some(s) = service_type_of(&rr.name) {
                    push_unique(&mut info.services, s);
                }
            }
            RecordData::Other(_) => {}
        }
    }

    info
}

/// Prefers the shortest hostname seen, which avoids a service instance name
/// overwriting the real host name.
fn set_hostname(info: &mut MdnsInfo, candidate: &str) {
    if candidate.is_empty() {
        return;
    }
    match &info.hostname {
        Some(existing) if existing.len() <= candidate.len() => {}
        _ => info.hostname = Some(candidate.to_string()),
    }
}

fn push_unique(v: &mut Vec<String>, s: String) {
    if !s.is_empty() && !v.contains(&s) {
        v.push(s);
    }
}

fn push_unique_addr(v: &mut Vec<IpAddr>, a: IpAddr) {
    if !v.contains(&a) {
        v.push(a);
    }
}

/// Strips a trailing `.local`, returning `None` for names outside it.
fn strip_local(name: &str) -> Option<&str> {
    name.strip_suffix(".local")
        .or_else(|| name.strip_suffix(".local."))
}

/// Extracts the service type from a full instance name.
///
/// `"Kitchen Speaker._airplay._tcp.local"` yields `"_airplay._tcp"`. Instance
/// labels may themselves contain dots, so this searches for the first label
/// beginning with an underscore rather than splitting from the left.
fn service_type_of(name: &str) -> Option<String> {
    let stripped = strip_local(name)?;
    let idx = stripped.find("._")?;
    Some(stripped[idx + 1..].to_string())
}

/// Extracts the human-readable instance label from a full instance name.
fn instance_label(name: &str) -> Option<String> {
    let stripped = strip_local(name)?;
    let idx = stripped.find("._")?;
    let label = &stripped[..idx];
    if label.is_empty() {
        None
    } else {
        // DNS-SD escapes dots and spaces inside instance labels.
        Some(label.replace("\\.", ".").replace("\\032", " "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::dns::{encode_name, rclass, rtype};

    // ---- query construction ------------------------------------------------

    #[test]
    fn queries_use_transaction_id_zero_per_rfc6762() {
        let q = build_query("_ipp._tcp.local", rtype::PTR, false).unwrap();
        let m = dns::parse_message(&q).unwrap();
        assert_eq!(m.id, 0);
        assert_eq!(m.questions[0].name, "_ipp._tcp.local");
    }

    #[test]
    fn the_unicast_response_bit_is_set_only_when_asked() {
        let uni = dns::parse_message(&build_query("x.local", rtype::A, true).unwrap()).unwrap();
        assert_eq!(uni.questions[0].qclass & rclass::UNICAST_RESPONSE, rclass::UNICAST_RESPONSE);
        assert_eq!(uni.questions[0].qclass & 0x7fff, rclass::IN);

        let multi = dns::parse_message(&build_query("x.local", rtype::A, false).unwrap()).unwrap();
        assert_eq!(multi.questions[0].qclass, rclass::IN);
    }

    #[test]
    fn the_service_enumeration_query_is_well_formed() {
        let m = dns::parse_message(&build_service_enumeration_query().unwrap()).unwrap();
        assert_eq!(m.questions[0].name, SERVICE_ENUMERATION);
        assert_eq!(m.questions[0].qtype, rtype::PTR);
    }

    #[test]
    fn the_group_addresses_are_the_documented_ones() {
        assert_eq!(MDNS_IPV4_GROUP, Ipv4Addr::new(224, 0, 0, 251));
        assert_eq!(MDNS_IPV6_GROUP, "ff02::fb".parse::<Ipv6Addr>().unwrap());
        assert!(MDNS_IPV4_GROUP.is_multicast());
        assert!(MDNS_IPV6_GROUP.is_multicast());
    }

    #[test]
    fn every_interesting_service_name_is_encodable_and_well_formed() {
        for s in INTERESTING_SERVICES {
            assert!(s.starts_with('_'), "{s} should start with an underscore");
            assert!(s.ends_with(".local"), "{s} should be in the .local domain");
            let mut b = Vec::new();
            encode_name(s, &mut b).expect("service name must encode");
        }
    }

    // ---- response extraction -----------------------------------------------

    /// Builds an mDNS response containing the given records.
    fn response(records: &[(&str, u16, Vec<u8>)]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0x8400u16.to_be_bytes()); // response, authoritative
        m.extend_from_slice(&0u16.to_be_bytes()); // qdcount
        m.extend_from_slice(&(records.len() as u16).to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        for (name, rtype, rdata) in records {
            encode_name(name, &mut m).unwrap();
            m.extend_from_slice(&rtype.to_be_bytes());
            m.extend_from_slice(&rclass::IN.to_be_bytes());
            m.extend_from_slice(&120u32.to_be_bytes());
            m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            m.extend_from_slice(rdata);
        }
        m
    }

    fn name_rdata(name: &str) -> Vec<u8> {
        let mut v = Vec::new();
        encode_name(name, &mut v).unwrap();
        v
    }

    fn txt_rdata(entries: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        for e in entries {
            v.push(e.len() as u8);
            v.extend_from_slice(e.as_bytes());
        }
        v
    }

    fn extract_from(records: &[(&str, u16, Vec<u8>)]) -> MdnsInfo {
        extract(&dns::parse_message(&response(records)).unwrap())
    }

    #[test]
    fn extracts_hostname_and_address_from_an_a_record() {
        let info = extract_from(&[("macbook.local", rtype::A, vec![192, 168, 1, 42])]);
        assert_eq!(info.hostname.as_deref(), Some("macbook"));
        assert_eq!(info.addresses, vec!["192.168.1.42".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn extracts_service_types_from_the_enumeration_response() {
        let info = extract_from(&[
            (SERVICE_ENUMERATION, rtype::PTR, name_rdata("_airplay._tcp.local")),
            (SERVICE_ENUMERATION, rtype::PTR, name_rdata("_raop._tcp.local")),
        ]);
        assert_eq!(info.services, vec!["_airplay._tcp", "_raop._tcp"]);
    }

    #[test]
    fn extracts_the_instance_name_from_a_service_ptr() {
        let info = extract_from(&[(
            "_airplay._tcp.local",
            rtype::PTR,
            name_rdata("Living Room TV._airplay._tcp.local"),
        )]);
        assert_eq!(info.services, vec!["_airplay._tcp"]);
        assert_eq!(info.instance_names, vec!["Living Room TV"]);
    }

    #[test]
    fn instance_labels_containing_dots_do_not_truncate_the_service_type() {
        // "Simon's iPhone 15.local" style names contain dots inside the label,
        // so splitting from the left would mangle both parts.
        let info = extract_from(&[(
            "_companion-link._tcp.local",
            rtype::PTR,
            name_rdata("Office v2.0 Hub._companion-link._tcp.local"),
        )]);
        assert_eq!(info.services, vec!["_companion-link._tcp"]);
        assert_eq!(info.instance_names, vec!["Office v2.0 Hub"]);
    }

    #[test]
    fn dns_sd_escapes_in_instance_labels_are_decoded() {
        let info = extract_from(&[(
            "_ipp._tcp.local",
            rtype::PTR,
            name_rdata("Front\\032Desk._ipp._tcp.local"),
        )]);
        assert_eq!(info.instance_names, vec!["Front Desk"]);
    }

    #[test]
    fn extracts_txt_key_value_pairs() {
        let info = extract_from(&[(
            "printer._ipp._tcp.local",
            rtype::TXT,
            txt_rdata(&["ty=Acme LaserJet 400", "product=(Acme)", "rp=ipp/print"]),
        )]);
        assert_eq!(info.txt_value("ty"), Some("Acme LaserJet 400"));
        assert_eq!(info.txt_value("TY"), Some("Acme LaserJet 400"), "lookup is case-insensitive");
        assert_eq!(info.txt_value("rp"), Some("ipp/print"));
        assert_eq!(info.txt_value("missing"), None);
    }

    #[test]
    fn txt_entries_without_an_equals_sign_become_valueless_flags() {
        let info = extract_from(&[("d._http._tcp.local", rtype::TXT, txt_rdata(&["flag"]))]);
        assert_eq!(info.txt_value("flag"), Some(""));
    }

    #[test]
    fn extracts_the_target_host_from_an_srv_record() {
        let mut rdata = vec![0, 10, 0, 5];
        rdata.extend_from_slice(&631u16.to_be_bytes());
        rdata.extend(name_rdata("printer.local"));
        let info = extract_from(&[("p._ipp._tcp.local", rtype::SRV, rdata)]);
        assert_eq!(info.hostname.as_deref(), Some("printer"));
        assert_eq!(info.services, vec!["_ipp._tcp"]);
    }

    #[test]
    fn the_shortest_hostname_wins_over_longer_instance_names() {
        // An SRV target and an A record can disagree; the bare host name is the
        // useful one.
        let info = extract_from(&[
            ("verylongservicename.local", rtype::A, vec![10, 0, 0, 1]),
            ("nas.local", rtype::A, vec![10, 0, 0, 1]),
        ]);
        assert_eq!(info.hostname.as_deref(), Some("nas"));
    }

    #[test]
    fn duplicate_records_are_collapsed() {
        let info = extract_from(&[
            ("h.local", rtype::A, vec![10, 0, 0, 1]),
            ("h.local", rtype::A, vec![10, 0, 0, 1]),
            (SERVICE_ENUMERATION, rtype::PTR, name_rdata("_ssh._tcp.local")),
            (SERVICE_ENUMERATION, rtype::PTR, name_rdata("_ssh._tcp.local")),
        ]);
        assert_eq!(info.addresses.len(), 1);
        assert_eq!(info.services, vec!["_ssh._tcp"]);
    }

    #[test]
    fn names_outside_the_local_domain_are_ignored() {
        let info = extract_from(&[("host.example.com", rtype::A, vec![10, 0, 0, 1])]);
        assert_eq!(info.hostname, None);
        // The address is still recorded; only the name is out of scope.
        assert_eq!(info.addresses.len(), 1);
    }

    #[test]
    fn an_empty_response_yields_empty_info() {
        let info = extract_from(&[]);
        assert!(info.is_empty());
    }

    #[test]
    fn a_realistic_apple_tv_response_is_fully_decoded() {
        let mut srv = vec![0, 0, 0, 0];
        srv.extend_from_slice(&7000u16.to_be_bytes());
        srv.extend(name_rdata("Apple-TV.local"));

        let info = extract_from(&[
            ("Apple-TV.local", rtype::A, vec![192, 168, 1, 77]),
            ("_airplay._tcp.local", rtype::PTR, name_rdata("Apple TV._airplay._tcp.local")),
            ("Apple TV._airplay._tcp.local", rtype::SRV, srv),
            (
                "Apple TV._airplay._tcp.local",
                rtype::TXT,
                txt_rdata(&["model=AppleTV6,2", "osvers=17.4", "deviceid=AA:BB:CC:DD:EE:FF"]),
            ),
        ]);

        assert_eq!(info.hostname.as_deref(), Some("Apple-TV"));
        assert_eq!(info.addresses, vec!["192.168.1.77".parse::<IpAddr>().unwrap()]);
        assert!(info.services.contains(&"_airplay._tcp".to_string()));
        assert_eq!(info.instance_names, vec!["Apple TV"]);
        assert_eq!(info.txt_value("model"), Some("AppleTV6,2"));
        assert_eq!(info.txt_value("osvers"), Some("17.4"));
    }
}
