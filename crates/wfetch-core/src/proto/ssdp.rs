//! SSDP / UPnP discovery.
//!
//! SSDP is HTTP-over-UDP multicast. It is the counterpart to mDNS for the
//! non-Apple half of a consumer network: routers, smart TVs, games consoles,
//! NAS boxes, printers and IoT gear answer it, and the `SERVER` header usually
//! names the operating system and the product outright.
//!
//! Like mDNS it needs only an unprivileged UDP socket, so it is one of the few
//! techniques available on Android.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The IPv4 SSDP group address.
pub const SSDP_IPV4_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
/// The IPv6 site-local SSDP group, `ff05::c`.
pub const SSDP_IPV6_GROUP: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0x000c);
pub const SSDP_PORT: u16 = 1900;

/// Search targets worth issuing.
///
/// `ssdp:all` gets everything but is noisy and some devices rate-limit it, so
/// the specific root-device target is issued too; devices that ignore one often
/// answer the other.
pub const SEARCH_TARGETS: &[&str] = &[
    "ssdp:all",
    "upnp:rootdevice",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:MediaRenderer:1",
    "urn:schemas-upnp-org:device:MediaServer:1",
    "urn:dial-multiscreen-org:service:dial:1",
];

/// Builds an M-SEARCH request.
///
/// `mx` is the maximum number of seconds a responder may wait before replying;
/// it exists so that a large network does not answer all at once. Responders
/// clamp it to 5, so values above that are pointless, and a value of 0 makes
/// some devices ignore the request entirely.
pub fn build_msearch(target: &str, mx: Duration) -> String {
    let mx_secs = mx.as_secs().clamp(1, 5);
    // CRLF line endings and the trailing blank line are mandatory; devices are
    // strict about this because they parse it as HTTP.
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: {}:{}\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: {}\r\n\
         ST: {}\r\n\
         \r\n",
        SSDP_IPV4_GROUP, SSDP_PORT, mx_secs, target
    )
}

/// A parsed SSDP response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsdpResponse {
    /// `SERVER`: usually "OS/version UPnP/1.0 product/version".
    pub server: Option<String>,
    /// `LOCATION`: URL of the device description document.
    pub location: Option<String>,
    /// `ST` or `NT`: what the device claims to be.
    pub search_target: Option<String>,
    /// `USN`: unique service name, normally containing the device UUID.
    pub usn: Option<String>,
    /// Every header, lowercased, for callers that want more.
    pub headers: Vec<(String, String)>,
}

impl SsdpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The device UUID from the USN, if present.
    ///
    /// USNs look like `uuid:2f402f80-da50-11e1-9b23-001788102201::upnp:rootdevice`.
    pub fn uuid(&self) -> Option<&str> {
        let usn = self.usn.as_deref()?;
        let rest = usn.strip_prefix("uuid:")?;
        Some(rest.split("::").next().unwrap_or(rest))
    }
}

/// Parses an SSDP response or NOTIFY.
///
/// Accepts both `HTTP/1.1 200 OK` responses to an M-SEARCH and `NOTIFY *`
/// announcements, which carry the same headers under slightly different names.
/// Returns `None` for anything that is not one of those, including our own
/// outgoing M-SEARCH echoed back by the multicast loopback.
pub fn parse_response(data: &[u8]) -> Option<SsdpResponse> {
    // Device firmware emits plenty of invalid UTF-8 in these headers.
    let text = String::from_utf8_lossy(data);
    let mut lines = text.lines();

    let start_line = lines.next()?.trim();
    let is_response = start_line.starts_with("HTTP/1.1 200") || start_line.starts_with("HTTP/1.0 200");
    let is_notify = start_line.starts_with("NOTIFY");
    if !is_response && !is_notify {
        return None;
    }

    let mut out = SsdpResponse::default();
    for line in lines {
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let value = v.trim().to_string();
        if key.is_empty() {
            continue;
        }

        match key.as_str() {
            "server" => out.server = Some(value.clone()),
            "location" => out.location = Some(value.clone()),
            // ST in a search response, NT in a NOTIFY announcement.
            "st" | "nt" => out.search_target = Some(value.clone()),
            "usn" => out.usn = Some(value.clone()),
            _ => {}
        }
        out.headers.push((key, value));
    }

    Some(out)
}

/// Splits a `SERVER` header into its product tokens.
///
/// `"Linux/4.4 UPnP/1.0 MiniDLNA/1.2.1"` yields the three tokens. The UPnP
/// token is dropped because every device carries it and it identifies nothing.
pub fn server_tokens(server: &str) -> Vec<String> {
    server
        .split_whitespace()
        .filter(|t| !t.is_empty() && !t.to_ascii_lowercase().starts_with("upnp/"))
        .map(|t| t.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- request construction ----------------------------------------------

    #[test]
    fn msearch_has_the_mandatory_headers_and_line_endings() {
        let m = build_msearch("ssdp:all", Duration::from_secs(2));
        assert!(m.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(m.contains("HOST: 239.255.255.250:1900\r\n"));
        // The quotes around ssdp:discover are required by the spec and devices
        // reject the request without them.
        assert!(m.contains("MAN: \"ssdp:discover\"\r\n"));
        assert!(m.contains("ST: ssdp:all\r\n"));
        assert!(m.contains("MX: 2\r\n"));
        // A blank line must terminate the request.
        assert!(m.ends_with("\r\n\r\n"));
    }

    #[test]
    fn msearch_uses_only_crlf_line_endings() {
        let m = build_msearch("upnp:rootdevice", Duration::from_secs(1));
        assert_eq!(
            m.matches('\n').count(),
            m.matches("\r\n").count(),
            "a bare LF would break strict HTTP parsers in device firmware"
        );
    }

    #[test]
    fn mx_is_clamped_to_the_range_devices_accept() {
        // 0 makes some devices ignore the request; above 5 is meaningless.
        assert!(build_msearch("ssdp:all", Duration::from_secs(0)).contains("MX: 1\r\n"));
        assert!(build_msearch("ssdp:all", Duration::from_secs(99)).contains("MX: 5\r\n"));
        assert!(build_msearch("ssdp:all", Duration::from_secs(3)).contains("MX: 3\r\n"));
    }

    #[test]
    fn the_group_addresses_are_the_documented_ones() {
        assert_eq!(SSDP_IPV4_GROUP, Ipv4Addr::new(239, 255, 255, 250));
        assert!(SSDP_IPV4_GROUP.is_multicast());
        assert!(SSDP_IPV6_GROUP.is_multicast());
    }

    // ---- response parsing --------------------------------------------------

    const ROUTER: &str = "HTTP/1.1 200 OK\r\n\
CACHE-CONTROL: max-age=120\r\n\
DATE: Mon, 07 Aug 2026 10:00:00 GMT\r\n\
EXT:\r\n\
LOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n\
SERVER: Linux/4.4.60 UPnP/1.0 MiniUPnPd/2.1\r\n\
ST: upnp:rootdevice\r\n\
USN: uuid:2f402f80-da50-11e1-9b23-001788102201::upnp:rootdevice\r\n\
\r\n";

    #[test]
    fn parses_a_realistic_router_response() {
        let r = parse_response(ROUTER.as_bytes()).unwrap();
        assert_eq!(r.server.as_deref(), Some("Linux/4.4.60 UPnP/1.0 MiniUPnPd/2.1"));
        assert_eq!(
            r.location.as_deref(),
            Some("http://192.168.1.1:5000/rootDesc.xml")
        );
        assert_eq!(r.search_target.as_deref(), Some("upnp:rootdevice"));
        assert_eq!(r.uuid(), Some("2f402f80-da50-11e1-9b23-001788102201"));
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let r = parse_response(ROUTER.as_bytes()).unwrap();
        assert_eq!(r.header("cache-control"), Some("max-age=120"));
        assert_eq!(r.header("CACHE-CONTROL"), Some("max-age=120"));
        assert_eq!(r.header("Location"), Some("http://192.168.1.1:5000/rootDesc.xml"));
    }

    #[test]
    fn parses_notify_announcements_using_the_nt_header() {
        let notify = "NOTIFY * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
NT: urn:schemas-upnp-org:device:MediaRenderer:1\r\n\
NTS: ssdp:alive\r\n\
SERVER: Sonos/72.1 UPnP/1.0\r\n\
USN: uuid:RINCON_ABC::urn:schemas-upnp-org:device:MediaRenderer:1\r\n\
\r\n";
        let r = parse_response(notify.as_bytes()).unwrap();
        assert_eq!(
            r.search_target.as_deref(),
            Some("urn:schemas-upnp-org:device:MediaRenderer:1")
        );
        assert_eq!(r.server.as_deref(), Some("Sonos/72.1 UPnP/1.0"));
        assert_eq!(r.uuid(), Some("RINCON_ABC"));
    }

    #[test]
    fn our_own_msearch_is_not_parsed_as_a_response() {
        // Multicast loopback delivers our own request back to us.
        let m = build_msearch("ssdp:all", Duration::from_secs(2));
        assert!(parse_response(m.as_bytes()).is_none());
    }

    #[test]
    fn non_ssdp_payloads_are_rejected() {
        for junk in [
            &b""[..],
            b"garbage",
            b"HTTP/1.1 404 Not Found\r\n\r\n",
            b"GET / HTTP/1.1\r\n\r\n",
        ] {
            assert!(parse_response(junk).is_none(), "should reject {junk:?}");
        }
    }

    #[test]
    fn headers_with_no_value_and_no_colon_do_not_break_parsing() {
        // "EXT:" with an empty value is required by the spec and is common.
        let r = parse_response(ROUTER.as_bytes()).unwrap();
        assert_eq!(r.header("ext"), Some(""));

        let odd = "HTTP/1.1 200 OK\r\nnonsense-line\r\nSERVER: X/1\r\n\r\n";
        let r = parse_response(odd.as_bytes()).unwrap();
        assert_eq!(r.server.as_deref(), Some("X/1"));
    }

    #[test]
    fn values_containing_colons_are_kept_whole() {
        // LOCATION URLs and USNs both contain colons after the first one.
        let r = parse_response(ROUTER.as_bytes()).unwrap();
        assert!(r.location.unwrap().starts_with("http://"));
        assert!(r.usn.unwrap().contains("::upnp:rootdevice"));
    }

    #[test]
    fn invalid_utf8_in_firmware_headers_does_not_reject_the_response() {
        let mut data = b"HTTP/1.1 200 OK\r\nSERVER: Caf\xe9Router/1.0\r\n\r\n".to_vec();
        data.push(b'\n');
        let r = parse_response(&data).unwrap();
        assert!(r.server.is_some());
    }

    #[test]
    fn a_usn_without_a_uuid_prefix_yields_none() {
        let s = "HTTP/1.1 200 OK\r\nUSN: something-else\r\n\r\n";
        assert_eq!(parse_response(s.as_bytes()).unwrap().uuid(), None);
    }

    #[test]
    fn arbitrary_byte_soup_never_panics() {
        let mut seed = 0x5eedu32;
        for _ in 0..2000 {
            let len = (seed % 200) as usize;
            let buf: Vec<u8> = (0..len)
                .map(|i| {
                    seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                    (seed >> ((i % 4) * 8)) as u8
                })
                .collect();
            let _ = parse_response(&buf);
        }
    }

    // ---- server token splitting -------------------------------------------

    #[test]
    fn server_tokens_drop_the_uninformative_upnp_version() {
        assert_eq!(
            server_tokens("Linux/4.4.60 UPnP/1.0 MiniUPnPd/2.1"),
            vec!["Linux/4.4.60", "MiniUPnPd/2.1"]
        );
        assert_eq!(
            server_tokens("Windows NT/10.0 UPnP/1.0 Xbox/1.0"),
            vec!["Windows", "NT/10.0", "Xbox/1.0"]
        );
    }

    #[test]
    fn server_tokens_handles_empty_and_upnp_only_headers() {
        assert!(server_tokens("").is_empty());
        assert!(server_tokens("UPnP/1.0").is_empty());
        assert!(server_tokens("   ").is_empty());
    }
}
