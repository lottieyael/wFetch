//! SNMP v2c.
//!
//! The inventory path for network equipment. A managed switch, router,
//! access point, printer or UPS will not accept an SSH login from an inventory
//! tool, but almost all of them answer SNMP, and `sysDescr` alone usually names
//! the vendor, model and firmware version outright.
//!
//! Only v2c is implemented. v1 is strictly less capable, and v3 adds a
//! user-based security model with key derivation that would need a cryptography
//! dependency — worth adding, but not something to half-implement, since a
//! broken v3 implementation fails in ways that look like the device is down.
//!
//! # Security note
//!
//! v2c authenticates with a community string sent in clear text, and offers no
//! encryption. It is appropriate for reading inventory on a trusted management
//! network and nothing else. The CLI never defaults to writing, and this module
//! implements no SET operation at all.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::ber::{self, tag, BerError};

pub const SNMP_PORT: u16 = 161;

/// SNMP version field value for v2c.
const VERSION_2C: i64 = 1;

/// Object identifiers worth reading, from the system group of RFC 1213.
pub mod oids {
    /// A free-text description: usually vendor, model and firmware version.
    pub const SYS_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
    /// Identifies the vendor's registered enterprise branch.
    pub const SYS_OBJECT_ID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 2, 0];
    /// Time since the agent last restarted, in hundredths of a second.
    pub const SYS_UPTIME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];
    pub const SYS_CONTACT: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 4, 0];
    /// The device's configured name.
    pub const SYS_NAME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];
    pub const SYS_LOCATION: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 6, 0];
    /// A bitmask of the OSI layers the device claims to operate at.
    pub const SYS_SERVICES: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 7, 0];
    /// Number of network interfaces.
    pub const IF_NUMBER: &[u32] = &[1, 3, 6, 1, 2, 1, 2, 1, 0];
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnmpError {
    #[error("encoding error: {0}")]
    Ber(#[from] BerError),
    #[error("agent reported error status {status} at index {index}")]
    AgentError { status: i64, index: i64 },
    #[error("response request-id {got} does not match request {expected}")]
    IdMismatch { got: i64, expected: i64 },
    #[error("no response within the timeout")]
    Timeout,
    #[error("socket error: {0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, SnmpError>;

/// A decoded SNMP value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum SnmpValue {
    Integer(i64),
    /// Rendered lossily: device strings are frequently not valid UTF-8.
    String(String),
    Oid(String),
    IpAddress(IpAddr),
    Counter32(u32),
    Gauge32(u32),
    /// Hundredths of a second since the agent restarted.
    TimeTicks(u32),
    Counter64(u64),
    Null,
    /// The agent explicitly reported that it does not have this object. This is
    /// a normal answer, not a failure: it means the device does not implement
    /// that part of the MIB.
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

impl SnmpValue {
    /// Renders the value as text for display.
    pub fn to_display_string(&self) -> String {
        match self {
            SnmpValue::Integer(v) => v.to_string(),
            SnmpValue::String(s) => s.clone(),
            SnmpValue::Oid(s) => s.clone(),
            SnmpValue::IpAddress(a) => a.to_string(),
            SnmpValue::Counter32(v) | SnmpValue::Gauge32(v) => v.to_string(),
            SnmpValue::TimeTicks(t) => format_timeticks(*t),
            SnmpValue::Counter64(v) => v.to_string(),
            SnmpValue::Null => "(null)".to_string(),
            SnmpValue::NoSuchObject => "(no such object)".to_string(),
            SnmpValue::NoSuchInstance => "(no such instance)".to_string(),
            SnmpValue::EndOfMibView => "(end of MIB)".to_string(),
        }
    }

    /// The text of a string value, if it is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            SnmpValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Whether the agent answered with an absence rather than a value.
    pub fn is_absent(&self) -> bool {
        matches!(
            self,
            SnmpValue::NoSuchObject | SnmpValue::NoSuchInstance | SnmpValue::EndOfMibView
        )
    }
}

/// Renders TimeTicks as a human-readable uptime.
fn format_timeticks(ticks: u32) -> String {
    let total_secs = ticks as u64 / 100;
    let days = total_secs / 86_400;
    let hours = (total_secs % 86_400) / 3_600;
    let mins = (total_secs % 3_600) / 60;
    let secs = total_secs % 60;
    if days > 0 {
        format!("{days}d {hours}h {mins}m {secs}s")
    } else if hours > 0 {
        format!("{hours}h {mins}m {secs}s")
    } else {
        format!("{mins}m {secs}s")
    }
}

/// One binding from a response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VarBind {
    pub oid: String,
    pub value: SnmpValue,
}

/// Builds a GetRequest for the given object identifiers.
pub fn build_get_request(community: &str, request_id: i64, oids: &[&[u32]]) -> Result<Vec<u8>> {
    build_request(tag::GET_REQUEST, community, request_id, oids)
}

/// Builds a GetNextRequest, used for walking a subtree.
pub fn build_get_next_request(community: &str, request_id: i64, oids: &[&[u32]]) -> Result<Vec<u8>> {
    build_request(tag::GET_NEXT_REQUEST, community, request_id, oids)
}

fn build_request(pdu_tag: u8, community: &str, request_id: i64, oids: &[&[u32]]) -> Result<Vec<u8>> {
    // Variable bindings: each is a SEQUENCE of an OID and a NULL placeholder.
    let mut bindings = Vec::new();
    for oid in oids {
        let mut one = Vec::new();
        ber::encode_oid(oid, &mut one)?;
        ber::encode_tlv(tag::NULL, &[], &mut one);
        ber::encode_tlv(tag::SEQUENCE, &one, &mut bindings);
    }

    let mut binding_list = Vec::new();
    ber::encode_tlv(tag::SEQUENCE, &bindings, &mut binding_list);

    let mut pdu = Vec::new();
    ber::encode_integer(request_id, &mut pdu);
    ber::encode_integer(0, &mut pdu); // error-status
    ber::encode_integer(0, &mut pdu); // error-index
    pdu.extend_from_slice(&binding_list);

    let mut pdu_wrapped = Vec::new();
    ber::encode_tlv(pdu_tag, &pdu, &mut pdu_wrapped);

    let mut message = Vec::new();
    ber::encode_integer(VERSION_2C, &mut message);
    ber::encode_tlv(tag::OCTET_STRING, community.as_bytes(), &mut message);
    message.extend_from_slice(&pdu_wrapped);

    let mut out = Vec::new();
    ber::encode_tlv(tag::SEQUENCE, &message, &mut out);
    Ok(out)
}

/// A parsed response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub request_id: i64,
    pub bindings: Vec<VarBind>,
}

/// Parses a GetResponse.
pub fn parse_response(buf: &[u8]) -> Result<Response> {
    let message = ber::expect_element(buf, 0, tag::SEQUENCE)?;
    let body = message.body;

    // version, community, then the PDU.
    let version = ber::expect_element(body, 0, tag::INTEGER)?;
    let _ = ber::decode_integer(version.body)?;
    let community = ber::expect_element(body, version.next, tag::OCTET_STRING)?;

    let pdu = ber::read_element(body, community.next)?;
    if pdu.tag != tag::GET_RESPONSE {
        return Err(SnmpError::Ber(BerError::UnexpectedTag {
            expected: tag::GET_RESPONSE,
            found: pdu.tag,
        }));
    }

    let p = pdu.body;
    let id_el = ber::expect_element(p, 0, tag::INTEGER)?;
    let request_id = ber::decode_integer(id_el.body)?;
    let status_el = ber::expect_element(p, id_el.next, tag::INTEGER)?;
    let error_status = ber::decode_integer(status_el.body)?;
    let index_el = ber::expect_element(p, status_el.next, tag::INTEGER)?;
    let error_index = ber::decode_integer(index_el.body)?;

    if error_status != 0 {
        return Err(SnmpError::AgentError {
            status: error_status,
            index: error_index,
        });
    }

    let list = ber::expect_element(p, index_el.next, tag::SEQUENCE)?;
    let mut bindings = Vec::new();
    let mut offset = 0usize;
    while offset < list.body.len() {
        let binding = ber::expect_element(list.body, offset, tag::SEQUENCE)?;
        offset = binding.next;

        let oid_el = ber::expect_element(binding.body, 0, tag::OID)?;
        let arcs = ber::decode_oid(oid_el.body)?;
        let value_el = ber::read_element(binding.body, oid_el.next)?;

        bindings.push(VarBind {
            oid: ber::oid_to_string(&arcs),
            value: decode_value(value_el.tag, value_el.body)?,
        });
    }

    Ok(Response {
        request_id,
        bindings,
    })
}

fn decode_value(value_tag: u8, body: &[u8]) -> Result<SnmpValue> {
    Ok(match value_tag {
        tag::INTEGER => SnmpValue::Integer(ber::decode_integer(body)?),
        // Device strings routinely contain invalid UTF-8 and embedded NULs.
        tag::OCTET_STRING => SnmpValue::String(
            String::from_utf8_lossy(body)
                .trim_end_matches('\0')
                .to_string(),
        ),
        tag::OID => SnmpValue::Oid(ber::oid_to_string(&ber::decode_oid(body)?)),
        tag::NULL => SnmpValue::Null,
        tag::IP_ADDRESS if body.len() == 4 => SnmpValue::IpAddress(IpAddr::from([
            body[0], body[1], body[2], body[3],
        ])),
        tag::COUNTER32 => SnmpValue::Counter32(decode_unsigned(body) as u32),
        tag::GAUGE32 => SnmpValue::Gauge32(decode_unsigned(body) as u32),
        tag::TIMETICKS => SnmpValue::TimeTicks(decode_unsigned(body) as u32),
        tag::COUNTER64 => SnmpValue::Counter64(decode_unsigned(body)),
        tag::NO_SUCH_OBJECT => SnmpValue::NoSuchObject,
        tag::NO_SUCH_INSTANCE => SnmpValue::NoSuchInstance,
        tag::END_OF_MIB_VIEW => SnmpValue::EndOfMibView,
        // An unrecognised type is not a failure; report it as a string.
        _ => SnmpValue::String(format!("(unsupported type {value_tag:#04x})")),
    })
}

/// Decodes an unsigned application-class integer.
///
/// Unlike `INTEGER` these are unsigned, so a leading zero byte is padding
/// rather than a sign bit and must not be treated as significant.
fn decode_unsigned(body: &[u8]) -> u64 {
    let mut v: u64 = 0;
    for b in body.iter().take(8) {
        v = (v << 8) | *b as u64;
    }
    v
}

/// An SNMP v2c client.
pub struct SnmpClient {
    community: String,
    timeout: Duration,
    retries: u32,
}

impl SnmpClient {
    pub fn new(community: &str) -> Self {
        Self {
            community: community.to_string(),
            timeout: Duration::from_secs(2),
            retries: 1,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    /// Reads the given objects from an agent.
    pub fn get(&self, target: IpAddr, oids: &[&[u32]]) -> Result<Vec<VarBind>> {
        // A per-request identifier lets a late reply to a previous request be
        // recognised and discarded rather than attributed to this one.
        let request_id = (Instant::now().elapsed().subsec_nanos() as i64)
            ^ (std::process::id() as i64)
            ^ (target_seed(target));
        let request_id = request_id.abs() % 0x7fff_ffff;

        let payload = build_get_request(&self.community, request_id, oids)?;

        let socket = UdpSocket::bind(if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .map_err(|e| SnmpError::Io(e.to_string()))?;
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| SnmpError::Io(e.to_string()))?;

        let dest = SocketAddr::new(target, SNMP_PORT);
        let mut buf = vec![0u8; 65535];

        for _ in 0..=self.retries {
            if socket.send_to(&payload, dest).is_err() {
                continue;
            }
            let deadline = Instant::now() + self.timeout;
            while Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                socket.set_read_timeout(Some(remaining)).ok();
                match socket.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        if from.ip() != target {
                            continue;
                        }
                        match parse_response(&buf[..n]) {
                            Ok(r) if r.request_id == request_id => return Ok(r.bindings),
                            // A stale reply to an earlier request: keep waiting.
                            Ok(_) => continue,
                            Err(e) => return Err(e),
                        }
                    }
                    Err(_) => break,
                }
            }
        }
        Err(SnmpError::Timeout)
    }

    /// Reads the standard system group.
    pub fn system_info(&self, target: IpAddr) -> Result<SystemInfo> {
        let bindings = self.get(
            target,
            &[
                oids::SYS_DESCR,
                oids::SYS_OBJECT_ID,
                oids::SYS_UPTIME,
                oids::SYS_CONTACT,
                oids::SYS_NAME,
                oids::SYS_LOCATION,
            ],
        )?;

        let find = |oid: &[u32]| -> Option<&SnmpValue> {
            let want = ber::oid_to_string(oid);
            bindings
                .iter()
                .find(|b| b.oid == want)
                .map(|b| &b.value)
                .filter(|v| !v.is_absent())
        };

        Ok(SystemInfo {
            descr: find(oids::SYS_DESCR).and_then(|v| v.as_str().map(str::to_string)),
            object_id: find(oids::SYS_OBJECT_ID).map(|v| v.to_display_string()),
            uptime: find(oids::SYS_UPTIME).map(|v| v.to_display_string()),
            contact: find(oids::SYS_CONTACT).and_then(|v| v.as_str().map(str::to_string)),
            name: find(oids::SYS_NAME).and_then(|v| v.as_str().map(str::to_string)),
            location: find(oids::SYS_LOCATION).and_then(|v| v.as_str().map(str::to_string)),
        })
    }
}

fn target_seed(target: IpAddr) -> i64 {
    match target {
        IpAddr::V4(a) => u32::from(a) as i64,
        IpAddr::V6(a) => (u128::from(a) & 0xffff_ffff) as i64,
    }
}

/// The system group of an SNMP agent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

impl SystemInfo {
    pub fn is_empty(&self) -> bool {
        self.descr.is_none() && self.name.is_none() && self.object_id.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- request construction ----------------------------------------------

    #[test]
    fn a_get_request_has_the_documented_structure() {
        let req = build_get_request("public", 0x1234, &[oids::SYS_DESCR]).unwrap();

        let msg = ber::expect_element(&req, 0, tag::SEQUENCE).unwrap();
        let version = ber::expect_element(msg.body, 0, tag::INTEGER).unwrap();
        assert_eq!(ber::decode_integer(version.body).unwrap(), VERSION_2C);

        let community = ber::expect_element(msg.body, version.next, tag::OCTET_STRING).unwrap();
        assert_eq!(community.body, b"public");

        let pdu = ber::read_element(msg.body, community.next).unwrap();
        assert_eq!(pdu.tag, tag::GET_REQUEST);

        let id = ber::expect_element(pdu.body, 0, tag::INTEGER).unwrap();
        assert_eq!(ber::decode_integer(id.body).unwrap(), 0x1234);
    }

    #[test]
    fn get_next_uses_a_different_pdu_tag() {
        let get = build_get_request("public", 1, &[oids::SYS_DESCR]).unwrap();
        let next = build_get_next_request("public", 1, &[oids::SYS_DESCR]).unwrap();
        assert_ne!(get, next);

        let msg = ber::expect_element(&next, 0, tag::SEQUENCE).unwrap();
        let v = ber::read_element(msg.body, 0).unwrap();
        let c = ber::read_element(msg.body, v.next).unwrap();
        assert_eq!(ber::read_element(msg.body, c.next).unwrap().tag, tag::GET_NEXT_REQUEST);
    }

    #[test]
    fn multiple_oids_produce_multiple_bindings() {
        let req = build_get_request("public", 1, &[oids::SYS_DESCR, oids::SYS_NAME]).unwrap();
        let msg = ber::expect_element(&req, 0, tag::SEQUENCE).unwrap();
        let v = ber::read_element(msg.body, 0).unwrap();
        let c = ber::read_element(msg.body, v.next).unwrap();
        let pdu = ber::read_element(msg.body, c.next).unwrap();

        let id = ber::read_element(pdu.body, 0).unwrap();
        let st = ber::read_element(pdu.body, id.next).unwrap();
        let ix = ber::read_element(pdu.body, st.next).unwrap();
        let list = ber::expect_element(pdu.body, ix.next, tag::SEQUENCE).unwrap();

        let mut count = 0;
        let mut off = 0;
        while off < list.body.len() {
            let b = ber::expect_element(list.body, off, tag::SEQUENCE).unwrap();
            off = b.next;
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn a_long_community_string_encodes_correctly() {
        // Crosses the BER short/long length boundary.
        let community = "c".repeat(200);
        let req = build_get_request(&community, 1, &[oids::SYS_DESCR]).unwrap();
        let msg = ber::expect_element(&req, 0, tag::SEQUENCE).unwrap();
        let v = ber::read_element(msg.body, 0).unwrap();
        let c = ber::expect_element(msg.body, v.next, tag::OCTET_STRING).unwrap();
        assert_eq!(c.body.len(), 200);
    }

    // ---- response parsing --------------------------------------------------

    /// Builds a GetResponse carrying the given bindings.
    fn response(request_id: i64, error_status: i64, bindings: &[(&[u32], u8, Vec<u8>)]) -> Vec<u8> {
        let mut binding_bytes = Vec::new();
        for (oid, value_tag, value) in bindings {
            let mut one = Vec::new();
            ber::encode_oid(oid, &mut one).unwrap();
            ber::encode_tlv(*value_tag, value, &mut one);
            ber::encode_tlv(tag::SEQUENCE, &one, &mut binding_bytes);
        }
        let mut list = Vec::new();
        ber::encode_tlv(tag::SEQUENCE, &binding_bytes, &mut list);

        let mut pdu = Vec::new();
        ber::encode_integer(request_id, &mut pdu);
        ber::encode_integer(error_status, &mut pdu);
        ber::encode_integer(0, &mut pdu);
        pdu.extend_from_slice(&list);

        let mut wrapped = Vec::new();
        ber::encode_tlv(tag::GET_RESPONSE, &pdu, &mut wrapped);

        let mut message = Vec::new();
        ber::encode_integer(VERSION_2C, &mut message);
        ber::encode_tlv(tag::OCTET_STRING, b"public", &mut message);
        message.extend_from_slice(&wrapped);

        let mut out = Vec::new();
        ber::encode_tlv(tag::SEQUENCE, &message, &mut out);
        out
    }

    #[test]
    fn parses_a_realistic_switch_response() {
        let descr = b"Acme Networks GS724T, Firmware 6.3.1.18, Boot 1.0.0.9".to_vec();
        let buf = response(
            0x1234,
            0,
            &[
                (oids::SYS_DESCR, tag::OCTET_STRING, descr.clone()),
                (oids::SYS_NAME, tag::OCTET_STRING, b"core-sw-01".to_vec()),
                (oids::SYS_UPTIME, tag::TIMETICKS, 123_456_789u32.to_be_bytes().to_vec()),
            ],
        );

        let r = parse_response(&buf).unwrap();
        assert_eq!(r.request_id, 0x1234);
        assert_eq!(r.bindings.len(), 3);
        assert_eq!(
            r.bindings[0].value.as_str().unwrap(),
            "Acme Networks GS724T, Firmware 6.3.1.18, Boot 1.0.0.9"
        );
        assert_eq!(r.bindings[0].oid, "1.3.6.1.2.1.1.1.0");
        assert_eq!(r.bindings[1].value.as_str().unwrap(), "core-sw-01");
        assert_eq!(r.bindings[2].value, SnmpValue::TimeTicks(123_456_789));
    }

    #[test]
    fn a_description_longer_than_127_bytes_parses() {
        // The BER long-form length boundary, which most real devices cross.
        let descr = vec![b'A'; 400];
        let buf = response(1, 0, &[(oids::SYS_DESCR, tag::OCTET_STRING, descr)]);
        let r = parse_response(&buf).unwrap();
        assert_eq!(r.bindings[0].value.as_str().unwrap().len(), 400);
    }

    #[test]
    fn agent_errors_are_surfaced() {
        // Error status 2 is noSuchName.
        let buf = response(1, 2, &[(oids::SYS_DESCR, tag::NULL, vec![])]);
        assert!(matches!(
            parse_response(&buf),
            Err(SnmpError::AgentError { status: 2, .. })
        ));
    }

    #[test]
    fn absent_objects_are_reported_as_absence_not_failure() {
        // A device that does not implement part of the MIB says so per binding.
        let buf = response(
            1,
            0,
            &[
                (oids::SYS_DESCR, tag::OCTET_STRING, b"x".to_vec()),
                (oids::SYS_LOCATION, tag::NO_SUCH_OBJECT, vec![]),
                (oids::SYS_CONTACT, tag::NO_SUCH_INSTANCE, vec![]),
            ],
        );
        let r = parse_response(&buf).unwrap();
        assert_eq!(r.bindings[1].value, SnmpValue::NoSuchObject);
        assert!(r.bindings[1].value.is_absent());
        assert!(r.bindings[2].value.is_absent());
        assert!(!r.bindings[0].value.is_absent());
    }

    #[test]
    fn decodes_every_supported_value_type() {
        let buf = response(
            1,
            0,
            &[
                (&[1, 3, 6, 1, 2, 1, 1, 7, 0], tag::INTEGER, vec![0x4e]),
                (&[1, 3, 6, 1, 2, 1, 2, 1, 0], tag::COUNTER32, 4_000_000_000u32.to_be_bytes().to_vec()),
                (&[1, 3, 6, 1, 2, 1, 2, 2, 0], tag::GAUGE32, 100u32.to_be_bytes().to_vec()),
                (&[1, 3, 6, 1, 2, 1, 4, 20, 0], tag::IP_ADDRESS, vec![192, 168, 1, 1]),
                (&[1, 3, 6, 1, 2, 1, 4, 21, 0], tag::COUNTER64, 1_234_567_890_123u64.to_be_bytes().to_vec()),
            ],
        );
        let r = parse_response(&buf).unwrap();
        assert_eq!(r.bindings[0].value, SnmpValue::Integer(78));
        assert_eq!(r.bindings[1].value, SnmpValue::Counter32(4_000_000_000));
        assert_eq!(r.bindings[2].value, SnmpValue::Gauge32(100));
        assert_eq!(
            r.bindings[3].value,
            SnmpValue::IpAddress("192.168.1.1".parse().unwrap())
        );
        assert_eq!(r.bindings[4].value, SnmpValue::Counter64(1_234_567_890_123));
    }

    #[test]
    fn large_unsigned_counters_are_not_read_as_negative() {
        // Counter32 is unsigned; a signed read turns 4 billion into a negative
        // number, which is how interface counters end up nonsensical.
        let buf = response(
            1,
            0,
            &[(oids::IF_NUMBER, tag::COUNTER32, 0xffff_ffffu32.to_be_bytes().to_vec())],
        );
        let r = parse_response(&buf).unwrap();
        assert_eq!(r.bindings[0].value, SnmpValue::Counter32(u32::MAX));
    }

    #[test]
    fn invalid_utf8_in_device_strings_does_not_fail_parsing() {
        let buf = response(
            1,
            0,
            &[(oids::SYS_DESCR, tag::OCTET_STRING, vec![0x41, 0xff, 0xfe, 0x42])],
        );
        let r = parse_response(&buf).unwrap();
        assert!(r.bindings[0].value.as_str().unwrap().starts_with('A'));
    }

    #[test]
    fn trailing_nul_padding_is_trimmed_from_strings() {
        let buf = response(
            1,
            0,
            &[(oids::SYS_NAME, tag::OCTET_STRING, b"switch\0\0\0".to_vec())],
        );
        assert_eq!(parse_response(&buf).unwrap().bindings[0].value.as_str().unwrap(), "switch");
    }

    #[test]
    fn an_unknown_value_type_is_reported_rather_than_failing() {
        let buf = response(1, 0, &[(oids::SYS_DESCR, 0x7f, vec![1, 2, 3])]);
        let r = parse_response(&buf).unwrap();
        assert!(r.bindings[0].value.to_display_string().contains("unsupported"));
    }

    #[test]
    fn a_request_pdu_is_not_accepted_as_a_response() {
        let req = build_get_request("public", 1, &[oids::SYS_DESCR]).unwrap();
        assert!(parse_response(&req).is_err());
    }

    #[test]
    fn malformed_responses_are_rejected_without_panicking() {
        assert!(parse_response(&[]).is_err());
        assert!(parse_response(&[0x30]).is_err());
        assert!(parse_response(&[0x30, 0x05, 0x02, 0x01, 0x01]).is_err());
    }

    #[test]
    fn arbitrary_byte_soup_never_panics() {
        let mut seed = 0x51ffu32;
        for _ in 0..3000 {
            let len = (seed % 96) as usize;
            let mut buf: Vec<u8> = (0..len)
                .map(|i| {
                    seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                    (seed >> ((i % 4) * 8)) as u8
                })
                .collect();
            // Bias towards reaching the parsing body.
            if !buf.is_empty() {
                buf[0] = 0x30;
            }
            let _ = parse_response(&buf);
        }
    }

    // ---- rendering ---------------------------------------------------------

    #[test]
    fn timeticks_render_as_a_readable_uptime() {
        // TimeTicks are hundredths of a second.
        assert_eq!(format_timeticks(0), "0m 0s");
        assert_eq!(format_timeticks(6_000), "1m 0s");
        assert_eq!(format_timeticks(360_000), "1h 0m 0s");
        assert_eq!(format_timeticks(8_640_000), "1d 0h 0m 0s");
        assert_eq!(format_timeticks(123_456_789), "14d 6h 56m 7s");
    }

    #[test]
    fn system_info_omits_objects_the_device_does_not_implement() {
        let info = SystemInfo {
            descr: Some("Router".into()),
            ..Default::default()
        };
        let j = serde_json::to_value(&info).unwrap();
        assert!(j.get("descr").is_some());
        assert!(j.get("location").is_none());
        assert!(!info.is_empty());
        assert!(SystemInfo::default().is_empty());
    }

    #[test]
    fn values_round_trip_through_json() {
        for v in [
            SnmpValue::Integer(-5),
            SnmpValue::String("x".into()),
            SnmpValue::Counter64(u64::MAX),
            SnmpValue::NoSuchObject,
            SnmpValue::IpAddress("10.0.0.1".parse().unwrap()),
        ] {
            let j = serde_json::to_string(&v).unwrap();
            assert_eq!(serde_json::from_str::<SnmpValue>(&j).unwrap(), v);
        }
    }

    // ---- client behaviour --------------------------------------------------

    #[test]
    fn a_get_against_a_dead_address_times_out_rather_than_hanging() {
        let client = SnmpClient::new("public")
            .with_timeout(Duration::from_millis(200))
            .with_retries(0);
        let start = Instant::now();
        let err = client
            .get("203.0.113.199".parse().unwrap(), &[oids::SYS_DESCR])
            .unwrap_err();
        assert!(matches!(err, SnmpError::Timeout));
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "timeout was not honoured"
        );
    }
}
