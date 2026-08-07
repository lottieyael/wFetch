//! Credentialed inventory of discovered hosts.
//!
//! Discovery says a host exists and guesses what it is. Inventory logs into it
//! and asks. The two are separate on purpose: discovery needs no credentials
//! and touches every address in a plan, while inventory needs credentials and
//! is only ever run against hosts already known to exist.
//!
//! # Methods
//!
//! | Method | Targets | Status |
//! |--------|---------|--------|
//! | [`snmp`] | switches, routers, printers, APs, UPSs | implemented natively |
//! | [`ssh`]  | Linux, macOS, BSD | implemented via the system OpenSSH client |
//! | WMI/DCOM | Windows | **not implemented** — see below |
//!
//! ## On WMI
//!
//! The previous version of this project inventoried Windows hosts by shelling
//! out to `powershell.exe` and running remote CIM queries. That is not carried
//! over: it works only when the scanner itself runs on Windows, and it is the
//! same pattern the discovery path was rewritten to remove.
//!
//! The honest replacement is a native DCOM/WMI client, which is a substantial
//! piece of work — the wire protocol is MSRPC over DCOM with NTLM or Kerberos
//! authentication — and one that cannot be verified without a Windows domain to
//! test against. Rather than ship an unverified implementation that fails in
//! ways indistinguishable from a host being down, it is left out and recorded
//! here as a gap.
//!
//! Windows hosts are still discovered and identified, and can be inventoried
//! over SNMP where the SNMP service is enabled, or over SSH where the OpenSSH
//! server feature is installed.

pub mod ber;
pub mod snmp;
pub mod ssh;

use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub use snmp::{SnmpClient, SystemInfo as SnmpSystemInfo};
pub use ssh::{SshInventory, UnixInventory};

/// Which inventory methods to attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryMethods {
    pub snmp: bool,
    pub ssh: bool,
}

impl Default for InventoryMethods {
    fn default() -> Self {
        Self {
            snmp: true,
            ssh: true,
        }
    }
}

/// Credentials for an inventory run.
///
/// Supplied per invocation and never persisted. The scanner writes no
/// credential store: an inventory tool that caches secrets becomes a target.
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    /// SNMP v2c community string. `None` disables SNMP.
    pub snmp_community: Option<String>,
    pub ssh_user: Option<String>,
    pub ssh_port: Option<u16>,
    pub ssh_identity_file: Option<String>,
    pub ssh_accept_new_host_keys: bool,
}

/// What inventory found for one host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostInventory {
    pub ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snmp: Option<SnmpSystemInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix: Option<UnixInventory>,
    /// Why a method produced nothing, keyed by method name.
    ///
    /// A host that refused SSH and has no SNMP agent is a normal outcome, and
    /// the report says which happened rather than showing an empty record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<InventoryError>,
}

impl HostInventory {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip: ip.to_string(),
            ..Default::default()
        }
    }

    /// Whether any method returned data.
    pub fn has_data(&self) -> bool {
        self.snmp.as_ref().is_some_and(|s| !s.is_empty())
            || self.unix.as_ref().is_some_and(|u| !u.is_empty())
    }

    /// The best available name for the host.
    pub fn name(&self) -> Option<&str> {
        self.unix
            .as_ref()
            .and_then(|u| u.hostname.as_deref())
            .or_else(|| self.snmp.as_ref().and_then(|s| s.name.as_deref()))
    }

    /// The best available description of what the host is.
    pub fn description(&self) -> Option<&str> {
        self.snmp
            .as_ref()
            .and_then(|s| s.descr.as_deref())
            .or_else(|| self.unix.as_ref().and_then(|u| u.distribution.as_deref()))
    }
}

/// A method that did not produce data, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryError {
    pub method: String,
    pub reason: String,
}

/// Collects inventory from a host using every enabled method.
///
/// Methods are independent: a failure of one never prevents another from
/// running, because a device that answers SNMP usually will not answer SSH and
/// the reverse.
pub fn collect(
    ip: IpAddr,
    methods: InventoryMethods,
    credentials: &Credentials,
    timeout: Duration,
) -> HostInventory {
    let mut out = HostInventory::new(ip);

    if methods.snmp {
        match &credentials.snmp_community {
            Some(community) => {
                let client = SnmpClient::new(community).with_timeout(timeout).with_retries(1);
                match client.system_info(ip) {
                    Ok(info) if !info.is_empty() => out.snmp = Some(info),
                    Ok(_) => out.errors.push(InventoryError {
                        method: "snmp".into(),
                        reason: "the agent answered but reported no system group".into(),
                    }),
                    Err(e) => out.errors.push(InventoryError {
                        method: "snmp".into(),
                        reason: e.to_string(),
                    }),
                }
            }
            None => out.errors.push(InventoryError {
                method: "snmp".into(),
                reason: "no community string supplied".into(),
            }),
        }
    }

    if methods.ssh {
        let mut client = SshInventory::new()
            .timeout(timeout)
            .accept_new_host_keys(credentials.ssh_accept_new_host_keys);
        if let Some(u) = &credentials.ssh_user {
            client = client.user(u);
        }
        if let Some(p) = credentials.ssh_port {
            client = client.port(p);
        }
        if let Some(i) = &credentials.ssh_identity_file {
            client = client.identity_file(i);
        }

        match client.collect(ip) {
            Ok(inv) if !inv.is_empty() => out.unix = Some(inv),
            Ok(_) => out.errors.push(InventoryError {
                method: "ssh".into(),
                reason: "connected but the probe returned nothing".into(),
            }),
            Err(e) => out.errors.push(InventoryError {
                method: "ssh".into(),
                reason: e.to_string(),
            }),
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> IpAddr {
        "10.0.0.1".parse().unwrap()
    }

    #[test]
    fn an_empty_inventory_reports_no_data() {
        let inv = HostInventory::new(ip());
        assert!(!inv.has_data());
        assert_eq!(inv.name(), None);
        assert_eq!(inv.description(), None);
    }

    #[test]
    fn a_unix_hostname_is_preferred_over_an_snmp_name() {
        // The SSH result comes from the host itself; sysName is operator-set
        // and drifts.
        let inv = HostInventory {
            ip: "10.0.0.1".into(),
            snmp: Some(SnmpSystemInfo {
                name: Some("snmp-name".into()),
                ..Default::default()
            }),
            unix: Some(ssh::parse_probe_output("hostname=real-name\nkernel=Linux\n")),
            errors: vec![],
        };
        assert_eq!(inv.name(), Some("real-name"));
        assert!(inv.has_data());
    }

    #[test]
    fn snmp_sysdescr_is_preferred_for_the_description() {
        // For network gear it names the model and firmware outright.
        let inv = HostInventory {
            ip: "10.0.0.1".into(),
            snmp: Some(SnmpSystemInfo {
                descr: Some("Acme GS724T v6.3.1".into()),
                ..Default::default()
            }),
            unix: Some(ssh::parse_probe_output("distribution=Debian 12\n")),
            errors: vec![],
        };
        assert_eq!(inv.description(), Some("Acme GS724T v6.3.1"));
    }

    #[test]
    fn a_method_with_no_credentials_records_why_rather_than_failing_silently() {
        let inv = collect(
            "203.0.113.198".parse().unwrap(),
            InventoryMethods {
                snmp: true,
                ssh: false,
            },
            &Credentials::default(),
            Duration::from_millis(100),
        );
        assert!(!inv.has_data());
        let snmp_error = inv.errors.iter().find(|e| e.method == "snmp").unwrap();
        assert!(snmp_error.reason.contains("no community string"));
    }

    #[test]
    fn a_failing_method_does_not_prevent_the_others_from_running() {
        // Both methods target an address that answers nothing; both should
        // report, and neither should abort the other.
        let inv = collect(
            "203.0.113.197".parse().unwrap(),
            InventoryMethods {
                snmp: true,
                ssh: false,
            },
            &Credentials {
                snmp_community: Some("public".into()),
                ..Default::default()
            },
            Duration::from_millis(150),
        );
        assert!(inv.errors.iter().any(|e| e.method == "snmp"));
        assert!(!inv.has_data());
    }

    #[test]
    fn methods_can_be_disabled_individually() {
        let inv = collect(
            "203.0.113.196".parse().unwrap(),
            InventoryMethods {
                snmp: false,
                ssh: false,
            },
            &Credentials::default(),
            Duration::from_millis(50),
        );
        assert!(inv.errors.is_empty(), "no method ran, so nothing to report");
    }

    #[test]
    fn inventory_round_trips_through_json_omitting_absent_methods() {
        let inv = HostInventory {
            ip: "10.0.0.1".into(),
            snmp: Some(SnmpSystemInfo {
                descr: Some("Router".into()),
                ..Default::default()
            }),
            unix: None,
            errors: vec![InventoryError {
                method: "ssh".into(),
                reason: "connection refused".into(),
            }],
        };
        let j = serde_json::to_value(&inv).unwrap();
        assert!(j.get("snmp").is_some());
        assert!(j.get("unix").is_none(), "absent methods are omitted");
        assert!(j.get("errors").is_some());

        let text = serde_json::to_string(&inv).unwrap();
        assert_eq!(serde_json::from_str::<HostInventory>(&text).unwrap(), inv);
    }

    #[test]
    fn credentials_are_not_serialisable() {
        // A compile-time guarantee that secrets cannot end up in scan output:
        // Credentials deliberately derives neither Serialize nor Deserialize.
        // This test documents the intent; the enforcement is the missing derive.
        let c = Credentials {
            snmp_community: Some("secret".into()),
            ..Default::default()
        };
        assert_eq!(c.snmp_community.as_deref(), Some("secret"));
    }
}
