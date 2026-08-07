//! Inventory of Unix-like hosts over SSH.
//!
//! # Why the system client
//!
//! This drives the host's own OpenSSH client rather than embedding an SSH
//! implementation. That is a deliberate trade, and it is not the same mistake
//! as the PowerShell shelling this project replaced:
//!
//! * The command is built as an argument vector and never as a shell string, so
//!   no value is interpolated into anything a shell parses.
//! * `ssh` has a stable, standardised command line, unlike a PowerShell script
//!   whose behaviour depends on execution policy and module availability.
//! * It is present on Linux, macOS, the BSDs and Windows 10 and later.
//! * Most importantly, it honours the operator's existing configuration:
//!   `~/.ssh/config`, agent forwarding, jump hosts, per-host keys and
//!   `known_hosts`. An embedded client would need all of that reimplemented,
//!   and would get host-key verification wrong in the meantime.
//!
//! The cost is a process spawn per host and a dependency on `ssh` being
//! installed, which [`SshInventory::is_available`] reports rather than
//! discovering at the first failure.
//!
//! # Host key verification
//!
//! Verification is left on. An inventory tool that disables host-key checking
//! to be convenient is a tool that will happily inventory a machine-in-the-
//! middle. Unknown hosts are reported as an error naming the cause, so the
//! operator can decide.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SshError {
    #[error("the ssh client is not installed or not on PATH")]
    ClientMissing,
    #[error("connection to {host} failed: {detail}")]
    ConnectionFailed { host: String, detail: String },
    #[error("authentication to {host} failed")]
    AuthFailed { host: String },
    #[error("the host key for {host} is unknown or has changed")]
    HostKeyUnverified { host: String },
    #[error("the command timed out after {0:?}")]
    Timeout(Duration),
    #[error("failed to run ssh: {0}")]
    Spawn(String),
}

pub type Result<T> = std::result::Result<T, SshError>;

/// What an SSH inventory collected from a host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnixInventory {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// `uname -s`: Linux, Darwin, FreeBSD and so on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    /// `PRETTY_NAME` from `/etc/os-release`, where present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distribution: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_total_kb: Option<u64>,
    /// Anything else the probe script reported, unparsed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, String>,
}

impl UnixInventory {
    pub fn is_empty(&self) -> bool {
        self.hostname.is_none() && self.kernel.is_none() && self.distribution.is_none()
    }
}

/// Collects inventory over SSH.
pub struct SshInventory {
    user: Option<String>,
    port: u16,
    timeout: Duration,
    identity_file: Option<String>,
    /// Whether to accept unknown host keys on first connection.
    accept_new_host_keys: bool,
}

impl Default for SshInventory {
    fn default() -> Self {
        Self {
            user: None,
            port: 22,
            timeout: Duration::from_secs(10),
            identity_file: None,
            accept_new_host_keys: false,
        }
    }
}

impl SshInventory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn user(mut self, user: &str) -> Self {
        self.user = Some(user.to_string());
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn identity_file(mut self, path: &str) -> Self {
        self.identity_file = Some(path.to_string());
        self
    }

    /// Accepts and records host keys not yet in `known_hosts`.
    ///
    /// This uses `StrictHostKeyChecking=accept-new`, which still refuses a key
    /// that has *changed* — the case that actually indicates interception.
    /// Verification is never disabled outright.
    pub fn accept_new_host_keys(mut self, accept: bool) -> Self {
        self.accept_new_host_keys = accept;
        self
    }

    /// Whether an `ssh` client is available.
    pub fn is_available() -> bool {
        Command::new("ssh")
            .arg("-V")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Builds the argument vector for a connection.
    ///
    /// Kept separate from execution so the arguments are testable without a
    /// network, and so it is visible that nothing is ever passed through a
    /// shell on the local side.
    pub fn build_args(&self, host: &str, remote_command: &str) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "-o".into(),
            "BatchMode=yes".into(), // never prompt for a password
            "-o".into(),
            format!("ConnectTimeout={}", self.timeout.as_secs().max(1)),
            "-o".into(),
            format!(
                "StrictHostKeyChecking={}",
                if self.accept_new_host_keys {
                    "accept-new"
                } else {
                    "yes"
                }
            ),
            "-o".into(),
            // Inventory is read-only; nothing needs a tty or an agent forwarded.
            "ForwardAgent=no".into(),
            "-o".into(),
            "ForwardX11=no".into(),
            "-p".into(),
            self.port.to_string(),
        ];

        if let Some(id) = &self.identity_file {
            args.push("-i".into());
            args.push(id.clone());
            // With an explicit key, do not fall back to every agent identity.
            args.push("-o".into());
            args.push("IdentitiesOnly=yes".into());
        }

        args.push(match &self.user {
            Some(u) => format!("{u}@{host}"),
            None => host.to_string(),
        });
        args.push(remote_command.to_string());
        args
    }

    /// Collects inventory from a host.
    pub fn collect(&self, host: IpAddr) -> Result<UnixInventory> {
        if !Self::is_available() {
            return Err(SshError::ClientMissing);
        }
        let output = self.run(&host.to_string(), PROBE_SCRIPT)?;
        Ok(parse_probe_output(&output))
    }

    fn run(&self, host: &str, remote_command: &str) -> Result<String> {
        let args = self.build_args(host, remote_command);

        // Arguments are passed as a vector; no local shell is involved.
        let output = Command::new("ssh")
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    SshError::ClientMissing
                } else {
                    SshError::Spawn(e.to_string())
                }
            })?;

        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(classify_failure(host, &stderr))
    }
}

/// Maps ssh's diagnostics onto a specific error.
///
/// The distinction matters operationally: a refused connection means scan the
/// host differently, a failed key means fix credentials, and a changed host key
/// means stop and investigate.
fn classify_failure(host: &str, stderr: &str) -> SshError {
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("host key verification failed")
        || lower.contains("remote host identification has changed")
        || lower.contains("no matching host key")
    {
        return SshError::HostKeyUnverified {
            host: host.to_string(),
        };
    }
    if lower.contains("permission denied")
        || lower.contains("authentication failed")
        || lower.contains("no supported authentication methods")
    {
        return SshError::AuthFailed {
            host: host.to_string(),
        };
    }
    SshError::ConnectionFailed {
        host: host.to_string(),
        detail: stderr.trim().lines().next().unwrap_or("unknown").to_string(),
    }
}

/// The remote probe.
///
/// Emits `key=value` lines, tolerating absent tools: a minimal container may
/// have no `/etc/os-release` and a BSD has no `/proc`. Every lookup is guarded
/// so a missing file yields a missing key rather than a failed inventory.
const PROBE_SCRIPT: &str = r#"
hostname 2>/dev/null | sed 's/^/hostname=/'
uname -s 2>/dev/null | sed 's/^/kernel=/'
uname -r 2>/dev/null | sed 's/^/kernel_version=/'
uname -m 2>/dev/null | sed 's/^/architecture=/'
if [ -r /etc/os-release ]; then
  . /etc/os-release 2>/dev/null
  echo "distribution=${PRETTY_NAME:-$NAME}"
fi
uptime 2>/dev/null | sed 's/^/uptime=/'
if [ -r /proc/cpuinfo ]; then
  grep -m1 '^model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//' | sed 's/^/cpu_model=/'
  grep -c '^processor' /proc/cpuinfo 2>/dev/null | sed 's/^/cpu_count=/'
fi
if [ -r /proc/meminfo ]; then
  grep -m1 '^MemTotal' /proc/meminfo 2>/dev/null | awk '{print "memory_total_kb=" $2}'
fi
"#;

/// Parses the `key=value` output of the probe script.
pub fn parse_probe_output(text: &str) -> UnixInventory {
    let mut inv = UnixInventory::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key {
            "hostname" => inv.hostname = Some(value.to_string()),
            "kernel" => inv.kernel = Some(value.to_string()),
            "kernel_version" => inv.kernel_version = Some(value.to_string()),
            "architecture" => inv.architecture = Some(value.to_string()),
            "distribution" => inv.distribution = Some(value.trim_matches('"').to_string()),
            "uptime" => inv.uptime = Some(value.to_string()),
            "cpu_model" => inv.cpu_model = Some(value.to_string()),
            "cpu_count" => inv.cpu_count = value.parse().ok(),
            "memory_total_kb" => inv.memory_total_kb = value.parse().ok(),
            other => {
                inv.extra.insert(other.to_string(), value.to_string());
            }
        }
    }
    inv
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- argument construction ---------------------------------------------

    #[test]
    fn arguments_never_prompt_interactively() {
        // A scan that blocks on a password prompt hangs the whole run.
        let args = SshInventory::new().build_args("10.0.0.1", "uname -a");
        assert!(args.iter().any(|a| a == "BatchMode=yes"));
    }

    #[test]
    fn host_key_checking_is_strict_by_default() {
        let args = SshInventory::new().build_args("10.0.0.1", "x");
        assert!(
            args.iter().any(|a| a == "StrictHostKeyChecking=yes"),
            "verification must not be disabled for convenience"
        );
        assert!(!args.iter().any(|a| a.contains("StrictHostKeyChecking=no")));
    }

    #[test]
    fn accepting_new_keys_still_refuses_changed_ones() {
        // accept-new records unknown keys but rejects a key that has changed,
        // which is the case that indicates interception.
        let args = SshInventory::new()
            .accept_new_host_keys(true)
            .build_args("10.0.0.1", "x");
        assert!(args.iter().any(|a| a == "StrictHostKeyChecking=accept-new"));
        assert!(!args.iter().any(|a| a == "StrictHostKeyChecking=no"));
    }

    #[test]
    fn agent_and_x11_forwarding_are_disabled() {
        // Inventory is read-only and should not expose the operator's agent to
        // every host it touches.
        let args = SshInventory::new().build_args("10.0.0.1", "x");
        assert!(args.iter().any(|a| a == "ForwardAgent=no"));
        assert!(args.iter().any(|a| a == "ForwardX11=no"));
    }

    #[test]
    fn user_and_port_are_applied() {
        let args = SshInventory::new()
            .user("admin")
            .port(2222)
            .build_args("10.0.0.1", "uname");
        assert!(args.contains(&"admin@10.0.0.1".to_string()));
        assert!(args.windows(2).any(|w| w[0] == "-p" && w[1] == "2222"));
    }

    #[test]
    fn without_a_user_the_target_is_the_bare_host() {
        let args = SshInventory::new().build_args("10.0.0.1", "uname");
        assert!(args.contains(&"10.0.0.1".to_string()));
        assert!(!args.iter().any(|a| a.contains('@')));
    }

    #[test]
    fn an_explicit_identity_file_disables_agent_fallback() {
        let args = SshInventory::new()
            .identity_file("/keys/id_ed25519")
            .build_args("10.0.0.1", "x");
        assert!(args.windows(2).any(|w| w[0] == "-i" && w[1] == "/keys/id_ed25519"));
        assert!(args.iter().any(|a| a == "IdentitiesOnly=yes"));
    }

    #[test]
    fn the_remote_command_is_the_final_argument() {
        // It is passed as one argv element, never concatenated into a local
        // shell string.
        let args = SshInventory::new().build_args("10.0.0.1", "uname -a; echo hi");
        assert_eq!(args.last().unwrap(), "uname -a; echo hi");
    }

    #[test]
    fn a_connect_timeout_is_always_set() {
        let args = SshInventory::new()
            .timeout(Duration::from_secs(5))
            .build_args("10.0.0.1", "x");
        assert!(args.iter().any(|a| a == "ConnectTimeout=5"));

        // Sub-second timeouts round up: ssh rejects a value of 0.
        let args = SshInventory::new()
            .timeout(Duration::from_millis(100))
            .build_args("10.0.0.1", "x");
        assert!(args.iter().any(|a| a == "ConnectTimeout=1"));
    }

    // ---- failure classification --------------------------------------------

    #[test]
    fn a_changed_host_key_is_distinguished_from_an_auth_failure() {
        // These need different operator responses: one is a credentials
        // problem, the other is a reason to stop and investigate.
        assert!(matches!(
            classify_failure("h", "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@"),
            SshError::HostKeyUnverified { .. }
        ));
        assert!(matches!(
            classify_failure("h", "Host key verification failed."),
            SshError::HostKeyUnverified { .. }
        ));
        assert!(matches!(
            classify_failure("h", "Permission denied (publickey)."),
            SshError::AuthFailed { .. }
        ));
    }

    #[test]
    fn other_failures_keep_their_first_diagnostic_line() {
        match classify_failure("h", "ssh: connect to host 10.0.0.1 port 22: Connection refused\nmore") {
            SshError::ConnectionFailed { detail, .. } => {
                assert!(detail.contains("Connection refused"));
                assert!(!detail.contains("more"), "only the first line is kept");
            }
            other => panic!("expected ConnectionFailed, got {other:?}"),
        }
    }

    #[test]
    fn classification_is_case_insensitive() {
        assert!(matches!(
            classify_failure("h", "permission denied (PUBLICKEY)"),
            SshError::AuthFailed { .. }
        ));
    }

    // ---- probe output parsing ----------------------------------------------

    #[test]
    fn parses_a_realistic_linux_probe_output() {
        let out = "hostname=web-01\n\
kernel=Linux\n\
kernel_version=6.1.0-18-amd64\n\
architecture=x86_64\n\
distribution=Debian GNU/Linux 12 (bookworm)\n\
uptime= 14:22:01 up 42 days,  3:11,  1 user,  load average: 0.15\n\
cpu_model=Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz\n\
cpu_count=8\n\
memory_total_kb=16316412\n";

        let inv = parse_probe_output(out);
        assert_eq!(inv.hostname.as_deref(), Some("web-01"));
        assert_eq!(inv.kernel.as_deref(), Some("Linux"));
        assert_eq!(inv.architecture.as_deref(), Some("x86_64"));
        assert_eq!(
            inv.distribution.as_deref(),
            Some("Debian GNU/Linux 12 (bookworm)")
        );
        assert_eq!(inv.cpu_count, Some(8));
        assert_eq!(inv.memory_total_kb, Some(16_316_412));
        assert!(!inv.is_empty());
    }

    #[test]
    fn a_bsd_or_macos_host_without_proc_still_parses() {
        // No /proc means no CPU or memory keys; that is a partial inventory,
        // not a failure.
        let out = "hostname=mac-mini\nkernel=Darwin\nkernel_version=23.4.0\narchitecture=arm64\n";
        let inv = parse_probe_output(out);
        assert_eq!(inv.kernel.as_deref(), Some("Darwin"));
        assert_eq!(inv.cpu_model, None);
        assert_eq!(inv.memory_total_kb, None);
        assert!(!inv.is_empty());
    }

    #[test]
    fn quoted_distribution_names_are_unquoted() {
        // PRETTY_NAME is quoted in /etc/os-release.
        let inv = parse_probe_output("distribution=\"Ubuntu 22.04.4 LTS\"\n");
        assert_eq!(inv.distribution.as_deref(), Some("Ubuntu 22.04.4 LTS"));
    }

    #[test]
    fn values_containing_equals_signs_are_kept_whole() {
        let inv = parse_probe_output("cpu_model=Intel(R) Xeon(R) CPU @ 2.30GHz rev=3\n");
        assert_eq!(
            inv.cpu_model.as_deref(),
            Some("Intel(R) Xeon(R) CPU @ 2.30GHz rev=3")
        );
    }

    #[test]
    fn unknown_keys_are_preserved_rather_than_dropped() {
        let inv = parse_probe_output("hostname=h\nsomething_new=42\n");
        assert_eq!(inv.extra.get("something_new").map(String::as_str), Some("42"));
    }

    #[test]
    fn empty_values_and_junk_lines_are_skipped() {
        let inv = parse_probe_output("hostname=\nkernel=Linux\nno-equals-sign\n\n=novalue\n");
        assert_eq!(inv.hostname, None);
        assert_eq!(inv.kernel.as_deref(), Some("Linux"));
    }

    #[test]
    fn unparseable_numbers_do_not_fail_the_inventory() {
        let inv = parse_probe_output("hostname=h\ncpu_count=many\nmemory_total_kb=lots\n");
        assert_eq!(inv.hostname.as_deref(), Some("h"));
        assert_eq!(inv.cpu_count, None);
        assert_eq!(inv.memory_total_kb, None);
    }

    #[test]
    fn empty_output_yields_an_empty_inventory() {
        assert!(parse_probe_output("").is_empty());
    }

    #[test]
    fn inventory_round_trips_through_json_omitting_absent_fields() {
        let inv = parse_probe_output("hostname=h\nkernel=Linux\n");
        let j = serde_json::to_value(&inv).unwrap();
        assert!(j.get("hostname").is_some());
        assert!(j.get("cpu_model").is_none());

        let text = serde_json::to_string(&inv).unwrap();
        assert_eq!(serde_json::from_str::<UnixInventory>(&text).unwrap(), inv);
    }

    #[test]
    fn the_probe_script_guards_every_platform_specific_path() {
        // A missing /proc or /etc/os-release must not abort the script.
        assert!(PROBE_SCRIPT.contains("[ -r /etc/os-release ]"));
        assert!(PROBE_SCRIPT.contains("[ -r /proc/cpuinfo ]"));
        assert!(PROBE_SCRIPT.contains("[ -r /proc/meminfo ]"));
    }
}
