//! Output rendering.
//!
//! Two audiences, two formats, one source of truth. The human format is a
//! table meant to be read at a glance; the JSON format is the serialised core
//! types, so an agent parsing the output sees exactly the structures the engine
//! produced with nothing reformatted on the way out.
//!
//! Diagnostics always go to stderr and data always to stdout, so
//! `wfetch scan -o json | jq` works without the progress notes corrupting the
//! stream.

use std::io::{self, Write};

use wfetch_core::fingerprint::{DeviceClass, OsFamily};
use wfetch_core::inventory::HostInventory;
use wfetch_core::platform::{Interface, NeighborEntry};
use wfetch_core::scan::result::{Confidence, Host, ScanReport};

/// How to render results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// Aligned table for reading.
    Human,
    /// One JSON document for the whole result.
    Json,
    /// One JSON object per line, for streaming into other tools.
    Ndjson,
}

/// Renders a scan report.
pub fn write_scan_report(w: &mut impl Write, report: &ScanReport, format: Format) -> io::Result<()> {
    match format {
        Format::Json => {
            serde_json::to_writer_pretty(&mut *w, report)?;
            writeln!(w)
        }
        Format::Ndjson => {
            // Only the hosts stream; the summary would break the one-object-
            // per-host contract that makes NDJSON useful.
            for host in &report.hosts {
                serde_json::to_writer(&mut *w, host)?;
                writeln!(w)?;
            }
            Ok(())
        }
        Format::Human => write_scan_table(w, report),
    }
}

fn write_scan_table(w: &mut impl Write, report: &ScanReport) -> io::Result<()> {
    if report.hosts.is_empty() {
        writeln!(
            w,
            "No hosts found ({} addresses probed in {:.1}s).",
            report.addresses_probed,
            report.duration().as_secs_f64()
        )?;
        return Ok(());
    }

    let rows: Vec<[String; 6]> = report
        .hosts
        .iter()
        .map(|h| {
            [
                h.ip.to_string(),
                h.mac.map(|m| m.to_string()).unwrap_or_else(|| "-".into()),
                truncate(h.hostname.as_deref().unwrap_or("-"), 24),
                describe_identity(h),
                format_ports(&h.open_ports),
                evidence_summary(h),
            ]
        })
        .collect();

    let headers = ["ADDRESS", "MAC", "HOSTNAME", "DEVICE", "PORTS", "EVIDENCE"];
    let widths = column_widths(&headers, &rows);

    writeln!(w, "{}", format_row(&headers.map(String::from), &widths))?;
    for row in &rows {
        writeln!(w, "{}", format_row(row, &widths))?;
    }

    writeln!(w)?;
    writeln!(
        w,
        "{} host{} found from {} address{} in {:.1}s.",
        report.hosts.len(),
        plural(report.hosts.len()),
        report.addresses_probed,
        if report.addresses_probed == 1 { "" } else { "es" },
        report.duration().as_secs_f64()
    )?;

    let low_confidence = report
        .hosts
        .iter()
        .filter(|h| h.confidence != Confidence::Confirmed)
        .count();
    if low_confidence > 0 {
        writeln!(
            w,
            "{low_confidence} rest on indirect evidence only; \
             re-run with --json to see what supports each."
        )?;
    }

    Ok(())
}

/// A short description of what a host was identified as.
fn describe_identity(host: &Host) -> String {
    let Some(id) = &host.identity else {
        return "-".into();
    };
    let mut parts: Vec<String> = Vec::new();

    if id.class != DeviceClass::Unknown {
        parts.push(class_label(id.class).to_string());
    }
    if id.os != OsFamily::Unknown {
        parts.push(os_label(id.os).to_string());
    }
    if let Some(v) = &id.vendor {
        parts.push(truncate(v, 18));
    }

    if parts.is_empty() {
        return "-".into();
    }
    let text = parts.join(" / ");
    // A low-confidence identification is marked rather than silently presented
    // as fact.
    if id.confidence < 50 {
        format!("{text}?")
    } else {
        text
    }
}

pub fn class_label(c: DeviceClass) -> &'static str {
    match c {
        DeviceClass::Router => "router",
        DeviceClass::Switch => "switch",
        DeviceClass::AccessPoint => "access point",
        DeviceClass::Printer => "printer",
        DeviceClass::Scanner => "scanner",
        DeviceClass::Computer => "computer",
        DeviceClass::Server => "server",
        DeviceClass::Nas => "NAS",
        DeviceClass::Phone => "phone",
        DeviceClass::Tablet => "tablet",
        DeviceClass::MediaDevice => "media",
        DeviceClass::GameConsole => "console",
        DeviceClass::Camera => "camera",
        DeviceClass::IotDevice => "IoT",
        DeviceClass::VirtualMachine => "VM",
        DeviceClass::SingleBoardComputer => "SBC",
        DeviceClass::Unknown => "unknown",
    }
}

pub fn os_label(o: OsFamily) -> &'static str {
    match o {
        OsFamily::Windows => "Windows",
        OsFamily::Linux => "Linux",
        OsFamily::MacOs => "macOS",
        OsFamily::Ios => "iOS",
        OsFamily::Android => "Android",
        OsFamily::Bsd => "BSD",
        OsFamily::NetworkOs => "network OS",
        OsFamily::Embedded => "embedded",
        OsFamily::Unknown => "unknown",
    }
}

fn format_ports(ports: &[u16]) -> String {
    if ports.is_empty() {
        return "-".into();
    }
    // Keep the column readable on hosts with many open ports.
    if ports.len() > 6 {
        let shown: Vec<String> = ports[..6].iter().map(u16::to_string).collect();
        format!("{} +{}", shown.join(","), ports.len() - 6)
    } else {
        ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn evidence_summary(host: &Host) -> String {
    let mut labels: Vec<&str> = host.evidence.iter().map(|e| e.label()).collect();
    labels.sort_unstable();
    labels.dedup();
    if labels.is_empty() {
        "-".into()
    } else {
        labels.join(",")
    }
}

/// Renders the local interface list.
pub fn write_interfaces(
    w: &mut impl Write,
    interfaces: &[Interface],
    format: Format,
) -> io::Result<()> {
    match format {
        Format::Json => {
            serde_json::to_writer_pretty(&mut *w, interfaces)?;
            writeln!(w)
        }
        Format::Ndjson => {
            for i in interfaces {
                serde_json::to_writer(&mut *w, i)?;
                writeln!(w)?;
            }
            Ok(())
        }
        Format::Human => {
            let rows: Vec<[String; 5]> = interfaces
                .iter()
                .map(|i| {
                    [
                        i.name.clone(),
                        i.index.to_string(),
                        i.mac.map(|m| m.to_string()).unwrap_or_else(|| "-".into()),
                        if i.addrs.is_empty() {
                            "-".into()
                        } else {
                            i.addrs
                                .iter()
                                .map(|a| format!("{}/{}", a.addr, a.prefix_len))
                                .collect::<Vec<_>>()
                                .join(", ")
                        },
                        interface_flags(i),
                    ]
                })
                .collect();
            let headers = ["NAME", "INDEX", "MAC", "ADDRESSES", "FLAGS"];
            let widths = column_widths(&headers, &rows);
            writeln!(w, "{}", format_row(&headers.map(String::from), &widths))?;
            for row in &rows {
                writeln!(w, "{}", format_row(row, &widths))?;
            }
            Ok(())
        }
    }
}

fn interface_flags(i: &Interface) -> String {
    let mut f = Vec::new();
    f.push(if i.is_up { "up" } else { "down" });
    if i.is_loopback {
        f.push("loopback");
    }
    if i.is_point_to_point {
        f.push("p2p");
    }
    if i.supports_multicast {
        f.push("multicast");
    }
    if i.is_scannable() {
        f.push("scannable");
    }
    f.join(",")
}

/// Renders the neighbour table.
pub fn write_neighbors(
    w: &mut impl Write,
    entries: &[NeighborEntry],
    format: Format,
) -> io::Result<()> {
    match format {
        Format::Json => {
            serde_json::to_writer_pretty(&mut *w, entries)?;
            writeln!(w)
        }
        Format::Ndjson => {
            for e in entries {
                serde_json::to_writer(&mut *w, e)?;
                writeln!(w)?;
            }
            Ok(())
        }
        Format::Human => {
            if entries.is_empty() {
                return writeln!(w, "The neighbour table is empty.");
            }
            let rows: Vec<[String; 4]> = entries
                .iter()
                .map(|e| {
                    [
                        e.ip.to_string(),
                        e.mac.map(|m| m.to_string()).unwrap_or_else(|| "-".into()),
                        format!("{:?}", e.state).to_lowercase(),
                        e.if_name.clone().unwrap_or_else(|| e.if_index.to_string()),
                    ]
                })
                .collect();
            let headers = ["ADDRESS", "MAC", "STATE", "INTERFACE"];
            let widths = column_widths(&headers, &rows);
            writeln!(w, "{}", format_row(&headers.map(String::from), &widths))?;
            for row in &rows {
                writeln!(w, "{}", format_row(row, &widths))?;
            }
            Ok(())
        }
    }
}

/// Renders inventory results.
pub fn write_inventory(
    w: &mut impl Write,
    results: &[HostInventory],
    format: Format,
) -> io::Result<()> {
    match format {
        Format::Json => {
            serde_json::to_writer_pretty(&mut *w, results)?;
            writeln!(w)
        }
        Format::Ndjson => {
            for r in results {
                serde_json::to_writer(&mut *w, r)?;
                writeln!(w)?;
            }
            Ok(())
        }
        Format::Human => {
            for r in results {
                writeln!(w, "{}", r.ip)?;
                if let Some(name) = r.name() {
                    writeln!(w, "  name:        {name}")?;
                }
                if let Some(d) = r.description() {
                    writeln!(w, "  description: {}", truncate(d, 100))?;
                }
                if let Some(s) = &r.snmp {
                    if let Some(u) = &s.uptime {
                        writeln!(w, "  uptime:      {u}")?;
                    }
                    if let Some(l) = &s.location {
                        writeln!(w, "  location:    {l}")?;
                    }
                }
                if let Some(u) = &r.unix {
                    if let (Some(k), Some(v)) = (&u.kernel, &u.kernel_version) {
                        writeln!(w, "  kernel:      {k} {v}")?;
                    }
                    if let Some(a) = &u.architecture {
                        writeln!(w, "  arch:        {a}")?;
                    }
                    if let Some(c) = &u.cpu_model {
                        let count = u.cpu_count.map(|n| format!(" x{n}")).unwrap_or_default();
                        writeln!(w, "  cpu:         {}{}", truncate(c, 60), count)?;
                    }
                    if let Some(m) = u.memory_total_kb {
                        writeln!(w, "  memory:      {:.1} GiB", m as f64 / 1024.0 / 1024.0)?;
                    }
                }
                for e in &r.errors {
                    writeln!(w, "  {} unavailable: {}", e.method, e.reason)?;
                }
                writeln!(w)?;
            }
            Ok(())
        }
    }
}

// ---- table helpers ---------------------------------------------------------

fn column_widths<const N: usize>(headers: &[&str; N], rows: &[[String; N]]) -> [usize; N] {
    let mut widths = [0usize; N];
    for (i, h) in headers.iter().enumerate() {
        widths[i] = h.chars().count();
    }
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    widths
}

fn format_row<const N: usize>(row: &[String; N], widths: &[usize; N]) -> String {
    let mut out = String::new();
    for (i, cell) in row.iter().enumerate() {
        if i > 0 {
            out.push_str("  ");
        }
        out.push_str(cell);
        // The final column is not padded, so lines have no trailing spaces.
        if i + 1 < N {
            let pad = widths[i].saturating_sub(cell.chars().count());
            out.extend(std::iter::repeat_n(' ', pad));
        }
    }
    out
}

/// Shortens a string to `max` characters, marking the cut with an ellipsis.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let kept: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::net::IpAddr;
    use wfetch_core::scan::result::Evidence;

    fn host(ip: &str) -> Host {
        Host::new(ip.parse::<IpAddr>().unwrap())
    }

    fn report(hosts: Vec<Host>) -> ScanReport {
        ScanReport {
            addresses_probed: 254,
            duration_micros: 1_500_000,
            techniques_used: vec!["tcp_connect".into()],
            techniques_skipped: BTreeMap::new(),
            hosts,
        }
    }

    fn render(report: &ScanReport, format: Format) -> String {
        let mut buf = Vec::new();
        write_scan_report(&mut buf, report, format).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn json_output_is_valid_and_contains_the_full_report() {
        let mut h = host("10.0.0.1");
        h.add_evidence(Evidence::TcpOpen {
            port: 22,
            rtt_micros: 900,
        });
        let out = render(&report(vec![h]), Format::Json);

        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["hosts"][0]["ip"], "10.0.0.1");
        assert_eq!(parsed["addresses_probed"], 254);
        assert!(parsed["techniques_used"].is_array());
    }

    #[test]
    fn ndjson_emits_exactly_one_parseable_object_per_host() {
        let out = render(
            &report(vec![host("10.0.0.1"), host("10.0.0.2"), host("10.0.0.3")]),
            Format::Ndjson,
        );
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(v["ip"].is_string());
        }
    }

    #[test]
    fn ndjson_of_an_empty_report_is_empty_not_a_blank_line() {
        assert_eq!(render(&report(vec![]), Format::Ndjson), "");
    }

    #[test]
    fn the_human_table_aligns_columns_and_has_no_trailing_whitespace() {
        let mut a = host("10.0.0.1");
        a.hostname = Some("a-very-long-hostname".into());
        a.add_evidence(Evidence::TcpOpen {
            port: 22,
            rtt_micros: 1,
        });
        let mut b = host("10.0.0.100");
        b.add_evidence(Evidence::Mdns);

        let out = render(&report(vec![a, b]), Format::Human);
        for line in out.lines() {
            assert_eq!(line, line.trim_end(), "line has trailing whitespace: {line:?}");
        }
        assert!(out.contains("ADDRESS"));
        assert!(out.contains("10.0.0.100"));
        assert!(out.contains("2 hosts found"));
    }

    #[test]
    fn an_empty_scan_says_so_plainly() {
        let out = render(&report(vec![]), Format::Human);
        assert!(out.contains("No hosts found"));
        assert!(out.contains("254 addresses probed"));
    }

    #[test]
    fn singular_and_plural_counts_read_correctly() {
        let mut r = report(vec![host("10.0.0.1")]);
        r.addresses_probed = 1;
        let out = render(&r, Format::Human);
        assert!(out.contains("1 host found from 1 address"), "got: {out}");
    }

    #[test]
    fn low_confidence_hosts_are_flagged_in_the_summary() {
        let mut h = host("10.0.0.1");
        h.add_evidence(Evidence::ReverseDns {
            name: "old".into(),
        });
        let out = render(&report(vec![h]), Format::Human);
        assert!(out.contains("indirect evidence"), "got: {out}");
    }

    #[test]
    fn a_confirmed_only_report_carries_no_confidence_warning() {
        let mut h = host("10.0.0.1");
        h.add_evidence(Evidence::TcpOpen {
            port: 22,
            rtt_micros: 1,
        });
        assert!(!render(&report(vec![h]), Format::Human).contains("indirect evidence"));
    }

    #[test]
    fn long_port_lists_are_summarised() {
        assert_eq!(format_ports(&[]), "-");
        assert_eq!(format_ports(&[22, 80]), "22,80");
        assert_eq!(
            format_ports(&[1, 2, 3, 4, 5, 6, 7, 8]),
            "1,2,3,4,5,6 +2",
            "the column must stay readable"
        );
    }

    #[test]
    fn evidence_labels_are_deduplicated_and_sorted() {
        let mut h = host("10.0.0.1");
        h.add_evidence(Evidence::TcpOpen {
            port: 22,
            rtt_micros: 1,
        });
        h.add_evidence(Evidence::TcpOpen {
            port: 80,
            rtt_micros: 1,
        });
        h.add_evidence(Evidence::Mdns);
        assert_eq!(evidence_summary(&h), "mdns,tcp");
    }

    #[test]
    fn truncation_marks_the_cut_and_counts_characters_not_bytes() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("exactly-10", 10), "exactly-10");
        assert_eq!(truncate("far-too-long-for-here", 10), "far-too-l…");
        // Multi-byte characters must not be split mid-sequence.
        assert_eq!(truncate("ünïcödé-string", 6), "ünïcö…");
    }

    #[test]
    fn an_unidentified_host_renders_a_placeholder_not_a_guess() {
        assert_eq!(describe_identity(&host("10.0.0.1")), "-");
    }

    #[test]
    fn a_low_confidence_identification_is_marked_with_a_question_mark() {
        let mut h = host("10.0.0.1");
        h.identity = Some(wfetch_core::fingerprint::DeviceIdentity {
            class: DeviceClass::Router,
            os: OsFamily::Unknown,
            vendor: None,
            model: None,
            confidence: 20,
            reasons: vec![],
        });
        assert!(describe_identity(&h).ends_with('?'));

        h.identity.as_mut().unwrap().confidence = 90;
        assert!(!describe_identity(&h).ends_with('?'));
    }

    #[test]
    fn every_device_class_and_os_family_has_a_label() {
        // A missing arm would render as an empty column.
        for c in [
            DeviceClass::Router, DeviceClass::Switch, DeviceClass::AccessPoint,
            DeviceClass::Printer, DeviceClass::Scanner, DeviceClass::Computer,
            DeviceClass::Server, DeviceClass::Nas, DeviceClass::Phone,
            DeviceClass::Tablet, DeviceClass::MediaDevice, DeviceClass::GameConsole,
            DeviceClass::Camera, DeviceClass::IotDevice, DeviceClass::VirtualMachine,
            DeviceClass::SingleBoardComputer, DeviceClass::Unknown,
        ] {
            assert!(!class_label(c).is_empty(), "{c:?}");
        }
        for o in [
            OsFamily::Windows, OsFamily::Linux, OsFamily::MacOs, OsFamily::Ios,
            OsFamily::Android, OsFamily::Bsd, OsFamily::NetworkOs,
            OsFamily::Embedded, OsFamily::Unknown,
        ] {
            assert!(!os_label(o).is_empty(), "{o:?}");
        }
    }

    #[test]
    fn interface_output_renders_in_every_format() {
        let interfaces = vec![Interface {
            name: "eth0".into(),
            index: 2,
            mac: Some("aa:bb:cc:dd:ee:ff".parse().unwrap()),
            addrs: vec![wfetch_core::platform::InterfaceAddr {
                addr: "10.0.0.5".parse().unwrap(),
                prefix_len: 24,
            }],
            is_up: true,
            is_loopback: false,
            is_point_to_point: false,
            supports_multicast: true,
        }];

        for format in [Format::Human, Format::Json, Format::Ndjson] {
            let mut buf = Vec::new();
            write_interfaces(&mut buf, &interfaces, format).unwrap();
            let out = String::from_utf8(buf).unwrap();
            assert!(out.contains("eth0"), "format {format:?}");
        }

        let mut buf = Vec::new();
        write_interfaces(&mut buf, &interfaces, Format::Human).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("10.0.0.5/24"));
        assert!(out.contains("scannable"));
    }

    #[test]
    fn an_empty_neighbour_table_says_so() {
        let mut buf = Vec::new();
        write_neighbors(&mut buf, &[], Format::Human).unwrap();
        assert!(String::from_utf8(buf).unwrap().contains("empty"));
    }

    #[test]
    fn inventory_output_reports_failures_alongside_results() {
        let results = vec![HostInventory {
            ip: "10.0.0.1".into(),
            snmp: None,
            unix: None,
            errors: vec![wfetch_core::inventory::InventoryError {
                method: "ssh".into(),
                reason: "connection refused".into(),
            }],
        }];
        let mut buf = Vec::new();
        write_inventory(&mut buf, &results, Format::Human).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("ssh unavailable"));
        assert!(out.contains("connection refused"));
    }
}
