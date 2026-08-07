//! `wfetch` — a cross-platform network scanner for administrators and agents.
//!
//! Both audiences are first class. Humans get an aligned table and diagnostics
//! on stderr; agents get `--output json` or `--output ndjson` on stdout, with
//! the core types serialised directly so the schema follows the engine rather
//! than a presentation layer. Exit codes distinguish "scan ran, found nothing"
//! from "scan could not run", which is the distinction a script needs.

mod output;

use std::io::{self, IsTerminal, Write};
use std::net::IpAddr;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use output::Format;
use wfetch_core::addr::AddrClass;
use wfetch_core::fingerprint::oui::OuiDatabase;
use wfetch_core::inventory::{self, Credentials, InventoryMethods};
use wfetch_core::platform::{self, HostPlatform};
use wfetch_core::scan::engine::{Engine, ScanConfig, Techniques, DEFAULT_PORTS};
use wfetch_core::scan::transport::SystemTransport;
use wfetch_core::target::{TargetPlan, TargetPlanBuilder, TargetSpec, DEFAULT_MAX_HOSTS};

/// Exit code for a run that could not be performed at all.
const EXIT_ERROR: u8 = 1;
/// Exit code for a scan that ran cleanly but found nothing, under
/// `--fail-if-empty`.
const EXIT_NO_HOSTS: u8 = 2;

#[derive(Parser)]
#[command(
    name = "wfetch",
    version,
    about = "Cross-platform network scanner for administrators and agents.",
    long_about = "Discovers hosts on a network, identifies what they are, and \
                  optionally inventories them over SNMP or SSH.\n\n\
                  Results go to stdout and diagnostics to stderr, so JSON output \
                  can be piped directly into other tools."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Output format.
    #[arg(long, short, global = true, value_enum, default_value = "human")]
    output: Format,

    /// Suppress progress notes on stderr.
    #[arg(long, short, global = true)]
    quiet: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Discover hosts on a network.
    #[command(long_about = "Discover hosts on a network.\n\n\
        With no target, scans the subnet of the default interface. Targets may \
        be CIDR blocks (10.0.0.0/24), ranges (10.0.0.1-50), or single \
        addresses.")]
    Scan(ScanArgs),

    /// List local network interfaces.
    Interfaces,

    /// Show the kernel neighbour (ARP/NDP) table.
    Neighbors,

    /// Report what discovery techniques this host can use.
    #[command(long_about = "Report what discovery techniques this host can use.\n\n\
        Capabilities are runtime facts: the same binary has different \
        capabilities as root and as a normal user.")]
    Capabilities,

    /// Collect inventory from hosts over SNMP or SSH.
    Inventory(InventoryArgs),
}

#[derive(Args)]
struct ScanArgs {
    /// Targets: CIDR blocks, ranges, or single addresses.
    #[arg(value_name = "TARGET")]
    targets: Vec<String>,

    /// Addresses to leave out. Repeatable.
    #[arg(long, short = 'x', value_name = "TARGET")]
    exclude: Vec<String>,

    /// TCP ports to probe. Repeatable, or comma-separated.
    #[arg(long, short, value_delimiter = ',')]
    port: Vec<u16>,

    /// Concurrent probe workers.
    #[arg(long, short = 'c', default_value_t = 64)]
    concurrency: usize,

    /// Per-probe timeout in milliseconds.
    #[arg(long, short = 't', default_value_t = 1000)]
    timeout: u64,

    /// Extra attempts against addresses that do not answer.
    #[arg(long, short, default_value_t = 1)]
    retries: u32,

    /// Probes per second. 0 removes the limit.
    #[arg(
        long,
        default_value_t = 2000.0,
        long_help = "Probes per second across all workers. Pacing matters on \
                     real networks: an unpaced sweep can overflow a switch's \
                     ARP table, and many access points treat a burst of ARP \
                     requests as an attack and start dropping them, which makes \
                     a faster scan find fewer hosts."
    )]
    rate: f64,

    /// Maximum addresses a plan may cover.
    #[arg(long, default_value_t = DEFAULT_MAX_HOSTS)]
    max_hosts: u64,

    /// Do not send anything: report only what the host already knows.
    #[arg(
        long,
        long_help = "Report only what this machine already knows: the kernel \
                     neighbour table and whatever hosts volunteer over mDNS and \
                     SSDP. Sends no probes to individual addresses."
    )]
    passive: bool,

    /// Skip techniques that need elevated privileges.
    #[arg(long)]
    unprivileged: bool,

    /// Seconds to listen for mDNS and SSDP responses.
    #[arg(long, default_value_t = 3)]
    multicast_timeout: u64,

    /// Treat this address as the default gateway when identifying devices.
    #[arg(long, value_name = "ADDRESS")]
    gateway: Option<IpAddr>,

    /// Load the IEEE OUI registry for full vendor coverage.
    #[arg(
        long,
        value_name = "PATH",
        long_help = "Load the IEEE OUI registry in its published oui.csv form. \
                     The built-in vendor table is a curated subset covering what \
                     usually appears on a LAN; this replaces guesswork with the \
                     full registry."
    )]
    oui_file: Option<String>,

    /// Also scan loopback, link-local and other non-routable addresses.
    #[arg(long)]
    include_all_addresses: bool,

    /// Exit with code 2 if no hosts are found.
    #[arg(long)]
    fail_if_empty: bool,
}

#[derive(Args)]
struct InventoryArgs {
    /// Hosts to inventory.
    #[arg(value_name = "HOST", required = true)]
    hosts: Vec<IpAddr>,

    /// SNMP v2c community string.
    #[arg(
        long,
        value_name = "COMMUNITY",
        long_help = "SNMP v2c community string. v2c sends this in clear text \
                     and provides no encryption, so it is appropriate for a \
                     trusted management network only. Prefer WFETCH_SNMP_COMMUNITY \
                     in the environment over a command line other users can read."
    )]
    snmp_community: Option<String>,

    /// SSH username.
    #[arg(long, value_name = "USER")]
    ssh_user: Option<String>,

    /// SSH port.
    #[arg(long, default_value_t = 22)]
    ssh_port: u16,

    /// SSH private key file.
    #[arg(long, value_name = "PATH")]
    ssh_key: Option<String>,

    /// Record host keys not yet in known_hosts.
    #[arg(
        long,
        long_help = "Accept and record host keys not yet in known_hosts. A key \
                     that has *changed* is still refused, since that is the case \
                     indicating interception."
    )]
    ssh_accept_new: bool,

    /// Do not attempt SNMP.
    #[arg(long)]
    no_snmp: bool,

    /// Do not attempt SSH.
    #[arg(long)]
    no_ssh: bool,

    /// Per-method timeout in seconds.
    #[arg(long, default_value_t = 5)]
    timeout: u64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut stdout = io::stdout().lock();

    let result = match &cli.command {
        Command::Scan(args) => run_scan(args, &cli, &mut stdout),
        Command::Interfaces => run_interfaces(&cli, &mut stdout),
        Command::Neighbors => run_neighbors(&cli, &mut stdout),
        Command::Capabilities => run_capabilities(&cli, &mut stdout),
        Command::Inventory(args) => run_inventory(args, &cli, &mut stdout),
    };

    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("wfetch: {e}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

/// Notes progress on stderr, leaving stdout for data.
fn note(cli: &Cli, message: impl std::fmt::Display) {
    if !cli.quiet {
        eprintln!("{message}");
    }
}

fn run_scan(args: &ScanArgs, cli: &Cli, out: &mut impl Write) -> Result<ExitCode, String> {
    let platform = platform::host_platform();
    let capabilities = platform.capabilities();

    let plan = build_plan(args, platform.as_ref())?;
    if plan.is_empty() {
        return Err("the target plan is empty after filtering".into());
    }

    let mut techniques = if args.passive {
        Techniques::passive()
    } else if args.unprivileged {
        Techniques::unprivileged()
    } else {
        Techniques::all()
    };

    // Passive mode is a user instruction, not a capability limit, so it is
    // applied before capabilities narrow things further.
    if args.passive {
        techniques.tcp_connect = false;
        techniques.icmp_echo = false;
        techniques.netbios = false;
    }

    let mut config = ScanConfig {
        concurrency: args.concurrency.max(1),
        timeout: Duration::from_millis(args.timeout.max(1)),
        min_timeout: Duration::from_millis(20),
        retries: args.retries,
        rate_limit: if args.rate > 0.0 { Some(args.rate) } else { None },
        ports: if args.port.is_empty() {
            DEFAULT_PORTS.to_vec()
        } else {
            args.port.clone()
        },
        techniques,
        multicast_timeout: Duration::from_secs(args.multicast_timeout.max(1)),
        default_gateway: args.gateway,
    };

    let skipped = config.constrain_to(&capabilities);
    for (technique, reason) in &skipped {
        note(cli, format!("wfetch: skipping {technique}: {reason}"));
    }

    note(
        cli,
        format!(
            "wfetch: scanning {} address{} with {} worker{}…",
            plan.len(),
            if plan.len() == 1 { "" } else { "es" },
            config.concurrency,
            if config.concurrency == 1 { "" } else { "s" }
        ),
    );

    let mut engine = Engine::new(SystemTransport::new(), config);
    if let Some(path) = &args.oui_file {
        let csv = std::fs::read_to_string(path)
            .map_err(|e| format!("could not read OUI file {path}: {e}"))?;
        let mut db = OuiDatabase::builtin();
        let added = db.load_ieee_csv(&csv);
        note(cli, format!("wfetch: loaded {added} OUI entries from {path}"));
        engine = engine.with_oui_database(db);
    }

    let mut report = engine.scan(&plan, Some(platform.as_ref()));
    // Merge in anything the capability check removed before the scan started.
    for (k, v) in skipped {
        report.techniques_skipped.entry(k).or_insert(v);
    }

    output::write_scan_report(out, &report, cli.output).map_err(|e| e.to_string())?;

    if report.hosts.is_empty() && args.fail_if_empty {
        return Ok(ExitCode::from(EXIT_NO_HOSTS));
    }
    Ok(ExitCode::SUCCESS)
}

/// Builds the scan plan from arguments, defaulting to the local subnet.
fn build_plan(args: &ScanArgs, platform: &dyn HostPlatform) -> Result<TargetPlan, String> {
    let mut builder = TargetPlanBuilder::new()
        .max_hosts(args.max_hosts)
        .allow_non_probeable(args.include_all_addresses);

    if args.targets.is_empty() {
        // No target given: scan the subnet of the interface a LAN scan would
        // naturally use.
        let interface = platform
            .default_scan_interface()
            .map_err(|e| format!("could not determine the default interface: {e}"))?
            .ok_or("no scannable interface found; give a target explicitly")?;

        let addr = interface
            .ipv4_addrs()
            .find(|a| wfetch_core::addr::classify(a.addr).is_probeable())
            .ok_or_else(|| {
                format!(
                    "interface {} has no routable IPv4 address; give a target explicitly",
                    interface.name
                )
            })?;

        let cidr = format!("{}/{}", addr.addr, addr.prefix_len);
        let spec: TargetSpec = cidr
            .parse()
            .map_err(|e| format!("could not derive a target from {cidr}: {e}"))?;
        eprintln!("wfetch: no target given, scanning {cidr} on {}", interface.name);
        builder = builder.include(spec);

        // Never probe our own address: it answers differently from every other
        // host and tells us nothing.
        builder = builder.exclude(TargetSpec::Single(addr.addr));
    } else {
        for t in &args.targets {
            let spec: TargetSpec = t
                .parse()
                .map_err(|e| format!("invalid target {t:?}: {e}"))?;
            builder = builder.include(spec);
        }
    }

    for e in &args.exclude {
        let spec: TargetSpec = e
            .parse()
            .map_err(|err| format!("invalid exclusion {e:?}: {err}"))?;
        builder = builder.exclude(spec);
    }

    builder.build().map_err(|e| e.to_string())
}

fn run_interfaces(cli: &Cli, out: &mut impl Write) -> Result<ExitCode, String> {
    let platform = platform::host_platform();
    let interfaces = platform
        .interfaces()
        .map_err(|e| format!("could not enumerate interfaces: {e}"))?;
    output::write_interfaces(out, &interfaces, cli.output).map_err(|e| e.to_string())?;
    Ok(ExitCode::SUCCESS)
}

fn run_neighbors(cli: &Cli, out: &mut impl Write) -> Result<ExitCode, String> {
    let platform = platform::host_platform();
    let entries = platform
        .neighbors()
        .map_err(|e| format!("could not read the neighbour table: {e}"))?;
    output::write_neighbors(out, &entries, cli.output).map_err(|e| e.to_string())?;
    Ok(ExitCode::SUCCESS)
}

fn run_capabilities(cli: &Cli, out: &mut impl Write) -> Result<ExitCode, String> {
    let platform = platform::host_platform();
    let caps = platform.capabilities();

    match cli.output {
        Format::Json | Format::Ndjson => {
            let value = serde_json::json!({
                "platform": platform.name(),
                "capabilities": caps,
            });
            serde_json::to_writer_pretty(&mut *out, &value).map_err(|e| e.to_string())?;
            writeln!(out).map_err(|e| e.to_string())?;
        }
        Format::Human => {
            writeln!(out, "platform:         {}", platform.name()).map_err(|e| e.to_string())?;
            for (name, available, note) in [
                (
                    "neighbour table",
                    caps.neighbor_table,
                    "read hosts this machine has already talked to",
                ),
                ("raw sockets", caps.raw_sockets, "TCP SYN and ARP probes"),
                ("ICMP echo", caps.icmp_echo, "ping sweeps"),
                ("multicast", caps.multicast, "mDNS and SSDP discovery"),
                ("broadcast", caps.broadcast, "NetBIOS name queries"),
            ] {
                writeln!(
                    out,
                    "  {:<16} {:<14} {}",
                    name,
                    if available { "available" } else { "unavailable" },
                    note
                )
                .map_err(|e| e.to_string())?;
            }
            if !caps.raw_sockets && io::stderr().is_terminal() {
                eprintln!(
                    "\nwfetch: running without raw sockets. Re-run with elevated \
                     privileges for the full technique set."
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run_inventory(args: &InventoryArgs, cli: &Cli, out: &mut impl Write) -> Result<ExitCode, String> {
    // Prefer the environment for the community string: a command line is
    // readable by every other user on the machine.
    let snmp_community = args
        .snmp_community
        .clone()
        .or_else(|| std::env::var("WFETCH_SNMP_COMMUNITY").ok());

    let credentials = Credentials {
        snmp_community,
        ssh_user: args.ssh_user.clone(),
        ssh_port: Some(args.ssh_port),
        ssh_identity_file: args.ssh_key.clone(),
        ssh_accept_new_host_keys: args.ssh_accept_new,
    };

    let methods = InventoryMethods {
        snmp: !args.no_snmp,
        ssh: !args.no_ssh,
    };

    if !methods.snmp && !methods.ssh {
        return Err("both inventory methods are disabled; nothing to do".into());
    }

    let timeout = Duration::from_secs(args.timeout.max(1));
    let mut results = Vec::with_capacity(args.hosts.len());

    for host in &args.hosts {
        if wfetch_core::addr::classify(*host) == AddrClass::Multicast {
            note(cli, format!("wfetch: skipping multicast address {host}"));
            continue;
        }
        note(cli, format!("wfetch: inventorying {host}…"));
        results.push(inventory::collect(*host, methods, &credentials, timeout));
    }

    output::write_inventory(out, &results, cli.output).map_err(|e| e.to_string())?;

    if results.iter().all(|r| !r.has_data()) && !results.is_empty() {
        return Ok(ExitCode::from(EXIT_NO_HOSTS));
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_definition_is_internally_consistent() {
        // Catches conflicting short flags and malformed help at build time.
        Cli::command().debug_assert();
    }

    #[test]
    fn a_bare_scan_needs_no_target() {
        let cli = Cli::try_parse_from(["wfetch", "scan"]).unwrap();
        match cli.command {
            Command::Scan(a) => assert!(a.targets.is_empty()),
            _ => panic!("expected scan"),
        }
    }

    #[test]
    fn multiple_targets_and_exclusions_are_accepted() {
        let cli = Cli::try_parse_from([
            "wfetch", "scan", "10.0.0.0/24", "192.168.1.1-50", "-x", "10.0.0.1",
        ])
        .unwrap();
        match cli.command {
            Command::Scan(a) => {
                assert_eq!(a.targets.len(), 2);
                assert_eq!(a.exclude, vec!["10.0.0.1"]);
            }
            _ => panic!("expected scan"),
        }
    }

    #[test]
    fn ports_accept_both_repetition_and_comma_separation() {
        let a = Cli::try_parse_from(["wfetch", "scan", "-p", "22,80,443"]).unwrap();
        let b = Cli::try_parse_from(["wfetch", "scan", "-p", "22", "-p", "80", "-p", "443"])
            .unwrap();
        for cli in [a, b] {
            match cli.command {
                Command::Scan(s) => assert_eq!(s.port, vec![22, 80, 443]),
                _ => panic!("expected scan"),
            }
        }
    }

    #[test]
    fn the_output_format_is_a_global_flag() {
        // It must work before or after the subcommand, since both are natural.
        for argv in [
            vec!["wfetch", "--output", "json", "scan"],
            vec!["wfetch", "scan", "--output", "json"],
        ] {
            assert_eq!(Cli::try_parse_from(argv).unwrap().output, Format::Json);
        }
    }

    #[test]
    fn invalid_arguments_are_rejected() {
        // Unknown format, unparseable port, missing required host.
        assert!(Cli::try_parse_from(["wfetch", "scan", "-o", "yaml"]).is_err());
        assert!(Cli::try_parse_from(["wfetch", "scan", "-p", "notaport"]).is_err());
        assert!(Cli::try_parse_from(["wfetch", "inventory"]).is_err());
        assert!(Cli::try_parse_from(["wfetch", "inventory", "not-an-ip"]).is_err());
    }

    #[test]
    fn defaults_match_the_documented_values() {
        let cli = Cli::try_parse_from(["wfetch", "scan"]).unwrap();
        match cli.command {
            Command::Scan(a) => {
                assert_eq!(a.concurrency, 64);
                assert_eq!(a.timeout, 1000);
                assert_eq!(a.retries, 1);
                assert_eq!(a.rate, 2000.0);
                assert_eq!(a.max_hosts, DEFAULT_MAX_HOSTS);
                assert!(!a.passive);
                assert!(!a.fail_if_empty);
            }
            _ => panic!("expected scan"),
        }
        assert_eq!(cli.output, Format::Human);
    }

    #[test]
    fn inventory_parses_credentials_and_method_switches() {
        let cli = Cli::try_parse_from([
            "wfetch",
            "inventory",
            "10.0.0.1",
            "10.0.0.2",
            "--snmp-community",
            "public",
            "--ssh-user",
            "admin",
            "--no-ssh",
        ])
        .unwrap();
        match cli.command {
            Command::Inventory(a) => {
                assert_eq!(a.hosts.len(), 2);
                assert_eq!(a.snmp_community.as_deref(), Some("public"));
                assert_eq!(a.ssh_user.as_deref(), Some("admin"));
                assert!(a.no_ssh);
                assert!(!a.no_snmp);
            }
            _ => panic!("expected inventory"),
        }
    }

    #[test]
    fn every_subcommand_parses() {
        for argv in [
            vec!["wfetch", "interfaces"],
            vec!["wfetch", "neighbors"],
            vec!["wfetch", "capabilities"],
            vec!["wfetch", "scan"],
        ] {
            assert!(Cli::try_parse_from(&argv).is_ok(), "failed: {argv:?}");
        }
    }

    #[test]
    fn passive_and_unprivileged_are_distinct_modes() {
        let passive = Cli::try_parse_from(["wfetch", "scan", "--passive"]).unwrap();
        let unpriv = Cli::try_parse_from(["wfetch", "scan", "--unprivileged"]).unwrap();
        match (passive.command, unpriv.command) {
            (Command::Scan(p), Command::Scan(u)) => {
                assert!(p.passive && !p.unprivileged);
                assert!(u.unprivileged && !u.passive);
            }
            _ => panic!("expected scans"),
        }
    }
}
