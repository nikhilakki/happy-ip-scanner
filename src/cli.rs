use clap::{Parser, ValueEnum};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;

use crate::engine::ip_range::{
    detect_local_range, generate_random_ips, generate_range_v4, parse_target,
};
use crate::engine::pinger::PingMethod;
use crate::engine::port_scanner::{format_ports, parse_ports};
use crate::engine::scanner::{HostResult, ScanEvent, ScanOptions, run_scan};
use crate::export::{write_csv, write_json, write_txt};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Pretty table (default)
    Table,
    Csv,
    Json,
    /// One host per line
    Txt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum PingMethodArg {
    /// TCP connect to common ports; works without root
    Tcp,
    /// ICMP echo via the system `ping` command
    Icmp,
    /// TCP first, then ICMP as a fallback
    Combined,
    /// No ping; a host is alive if any port is open
    Always,
}

impl From<PingMethodArg> for PingMethod {
    fn from(arg: PingMethodArg) -> Self {
        match arg {
            PingMethodArg::Tcp => PingMethod::TcpPort,
            PingMethodArg::Icmp => PingMethod::Icmp,
            PingMethodArg::Combined => PingMethod::Combined,
            PingMethodArg::Always => PingMethod::AlwaysScan,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "happy-ip-scanner",
    author,
    version,
    about = "A fast, friendly, cross-platform IP and port scanner in Rust (Angry IP Scanner port)"
)]
pub struct CliArgs {
    /// Target: IP, hostname, CIDR (192.168.1.0/24) or range (192.168.1.1-254).
    /// Defaults to the local /24 subnet when omitted.
    #[arg(value_name = "TARGET")]
    pub target: Option<String>,

    /// Launch the desktop GUI (also the default when run with no arguments)
    #[arg(long)]
    pub gui: bool,

    /// Ports to scan, e.g. "80,443,22,8000-8010"
    #[arg(short, long, default_value = "80,443,22,8080")]
    pub ports: String,

    /// Maximum number of hosts scanned concurrently
    #[arg(short, long, default_value_t = 64, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=2000))]
    pub threads: usize,

    /// Socket timeout per probe in milliseconds
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(1..=60_000))]
    pub timeout: u64,

    /// Liveness check used before port scanning
    #[arg(long, value_enum, default_value_t = PingMethodArg::Tcp)]
    pub ping: PingMethodArg,

    /// Write results to this file (format from --format, or guessed from the extension)
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Output format; non-table formats are written to stdout unless --output is given
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
    pub format: OutputFormat,

    /// Only display / export alive hosts
    #[arg(short, long)]
    pub alive_only: bool,

    /// Disable reverse DNS hostname resolution
    #[arg(long)]
    pub no_dns: bool,

    /// Disable MAC address / vendor lookup
    #[arg(long)]
    pub no_mac: bool,

    /// Disable HTTP web banner & title grabbing
    #[arg(long)]
    pub no_banner: bool,

    /// Generate and scan N random public IPv4 addresses instead of TARGET
    #[arg(long, value_name = "N", conflicts_with = "target")]
    pub random: Option<usize>,

    /// Scan ports even on hosts that don't respond to ping
    #[arg(long)]
    pub scan_dead: bool,
}

fn resolve_targets(args: &CliArgs) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
    if let Some(count) = args.random {
        eprintln!("🎲 Generating {count} random public IPv4 addresses...");
        return Ok(generate_random_ips(count));
    }
    if let Some(target) = &args.target {
        return Ok(parse_target(target)?);
    }
    if let Some((_local, start, end)) = detect_local_range() {
        eprintln!("ℹ️  No target provided. Auto-detected local subnet: {start}-{end}");
        return Ok(generate_range_v4(start, end));
    }
    Err("No target specified and no local network detected. \
         Provide a target such as 192.168.1.0/24, or run without arguments for the GUI."
        .into())
}

pub async fn run_cli(args: CliArgs) -> Result<(), Box<dyn std::error::Error>> {
    let ips = resolve_targets(&args)?;

    let ports = parse_ports(&args.ports);
    if ports.is_empty() && !args.ports.trim().is_empty() {
        return Err(format!("No valid ports in '{}'", args.ports).into());
    }

    let options = ScanOptions {
        ports,
        ping_method: args.ping.into(),
        timeout_ms: args.timeout,
        threads: args.threads,
        resolve_hostname: !args.no_dns,
        lookup_mac: !args.no_mac,
        fetch_web_title: !args.no_banner,
        scan_dead_hosts: args.scan_dead,
    };

    // Progress and status go to stderr so stdout stays clean for piped CSV/JSON output.
    eprintln!("⚡ Happy IP Scanner v{}", env!("CARGO_PKG_VERSION"));
    eprintln!(
        "🎯 Scanning {} hosts | Ports: [{}] | Ping: {} | Concurrency: {} | Timeout: {}ms",
        ips.len(),
        format_ports(&options.ports, ", "),
        options.ping_method.label(),
        options.threads,
        options.timeout_ms
    );

    let pb = ProgressBar::new(ips.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) | Alive: {msg}")
            .expect("Invalid progress bar template")
            .progress_chars("━╸ "),
    );
    pb.set_message("0");
    pb.enable_steady_tick(Duration::from_millis(100));

    let (tx, mut rx) = mpsc::channel(256);
    let cancel_token = Arc::new(AtomicBool::new(false));

    // First Ctrl-C stops the scan and prints what was found; a second one quits immediately.
    let cancel_on_ctrlc = Arc::clone(&cancel_token);
    let pb_for_ctrlc = pb.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancel_on_ctrlc.store(true, Ordering::Relaxed);
            pb_for_ctrlc.println(
                "⚠️  Interrupted. Stopping scan (press Ctrl-C again to quit immediately)...",
            );
            if tokio::signal::ctrl_c().await.is_ok() {
                std::process::exit(130);
            }
        }
    });

    let scan_handle = tokio::spawn(run_scan(ips, options, cancel_token, tx));

    let mut results: Vec<HostResult> = Vec::new();
    let mut alive_count = 0usize;

    while let Some(event) = rx.recv().await {
        match event {
            ScanEvent::Started { total_ips } => pb.set_length(total_ips as u64),
            ScanEvent::Host(host) => {
                if host.is_alive {
                    alive_count += 1;
                }
                results.push(*host);
                pb.set_position(results.len() as u64);
                pb.set_message(alive_count.to_string());
            }
            ScanEvent::Finished { elapsed_secs, .. } => {
                pb.finish_with_message(format!("{alive_count} (done in {elapsed_secs:.2}s)"));
            }
            ScanEvent::Stopped => {
                pb.finish_with_message(format!("{alive_count} (stopped)"));
            }
        }
    }
    let _ = scan_handle.await;

    results.sort_by_key(|r| r.ip);
    if args.alive_only {
        results.retain(|r| r.is_alive);
    }

    match (args.format, &args.output) {
        (OutputFormat::Table, None) => print_table(&results),
        (OutputFormat::Table, Some(path)) => {
            print_table(&results);
            save_to_file(format_for_path(path), &results, path)?;
        }
        (format, Some(path)) => save_to_file(format, &results, path)?,
        (format, None) => write_results(format, &results, io::stdout().lock())?,
    }

    Ok(())
}

/// Pick an export format from a file extension: `.json`, `.txt`, otherwise CSV.
fn format_for_path(path: &Path) -> OutputFormat {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("json") => OutputFormat::Json,
        Some("txt") => OutputFormat::Txt,
        _ => OutputFormat::Csv,
    }
}

fn save_to_file(format: OutputFormat, results: &[HostResult], path: &Path) -> io::Result<()> {
    let file = io::BufWriter::new(std::fs::File::create(path)?);
    write_results(format, results, file)?;
    eprintln!(
        "💾 Saved {} host(s) as {} to {}",
        results.len(),
        format
            .to_possible_value()
            .map(|v| v.get_name().to_uppercase())
            .unwrap_or_default(),
        path.display()
    );
    Ok(())
}

fn write_results<W: Write>(
    format: OutputFormat,
    results: &[HostResult],
    mut writer: W,
) -> io::Result<()> {
    match format {
        OutputFormat::Csv => write_csv(results, writer),
        OutputFormat::Json => write_json(results, writer),
        OutputFormat::Txt => write_txt(results, writer),
        OutputFormat::Table => writeln!(writer, "{}", render_table(results)),
    }
}

fn print_table(results: &[HostResult]) {
    if results.is_empty() {
        eprintln!("No hosts to display.");
        return;
    }
    println!("\n{}", render_table(results));
}

fn render_table(results: &[HostResult]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header([
            "Status",
            "IP Address",
            "Ping",
            "Hostname",
            "Open Ports",
            "MAC Address",
            "Vendor",
            "Web / Banner",
        ]);

    for r in results {
        let status_cell = match (r.is_alive, r.open_ports.is_empty()) {
            (true, false) => Cell::new("● ALIVE").fg(Color::Green),
            (true, true) => Cell::new("● ALIVE").fg(Color::Blue),
            (false, _) => Cell::new("○ DEAD").fg(Color::Red),
        };
        let ping = r
            .ping_ms
            .map(|p| format!("{p:.1}ms"))
            .unwrap_or_else(|| "-".into());
        let ports = if r.open_ports.is_empty() {
            "-".to_string()
        } else {
            format_ports(&r.open_ports, ", ")
        };

        table.add_row(vec![
            status_cell,
            Cell::new(r.ip.to_string()).fg(Color::Cyan),
            Cell::new(ping).fg(Color::Yellow),
            Cell::new(r.hostname.as_deref().unwrap_or("-")),
            Cell::new(ports).fg(Color::Green),
            Cell::new(r.mac_address.as_deref().unwrap_or("-")),
            Cell::new(r.vendor.as_deref().unwrap_or("-")),
            Cell::new(r.web_title.as_deref().unwrap_or("-")),
        ]);
    }

    table
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        CliArgs::command().debug_assert();
    }

    #[test]
    fn defaults_and_flags_parse() {
        let args = CliArgs::try_parse_from([
            "hip",
            "192.168.1.0/24",
            "-p",
            "22",
            "-t",
            "10",
            "--ping",
            "combined",
            "-f",
            "json",
            "-a",
        ])
        .unwrap();
        assert_eq!(args.target.as_deref(), Some("192.168.1.0/24"));
        assert_eq!(args.threads, 10);
        assert_eq!(args.ping, PingMethodArg::Combined);
        assert_eq!(args.format, OutputFormat::Json);
        assert!(args.alive_only);
        assert!(!args.gui);
    }

    #[test]
    fn rejects_out_of_range_and_conflicting_values() {
        assert!(CliArgs::try_parse_from(["hip", "-t", "0"]).is_err());
        assert!(CliArgs::try_parse_from(["hip", "--timeout", "0"]).is_err());
        assert!(CliArgs::try_parse_from(["hip", "-f", "xml"]).is_err());
        assert!(CliArgs::try_parse_from(["hip", "--random", "5", "1.1.1.1"]).is_err());
    }

    #[test]
    fn output_format_follows_extension() {
        assert_eq!(format_for_path(Path::new("out.JSON")), OutputFormat::Json);
        assert_eq!(format_for_path(Path::new("alive.txt")), OutputFormat::Txt);
        assert_eq!(format_for_path(Path::new("scan.csv")), OutputFormat::Csv);
        assert_eq!(format_for_path(Path::new("scan")), OutputFormat::Csv);
    }
}
