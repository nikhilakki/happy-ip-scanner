use clap::Parser;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use indicatif::{ProgressBar, ProgressStyle};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::engine::ip_range::{detect_local_range, generate_random_ips, parse_target};
use crate::engine::pinger::PingMethod;
use crate::engine::port_scanner::parse_ports;
use crate::engine::scanner::{HostResult, ScanEvent, ScanOptions, run_scan};
use crate::export::{export_to_csv, export_to_json, export_to_txt};

#[derive(Parser, Debug)]
#[command(
    name = "happy-ip-scanner",
    author,
    version,
    about = "A fast, friendly, cross-platform IP and port scanner in Rust (Angry IP Scanner port)"
)]
pub struct CliArgs {
    /// Target IP, CIDR (e.g. 192.168.1.0/24), or range (e.g. 192.168.1.1-254)
    #[arg(value_name = "TARGET")]
    pub target: Option<String>,

    /// Launch desktop GUI interface
    #[arg(long, default_value_t = false)]
    pub gui: bool,

    /// Ports to scan, e.g. "80,443,22,8000-8010"
    #[arg(short = 'p', long = "ports", default_value = "80,443,22,8080")]
    pub ports: String,

    /// Maximum concurrent worker threads
    #[arg(short = 't', long = "threads", default_value_t = 64)]
    pub threads: usize,

    /// Socket timeout per probe in milliseconds
    #[arg(long = "timeout", default_value_t = 1000)]
    pub timeout: u64,

    /// Save scan results to a file
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// Output format: table, csv, json, txt
    #[arg(short = 'f', long = "format", default_value = "table")]
    pub format: String,

    /// Only display / export alive hosts
    #[arg(short = 'a', long = "alive-only", default_value_t = false)]
    pub alive_only: bool,

    /// Disable reverse DNS hostname resolution
    #[arg(long = "no-dns", default_value_t = false)]
    pub no_dns: bool,

    /// Disable MAC address / vendor lookup
    #[arg(long = "no-mac", default_value_t = false)]
    pub no_mac: bool,

    /// Disable HTTP web banner & title grabbing
    #[arg(long = "no-banner", default_value_t = false)]
    pub no_banner: bool,

    /// Generate and scan N random IPs
    #[arg(long = "random")]
    pub random: Option<usize>,

    /// Scan ports even on hosts that don't respond to ping
    #[arg(long = "scan-dead", default_value_t = false)]
    pub scan_dead: bool,
}

pub async fn run_cli(args: CliArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Determine targets
    let ips: Vec<IpAddr> = if let Some(random_count) = args.random {
        println!("🎲 Generating {} random IPv4 addresses...", random_count);
        generate_random_ips(random_count)
    } else if let Some(target) = &args.target {
        parse_target(target)?
    } else if let Some((_local, start, end)) = detect_local_range() {
        println!(
            "ℹ️  No target provided. Auto-detected local subnet: {}-{}",
            start, end
        );
        crate::engine::ip_range::generate_range_v4(start, end)
    } else {
        return Err("No target specified. Provide a target (e.g. 192.168.1.0/24) or run without arguments for GUI.".into());
    };

    let parsed_ports = parse_ports(&args.ports);

    let options = ScanOptions {
        ports: parsed_ports.clone(),
        ping_method: PingMethod::TcpPort,
        timeout_ms: args.timeout,
        threads: args.threads,
        resolve_hostname: !args.no_dns,
        lookup_mac: !args.no_mac,
        fetch_web_title: !args.no_banner,
        scan_dead_hosts: args.scan_dead,
    };

    println!("⚡ Happy IP Scanner v{}", env!("CARGO_PKG_VERSION"));
    println!(
        "🎯 Scanning {} hosts | Ports: [{}] | Concurrency: {} | Timeout: {}ms",
        ips.len(),
        args.ports,
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
    pb.enable_steady_tick(Duration::from_millis(100));

    let (tx, mut rx) = mpsc::channel(256);
    let cancel_token = Arc::new(AtomicBool::new(false));

    // Handle Ctrl-C gracefully
    let cancel_ctrlc = cancel_token.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        println!("\n⚠️  Scan interrupted by user. Finalizing completed hosts...");
        cancel_ctrlc.store(true, std::sync::atomic::Ordering::Relaxed);
    });

    let scan_handle = tokio::spawn(run_scan(ips, options, cancel_token, tx));

    let mut results: Vec<HostResult> = Vec::new();
    let mut alive_count = 0;

    while let Some(event) = rx.recv().await {
        match event {
            ScanEvent::Started { total_ips } => {
                pb.set_length(total_ips as u64);
            }
            ScanEvent::Host(host) => {
                if host.is_alive {
                    alive_count += 1;
                }
                results.push(*host);
            }
            ScanEvent::Progress { scanned, alive, .. } => {
                pb.set_position(scanned as u64);
                pb.set_message(format!("{}", alive));
            }
            ScanEvent::Finished { elapsed_secs, .. } => {
                pb.finish_with_message(format!("{} (Done in {:.2}s)", alive_count, elapsed_secs));
            }
            ScanEvent::Stopped => {
                pb.finish_with_message(format!("{} (Stopped)", alive_count));
            }
        }
    }

    let _ = scan_handle.await;

    // Sort results by IP address for predictable, clean display
    results.sort_by_key(|r| r.ip);

    // Filter results if alive_only requested
    let display_results: Vec<&HostResult> = results
        .iter()
        .filter(|r| !args.alive_only || r.is_alive)
        .collect();

    // Print table if format is table
    if args.format.to_lowercase() == "table" {
        print_table(&display_results);
    }

    // Export to file if specified
    if let Some(out_path) = &args.output {
        match args.format.to_lowercase().as_str() {
            "csv" => {
                export_to_csv(&results, out_path)?;
                println!("💾 Exported CSV results to: {}", out_path);
            }
            "json" => {
                export_to_json(&results, out_path)?;
                println!("💾 Exported JSON results to: {}", out_path);
            }
            "txt" => {
                export_to_txt(&results, out_path, args.alive_only)?;
                println!("💾 Exported TXT results to: {}", out_path);
            }
            _ => {
                // Default export CSV
                export_to_csv(&results, out_path)?;
                println!("💾 Exported CSV results to: {}", out_path);
            }
        }
    }

    Ok(())
}

fn print_table(results: &[&HostResult]) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Status"),
            Cell::new("IP Address"),
            Cell::new("Ping"),
            Cell::new("Hostname"),
            Cell::new("Open Ports"),
            Cell::new("MAC Address"),
            Cell::new("Vendor"),
            Cell::new("Web / Banner"),
        ]);

    for r in results {
        let status_cell = if r.is_alive {
            if !r.open_ports.is_empty() {
                Cell::new("● ALIVE").fg(Color::Green)
            } else {
                Cell::new("● ALIVE").fg(Color::Blue)
            }
        } else {
            Cell::new("○ DEAD").fg(Color::Red)
        };

        let ping_str = r
            .ping_ms
            .map(|p| format!("{:.1}ms", p))
            .unwrap_or_else(|| "-".into());
        let host_str = r.hostname.as_deref().unwrap_or("-");
        let ports_str = if r.open_ports.is_empty() {
            "-".to_string()
        } else {
            r.open_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let mac_str = r.mac_address.as_deref().unwrap_or("-");
        let vendor_str = r.vendor.as_deref().unwrap_or("-");
        let banner_str = r.web_title.as_deref().unwrap_or("-");

        table.add_row(vec![
            status_cell,
            Cell::new(r.ip.to_string()).fg(Color::Cyan),
            Cell::new(ping_str).fg(Color::Yellow),
            Cell::new(host_str),
            Cell::new(ports_str).fg(Color::Green),
            Cell::new(mac_str),
            Cell::new(vendor_str),
            Cell::new(banner_str),
        ]);
    }

    println!("\n{}", table);
}
