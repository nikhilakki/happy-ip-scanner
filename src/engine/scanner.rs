use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::sync::mpsc;

use super::arp::lookup_mac;
use super::pinger::{PingMethod, ping_host};
use super::port_scanner::scan_ports;
use super::vendor::lookup_vendor;
use super::web_banner::fetch_web_title;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub ip: IpAddr,
    pub is_alive: bool,
    pub ping_ms: Option<f64>,
    pub hostname: Option<String>,
    pub open_ports: Vec<u16>,
    pub mac_address: Option<String>,
    pub vendor: Option<String>,
    pub web_title: Option<String>,
    pub comments: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub ports: Vec<u16>,
    pub ping_method: PingMethod,
    pub timeout_ms: u64,
    pub threads: usize,
    pub resolve_hostname: bool,
    pub lookup_mac: bool,
    pub fetch_web_title: bool,
    pub scan_dead_hosts: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            ports: vec![80, 443, 22, 8080],
            ping_method: PingMethod::TcpPort,
            timeout_ms: 1000,
            threads: 64,
            resolve_hostname: true,
            lookup_mac: true,
            fetch_web_title: true,
            scan_dead_hosts: false,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ScanEvent {
    Started {
        total_ips: usize,
    },
    Host(Box<HostResult>),
    Progress {
        scanned: usize,
        total: usize,
        alive: usize,
    },
    Finished {
        total_scanned: usize,
        total_alive: usize,
        elapsed_secs: f64,
    },
    Stopped,
}

/// Scan a single IP address with the given options
pub async fn scan_single_host(ip: IpAddr, options: &ScanOptions) -> HostResult {
    let timeout_duration = Duration::from_millis(options.timeout_ms);

    // 1. Host Liveness Ping
    let ping_res = ping_host(ip, options.ping_method, &options.ports, timeout_duration).await;
    let mut is_alive = ping_res.is_alive;
    let ping_ms = ping_res.rtt_ms;

    let should_scan_ports = is_alive || options.scan_dead_hosts;

    // 2. Open Ports Scan
    let open_ports = if should_scan_ports && !options.ports.is_empty() {
        let ports = scan_ports(ip, &options.ports, timeout_duration).await;
        if !ports.is_empty() {
            is_alive = true; // Finding open port proves host is alive
        }
        ports
    } else {
        Vec::new()
    };

    // 3. Hostname Reverse DNS
    let hostname = if is_alive && options.resolve_hostname {
        tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok())
            .await
            .unwrap_or(None)
    } else {
        None
    };

    // 4. MAC Address & Vendor
    let (mac_address, vendor) = if is_alive && options.lookup_mac {
        let mac = lookup_mac(ip).await;
        let v = mac
            .as_deref()
            .and_then(lookup_vendor)
            .map(|s| s.to_string());
        (mac, v)
    } else {
        (None, None)
    };

    // 5. Web Title / Banner
    let web_title = if is_alive && options.fetch_web_title {
        // Test port 80, 443, 8080 or the first open web-like port
        let web_port = open_ports
            .iter()
            .find(|&&p| p == 80 || p == 8080 || p == 3000 || p == 5000 || p == 8000);
        if let Some(&p) = web_port {
            fetch_web_title(ip, p, Duration::from_millis(options.timeout_ms.min(1500))).await
        } else {
            None
        }
    } else {
        None
    };

    HostResult {
        ip,
        is_alive,
        ping_ms,
        hostname,
        open_ports,
        mac_address,
        vendor,
        web_title,
        comments: None,
    }
}

/// Run an asynchronous scan over a list of IPs
pub async fn run_scan(
    ips: Vec<IpAddr>,
    options: ScanOptions,
    is_cancelled: Arc<AtomicBool>,
    event_sender: mpsc::Sender<ScanEvent>,
) {
    let total = ips.len();
    let _ = event_sender
        .send(ScanEvent::Started { total_ips: total })
        .await;

    let semaphore = Arc::new(Semaphore::new(options.threads.max(1)));
    let scanned_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let alive_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let start_time = Instant::now();

    let mut tasks = Vec::with_capacity(total);

    for ip in ips {
        if is_cancelled.load(Ordering::Relaxed) {
            let _ = event_sender.send(ScanEvent::Stopped).await;
            return;
        }

        let sem = semaphore.clone();
        let cancel = is_cancelled.clone();
        let opts = options.clone();
        let tx = event_sender.clone();
        let scanned = scanned_counter.clone();
        let alive = alive_counter.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            if cancel.load(Ordering::Relaxed) {
                return;
            }

            let result = scan_single_host(ip, &opts).await;

            if cancel.load(Ordering::Relaxed) {
                return;
            }

            let current_alive = if result.is_alive {
                alive.fetch_add(1, Ordering::Relaxed) + 1
            } else {
                alive.load(Ordering::Relaxed)
            };

            let current_scanned = scanned.fetch_add(1, Ordering::Relaxed) + 1;

            let _ = tx.send(ScanEvent::Host(Box::new(result))).await;
            let _ = tx
                .send(ScanEvent::Progress {
                    scanned: current_scanned,
                    total,
                    alive: current_alive,
                })
                .await;
        }));
    }

    for task in tasks {
        let _ = task.await;
    }

    if is_cancelled.load(Ordering::Relaxed) {
        let _ = event_sender.send(ScanEvent::Stopped).await;
    } else {
        let _ = event_sender
            .send(ScanEvent::Finished {
                total_scanned: scanned_counter.load(Ordering::Relaxed),
                total_alive: alive_counter.load(Ordering::Relaxed),
                elapsed_secs: start_time.elapsed().as_secs_f64(),
            })
            .await;
    }
}
