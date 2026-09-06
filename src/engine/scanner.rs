use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;

use super::arp::lookup_mac;
use super::limits::socket_budget;
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
            ports: vec![22, 80, 443, 8080],
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

/// Events streamed from [`run_scan`]. Exactly one `Host` event is sent per scanned address,
/// so consumers can count progress by counting `Host` events.
#[derive(Debug, Clone)]
pub enum ScanEvent {
    Started {
        total_ips: usize,
    },
    Host(Box<HostResult>),
    Finished {
        total_scanned: usize,
        total_alive: usize,
        elapsed_secs: f64,
    },
    Stopped,
}

/// Plain-HTTP ports worth asking for a page title, in order of preference.
const WEB_PORTS: [u16; 11] = [80, 8080, 8000, 8008, 8081, 8088, 8888, 81, 3000, 5000, 9000];

/// Upper bound for the HTTP banner exchange, regardless of the probe timeout.
const MAX_WEB_TIMEOUT: Duration = Duration::from_millis(1500);

/// Reverse DNS has its own resolver timeouts; never wait less than this for it.
const MIN_DNS_TIMEOUT: Duration = Duration::from_secs(2);

/// How often the scan loop re-checks the cancel flag while waiting for a worker slot.
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(100);

async fn reverse_dns(ip: IpAddr, timeout: Duration) -> Option<String> {
    let lookup = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok());
    tokio::time::timeout(timeout.max(MIN_DNS_TIMEOUT), lookup)
        .await
        .ok()?
        .ok()
        .flatten()
}

/// Scan a single address: liveness, open ports, then the optional fetchers.
pub async fn scan_single_host(
    ip: IpAddr,
    options: &ScanOptions,
    sockets: &Arc<Semaphore>,
) -> HostResult {
    let timeout = Duration::from_millis(options.timeout_ms);

    // 1. Liveness
    let ping = ping_host(ip, options.ping_method, &options.ports, timeout, sockets).await;
    let mut is_alive = ping.is_alive;

    // 2. Open ports
    let should_scan_ports =
        is_alive || options.scan_dead_hosts || options.ping_method == PingMethod::AlwaysScan;
    let open_ports = if should_scan_ports && !options.ports.is_empty() {
        scan_ports(ip, &options.ports, timeout, sockets).await
    } else {
        Vec::new()
    };
    if !open_ports.is_empty() {
        is_alive = true; // an open port proves the host is up
    }

    // 3. Reverse DNS
    let hostname = if is_alive && options.resolve_hostname {
        reverse_dns(ip, timeout).await
    } else {
        None
    };

    // 4. MAC address & vendor (only meaningful for hosts on the local segment)
    let (mac_address, vendor) = if is_alive && options.lookup_mac {
        let mac = lookup_mac(ip).await;
        let vendor = mac.as_deref().and_then(lookup_vendor).map(str::to_string);
        (mac, vendor)
    } else {
        (None, None)
    };

    // 5. Web title / banner from the first open HTTP-looking port
    let web_title = if is_alive && options.fetch_web_title {
        match WEB_PORTS.iter().find(|p| open_ports.contains(p)) {
            Some(&port) => fetch_web_title(ip, port, timeout.min(MAX_WEB_TIMEOUT)).await,
            None => None,
        }
    } else {
        None
    };

    HostResult {
        ip,
        is_alive,
        ping_ms: ping.rtt_ms,
        hostname,
        open_ports,
        mac_address,
        vendor,
        web_title,
        comments: None,
    }
}

/// Scan every address in `ips`, at most `options.threads` hosts at a time, streaming
/// [`ScanEvent`]s to `event_sender`. Setting `is_cancelled` stops the scan promptly:
/// in-flight hosts are abandoned and a `Stopped` event is sent instead of `Finished`.
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

    let options = Arc::new(options);
    let host_slots = Arc::new(Semaphore::new(options.threads.max(1)));
    let sockets = Arc::new(Semaphore::new(socket_budget()));
    let scanned_counter = Arc::new(AtomicUsize::new(0));
    let alive_counter = Arc::new(AtomicUsize::new(0));
    let start_time = Instant::now();
    let cancelled = || is_cancelled.load(Ordering::Relaxed);

    let mut tasks = JoinSet::new();

    for ip in ips {
        // Wait for a worker slot, waking up periodically to notice cancellation.
        let permit = loop {
            if cancelled() {
                break None;
            }
            tokio::select! {
                permit = host_slots.clone().acquire_owned() => break permit.ok(),
                _ = tokio::time::sleep(CANCEL_POLL_INTERVAL) => {}
            }
        };
        let Some(permit) = permit else {
            break;
        };

        let opts = Arc::clone(&options);
        let sockets = Arc::clone(&sockets);
        let cancel = Arc::clone(&is_cancelled);
        let tx = event_sender.clone();
        let scanned = Arc::clone(&scanned_counter);
        let alive = Arc::clone(&alive_counter);

        tasks.spawn(async move {
            let _permit = permit;
            let result = scan_single_host(ip, &opts, &sockets).await;
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            if result.is_alive {
                alive.fetch_add(1, Ordering::Relaxed);
            }
            scanned.fetch_add(1, Ordering::Relaxed);
            let _ = tx.send(ScanEvent::Host(Box::new(result))).await;
        });

        // Reap finished tasks so the set stays bounded by the worker count.
        while tasks.try_join_next().is_some() {}
    }

    if cancelled() {
        tasks.abort_all();
    }
    while tasks.join_next().await.is_some() {}

    let event = if cancelled() {
        ScanEvent::Stopped
    } else {
        ScanEvent::Finished {
            total_scanned: scanned_counter.load(Ordering::Relaxed),
            total_alive: alive_counter.load(Ordering::Relaxed),
            elapsed_secs: start_time.elapsed().as_secs_f64(),
        }
    };
    let _ = event_sender.send(event).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn loopback_options(port: u16) -> ScanOptions {
        ScanOptions {
            ports: vec![port],
            ping_method: PingMethod::AlwaysScan,
            timeout_ms: 1000,
            threads: 4,
            resolve_hostname: false,
            lookup_mac: false,
            fetch_web_title: false,
            scan_dead_hosts: false,
        }
    }

    #[tokio::test]
    async fn scan_streams_one_host_event_per_ip_then_finished() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Only 127.0.0.1 is guaranteed to exist on every OS, so scan it three times.
        let ips = vec![IpAddr::from([127, 0, 0, 1]); 3];

        let (tx, mut rx) = mpsc::channel(16);
        run_scan(
            ips,
            loopback_options(port),
            Arc::new(AtomicBool::new(false)),
            tx,
        )
        .await;

        let mut hosts = 0;
        let mut finished = false;
        while let Some(event) = rx.recv().await {
            match event {
                ScanEvent::Started { total_ips } => assert_eq!(total_ips, 3),
                ScanEvent::Host(h) => {
                    hosts += 1;
                    assert!(h.is_alive, "{} should be alive", h.ip);
                    assert_eq!(h.open_ports, vec![port]);
                }
                ScanEvent::Finished {
                    total_scanned,
                    total_alive,
                    ..
                } => {
                    finished = true;
                    assert_eq!((total_scanned, total_alive), (3, 3));
                }
                ScanEvent::Stopped => panic!("scan should not have been stopped"),
            }
        }
        assert_eq!(hosts, 3);
        assert!(finished);
    }

    #[tokio::test]
    async fn always_scan_marks_hosts_dead_when_no_port_is_open() {
        // Port 1 on loopback is refused immediately, so this is fast and deterministic.
        let (tx, mut rx) = mpsc::channel(16);
        let ips = vec![IpAddr::from([127, 0, 0, 1])];
        run_scan(
            ips,
            loopback_options(1),
            Arc::new(AtomicBool::new(false)),
            tx,
        )
        .await;

        let mut saw_host = false;
        while let Some(event) = rx.recv().await {
            if let ScanEvent::Host(h) = event {
                saw_host = true;
                assert!(!h.is_alive);
                assert!(h.open_ports.is_empty());
            }
        }
        assert!(saw_host);
    }

    #[tokio::test]
    async fn cancelled_scan_ends_with_stopped() {
        let (tx, mut rx) = mpsc::channel(16);
        let cancel = Arc::new(AtomicBool::new(true));
        let ips = vec![IpAddr::from([127, 0, 0, 1])];
        run_scan(ips, loopback_options(1), cancel, tx).await;

        let mut last = None;
        while let Some(event) = rx.recv().await {
            last = Some(event);
        }
        assert!(matches!(last, Some(ScanEvent::Stopped)));
    }
}
