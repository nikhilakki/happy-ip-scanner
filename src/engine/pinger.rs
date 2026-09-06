use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// How a host's liveness is decided before its ports are scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PingMethod {
    /// Connect to a handful of well-known ports; an accept *or* a reset means the host is up.
    /// Works without root/admin on every platform.
    #[default]
    TcpPort,
    /// ICMP echo via the system `ping` binary. Catches hosts that firewall every TCP port.
    Icmp,
    /// TCP probe first, ICMP echo as a fallback.
    Combined,
    /// Skip the liveness probe entirely; a host is alive if any scanned port is open.
    AlwaysScan,
}

impl PingMethod {
    /// Every method, in the order they should be offered to users.
    pub const ALL: [PingMethod; 4] = [
        PingMethod::TcpPort,
        PingMethod::Icmp,
        PingMethod::Combined,
        PingMethod::AlwaysScan,
    ];

    /// Human-readable name for menus and help text.
    pub fn label(self) -> &'static str {
        match self {
            PingMethod::TcpPort => "TCP Port Ping (fast, no root)",
            PingMethod::Icmp => "ICMP Ping (system ping)",
            PingMethod::Combined => "Combined (TCP, then ICMP fallback)",
            PingMethod::AlwaysScan => "Always Scan (no ping, alive if a port is open)",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PingResult {
    pub is_alive: bool,
    pub rtt_ms: Option<f64>,
}

impl PingResult {
    fn alive(rtt_ms: f64) -> Self {
        Self {
            is_alive: true,
            rtt_ms: Some(rtt_ms),
        }
    }
}

/// Well-known ports probed by the TCP pinger.
const DEFAULT_TCP_PING_PORTS: [u16; 5] = [80, 443, 22, 445, 139];

/// Upper bound on ports probed per host, so a `1-65535` port list does not turn the
/// liveness check into a second full port scan.
const MAX_TCP_PING_PORTS: usize = 8;

/// Extra time allowed for the `ping` child process on top of the configured timeout.
const ICMP_PROCESS_GRACE: Duration = Duration::from_secs(2);

fn elapsed_ms(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1000.0
}

/// The well-known probe ports followed by the first few user ports, capped at
/// [`MAX_TCP_PING_PORTS`] and without duplicates.
fn tcp_probe_ports(user_ports: &[u16]) -> Vec<u16> {
    let mut probe = DEFAULT_TCP_PING_PORTS.to_vec();
    for &port in user_ports {
        if probe.len() >= MAX_TCP_PING_PORTS {
            break;
        }
        if !probe.contains(&port) {
            probe.push(port);
        }
    }
    probe
}

/// One TCP connect attempt. Returns the round-trip time if the host answered, whether by
/// accepting the connection or by actively refusing it (a TCP RST proves the host is up).
async fn tcp_probe(ip: IpAddr, port: u16, timeout_duration: Duration) -> Option<f64> {
    let start = Instant::now();
    match timeout(
        timeout_duration,
        TcpStream::connect(SocketAddr::new(ip, port)),
    )
    .await
    {
        Ok(Ok(_stream)) => Some(elapsed_ms(start)),
        Ok(Err(err))
            if matches!(
                err.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
            ) =>
        {
            Some(elapsed_ms(start))
        }
        _ => None,
    }
}

/// Probe a host with concurrent TCP connection attempts to common ports.
///
/// Finishes as soon as one probe gets an answer, so a dead host costs one timeout rather
/// than one per port, and the reported RTT is that of the single winning probe.
pub async fn tcp_ping(
    ip: IpAddr,
    ports: &[u16],
    timeout_duration: Duration,
    sockets: &Arc<Semaphore>,
) -> PingResult {
    let mut probes = JoinSet::new();
    for port in tcp_probe_ports(ports) {
        let Ok(permit) = sockets.clone().acquire_owned().await else {
            break;
        };
        probes.spawn(async move {
            let _permit = permit;
            tcp_probe(ip, port, timeout_duration).await
        });
    }

    while let Some(result) = probes.join_next().await {
        if let Ok(Some(rtt)) = result {
            probes.abort_all();
            return PingResult::alive(rtt);
        }
    }
    PingResult::default()
}

/// Build the platform's `ping` invocation for a single echo request.
fn icmp_command(ip: &str, timeout_duration: Duration) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("ping");
    #[cfg(target_os = "windows")]
    {
        let wait_ms = timeout_duration.as_millis().to_string();
        cmd.args(["-n", "1", "-w", &wait_ms, ip]);
    }
    #[cfg(target_os = "macos")]
    {
        // On macOS/BSD `-W` is in milliseconds; `-n` skips reverse DNS of the target.
        let wait_ms = timeout_duration.as_millis().to_string();
        cmd.args(["-n", "-c", "1", "-W", &wait_ms, ip]);
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        // On Linux `-W` is in whole seconds.
        let wait_secs = timeout_duration.as_secs_f64().ceil().max(1.0) as u64;
        let wait_secs = wait_secs.to_string();
        cmd.args(["-n", "-c", "1", "-W", &wait_secs, ip]);
    }
    cmd.kill_on_drop(true);
    cmd
}

/// Pull the reported round-trip time out of `ping` output, e.g. `time=9.136 ms` on Unix
/// or `time=12ms` / `time<1ms` on Windows.
fn parse_ping_rtt(output: &str) -> Option<f64> {
    let idx = output.find("time=").or_else(|| output.find("time<"))?;
    let number: String = output[idx + "time=".len()..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    number.parse().ok()
}

/// ICMP echo via the system `ping` binary (works unprivileged on macOS, Linux and Windows).
pub async fn system_icmp_ping(ip: IpAddr, timeout_duration: Duration) -> PingResult {
    let start = Instant::now();
    let ip_str = ip.to_string();
    let run = icmp_command(&ip_str, timeout_duration).output();
    let Ok(Ok(output)) = timeout(timeout_duration + ICMP_PROCESS_GRACE, run).await else {
        return PingResult::default();
    };

    // Windows `ping` exits 0 even for "Destination host unreachable"; only a real echo
    // reply carries a TTL field, on every platform.
    let text = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() || !text.to_ascii_lowercase().contains("ttl=") {
        return PingResult::default();
    }

    PingResult::alive(parse_ping_rtt(&text).unwrap_or_else(|| elapsed_ms(start)))
}

/// Decide whether `ip` is alive using the configured method.
pub async fn ping_host(
    ip: IpAddr,
    method: PingMethod,
    custom_ports: &[u16],
    timeout_duration: Duration,
    sockets: &Arc<Semaphore>,
) -> PingResult {
    match method {
        PingMethod::TcpPort => tcp_ping(ip, custom_ports, timeout_duration, sockets).await,
        PingMethod::Icmp => system_icmp_ping(ip, timeout_duration).await,
        PingMethod::Combined => {
            let tcp = tcp_ping(ip, custom_ports, timeout_duration, sockets).await;
            if tcp.is_alive {
                tcp
            } else {
                system_icmp_ping(ip, timeout_duration).await
            }
        }
        // Liveness is decided by the port scan that follows.
        PingMethod::AlwaysScan => PingResult::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn probe_ports_merge_defaults_and_user_ports_without_duplicates() {
        assert_eq!(tcp_probe_ports(&[]), DEFAULT_TCP_PING_PORTS.to_vec());
        assert_eq!(
            tcp_probe_ports(&[443, 3389]),
            vec![80, 443, 22, 445, 139, 3389]
        );
        let many: Vec<u16> = (1..=100).collect();
        assert_eq!(tcp_probe_ports(&many).len(), MAX_TCP_PING_PORTS);
    }

    #[test]
    fn parses_rtt_from_unix_and_windows_ping_output() {
        assert_eq!(
            parse_ping_rtt("64 bytes from 1.1.1.1: icmp_seq=0 ttl=53 time=9.136 ms"),
            Some(9.136)
        );
        assert_eq!(
            parse_ping_rtt("Reply from 1.1.1.1: bytes=32 time=12ms TTL=53"),
            Some(12.0)
        );
        assert_eq!(
            parse_ping_rtt("Reply from 192.168.1.1: bytes=32 time<1ms TTL=64"),
            Some(1.0)
        );
        assert_eq!(parse_ping_rtt("Request timeout for icmp_seq 0"), None);
    }

    #[tokio::test]
    async fn tcp_ping_reports_loopback_alive_via_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let sockets = Arc::new(Semaphore::new(8));
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        let result = tcp_ping(ip, &[port], Duration::from_secs(2), &sockets).await;
        assert!(result.is_alive);
        assert!(result.rtt_ms.is_some());
    }

    #[tokio::test]
    async fn always_scan_never_probes() {
        let sockets = Arc::new(Semaphore::new(1));
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let result = ping_host(
            ip,
            PingMethod::AlwaysScan,
            &[],
            Duration::from_secs(1),
            &sockets,
        )
        .await;
        assert!(!result.is_alive);
        assert_eq!(sockets.available_permits(), 1);
    }
}
