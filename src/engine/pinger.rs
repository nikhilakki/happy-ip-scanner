use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PingMethod {
    TcpPort,
    Combined,
    AlwaysScan,
}

impl Default for PingMethod {
    fn default() -> Self {
        PingMethod::TcpPort
    }
}

pub struct PingResult {
    pub is_alive: bool,
    pub rtt_ms: Option<f64>,
}

/// Standard ports used for TCP ping probe when testing host liveness
const DEFAULT_TCP_PING_PORTS: [u16; 5] = [80, 443, 22, 445, 139];

/// Probe an IP address using TCP connection attempts to common ports.
/// If any connection succeeds OR is actively rejected (TCP RST -> ConnectionRefused),
/// the machine is actively responding and therefore ALIVE!
pub async fn tcp_ping(ip: IpAddr, ports: &[u16], timeout_duration: Duration) -> PingResult {
    let check_ports = if ports.is_empty() {
        &DEFAULT_TCP_PING_PORTS[..]
    } else {
        ports
    };

    let start = Instant::now();

    for &port in check_ports {
        let addr = SocketAddr::new(ip, port);
        let attempt = timeout(timeout_duration, TcpStream::connect(addr)).await;

        match attempt {
            Ok(Ok(_stream)) => {
                let rtt = start.elapsed().as_secs_f64() * 1000.0;
                return PingResult {
                    is_alive: true,
                    rtt_ms: Some(rtt),
                };
            }
            Ok(Err(err)) => {
                // ConnectionRefused or HostUnreachable with RST received means host IP is active
                if err.kind() == std::io::ErrorKind::ConnectionRefused
                    || err.kind() == std::io::ErrorKind::ConnectionReset
                {
                    let rtt = start.elapsed().as_secs_f64() * 1000.0;
                    return PingResult {
                        is_alive: true,
                        rtt_ms: Some(rtt),
                    };
                }
            }
            Err(_) => {
                // Timed out on this port, continue to next
            }
        }
    }

    PingResult {
        is_alive: false,
        rtt_ms: None,
    }
}

/// System ping fallback (macOS, Linux, Windows)
pub async fn system_icmp_ping(ip: IpAddr, timeout_duration: Duration) -> PingResult {
    let start = Instant::now();
    let timeout_secs = (timeout_duration.as_millis().max(500) as f64 / 1000.0).ceil() as u64;

    #[cfg(target_os = "windows")]
    let output = tokio::process::Command::new("ping")
        .args([
            "-n",
            "1",
            "-w",
            &timeout_duration.as_millis().to_string(),
            &ip.to_string(),
        ])
        .output()
        .await;

    #[cfg(target_os = "macos")]
    let output = tokio::process::Command::new("ping")
        .args(["-c", "1", "-W", &timeout_secs.to_string(), &ip.to_string()])
        .output()
        .await;

    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    let output = tokio::process::Command::new("ping")
        .args(["-c", "1", "-W", &timeout_secs.to_string(), &ip.to_string()])
        .output()
        .await;

    if let Ok(res) = output {
        if res.status.success() {
            let rtt = start.elapsed().as_secs_f64() * 1000.0;
            return PingResult {
                is_alive: true,
                rtt_ms: Some(rtt),
            };
        }
    }

    PingResult {
        is_alive: false,
        rtt_ms: None,
    }
}

/// Primary ping dispatcher
pub async fn ping_host(
    ip: IpAddr,
    method: PingMethod,
    custom_ports: &[u16],
    timeout_duration: Duration,
) -> PingResult {
    match method {
        PingMethod::TcpPort => tcp_ping(ip, custom_ports, timeout_duration).await,
        PingMethod::Combined => {
            let tcp_res = tcp_ping(ip, custom_ports, timeout_duration).await;
            if tcp_res.is_alive {
                return tcp_res;
            }
            system_icmp_ping(ip, timeout_duration).await
        }
        PingMethod::AlwaysScan => PingResult {
            is_alive: true,
            rtt_ms: None,
        },
    }
}
