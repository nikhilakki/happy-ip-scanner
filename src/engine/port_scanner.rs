use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Parse user-supplied port string like "80, 443, 8080" or "8000-8010, 22"
pub fn parse_ports(port_str: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in port_str.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if let Some((start_s, end_s)) = part.split_once('-') {
            if let (Ok(start), Ok(end)) = (start_s.trim().parse::<u16>(), end_s.trim().parse::<u16>()) {
                let (min, max) = if start <= end { (start, end) } else { (end, start) };
                for p in min..=max {
                    ports.push(p);
                }
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }

    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Format list of open ports nicely e.g. "80, 443"
#[allow(dead_code)]
pub fn format_ports(ports: &[u16]) -> String {
    if ports.is_empty() {
        return String::new();
    }
    ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Check if a single TCP port is open with timeout
pub async fn check_port(ip: IpAddr, port: u16, timeout_duration: Duration) -> bool {
    let addr = SocketAddr::new(ip, port);
    matches!(timeout(timeout_duration, TcpStream::connect(addr)).await, Ok(Ok(_)))
}

/// Scan a list of ports concurrently for a given IP address
pub async fn scan_ports(ip: IpAddr, ports: &[u16], timeout_duration: Duration) -> Vec<u16> {
    if ports.is_empty() {
        return Vec::new();
    }

    let mut tasks = Vec::with_capacity(ports.len());
    for &port in ports {
        tasks.push(async move {
            if check_port(ip, port, timeout_duration).await {
                Some(port)
            } else {
                None
            }
        });
    }

    let results = futures_util_join(tasks).await;
    let mut open = Vec::new();
    for r in results {
        if let Some(port) = r {
            open.push(port);
        }
    }
    open.sort_unstable();
    open
}

// Simple join helper to avoid needing heavy extra dependencies if not imported
async fn futures_util_join<F: std::future::Future<Output = Option<u16>> + Send + 'static>(
    futures: Vec<F>,
) -> Vec<Option<u16>> {
    let mut handles = Vec::with_capacity(futures.len());
    for f in futures {
        handles.push(tokio::spawn(f));
    }
    let mut results = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(res) = h.await {
            results.push(res);
        } else {
            results.push(None);
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports() {
        assert_eq!(parse_ports("80, 443, 80"), vec![80, 443]);
        assert_eq!(parse_ports("8000-8003, 22"), vec![22, 8000, 8001, 8002, 8003]);
        assert_eq!(parse_ports(" 80 , 443 "), vec![80, 443]);
    }
}
