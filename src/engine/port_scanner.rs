use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// Parse a user-supplied port string like "80, 443, 8080" or "8000-8010, 22".
///
/// Returns a sorted, de-duplicated list. Unparsable pieces and port 0 are skipped.
pub fn parse_ports(port_str: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in port_str.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if let Some((start_s, end_s)) = part.split_once('-') {
            if let (Ok(start), Ok(end)) =
                (start_s.trim().parse::<u16>(), end_s.trim().parse::<u16>())
            {
                let (min, max) = if start <= end {
                    (start, end)
                } else {
                    (end, start)
                };
                ports.extend(min..=max);
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }

    ports.retain(|&p| p != 0);
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Join a port list for display, e.g. `format_ports(&[80, 443], ", ")` -> "80, 443".
pub fn format_ports(ports: &[u16], separator: &str) -> String {
    ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(separator)
}

/// Check whether a single TCP port accepts connections within the timeout.
pub async fn check_port(ip: IpAddr, port: u16, timeout_duration: Duration) -> bool {
    let addr = SocketAddr::new(ip, port);
    matches!(
        timeout(timeout_duration, TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

/// Scan a list of ports concurrently and return the open ones, sorted ascending.
///
/// `sockets` bounds how many connections may be in flight at once across the whole scan,
/// so a full 1-65535 sweep cannot exhaust the process's file descriptors.
pub async fn scan_ports(
    ip: IpAddr,
    ports: &[u16],
    timeout_duration: Duration,
    sockets: &Arc<Semaphore>,
) -> Vec<u16> {
    let mut tasks = JoinSet::new();
    for &port in ports {
        let Ok(permit) = sockets.clone().acquire_owned().await else {
            break;
        };
        tasks.spawn(async move {
            let _permit = permit;
            check_port(ip, port, timeout_duration).await.then_some(port)
        });
    }

    let mut open = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok(Some(port)) = result {
            open.push(port);
        }
    }
    open.sort_unstable();
    open
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn parses_lists_ranges_and_whitespace() {
        assert_eq!(parse_ports("80, 443, 80"), vec![80, 443]);
        assert_eq!(
            parse_ports("8000-8003, 22"),
            vec![22, 8000, 8001, 8002, 8003]
        );
        assert_eq!(parse_ports(" 80 , 443 "), vec![80, 443]);
    }

    #[test]
    fn handles_reversed_ranges_and_junk() {
        assert_eq!(parse_ports("25-22"), vec![22, 23, 24, 25]);
        assert_eq!(parse_ports("abc, 80, 70000, -, 0"), vec![80]);
        assert!(parse_ports("").is_empty());
        assert!(parse_ports(" , ,").is_empty());
    }

    #[test]
    fn formats_ports() {
        assert_eq!(format_ports(&[], ", "), "");
        assert_eq!(format_ports(&[80, 443], ", "), "80, 443");
        assert_eq!(format_ports(&[80, 443], ";"), "80;443");
    }

    #[tokio::test]
    async fn finds_open_port_on_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_port = listener.local_addr().unwrap().port();
        // Keep the listener alive for the duration of the scan.
        let _keep = &listener;

        let sockets = Arc::new(Semaphore::new(8));
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        // Port 1 is virtually never listening on loopback.
        let found = scan_ports(ip, &[1, open_port], Duration::from_secs(2), &sockets).await;
        assert_eq!(found, vec![open_port]);
    }
}
