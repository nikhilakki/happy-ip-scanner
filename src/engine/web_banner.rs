use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Extract page title or server banner from an open web port
pub async fn fetch_web_title(ip: IpAddr, port: u16, timeout_duration: Duration) -> Option<String> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = match timeout(timeout_duration, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: HappyIpScanner/1.0\r\nConnection: close\r\n\r\n",
        ip
    );

    if (timeout(timeout_duration, stream.write_all(req.as_bytes())).await).is_err() {
        return None;
    }

    let mut buf = vec![0u8; 4096];
    let n = match timeout(timeout_duration, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return None,
    };

    let text = String::from_utf8_lossy(&buf[..n]);

    // Check for <title>
    let lower = text.to_lowercase();
    if let Some(start) = lower.find("<title>") {
        if let Some(end) = lower[start + 7..].find("</title>") {
            let title = text[start + 7..start + 7 + end].trim();
            if !title.is_empty() {
                return Some(title.to_string());
            }
        }
    }

    // Fallback: Check for Server header
    for line in text.lines() {
        if line.to_lowercase().starts_with("server:") {
            let srv = line["server:".len()..].trim();
            if !srv.is_empty() {
                return Some(format!("Server: {}", srv));
            }
        }
    }

    None
}
