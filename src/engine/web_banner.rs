use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};

/// Stop reading the response after this many bytes; titles live near the top of a page.
const MAX_RESPONSE_BYTES: usize = 16 * 1024;

/// Longest banner we keep, so a verbose title cannot blow up the results table.
const MAX_BANNER_CHARS: usize = 120;

/// Fetch `/` from an HTTP port and summarise the response as the page `<title>`, else the
/// `Server:` header, else the HTTP status line.
///
/// `timeout_duration` is a single deadline for the whole exchange. Whatever has been read by
/// then is still used, so a server that ignores `Connection: close` still yields a banner.
pub async fn fetch_web_title(ip: IpAddr, port: u16, timeout_duration: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout_duration;
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout_at(deadline, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let request = format!(
        "GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: HappyIpScanner/{}\r\nAccept: text/html,*/*\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    timeout_at(deadline, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut response = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    while response.len() < MAX_RESPONSE_BYTES {
        match timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => {
                response.extend_from_slice(&chunk[..n]);
                if has_complete_title(&response) {
                    break;
                }
            }
            // EOF, read error, or deadline reached: summarise what we have.
            _ => break,
        }
    }

    extract_banner(&String::from_utf8_lossy(&response))
}

fn has_complete_title(response: &[u8]) -> bool {
    String::from_utf8_lossy(response)
        .to_ascii_lowercase()
        .contains("</title>")
}

/// Summarise a raw HTTP response: `<title>` text, else the `Server:` header, else the status line.
pub fn extract_banner(response: &str) -> Option<String> {
    extract_title(response)
        .or_else(|| extract_server_header(response))
        .or_else(|| extract_status_line(response))
}

fn extract_title(html: &str) -> Option<String> {
    // ASCII lowercasing keeps byte offsets identical to the original text, so the indices
    // found below can be used to slice `html` safely.
    let lower = html.to_ascii_lowercase();
    let tag_start = lower.find("<title")?;
    let content_start = tag_start + lower[tag_start..].find('>')? + 1;
    let content_len = lower[content_start..].find("</title>")?;
    let title = collapse_whitespace(&decode_entities(
        &html[content_start..content_start + content_len],
    ));
    (!title.is_empty()).then(|| truncate(&title))
}

fn extract_server_header(response: &str) -> Option<String> {
    let headers = response.split("\r\n\r\n").next().unwrap_or(response);
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.trim().eq_ignore_ascii_case("server") {
            return None;
        }
        let value = value.trim();
        (!value.is_empty()).then(|| truncate(&format!("Server: {value}")))
    })
}

fn extract_status_line(response: &str) -> Option<String> {
    let first = response.lines().next()?.trim();
    if !first.starts_with("HTTP/") {
        return None;
    }
    // "HTTP/1.1 301 Moved Permanently" -> "301 Moved Permanently"
    let status = first.split_once(' ')?.1.trim();
    (!status.is_empty()).then(|| truncate(status))
}

fn decode_entities(text: &str) -> String {
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
}

fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate(text: &str) -> String {
    if text.chars().count() <= MAX_BANNER_CHARS {
        text.to_string()
    } else {
        let mut cut: String = text.chars().take(MAX_BANNER_CHARS - 1).collect();
        cut.push('…');
        cut
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_title_over_server_header() {
        let response = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<html><head><title>\n  My &amp; Router  \n</title></head></html>";
        assert_eq!(extract_banner(response), Some("My & Router".into()));
    }

    #[test]
    fn handles_title_attributes_and_mixed_case() {
        let response = "HTTP/1.1 200 OK\r\n\r\n<HTML><TITLE lang=\"en\">Dashboard</TITLE></HTML>";
        assert_eq!(extract_banner(response), Some("Dashboard".into()));
    }

    #[test]
    fn falls_back_to_server_header_then_status_line() {
        let with_server = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nserver:  Apache/2.4 \r\n\r\nnope";
        assert_eq!(
            extract_banner(with_server),
            Some("Server: Apache/2.4".into())
        );

        let status_only = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(extract_banner(status_only), Some("403 Forbidden".into()));

        assert_eq!(extract_banner(""), None);
        assert_eq!(extract_banner("garbage"), None);
    }

    #[test]
    fn ignores_server_header_inside_body() {
        let response = "HTTP/1.1 200 OK\r\n\r\nServer: fake-in-body";
        assert_eq!(extract_banner(response), Some("200 OK".into()));
    }

    #[test]
    fn non_ascii_before_title_does_not_break_slicing() {
        // 'İ' changes byte length under Unicode lowercasing; ASCII lowercasing must not.
        let response = "HTTP/1.1 200 OK\r\n\r\n<html><p>İstanbul Ünïcode</p><title>Ok</title>";
        assert_eq!(extract_banner(response), Some("Ok".into()));
    }

    #[test]
    fn truncates_long_titles() {
        let long = "x".repeat(500);
        let response = format!("HTTP/1.1 200 OK\r\n\r\n<title>{long}</title>");
        let banner = extract_banner(&response).unwrap();
        assert_eq!(banner.chars().count(), MAX_BANNER_CHARS);
        assert!(banner.ends_with('…'));
    }
}
