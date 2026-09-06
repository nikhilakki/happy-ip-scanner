//! MAC address discovery through the operating system's ARP/neighbour cache.
//!
//! The scanner has just talked TCP to every alive host, so its entry is in the cache.

use std::net::IpAddr;

/// Normalise a MAC address to `AA:BB:CC:DD:EE:FF`.
///
/// macOS `arp` prints octets without zero padding (`3c:7:3f:1a:2b:c`) and Windows uses
/// dashes; both would otherwise break the OUI vendor lookup. Returns `None` for anything
/// that is not six hex octets, and for the all-zero placeholder of an incomplete entry.
pub fn normalize_mac(raw: &str) -> Option<String> {
    let parts: Vec<&str> = raw.trim().split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut octets = Vec::with_capacity(6);
    for part in parts {
        if part.is_empty() || part.len() > 2 || !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        octets.push(format!("{:0>2}", part.to_ascii_uppercase()));
    }
    let mac = octets.join(":");
    (mac != "00:00:00:00:00:00").then_some(mac)
}

/// Parse `arp -n <ip>` output on macOS/BSD, e.g.
/// `? (192.168.1.1) at 3c:7c:3f:1a:2b:3c on en0 ifscope [ethernet]`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_bsd_arp(output: &str, ip: &str) -> Option<String> {
    let needle = format!("({ip})");
    output
        .lines()
        .filter(|line| line.contains(&needle))
        .find_map(|line| {
            let rest = &line[line.find(" at ")? + " at ".len()..];
            normalize_mac(rest.split_whitespace().next()?)
        })
}

/// Parse `/proc/net/arp` on Linux (header line, then whitespace separated columns:
/// `IP address, HW type, Flags, HW address, Mask, Device`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_net_arp(content: &str, ip: &str) -> Option<String> {
    content.lines().skip(1).find_map(|line| {
        let mut cols = line.split_whitespace();
        (cols.next()? == ip)
            .then(|| cols.nth(2))
            .flatten()
            .and_then(normalize_mac)
    })
}

/// Parse `arp -a <ip>` output on Windows, e.g.
/// `  192.168.1.1           3c-7c-3f-1a-2b-3c     dynamic`.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_windows_arp(output: &str, ip: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let mut cols = line.split_whitespace();
        (cols.next()? == ip)
            .then(|| cols.next())
            .flatten()
            .and_then(normalize_mac)
    })
}

/// Look up the MAC address for `ip` in the system ARP cache.
pub async fn lookup_mac(ip: IpAddr) -> Option<String> {
    let ip_str = ip.to_string();

    #[cfg(target_os = "macos")]
    {
        let output = tokio::process::Command::new("arp")
            .args(["-n", &ip_str])
            .output()
            .await
            .ok()?;
        parse_bsd_arp(&String::from_utf8_lossy(&output.stdout), &ip_str)
    }

    #[cfg(target_os = "linux")]
    {
        let content = tokio::fs::read_to_string("/proc/net/arp").await.ok()?;
        parse_proc_net_arp(&content, &ip_str)
    }

    #[cfg(target_os = "windows")]
    {
        let output = tokio::process::Command::new("arp")
            .args(["-a", &ip_str])
            .output()
            .await
            .ok()?;
        parse_windows_arp(&String::from_utf8_lossy(&output.stdout), &ip_str)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_padding_case_and_separators() {
        assert_eq!(
            normalize_mac("3c:7:3f:1a:2b:c"),
            Some("3C:07:3F:1A:2B:0C".into())
        );
        assert_eq!(
            normalize_mac("3C-7C-3F-1A-2B-3C"),
            Some("3C:7C:3F:1A:2B:3C".into())
        );
        assert_eq!(
            normalize_mac("b4:a7:c6:f9:80:be"),
            Some("B4:A7:C6:F9:80:BE".into())
        );
    }

    #[test]
    fn rejects_placeholders_and_garbage() {
        assert_eq!(normalize_mac("(incomplete)"), None);
        assert_eq!(normalize_mac("00:00:00:00:00:00"), None);
        assert_eq!(normalize_mac("3c:7c:3f:1a:2b"), None);
        assert_eq!(normalize_mac("zz:7c:3f:1a:2b:3c"), None);
        assert_eq!(normalize_mac(""), None);
    }

    #[test]
    fn parses_bsd_arp_output() {
        let out = "? (192.168.29.1) at b4:a7:c6:f9:80:be on en0 ifscope [ethernet]\n";
        assert_eq!(
            parse_bsd_arp(out, "192.168.29.1"),
            Some("B4:A7:C6:F9:80:BE".into())
        );
        let incomplete = "? (192.168.29.2) at (incomplete) on en0 ifscope [ethernet]\n";
        assert_eq!(parse_bsd_arp(incomplete, "192.168.29.2"), None);
        // Must not match 192.168.29.1 when asked for 192.168.29.10
        assert_eq!(parse_bsd_arp(out, "192.168.29.10"), None);
    }

    #[test]
    fn parses_proc_net_arp() {
        let content = "IP address       HW type     Flags       HW address            Mask     Device\n\
                       192.168.1.1      0x1         0x2         3c:7c:3f:1a:2b:3c     *        eth0\n\
                       192.168.1.10     0x1         0x0         00:00:00:00:00:00     *        eth0\n";
        assert_eq!(
            parse_proc_net_arp(content, "192.168.1.1"),
            Some("3C:7C:3F:1A:2B:3C".into())
        );
        assert_eq!(parse_proc_net_arp(content, "192.168.1.10"), None);
        assert_eq!(parse_proc_net_arp(content, "192.168.1.2"), None);
    }

    #[test]
    fn parses_windows_arp_output() {
        let out = "\nInterface: 192.168.1.10 --- 0xc\n  Internet Address      Physical Address      Type\n  192.168.1.1           3c-7c-3f-1a-2b-3c     dynamic\n";
        assert_eq!(
            parse_windows_arp(out, "192.168.1.1"),
            Some("3C:7C:3F:1A:2B:3C".into())
        );
        // The interface line contains "192.168.1.1" as a substring but is not a match.
        assert_eq!(parse_windows_arp(out, "192.168.1.10"), None);
    }
}
