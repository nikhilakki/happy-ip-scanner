use std::net::IpAddr;

/// Query system ARP cache for the MAC address of an IP address
pub async fn lookup_mac(ip: IpAddr) -> Option<String> {
    let ip_str = ip.to_string();

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = tokio::process::Command::new("arp")
            .args(["-n", &ip_str])
            .output()
            .await
        {
            let text = String::from_utf8_lossy(&output.stdout);
            // Example: ? (192.168.1.1) at 3c:7c:3f:1a:2b:3c on en0 ifscope [ethernet]
            if let Some(at_idx) = text.find(" at ") {
                let rest = &text[at_idx + 4..];
                if let Some(token) = rest.split_whitespace().next() {
                    let clean = token.trim();
                    if clean.contains(':') && !clean.contains("(incomplete)") {
                        return Some(clean.to_uppercase());
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = tokio::fs::read_to_string("/proc/net/arp").await {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 && parts[0] == ip_str {
                    let mac = parts[3];
                    if mac != "00:00:00:00:00:00" {
                        return Some(mac.to_uppercase());
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = tokio::process::Command::new("arp")
            .args(["-a", &ip_str])
            .output()
            .await
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                if line.contains(&ip_str) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let mac = parts[1];
                        if mac.contains('-') || mac.contains(':') {
                            return Some(mac.replace('-', ":").to_uppercase());
                        }
                    }
                }
            }
        }
    }

    None
}
