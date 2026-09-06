use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::str::FromStr;

/// Automatically detect the primary local network IP and generate default range
pub fn detect_local_range() -> Option<(Ipv4Addr, Ipv4Addr, Ipv4Addr)> {
    if let Ok(local_ip) = local_ip_address::local_ip() {
        if let IpAddr::V4(ipv4) = local_ip {
            let octets = ipv4.octets();
            let start = Ipv4Addr::new(octets[0], octets[1], octets[2], 1);
            let end = Ipv4Addr::new(octets[0], octets[1], octets[2], 254);
            return Some((ipv4, start, end));
        }
    }
    None
}

/// Generate a list of IP addresses between start and end (inclusive)
pub fn generate_range_v4(start: Ipv4Addr, end: Ipv4Addr) -> Vec<IpAddr> {
    let start_u32 = u32::from(start);
    let end_u32 = u32::from(end);

    let (low, high) = if start_u32 <= end_u32 {
        (start_u32, end_u32)
    } else {
        (end_u32, start_u32)
    };

    (low..=high)
        .map(|val| IpAddr::V4(Ipv4Addr::from(val)))
        .collect()
}

/// Generate IP addresses for a given IPv4 subnet (CIDR)
pub fn generate_from_cidr(cidr_str: &str) -> Result<Vec<IpAddr>, String> {
    let net = Ipv4Net::from_str(cidr_str).map_err(|e| format!("Invalid CIDR: {}", e))?;
    // Collect host addresses
    let hosts: Vec<IpAddr> = net.hosts().map(IpAddr::V4).collect();
    if hosts.is_empty() {
        // For /31 or /32 where hosts() might be empty or single
        Ok(vec![IpAddr::V4(net.addr())])
    } else {
        Ok(hosts)
    }
}

/// Parse a target string which could be:
/// - CIDR: "192.168.1.0/24"
/// - Range: "192.168.1.1 - 192.168.1.254" or "192.168.1.1-192.168.1.254"
/// - Short range: "192.168.1.1-254"
/// - Single IP: "192.168.1.10"
/// - Hostname: "google.com" or "localhost"
pub fn parse_target(target: &str) -> Result<Vec<IpAddr>, String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("Target cannot be empty".to_string());
    }

    // 1. Check for CIDR
    if target.contains('/') {
        return generate_from_cidr(target);
    }

    // 2. Check for Range (with dash)
    if let Some((start_part, end_part)) = target.split_once('-') {
        let start_str = start_part.trim();
        let end_str = end_part.trim();

        let start_ip = Ipv4Addr::from_str(start_str)
            .map_err(|e| format!("Invalid start IP '{}': {}", start_str, e))?;

        // Support short end octet, e.g. "192.168.1.1-254"
        let end_ip = if let Ok(last_octet) = end_str.parse::<u8>() {
            let octets = start_ip.octets();
            Ipv4Addr::new(octets[0], octets[1], octets[2], last_octet)
        } else {
            Ipv4Addr::from_str(end_str)
                .map_err(|e| format!("Invalid end IP '{}': {}", end_str, e))?
        };

        return Ok(generate_range_v4(start_ip, end_ip));
    }

    // 3. Check for single IP address
    if let Ok(ip) = IpAddr::from_str(target) {
        return Ok(vec![ip]);
    }

    // 4. Fallback to DNS hostname resolution
    let socket_str = format!("{}:80", target);
    if let Ok(addrs) = socket_str.to_socket_addrs() {
        let ips: Vec<IpAddr> = addrs.map(|s| s.ip()).collect();
        if !ips.is_empty() {
            return Ok(ips);
        }
    }

    Err(format!(
        "Unable to parse target '{}' as CIDR, IP range, or hostname",
        target
    ))
}

/// Generate N random IPv4 addresses (useful for random scanning feature of Angry IP Scanner)
pub fn generate_random_ips(count: usize) -> Vec<IpAddr> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let mut ips = Vec::with_capacity(count);
    for _ in 0..count {
        // simple xorshift64
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let b1 = ((seed >> 24) & 0xFF) as u8;
        let b2 = ((seed >> 16) & 0xFF) as u8;
        let b3 = ((seed >> 8) & 0xFF) as u8;
        let b4 = (seed & 0xFF) as u8;
        // Avoid 0.x.x.x, 127.x.x.x, 224-255 multicast/reserved
        let b1_clean = if b1 == 0 || b1 == 127 || b1 >= 224 {
            (b1 % 220) + 1
        } else {
            b1
        };
        ips.push(IpAddr::V4(Ipv4Addr::new(b1_clean, b2, b3, b4)));
    }
    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_parsing() {
        let ips = generate_from_cidr("192.168.1.0/30").unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(ips[1], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
    }

    #[test]
    fn test_range_parsing() {
        let ips = parse_target("10.0.0.1 - 10.0.0.3").unwrap();
        assert_eq!(ips.len(), 3);
        assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(ips[2], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)));
    }

    #[test]
    fn test_short_range_parsing() {
        let ips = parse_target("192.168.1.1-3").unwrap();
        assert_eq!(ips.len(), 3);
        assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(ips[2], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)));
    }
}
