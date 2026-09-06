use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::str::FromStr;

/// Detect the primary local IPv4 address and derive a default `/24` range from it.
/// Returns `(local_ip, range_start, range_end)`.
pub fn detect_local_range() -> Option<(Ipv4Addr, Ipv4Addr, Ipv4Addr)> {
    match local_ip_address::local_ip().ok()? {
        IpAddr::V4(ipv4) => {
            let [a, b, c, _] = ipv4.octets();
            Some((ipv4, Ipv4Addr::new(a, b, c, 1), Ipv4Addr::new(a, b, c, 254)))
        }
        IpAddr::V6(_) => None,
    }
}

/// Generate every address between `start` and `end` inclusive, in ascending order
/// regardless of which bound is given first.
pub fn generate_range_v4(start: Ipv4Addr, end: Ipv4Addr) -> Vec<IpAddr> {
    let (low, high) = {
        let (s, e) = (u32::from(start), u32::from(end));
        if s <= e { (s, e) } else { (e, s) }
    };
    (low..=high)
        .map(|val| IpAddr::V4(Ipv4Addr::from(val)))
        .collect()
}

/// Generate the host addresses of an IPv4 subnet given in CIDR notation.
/// `/31` and `/32` networks, which have no "host" addresses, yield the network address itself.
pub fn generate_from_cidr(cidr_str: &str) -> Result<Vec<IpAddr>, String> {
    let net = Ipv4Net::from_str(cidr_str.trim()).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let hosts: Vec<IpAddr> = net.hosts().map(IpAddr::V4).collect();
    if hosts.is_empty() {
        Ok(vec![IpAddr::V4(net.addr())])
    } else {
        Ok(hosts)
    }
}

/// Interpret `target` as an IPv4 range if it looks like one.
///
/// Accepts `192.168.1.1-192.168.1.254`, `192.168.1.1 - 192.168.1.254` and the short form
/// `192.168.1.1-254`. Returns `None` when the text before the dash is not an IPv4 address,
/// so hostnames such as `my-nas.local` fall through to DNS resolution.
fn parse_range(target: &str) -> Option<Result<Vec<IpAddr>, String>> {
    let (start_str, end_str) = target.split_once('-')?;
    let start_ip = Ipv4Addr::from_str(start_str.trim()).ok()?;
    let end_str = end_str.trim();

    let end_ip = if let Ok(last_octet) = end_str.parse::<u8>() {
        let [a, b, c, _] = start_ip.octets();
        Ipv4Addr::new(a, b, c, last_octet)
    } else {
        match Ipv4Addr::from_str(end_str) {
            Ok(ip) => ip,
            Err(e) => return Some(Err(format!("Invalid end IP '{end_str}': {e}"))),
        }
    };

    Some(Ok(generate_range_v4(start_ip, end_ip)))
}

/// Parse a target expression into a list of addresses. Supported forms:
/// - CIDR: `192.168.1.0/24`
/// - Range: `192.168.1.1 - 192.168.1.254` or `192.168.1.1-192.168.1.254`
/// - Short range: `192.168.1.1-254`
/// - Single IP: `192.168.1.10` or `::1`
/// - Hostname: `router.local` or `scanme.nmap.org`
pub fn parse_target(target: &str) -> Result<Vec<IpAddr>, String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("Target cannot be empty".to_string());
    }

    if target.contains('/') {
        return generate_from_cidr(target);
    }

    if let Some(range) = parse_range(target) {
        return range;
    }

    if let Ok(ip) = IpAddr::from_str(target) {
        return Ok(vec![ip]);
    }

    if let Ok(addrs) = (target, 0u16).to_socket_addrs() {
        let mut ips: Vec<IpAddr> = addrs.map(|s| s.ip()).collect();
        ips.sort_unstable();
        ips.dedup();
        if !ips.is_empty() {
            return Ok(ips);
        }
    }

    Err(format!(
        "Unable to parse target '{target}' as CIDR, IP range, IP address, or hostname"
    ))
}

/// True for addresses that can exist on the public Internet, i.e. not private, loopback,
/// link-local, carrier-grade NAT, documentation, benchmarking, multicast or reserved space.
fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && ip.octets()[2] == 0)
        || (a == 198 && (18..=19).contains(&b)))
}

/// Generate `count` random public IPv4 addresses (the "random" scan feed of Angry IP Scanner).
pub fn generate_random_ips(count: usize) -> Vec<IpAddr> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    if seed == 0 {
        seed = 0x9E37_79B9_7F4A_7C15;
    }

    let mut ips = Vec::with_capacity(count);
    while ips.len() < count {
        // xorshift64
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let candidate = Ipv4Addr::from((seed >> 32) as u32);
        if is_public_ipv4(candidate) {
            ips.push(IpAddr::V4(candidate));
        }
    }
    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn cidr_parsing() {
        let ips = generate_from_cidr("192.168.1.0/30").unwrap();
        assert_eq!(ips, vec![v4(192, 168, 1, 1), v4(192, 168, 1, 2)]);
        assert_eq!(
            generate_from_cidr("10.0.0.5/32").unwrap(),
            vec![v4(10, 0, 0, 5)]
        );
        assert_eq!(generate_from_cidr("10.0.0.0/24").unwrap().len(), 254);
        assert!(generate_from_cidr("10.0.0.0/33").is_err());
    }

    #[test]
    fn range_parsing() {
        let ips = parse_target("10.0.0.1 - 10.0.0.3").unwrap();
        assert_eq!(ips, vec![v4(10, 0, 0, 1), v4(10, 0, 0, 2), v4(10, 0, 0, 3)]);
    }

    #[test]
    fn reversed_range_is_ascending() {
        let ips = parse_target("10.0.0.3-10.0.0.1").unwrap();
        assert_eq!(ips, vec![v4(10, 0, 0, 1), v4(10, 0, 0, 2), v4(10, 0, 0, 3)]);
    }

    #[test]
    fn short_range_parsing() {
        let ips = parse_target("192.168.1.1-3").unwrap();
        assert_eq!(
            ips,
            vec![v4(192, 168, 1, 1), v4(192, 168, 1, 2), v4(192, 168, 1, 3)]
        );
    }

    #[test]
    fn invalid_range_end_is_an_error() {
        let err = parse_target("192.168.1.1-999.1").unwrap_err();
        assert!(err.contains("Invalid end IP"), "{err}");
    }

    #[test]
    fn single_addresses() {
        assert_eq!(parse_target("1.1.1.1").unwrap(), vec![v4(1, 1, 1, 1)]);
        assert_eq!(
            parse_target("::1").unwrap(),
            vec![IpAddr::from_str("::1").unwrap()]
        );
        assert!(parse_target("   ").is_err());
    }

    #[test]
    fn hyphenated_hostnames_are_not_ranges() {
        assert!(parse_range("my-nas.local").is_none());
        assert!(parse_range("scanme-nmap.org").is_none());
        assert!(parse_range("192.168.1.1-254").is_some());
    }

    #[test]
    fn localhost_resolves() {
        let ips = parse_target("localhost").unwrap();
        assert!(ips.iter().any(|ip| ip.is_loopback()));
    }

    #[test]
    fn random_ips_are_public_and_counted() {
        let ips = generate_random_ips(200);
        assert_eq!(ips.len(), 200);
        for ip in ips {
            let IpAddr::V4(v4) = ip else {
                panic!("expected IPv4")
            };
            assert!(is_public_ipv4(v4), "{v4} is not public");
        }
    }

    #[test]
    fn public_ip_classification() {
        assert!(is_public_ipv4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(is_public_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
        for private in [
            Ipv4Addr::new(10, 1, 2, 3),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(0, 1, 2, 3),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(203, 0, 113, 9),
        ] {
            assert!(!is_public_ipv4(private), "{private} should not be public");
        }
    }
}
