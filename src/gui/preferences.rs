use crate::engine::pinger::PingMethod;
use crate::engine::port_scanner::parse_ports;
use crate::engine::scanner::ScanOptions;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerPreferences {
    pub ports_str: String,
    pub threads: usize,
    pub timeout_ms: u64,
    pub ping_method: PingMethod,
    pub resolve_hostname: bool,
    pub lookup_mac: bool,
    pub fetch_web_title: bool,
    pub scan_dead_hosts: bool,
}

impl Default for ScannerPreferences {
    fn default() -> Self {
        Self {
            ports_str: "80, 443, 22, 8080".to_string(),
            threads: 64,
            timeout_ms: 1000,
            ping_method: PingMethod::TcpPort,
            resolve_hostname: true,
            lookup_mac: true,
            fetch_web_title: true,
            scan_dead_hosts: false,
        }
    }
}

impl ScannerPreferences {
    pub fn to_scan_options(&self) -> ScanOptions {
        ScanOptions {
            ports: parse_ports(&self.ports_str),
            ping_method: self.ping_method,
            timeout_ms: self.timeout_ms,
            threads: self.threads,
            resolve_hostname: self.resolve_hostname,
            lookup_mac: self.lookup_mac,
            fetch_web_title: self.fetch_web_title,
            scan_dead_hosts: self.scan_dead_hosts,
        }
    }
}
