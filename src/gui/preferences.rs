use serde::{Deserialize, Serialize};

use crate::engine::pinger::PingMethod;
use crate::engine::port_scanner::parse_ports;
use crate::engine::scanner::ScanOptions;

/// Key under which preferences are stored by eframe between runs.
pub const STORAGE_KEY: &str = "preferences";

/// User-editable scan settings. `serde(default)` lets older saved files load after new
/// fields are added.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
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
        let defaults = ScanOptions::default();
        Self {
            ports_str: "80, 443, 22, 8080".to_string(),
            threads: defaults.threads,
            timeout_ms: defaults.timeout_ms,
            ping_method: defaults.ping_method,
            resolve_hostname: defaults.resolve_hostname,
            lookup_mac: defaults.lookup_mac,
            fetch_web_title: defaults.fetch_web_title,
            scan_dead_hosts: defaults.scan_dead_hosts,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_engine_defaults() {
        let opts = ScannerPreferences::default().to_scan_options();
        let engine = ScanOptions::default();
        assert_eq!(opts.ports, engine.ports);
        assert_eq!(opts.threads, engine.threads);
        assert_eq!(opts.timeout_ms, engine.timeout_ms);
    }

    #[test]
    fn missing_fields_fall_back_to_defaults() {
        let prefs: ScannerPreferences = serde_json::from_str(r#"{"threads": 12}"#).unwrap();
        assert_eq!(prefs.threads, 12);
        assert_eq!(prefs.ping_method, PingMethod::TcpPort);
        assert!(prefs.resolve_hostname);
    }
}
