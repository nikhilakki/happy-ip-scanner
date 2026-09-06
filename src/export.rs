//! Writers for the CSV, JSON and plain-text result formats.
//!
//! The `write_*` functions take any [`Write`] so results can go to a file or stdout; the
//! `export_to_*` helpers create the file for you.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use crate::engine::port_scanner::format_ports;
use crate::engine::scanner::HostResult;

/// Make a remote-supplied string safe to open in a spreadsheet.
///
/// A scanned host controls its reverse-DNS name and HTML title, so it could
/// return `=HYPERLINK(...)` or `+cmd|...` and have Excel or LibreOffice
/// evaluate it when the CSV is opened. Prefixing such cells with a single
/// quote makes spreadsheets treat them as plain text.
fn csv_text(value: &str) -> String {
    if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_string()
    }
}

pub fn write_csv<W: Write>(results: &[HostResult], writer: W) -> io::Result<()> {
    let mut wtr = csv::Writer::from_writer(writer);
    wtr.write_record([
        "IP Address",
        "Status",
        "Ping (ms)",
        "Hostname",
        "Open Ports",
        "MAC Address",
        "Vendor",
        "Web Title",
    ])?;

    for r in results {
        wtr.write_record([
            r.ip.to_string(),
            if r.is_alive { "Alive" } else { "Dead" }.to_string(),
            r.ping_ms.map(|p| format!("{p:.2}")).unwrap_or_default(),
            r.hostname.as_deref().map(csv_text).unwrap_or_default(),
            format_ports(&r.open_ports, "; "),
            r.mac_address.clone().unwrap_or_default(),
            r.vendor.as_deref().map(csv_text).unwrap_or_default(),
            r.web_title.as_deref().map(csv_text).unwrap_or_default(),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}

pub fn write_json<W: Write>(results: &[HostResult], mut writer: W) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut writer, results)?;
    writeln!(writer)?;
    writer.flush()
}

/// One host per line: `ip (hostname) [ping: 1.2ms] [ports: 80, 443]`.
pub fn write_txt<W: Write>(results: &[HostResult], mut writer: W) -> io::Result<()> {
    for r in results {
        let host = r
            .hostname
            .as_ref()
            .map(|h| format!(" ({h})"))
            .unwrap_or_default();
        let ping = r
            .ping_ms
            .map(|p| format!(" [ping: {p:.1}ms]"))
            .unwrap_or_default();
        let ports = if r.open_ports.is_empty() {
            String::new()
        } else {
            format!(" [ports: {}]", format_ports(&r.open_ports, ", "))
        };
        writeln!(writer, "{}{host}{ping}{ports}", r.ip)?;
    }
    writer.flush()
}

pub fn export_to_csv<P: AsRef<Path>>(results: &[HostResult], path: P) -> io::Result<()> {
    write_csv(results, BufWriter::new(File::create(path)?))
}

pub fn export_to_json<P: AsRef<Path>>(results: &[HostResult], path: P) -> io::Result<()> {
    write_json(results, BufWriter::new(File::create(path)?))
}

pub fn export_to_txt<P: AsRef<Path>>(results: &[HostResult], path: P) -> io::Result<()> {
    write_txt(results, BufWriter::new(File::create(path)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn sample() -> Vec<HostResult> {
        vec![
            HostResult {
                ip: IpAddr::from([192, 168, 1, 1]),
                is_alive: true,
                ping_ms: Some(1.234),
                hostname: Some("router.local".into()),
                open_ports: vec![80, 443],
                mac_address: Some("3C:7C:3F:1A:2B:3C".into()),
                vendor: Some("Apple, Inc.".into()),
                web_title: Some("Router, \"Admin\"".into()),
                comments: None,
            },
            HostResult {
                ip: IpAddr::from([192, 168, 1, 2]),
                is_alive: false,
                ping_ms: None,
                hostname: None,
                open_ports: vec![],
                mac_address: None,
                vendor: None,
                web_title: None,
                comments: None,
            },
        ]
    }

    #[test]
    fn csv_has_header_and_quotes_fields() {
        let mut out = Vec::new();
        write_csv(&sample(), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("IP Address,Status,Ping (ms)"));
        assert!(lines[1].contains("192.168.1.1,Alive,1.23,router.local,80; 443,"));
        assert!(lines[1].contains("\"Router, \"\"Admin\"\"\""));
        assert_eq!(lines[2], "192.168.1.2,Dead,,,,,,");
    }

    #[test]
    fn csv_neutralises_formula_injection() {
        let mut hostile = sample();
        hostile[0].hostname = Some("=HYPERLINK(\"http://evil\",\"click\")".into());
        hostile[0].web_title = Some("-2+3".into());
        hostile[0].vendor = Some("@SUM(1)".into());
        let mut out = Vec::new();
        write_csv(&hostile, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("\"'=HYPERLINK(\"\"http://evil\"\",\"\"click\"\")\""));
        assert!(text.contains(",'-2+3"));
        assert!(text.contains(",'@SUM(1),"));
        // IP addresses and MACs are never rewritten.
        assert!(text.contains("192.168.1.1,Alive"));
        assert!(text.contains("3C:7C:3F:1A:2B:3C"));
    }

    #[test]
    fn csv_text_leaves_ordinary_values_alone() {
        assert_eq!(csv_text("router.local"), "router.local");
        assert_eq!(csv_text("Apple, Inc."), "Apple, Inc.");
        assert_eq!(csv_text(""), "");
    }

    #[test]
    fn json_round_trips() {
        let mut out = Vec::new();
        write_json(&sample(), &mut out).unwrap();
        let parsed: Vec<HostResult> = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].open_ports, vec![80, 443]);
        assert!(!parsed[1].is_alive);
    }

    #[test]
    fn txt_is_one_line_per_host() {
        let mut out = Vec::new();
        write_txt(&sample(), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            "192.168.1.1 (router.local) [ping: 1.2ms] [ports: 80, 443]\n192.168.1.2\n"
        );
    }
}
