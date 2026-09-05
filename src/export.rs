use std::fs::File;
use std::io::Write;
use std::path::Path;
use crate::engine::scanner::HostResult;

pub fn export_to_csv<P: AsRef<Path>>(results: &[HostResult], path: P) -> Result<(), String> {
    let file = File::create(path).map_err(|e| e.to_string())?;
    let mut wtr = csv::Writer::from_writer(file);

    wtr.write_record([
        "IP Address",
        "Status",
        "Ping (ms)",
        "Hostname",
        "Open Ports",
        "MAC Address",
        "Vendor",
        "Web Title",
    ])
    .map_err(|e| e.to_string())?;

    for r in results {
        let status = if r.is_alive { "Alive" } else { "Dead" };
        let ping_str = r.ping_ms.map(|p| format!("{:.2}", p)).unwrap_or_default();
        let ports_str = r
            .open_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        let hostname = r.hostname.as_deref().unwrap_or_default();
        let mac = r.mac_address.as_deref().unwrap_or_default();
        let vendor = r.vendor.as_deref().unwrap_or_default();
        let web_title = r.web_title.as_deref().unwrap_or_default();

        wtr.write_record([
            &r.ip.to_string(),
            status,
            &ping_str,
            hostname,
            &ports_str,
            mac,
            vendor,
            web_title,
        ])
        .map_err(|e| e.to_string())?;
    }

    wtr.flush().map_err(|e| e.to_string())?;
    Ok(())
}

pub fn export_to_json<P: AsRef<Path>>(results: &[HostResult], path: P) -> Result<(), String> {
    let file = File::create(path).map_err(|e| e.to_string())?;
    serde_json::to_writer_pretty(file, results).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn export_to_txt<P: AsRef<Path>>(results: &[HostResult], path: P, alive_only: bool) -> Result<(), String> {
    let mut file = File::create(path).map_err(|e| e.to_string())?;

    for r in results {
        if alive_only && !r.is_alive {
            continue;
        }
        let ping_str = r.ping_ms.map(|p| format!(" [ping: {:.1}ms]", p)).unwrap_or_default();
        let host_str = r.hostname.as_ref().map(|h| format!(" ({})", h)).unwrap_or_default();
        let ports_str = if !r.open_ports.is_empty() {
            format!(" [ports: {}]", r.open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","))
        } else {
            String::new()
        };

        writeln!(file, "{}{}{}{}", r.ip, host_str, ping_str, ports_str).map_err(|e| e.to_string())?;
    }

    Ok(())
}
