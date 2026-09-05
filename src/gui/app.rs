use eframe::egui;
use egui::{Color32, RichText, Vec2};
use egui_extras::{Column, TableBuilder};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::engine::ip_range::{detect_local_range, generate_random_ips, generate_range_v4, parse_target};
use crate::engine::pinger::PingMethod;
use crate::engine::scanner::{run_scan, HostResult, ScanEvent};
use crate::export::{export_to_csv, export_to_json, export_to_txt};
use crate::gui::preferences::ScannerPreferences;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    IpRange,
    Netmask,
    Random,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    Status,
    Ip,
    Ping,
    Hostname,
    Ports,
    Mac,
    Vendor,
}

pub struct HappyIpScannerApp {
    // Target inputs
    pub ip_from: String,
    pub ip_to: String,
    pub selected_netmask: u8,
    pub scan_mode: ScanMode,
    pub random_count: usize,

    // Scan Execution State
    pub is_scanning: bool,
    pub scan_progress: f32,
    pub scanned_count: usize,
    pub total_ips: usize,
    pub alive_count: usize,
    pub status_message: String,

    // Channels & Cancellation
    pub cancel_token: Option<Arc<AtomicBool>>,
    pub rx: Option<mpsc::Receiver<ScanEvent>>,

    // Results & Filter/Sort
    pub results: Vec<HostResult>,
    pub filter_text: String,
    pub filter_alive_only: bool,
    pub sort_column: SortColumn,
    pub sort_ascending: bool,

    // Preferences & Modals
    pub preferences: ScannerPreferences,
    pub show_preferences: bool,
}

impl Default for HappyIpScannerApp {
    fn default() -> Self {
        let (default_from, default_to) = if let Some((_ip, start, end)) = detect_local_range() {
            (start.to_string(), end.to_string())
        } else {
            ("192.168.1.1".to_string(), "192.168.1.254".to_string())
        };

        Self {
            ip_from: default_from,
            ip_to: default_to,
            selected_netmask: 24,
            scan_mode: ScanMode::IpRange,
            random_count: 50,

            is_scanning: false,
            scan_progress: 0.0,
            scanned_count: 0,
            total_ips: 0,
            alive_count: 0,
            status_message: "Ready to scan. Click 'Start' to begin.".to_string(),

            cancel_token: None,
            rx: None,

            results: Vec::new(),
            filter_text: String::new(),
            filter_alive_only: false,
            sort_column: SortColumn::Ip,
            sort_ascending: true,

            preferences: ScannerPreferences::default(),
            show_preferences: false,
        }
    }
}

impl HappyIpScannerApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self::default()
    }

    fn update_to_ip_from_netmask(&mut self) {
        if let Ok(start_ip) = Ipv4Addr::from_str(&self.ip_from) {
            let cidr_str = format!("{}/{}", start_ip, self.selected_netmask);
            if let Ok(ips) = crate::engine::ip_range::generate_from_cidr(&cidr_str) {
                if let Some(last) = ips.last() {
                    self.ip_to = last.to_string();
                }
            }
        }
    }

    fn start_scan(&mut self) {
        if self.is_scanning {
            return;
        }

        // Determine target IPs
        let ips: Vec<IpAddr> = match self.scan_mode {
            ScanMode::Random => generate_random_ips(self.random_count),
            ScanMode::Netmask => {
                let cidr_str = format!("{}/{}", self.ip_from.trim(), self.selected_netmask);
                match crate::engine::ip_range::generate_from_cidr(&cidr_str) {
                    Ok(list) => list,
                    Err(e) => {
                        self.status_message = format!("Error: {}", e);
                        return;
                    }
                }
            }
            ScanMode::IpRange => {
                let from_res = Ipv4Addr::from_str(self.ip_from.trim());
                let to_res = Ipv4Addr::from_str(self.ip_to.trim());
                match (from_res, to_res) {
                    (Ok(start), Ok(end)) => generate_range_v4(start, end),
                    _ => {
                        // Fallback target parser
                        let combined = format!("{}-{}", self.ip_from.trim(), self.ip_to.trim());
                        match parse_target(&combined) {
                            Ok(list) => list,
                            Err(e) => {
                                self.status_message = format!("Invalid IP Range: {}", e);
                                return;
                            }
                        }
                    }
                }
            }
        };

        if ips.is_empty() {
            self.status_message = "No IP addresses to scan!".to_string();
            return;
        }

        self.results.clear();
        self.is_scanning = true;
        self.scanned_count = 0;
        self.alive_count = 0;
        self.total_ips = ips.len();
        self.scan_progress = 0.0;
        self.status_message = format!("Initializing scan of {} hosts...", self.total_ips);

        let (tx, rx) = mpsc::channel(256);
        let cancel_token = Arc::new(AtomicBool::new(false));
        self.cancel_token = Some(cancel_token.clone());
        self.rx = Some(rx);

        let scan_opts = self.preferences.to_scan_options();

        tokio::spawn(run_scan(ips, scan_opts, cancel_token, tx));
    }

    fn stop_scan(&mut self) {
        if let Some(cancel) = &self.cancel_token {
            cancel.store(true, Ordering::Relaxed);
        }
        self.is_scanning = false;
        self.status_message = "Stopping scan...".to_string();
    }

    fn sort_results(&mut self) {
        let asc = self.sort_ascending;
        match self.sort_column {
            SortColumn::Status => {
                self.results.sort_by(|a, b| {
                    let ord = a.is_alive.cmp(&b.is_alive);
                    if asc { ord } else { ord.reverse() }
                });
            }
            SortColumn::Ip => {
                self.results.sort_by(|a, b| {
                    let ord = a.ip.cmp(&b.ip);
                    if asc { ord } else { ord.reverse() }
                });
            }
            SortColumn::Ping => {
                self.results.sort_by(|a, b| {
                    let pa = a.ping_ms.unwrap_or(99999.0);
                    let pb = b.ping_ms.unwrap_or(99999.0);
                    let ord = pa.partial_cmp(&pb).unwrap_or(std::cmp::Ordering::Equal);
                    if asc { ord } else { ord.reverse() }
                });
            }
            SortColumn::Hostname => {
                self.results.sort_by(|a, b| {
                    let ha = a.hostname.as_deref().unwrap_or("");
                    let hb = b.hostname.as_deref().unwrap_or("");
                    let ord = ha.cmp(hb);
                    if asc { ord } else { ord.reverse() }
                });
            }
            SortColumn::Ports => {
                self.results.sort_by(|a, b| {
                    let ord = a.open_ports.len().cmp(&b.open_ports.len());
                    if asc { ord } else { ord.reverse() }
                });
            }
            SortColumn::Mac => {
                self.results.sort_by(|a, b| {
                    let ma = a.mac_address.as_deref().unwrap_or("");
                    let mb = b.mac_address.as_deref().unwrap_or("");
                    let ord = ma.cmp(mb);
                    if asc { ord } else { ord.reverse() }
                });
            }
            SortColumn::Vendor => {
                self.results.sort_by(|a, b| {
                    let va = a.vendor.as_deref().unwrap_or("");
                    let vb = b.vendor.as_deref().unwrap_or("");
                    let ord = va.cmp(vb);
                    if asc { ord } else { ord.reverse() }
                });
            }
        }
    }
}

impl eframe::App for HappyIpScannerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 1. Process background scan events
        let mut should_sort = false;
        if let Some(rx) = &mut self.rx {
            while let Ok(event) = rx.try_recv() {
                match event {
                    ScanEvent::Started { total_ips } => {
                        self.total_ips = total_ips;
                        self.status_message = format!("Scanning {} hosts...", total_ips);
                    }
                    ScanEvent::Host(host) => {
                        if host.is_alive {
                            self.alive_count += 1;
                        }
                        self.results.push(*host);
                    }
                    ScanEvent::Progress { scanned, total, alive } => {
                        self.scanned_count = scanned;
                        self.alive_count = alive;
                        self.scan_progress = if total > 0 {
                            scanned as f32 / total as f32
                        } else {
                            0.0
                        };
                        self.status_message = format!(
                            "Scanning: {}/{} completed ({} alive)",
                            scanned, total, alive
                        );
                    }
                    ScanEvent::Finished {
                        total_scanned,
                        total_alive,
                        elapsed_secs,
                    } => {
                        self.is_scanning = false;
                        self.scan_progress = 1.0;
                        should_sort = true;
                        self.status_message = format!(
                            "Finished in {:.2}s: {} scanned, {} alive",
                            elapsed_secs, total_scanned, total_alive
                        );
                    }
                    ScanEvent::Stopped => {
                        self.is_scanning = false;
                        should_sort = true;
                        self.status_message = "Scan stopped by user.".to_string();
                    }
                }
            }
        }
        if should_sort {
            self.sort_results();
        }

        if self.is_scanning {
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }

        // 2. Preferences Window Modal
        if self.show_preferences {
            let mut open = self.show_preferences;
            let mut should_close = false;
            egui::Window::new("⚙ Settings & Preferences")
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.add_space(5.0);
                    ui.heading("Scanning Options");
                    ui.separator();

                    ui.horizontal(|ui| {
                        ui.label("Ports to scan:");
                        ui.text_edit_singleline(&mut self.preferences.ports_str);
                    });
                    ui.small("Comma separated, e.g. 80, 443, 22, 8000-8010");

                    ui.add_space(5.0);
                    ui.horizontal(|ui| {
                        ui.label("Concurrency (threads):");
                        ui.add(egui::Slider::new(&mut self.preferences.threads, 1..=500));
                    });

                    ui.horizontal(|ui| {
                        ui.label("Timeout (ms):");
                        ui.add(egui::Slider::new(&mut self.preferences.timeout_ms, 100..=5000));
                    });

                    ui.add_space(5.0);
                    ui.horizontal(|ui| {
                        ui.label("Ping Method:");
                        egui::ComboBox::from_id_salt("ping_method")
                            .selected_text(match self.preferences.ping_method {
                                PingMethod::TcpPort => "TCP Port Ping (Fast, No Root)",
                                PingMethod::Combined => "Combined (TCP + ICMP Fallback)",
                                PingMethod::AlwaysScan => "Always Scan (Scan all ports)",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.preferences.ping_method,
                                    PingMethod::TcpPort,
                                    "TCP Port Ping (Fast, No Root)",
                                );
                                ui.selectable_value(
                                    &mut self.preferences.ping_method,
                                    PingMethod::Combined,
                                    "Combined (TCP + ICMP Fallback)",
                                );
                                ui.selectable_value(
                                    &mut self.preferences.ping_method,
                                    PingMethod::AlwaysScan,
                                    "Always Scan (Scan all ports)",
                                );
                            });
                    });

                    ui.add_space(5.0);
                    ui.heading("Fetchers");
                    ui.separator();
                    ui.checkbox(&mut self.preferences.resolve_hostname, "Resolve Hostnames (Reverse DNS)");
                    ui.checkbox(&mut self.preferences.lookup_mac, "Lookup MAC Address & OUI Vendor");
                    ui.checkbox(&mut self.preferences.fetch_web_title, "Fetch Web Title / HTTP Banner");
                    ui.checkbox(&mut self.preferences.scan_dead_hosts, "Scan ports on hosts that don't respond to ping");

                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("Restore Defaults").clicked() {
                            self.preferences = ScannerPreferences::default();
                        }
                        if ui.button("Close").clicked() {
                            should_close = true;
                        }
                    });
                });
            if should_close {
                open = false;
            }
            self.show_preferences = open;
        }

        // 3. Top Control Panel
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading(RichText::new("⚡ Happy IP Scanner").strong().color(Color32::from_rgb(46, 204, 113)));
                ui.label(RichText::new(format!("v{}", env!("CARGO_PKG_VERSION"))).weak());

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("⚙ Preferences").clicked() {
                        self.show_preferences = true;
                    }

                    // Export Menu Button
                    egui::ComboBox::from_id_salt("export_combo")
                        .selected_text("💾 Export Results")
                        .show_ui(ui, |ui| {
                            if ui.button("Export to CSV...").clicked() {
                                if let Some(path) = rfd::FileDialog::new()
                                    .add_filter("CSV Files", &["csv"])
                                    .set_file_name("scan_results.csv")
                                    .save_file()
                                {
                                    if let Err(e) = export_to_csv(&self.results, path) {
                                        self.status_message = format!("Export error: {}", e);
                                    } else {
                                        self.status_message = "Successfully exported to CSV!".to_string();
                                    }
                                }
                            }
                            if ui.button("Export to JSON...").clicked() {
                                if let Some(path) = rfd::FileDialog::new()
                                    .add_filter("JSON Files", &["json"])
                                    .set_file_name("scan_results.json")
                                    .save_file()
                                {
                                    if let Err(e) = export_to_json(&self.results, path) {
                                        self.status_message = format!("Export error: {}", e);
                                    } else {
                                        self.status_message = "Successfully exported to JSON!".to_string();
                                    }
                                }
                            }
                            if ui.button("Export to TXT (Alive hosts)...").clicked() {
                                if let Some(path) = rfd::FileDialog::new()
                                    .add_filter("Text Files", &["txt"])
                                    .set_file_name("alive_hosts.txt")
                                    .save_file()
                                {
                                    if let Err(e) = export_to_txt(&self.results, path, true) {
                                        self.status_message = format!("Export error: {}", e);
                                    } else {
                                        self.status_message = "Successfully exported to TXT!".to_string();
                                    }
                                }
                            }
                        });

                    if ui.button("🗑 Clear").clicked() {
                        self.results.clear();
                        self.scanned_count = 0;
                        self.alive_count = 0;
                        self.total_ips = 0;
                        self.scan_progress = 0.0;
                        self.status_message = "Results cleared.".to_string();
                    }
                });
            });

            ui.add_space(8.0);
            ui.separator();
            ui.add_space(6.0);

            // Range / Mode Controls
            ui.horizontal(|ui| {
                ui.label(RichText::new("Mode:").strong());
                egui::ComboBox::from_id_salt("scan_mode_combo")
                    .selected_text(match self.scan_mode {
                        ScanMode::IpRange => "IP Range",
                        ScanMode::Netmask => "Netmask / Subnet",
                        ScanMode::Random => "Random IPs",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.scan_mode, ScanMode::IpRange, "IP Range");
                        ui.selectable_value(&mut self.scan_mode, ScanMode::Netmask, "Netmask / Subnet");
                        ui.selectable_value(&mut self.scan_mode, ScanMode::Random, "Random IPs");
                    });

                match self.scan_mode {
                    ScanMode::IpRange => {
                        ui.label("IP Range: from");
                        ui.add(egui::TextEdit::singleline(&mut self.ip_from).desired_width(120.0));
                        ui.label("to");
                        ui.add(egui::TextEdit::singleline(&mut self.ip_to).desired_width(120.0));
                    }
                    ScanMode::Netmask => {
                        ui.label("IP:");
                        ui.add(egui::TextEdit::singleline(&mut self.ip_from).desired_width(120.0));
                        ui.label("Netmask:");
                        let mut changed = false;
                        egui::ComboBox::from_id_salt("netmask_combo")
                            .selected_text(format!("/{} ({} hosts)", self.selected_netmask, (1u64 << (32 - self.selected_netmask)).saturating_sub(2)))
                            .show_ui(ui, |ui| {
                                for &m in &[30, 29, 28, 27, 26, 25, 24, 23, 22, 20, 16] {
                                    let hosts = (1u64 << (32 - m)).saturating_sub(2);
                                    if ui.selectable_value(&mut self.selected_netmask, m, format!("/{} ({} hosts)", m, hosts)).clicked() {
                                        changed = true;
                                    }
                                }
                            });
                        if changed {
                            self.update_to_ip_from_netmask();
                        }
                    }
                    ScanMode::Random => {
                        ui.label("Random IPs Count:");
                        ui.add(egui::Slider::new(&mut self.random_count, 10..=1000));
                    }
                }

                // Quick Local Subnet Reset button
                if ui.button("📍 Local Subnet").clicked() {
                    if let Some((_ip, start, end)) = detect_local_range() {
                        self.ip_from = start.to_string();
                        self.ip_to = end.to_string();
                        self.scan_mode = ScanMode::IpRange;
                    }
                }

                // Start / Stop Button
                if !self.is_scanning {
                    let start_btn = egui::Button::new(RichText::new(" ▶ Start ").strong().size(14.0).color(Color32::WHITE))
                        .fill(Color32::from_rgb(39, 174, 96));
                    if ui.add(start_btn).clicked() {
                        self.start_scan();
                    }
                } else {
                    let stop_btn = egui::Button::new(RichText::new(" ⏹ Stop ").strong().size(14.0).color(Color32::WHITE))
                        .fill(Color32::from_rgb(192, 57, 43));
                    if ui.add(stop_btn).clicked() {
                        self.stop_scan();
                    }
                }
            });

            ui.add_space(4.0);
        });

        // 4. Bottom Status & Statistics Panel
        egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                // Status Text
                ui.label(RichText::new(&self.status_message).strong());

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let open_ports_count: usize = self.results.iter().map(|r| r.open_ports.len()).sum();
                    ui.label(RichText::new(format!(
                        "Alive: {} | Ports Open: {} | Total: {}",
                        self.alive_count, open_ports_count, self.scanned_count
                    )).weak());

                    let progress_bar = egui::ProgressBar::new(self.scan_progress)
                        .show_percentage()
                        .desired_width(180.0);
                    ui.add(progress_bar);
                });
            });
            ui.add_space(4.0);
        });

        // 5. Central Panel: Filter & Results Table
        egui::CentralPanel::default().show(ctx, |ui| {
            // Search & Filter Toolbar
            ui.horizontal(|ui| {
                ui.label("🔍 Filter:");
                ui.add(egui::TextEdit::singleline(&mut self.filter_text).hint_text("Search IP, hostname, vendor...").desired_width(200.0));

                ui.checkbox(&mut self.filter_alive_only, "Show alive only");

                let filtered_count = self.results.iter().filter(|r| {
                    if self.filter_alive_only && !r.is_alive {
                        return false;
                    }
                    if self.filter_text.is_empty() {
                        return true;
                    }
                    let query = self.filter_text.to_lowercase();
                    r.ip.to_string().contains(&query)
                        || r.hostname.as_deref().unwrap_or("").to_lowercase().contains(&query)
                        || r.vendor.as_deref().unwrap_or("").to_lowercase().contains(&query)
                        || r.open_ports.iter().any(|p| p.to_string().contains(&query))
                }).count();

                ui.label(RichText::new(format!("Showing {} of {} results", filtered_count, self.results.len())).weak());
            });

            ui.add_space(4.0);
            ui.separator();

            // Results Table
            let table = TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::exact(65.0))   // Status
                .column(Column::initial(120.0).at_least(100.0)) // IP
                .column(Column::initial(70.0).at_least(50.0))   // Ping
                .column(Column::initial(160.0).at_least(100.0)) // Hostname
                .column(Column::initial(110.0).at_least(70.0))  // Ports
                .column(Column::initial(130.0).at_least(100.0)) // MAC
                .column(Column::initial(140.0).at_least(100.0)) // Vendor
                .column(Column::remainder());                    // Web Title / Banner

            table
                .header(24.0, |mut header| {
                    header.col(|ui| {
                        if ui.button("Status").clicked() {
                            self.sort_column = SortColumn::Status;
                            self.sort_ascending = !self.sort_ascending;
                            self.sort_results();
                        }
                    });
                    header.col(|ui| {
                        if ui.button("IP Address").clicked() {
                            self.sort_column = SortColumn::Ip;
                            self.sort_ascending = !self.sort_ascending;
                            self.sort_results();
                        }
                    });
                    header.col(|ui| {
                        if ui.button("Ping").clicked() {
                            self.sort_column = SortColumn::Ping;
                            self.sort_ascending = !self.sort_ascending;
                            self.sort_results();
                        }
                    });
                    header.col(|ui| {
                        if ui.button("Hostname").clicked() {
                            self.sort_column = SortColumn::Hostname;
                            self.sort_ascending = !self.sort_ascending;
                            self.sort_results();
                        }
                    });
                    header.col(|ui| {
                        if ui.button("Ports").clicked() {
                            self.sort_column = SortColumn::Ports;
                            self.sort_ascending = !self.sort_ascending;
                            self.sort_results();
                        }
                    });
                    header.col(|ui| {
                        if ui.button("MAC Address").clicked() {
                            self.sort_column = SortColumn::Mac;
                            self.sort_ascending = !self.sort_ascending;
                            self.sort_results();
                        }
                    });
                    header.col(|ui| {
                        if ui.button("Vendor").clicked() {
                            self.sort_column = SortColumn::Vendor;
                            self.sort_ascending = !self.sort_ascending;
                            self.sort_results();
                        }
                    });
                    header.col(|ui| {
                        ui.label(RichText::new("Web Title / Info").strong());
                    });
                })
                .body(|mut body| {
                    let filter_alive = self.filter_alive_only;
                    let filter_query = self.filter_text.to_lowercase();

                    let matching_indices: Vec<usize> = self.results
                        .iter()
                        .enumerate()
                        .filter_map(|(idx, r)| {
                            if filter_alive && !r.is_alive {
                                return None;
                            }
                            if !filter_query.is_empty() {
                                let matches = r.ip.to_string().contains(&filter_query)
                                    || r.hostname.as_deref().unwrap_or("").to_lowercase().contains(&filter_query)
                                    || r.vendor.as_deref().unwrap_or("").to_lowercase().contains(&filter_query)
                                    || r.open_ports.iter().any(|p| p.to_string().contains(&filter_query));
                                if !matches {
                                    return None;
                                }
                            }
                            Some(idx)
                        })
                        .collect();

                    for idx in matching_indices {
                        let r = &self.results[idx];
                        body.row(20.0, |mut row| {
                            // Status
                            row.col(|ui| {
                                if r.is_alive {
                                    if !r.open_ports.is_empty() {
                                        ui.label(RichText::new("● ALIVE").color(Color32::from_rgb(46, 204, 113)));
                                    } else {
                                        ui.label(RichText::new("● ALIVE").color(Color32::from_rgb(52, 152, 219)));
                                    }
                                } else {
                                    ui.label(RichText::new("○ DEAD").color(Color32::from_rgb(231, 76, 60)));
                                }
                            });

                            // IP Address with context menu
                            row.col(|ui| {
                                let label = ui.selectable_label(false, r.ip.to_string());
                                label.context_menu(|ui| {
                                    if ui.button("Copy IP Address").clicked() {
                                        ui.ctx().copy_text(r.ip.to_string());
                                        ui.close_menu();
                                    }
                                    if let Some(host) = &r.hostname {
                                        if ui.button("Copy Hostname").clicked() {
                                            ui.ctx().copy_text(host.clone());
                                            ui.close_menu();
                                        }
                                    }
                                    if !r.open_ports.is_empty() {
                                        ui.separator();
                                        for &port in &r.open_ports {
                                            let proto = if port == 443 { "https" } else { "http" };
                                            let url = format!("{}://{}:{}", proto, r.ip, port);
                                            if ui.button(format!("Open in Browser ({})", url)).clicked() {
                                                let _ = open::that(&url);
                                                ui.close_menu();
                                            }
                                        }
                                    }
                                });
                            });

                            // Ping RTT
                            row.col(|ui| {
                                if let Some(ms) = r.ping_ms {
                                    ui.label(format!("{:.1}ms", ms));
                                } else {
                                    ui.label(RichText::new("-").weak());
                                }
                            });

                            // Hostname
                            row.col(|ui| {
                                ui.label(r.hostname.as_deref().unwrap_or("-"));
                            });

                            // Ports
                            row.col(|ui| {
                                if r.open_ports.is_empty() {
                                    ui.label(RichText::new("-").weak());
                                } else {
                                    let text = r.open_ports
                                        .iter()
                                        .map(|p| p.to_string())
                                        .collect::<Vec<_>>()
                                        .join(", ");
                                    ui.label(RichText::new(text).color(Color32::from_rgb(46, 204, 113)).strong());
                                }
                            });

                            // MAC Address
                            row.col(|ui| {
                                ui.label(r.mac_address.as_deref().unwrap_or("-"));
                            });

                            // Vendor
                            row.col(|ui| {
                                ui.label(r.vendor.as_deref().unwrap_or("-"));
                            });

                            // Web Title / Banner
                            row.col(|ui| {
                                ui.label(r.web_title.as_deref().unwrap_or("-"));
                            });
                        });
                    }
                });
        });
    }
}

pub fn run_gui() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(Vec2::new(980.0, 640.0))
            .with_min_inner_size(Vec2::new(600.0, 400.0))
            .with_title("Happy IP Scanner"),
        ..Default::default()
    };

    eframe::run_native(
        "Happy IP Scanner",
        options,
        Box::new(|cc| Ok(Box::new(HappyIpScannerApp::new(cc)))),
    )
}
