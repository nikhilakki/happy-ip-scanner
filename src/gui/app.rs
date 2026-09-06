use eframe::egui;
use egui::{Color32, RichText, Vec2};
use egui_extras::{Column, TableBuilder};
use std::cmp::Ordering as CmpOrdering;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;

use crate::engine::ip_range::{
    detect_local_range, generate_from_cidr, generate_random_ips, generate_range_v4, parse_target,
};
use crate::engine::pinger::PingMethod;
use crate::engine::port_scanner::format_ports;
use crate::engine::scanner::{HostResult, ScanEvent, run_scan};
use crate::export::{export_to_csv, export_to_json, export_to_txt};
use crate::gui::preferences::{STORAGE_KEY, ScannerPreferences};

const COLOR_ALIVE_PORTS: Color32 = Color32::from_rgb(46, 204, 113);
const COLOR_ALIVE: Color32 = Color32::from_rgb(52, 152, 219);
const COLOR_DEAD: Color32 = Color32::from_rgb(231, 76, 60);
const COLOR_START: Color32 = Color32::from_rgb(39, 174, 96);
const COLOR_STOP: Color32 = Color32::from_rgb(192, 57, 43);

const NETMASK_CHOICES: [u8; 11] = [30, 29, 28, 27, 26, 25, 24, 23, 22, 20, 16];
const ROW_HEIGHT: f32 = 20.0;

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

/// Sortable table columns with their header labels, in display order.
const SORTABLE_COLUMNS: [(&str, SortColumn); 7] = [
    ("Status", SortColumn::Status),
    ("IP Address", SortColumn::Ip),
    ("Ping", SortColumn::Ping),
    ("Hostname", SortColumn::Hostname),
    ("Ports", SortColumn::Ports),
    ("MAC Address", SortColumn::Mac),
    ("Vendor", SortColumn::Vendor),
];

fn host_count(prefix: u8) -> u64 {
    (1u64 << (32 - u32::from(prefix))).saturating_sub(2)
}

/// Case-insensitive match against IP, hostname, vendor, and open ports. `query` must
/// already be lower-cased.
fn matches_filter(r: &HostResult, query: &str, alive_only: bool) -> bool {
    if alive_only && !r.is_alive {
        return false;
    }
    if query.is_empty() {
        return true;
    }
    let contains = |field: Option<&str>| {
        field
            .map(|s| s.to_lowercase().contains(query))
            .unwrap_or(false)
    };
    r.ip.to_string().contains(query)
        || contains(r.hostname.as_deref())
        || contains(r.vendor.as_deref())
        || r.open_ports.iter().any(|p| p.to_string().contains(query))
}

fn compare_hosts(a: &HostResult, b: &HostResult, column: SortColumn) -> CmpOrdering {
    match column {
        SortColumn::Status => a.is_alive.cmp(&b.is_alive),
        SortColumn::Ip => a.ip.cmp(&b.ip),
        SortColumn::Ping => {
            // Hosts without a ping time sort last in ascending order.
            let pa = a.ping_ms.unwrap_or(f64::INFINITY);
            let pb = b.ping_ms.unwrap_or(f64::INFINITY);
            pa.partial_cmp(&pb).unwrap_or(CmpOrdering::Equal)
        }
        SortColumn::Hostname => a.hostname.cmp(&b.hostname),
        SortColumn::Ports => a.open_ports.len().cmp(&b.open_ports.len()),
        SortColumn::Mac => a.mac_address.cmp(&b.mac_address),
        SortColumn::Vendor => a.vendor.cmp(&b.vendor),
    }
}

fn browser_url(ip: IpAddr, port: u16) -> String {
    let scheme = if matches!(port, 443 | 8443) {
        "https"
    } else {
        "http"
    };
    format!("{scheme}://{ip}:{port}")
}

pub struct HappyIpScannerApp {
    // Target inputs
    pub ip_from: String,
    pub ip_to: String,
    pub selected_netmask: u8,
    pub scan_mode: ScanMode,
    pub random_count: usize,

    // Scan execution state
    pub is_scanning: bool,
    pub scanned_count: usize,
    pub total_ips: usize,
    pub alive_count: usize,
    pub status_message: String,

    // Channel & cancellation for the running (or winding-down) scan
    pub cancel_token: Option<Arc<AtomicBool>>,
    pub rx: Option<mpsc::Receiver<ScanEvent>>,

    // Results, filter & sort
    pub results: Vec<HostResult>,
    pub filter_text: String,
    pub filter_alive_only: bool,
    pub sort_column: SortColumn,
    pub sort_ascending: bool,

    // Preferences & modals
    pub preferences: ScannerPreferences,
    pub show_preferences: bool,
}

impl Default for HappyIpScannerApp {
    fn default() -> Self {
        let (default_from, default_to) = match detect_local_range() {
            Some((_ip, start, end)) => (start.to_string(), end.to_string()),
            None => ("192.168.1.1".to_string(), "192.168.1.254".to_string()),
        };

        Self {
            ip_from: default_from,
            ip_to: default_to,
            selected_netmask: 24,
            scan_mode: ScanMode::IpRange,
            random_count: 50,

            is_scanning: false,
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
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut app = Self::default();
        if let Some(prefs) = cc.storage.and_then(|s| eframe::get_value(s, STORAGE_KEY)) {
            app.preferences = prefs;
        }
        app
    }

    fn scan_progress(&self) -> f32 {
        if self.total_ips == 0 {
            0.0
        } else {
            self.scanned_count as f32 / self.total_ips as f32
        }
    }

    fn update_to_ip_from_netmask(&mut self) {
        if let Ok(start_ip) = Ipv4Addr::from_str(self.ip_from.trim())
            && let Ok(ips) = generate_from_cidr(&format!("{start_ip}/{}", self.selected_netmask))
            && let Some(last) = ips.last()
        {
            self.ip_to = last.to_string();
        }
    }

    /// Build the target list from the current mode and inputs.
    fn targets(&self) -> Result<Vec<IpAddr>, String> {
        match self.scan_mode {
            ScanMode::Random => Ok(generate_random_ips(self.random_count)),
            ScanMode::Netmask => generate_from_cidr(&format!(
                "{}/{}",
                self.ip_from.trim(),
                self.selected_netmask
            )),
            ScanMode::IpRange => {
                let from = self.ip_from.trim();
                let to = self.ip_to.trim();
                match (Ipv4Addr::from_str(from), Ipv4Addr::from_str(to)) {
                    (Ok(start), Ok(end)) => Ok(generate_range_v4(start, end)),
                    // Let the "from" box accept anything the CLI accepts: a hostname,
                    // a CIDR, or a short range such as 192.168.1.1-254.
                    _ if to.is_empty() => parse_target(from),
                    _ => Err(format!("'{from}' to '{to}' is not a valid IPv4 range")),
                }
            }
        }
    }

    fn start_scan(&mut self) {
        if self.is_scanning {
            return;
        }

        let ips = match self.targets() {
            Ok(ips) if ips.is_empty() => {
                self.status_message = "No IP addresses to scan!".to_string();
                return;
            }
            Ok(ips) => ips,
            Err(e) => {
                self.status_message = format!("Error: {e}");
                return;
            }
        };

        // Abandon any previous scan that is still winding down.
        self.stop_scan();

        self.results.clear();
        self.is_scanning = true;
        self.scanned_count = 0;
        self.alive_count = 0;
        self.total_ips = ips.len();
        self.status_message = format!("Initializing scan of {} hosts...", self.total_ips);

        let (tx, rx) = mpsc::channel(256);
        let cancel_token = Arc::new(AtomicBool::new(false));
        self.cancel_token = Some(Arc::clone(&cancel_token));
        self.rx = Some(rx);

        tokio::spawn(run_scan(
            ips,
            self.preferences.to_scan_options(),
            cancel_token,
            tx,
        ));
    }

    fn stop_scan(&mut self) {
        if let Some(cancel) = self.cancel_token.take() {
            cancel.store(true, Ordering::Relaxed);
        }
        self.rx = None;
        if self.is_scanning {
            self.is_scanning = false;
            self.status_message = "Scan stopped by user.".to_string();
        }
    }

    fn clear_results(&mut self) {
        self.results.clear();
        self.scanned_count = 0;
        self.alive_count = 0;
        self.total_ips = 0;
        self.status_message = "Results cleared.".to_string();
    }

    /// Clicking the active column flips the direction; clicking another sorts it ascending.
    fn set_sort(&mut self, column: SortColumn) {
        if self.sort_column == column {
            self.sort_ascending = !self.sort_ascending;
        } else {
            self.sort_column = column;
            self.sort_ascending = true;
        }
        self.sort_results();
    }

    fn sort_results(&mut self) {
        let column = self.sort_column;
        let ascending = self.sort_ascending;
        self.results.sort_by(|a, b| {
            let ord = compare_hosts(a, b, column);
            if ascending { ord } else { ord.reverse() }
        });
    }

    /// Drain events from the running scan. Returns true when the scan has ended.
    fn process_scan_events(&mut self) -> bool {
        let Some(rx) = self.rx.as_mut() else {
            return false;
        };
        let mut finished = false;
        loop {
            match rx.try_recv() {
                Ok(ScanEvent::Started { total_ips }) => {
                    self.total_ips = total_ips;
                    self.status_message = format!("Scanning {total_ips} hosts...");
                }
                Ok(ScanEvent::Host(host)) => {
                    if host.is_alive {
                        self.alive_count += 1;
                    }
                    self.scanned_count += 1;
                    self.results.push(*host);
                    self.status_message = format!(
                        "Scanning: {}/{} completed ({} alive)",
                        self.scanned_count, self.total_ips, self.alive_count
                    );
                }
                Ok(ScanEvent::Finished {
                    total_scanned,
                    total_alive,
                    elapsed_secs,
                }) => {
                    self.status_message = format!(
                        "Finished in {elapsed_secs:.2}s: {total_scanned} scanned, {total_alive} alive"
                    );
                    finished = true;
                }
                Ok(ScanEvent::Stopped) => {
                    self.status_message = "Scan stopped by user.".to_string();
                    finished = true;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    // The scan task went away without a final event (it should not).
                    if !finished {
                        self.status_message = "Scan ended unexpectedly.".to_string();
                    }
                    finished = true;
                }
            }
            if finished {
                break;
            }
        }
        if finished {
            self.is_scanning = false;
            self.rx = None;
            self.cancel_token = None;
            self.sort_results();
        }
        finished
    }

    fn export_results(&mut self, result: std::io::Result<()>, what: &str) {
        self.status_message = match result {
            Ok(()) => format!("Exported {what}."),
            Err(e) => format!("Export error: {e}"),
        };
    }

    fn show_preferences_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_preferences;
        let mut close_clicked = false;
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
                    ui.label("Concurrency (hosts):");
                    ui.add(egui::Slider::new(&mut self.preferences.threads, 1..=500));
                });

                ui.horizontal(|ui| {
                    ui.label("Timeout (ms):");
                    ui.add(egui::Slider::new(
                        &mut self.preferences.timeout_ms,
                        100..=5000,
                    ));
                });

                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    ui.label("Ping Method:");
                    egui::ComboBox::from_id_salt("ping_method")
                        .selected_text(self.preferences.ping_method.label())
                        .show_ui(ui, |ui| {
                            for method in PingMethod::ALL {
                                ui.selectable_value(
                                    &mut self.preferences.ping_method,
                                    method,
                                    method.label(),
                                );
                            }
                        });
                });

                ui.add_space(5.0);
                ui.heading("Fetchers");
                ui.separator();
                ui.checkbox(
                    &mut self.preferences.resolve_hostname,
                    "Resolve Hostnames (Reverse DNS)",
                );
                ui.checkbox(
                    &mut self.preferences.lookup_mac,
                    "Lookup MAC Address & OUI Vendor",
                );
                ui.checkbox(
                    &mut self.preferences.fetch_web_title,
                    "Fetch Web Title / HTTP Banner",
                );
                ui.checkbox(
                    &mut self.preferences.scan_dead_hosts,
                    "Scan ports on hosts that don't respond to ping",
                );

                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.button("Restore Defaults").clicked() {
                        self.preferences = ScannerPreferences::default();
                    }
                    if ui.button("Close").clicked() {
                        close_clicked = true;
                    }
                });
            });
        self.show_preferences = open && !close_clicked;
    }

    fn show_top_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading(
                    RichText::new("⚡ Happy IP Scanner")
                        .strong()
                        .color(COLOR_ALIVE_PORTS),
                );
                ui.label(RichText::new(format!("v{}", env!("CARGO_PKG_VERSION"))).weak());

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("⚙ Preferences").clicked() {
                        self.show_preferences = true;
                    }

                    ui.add_enabled_ui(!self.results.is_empty(), |ui| {
                        ui.menu_button("💾 Export", |ui| self.show_export_menu(ui));
                    });

                    let clear = egui::Button::new("🗑 Clear");
                    if ui
                        .add_enabled(!self.is_scanning && !self.results.is_empty(), clear)
                        .clicked()
                    {
                        self.clear_results();
                    }
                });
            });

            ui.add_space(8.0);
            ui.separator();
            ui.add_space(6.0);

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
                        ui.selectable_value(
                            &mut self.scan_mode,
                            ScanMode::Netmask,
                            "Netmask / Subnet",
                        );
                        ui.selectable_value(&mut self.scan_mode, ScanMode::Random, "Random IPs");
                    });

                match self.scan_mode {
                    ScanMode::IpRange => {
                        ui.label("IP Range: from");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.ip_from)
                                .hint_text("IP, hostname or CIDR")
                                .desired_width(140.0),
                        );
                        ui.label("to");
                        ui.add(egui::TextEdit::singleline(&mut self.ip_to).desired_width(120.0));
                    }
                    ScanMode::Netmask => {
                        ui.label("IP:");
                        ui.add(egui::TextEdit::singleline(&mut self.ip_from).desired_width(120.0));
                        ui.label("Netmask:");
                        let mut changed = false;
                        egui::ComboBox::from_id_salt("netmask_combo")
                            .selected_text(format!(
                                "/{} ({} hosts)",
                                self.selected_netmask,
                                host_count(self.selected_netmask)
                            ))
                            .show_ui(ui, |ui| {
                                for mask in NETMASK_CHOICES {
                                    let text = format!("/{mask} ({} hosts)", host_count(mask));
                                    if ui
                                        .selectable_value(&mut self.selected_netmask, mask, text)
                                        .clicked()
                                    {
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

                if ui.button("📍 Local Subnet").clicked()
                    && let Some((_ip, start, end)) = detect_local_range()
                {
                    self.ip_from = start.to_string();
                    self.ip_to = end.to_string();
                    self.scan_mode = ScanMode::IpRange;
                }

                if self.is_scanning {
                    let stop = egui::Button::new(
                        RichText::new(" ⏹ Stop ")
                            .strong()
                            .size(14.0)
                            .color(Color32::WHITE),
                    )
                    .fill(COLOR_STOP);
                    if ui.add(stop).clicked() {
                        self.stop_scan();
                    }
                } else {
                    let start = egui::Button::new(
                        RichText::new(" ▶ Start ")
                            .strong()
                            .size(14.0)
                            .color(Color32::WHITE),
                    )
                    .fill(COLOR_START);
                    if ui.add(start).clicked() {
                        self.start_scan();
                    }
                }
            });

            ui.add_space(4.0);
        });
    }

    fn show_export_menu(&mut self, ui: &mut egui::Ui) {
        if ui.button("Export to CSV...").clicked() {
            ui.close_menu();
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("CSV Files", &["csv"])
                .set_file_name("scan_results.csv")
                .save_file()
            {
                let result = export_to_csv(&self.results, path);
                self.export_results(result, "all results to CSV");
            }
        }
        if ui.button("Export to JSON...").clicked() {
            ui.close_menu();
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("JSON Files", &["json"])
                .set_file_name("scan_results.json")
                .save_file()
            {
                let result = export_to_json(&self.results, path);
                self.export_results(result, "all results to JSON");
            }
        }
        if ui.button("Export alive hosts to TXT...").clicked() {
            ui.close_menu();
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("Text Files", &["txt"])
                .set_file_name("alive_hosts.txt")
                .save_file()
            {
                let alive: Vec<HostResult> = self
                    .results
                    .iter()
                    .filter(|r| r.is_alive)
                    .cloned()
                    .collect();
                let result = export_to_txt(&alive, path);
                self.export_results(result, "alive hosts to TXT");
            }
        }
    }

    fn show_bottom_panel(&self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new(&self.status_message).strong());

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let open_ports: usize = self.results.iter().map(|r| r.open_ports.len()).sum();
                    ui.label(
                        RichText::new(format!(
                            "Alive: {} | Ports Open: {} | Total: {}",
                            self.alive_count, open_ports, self.scanned_count
                        ))
                        .weak(),
                    );

                    ui.add(
                        egui::ProgressBar::new(self.scan_progress())
                            .show_percentage()
                            .desired_width(180.0),
                    );
                });
            });
            ui.add_space(4.0);
        });
    }

    fn show_results_panel(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("🔍 Filter:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter_text)
                        .hint_text("Search IP, hostname, vendor, port...")
                        .desired_width(220.0),
                );
                ui.checkbox(&mut self.filter_alive_only, "Show alive only");
            });

            let query = self.filter_text.trim().to_lowercase();
            let alive_only = self.filter_alive_only;
            let visible: Vec<usize> = self
                .results
                .iter()
                .enumerate()
                .filter(|(_, r)| matches_filter(r, &query, alive_only))
                .map(|(idx, _)| idx)
                .collect();

            ui.label(
                RichText::new(format!(
                    "Showing {} of {} results",
                    visible.len(),
                    self.results.len()
                ))
                .weak(),
            );

            ui.add_space(4.0);
            ui.separator();

            let mut clicked_sort = None;
            let sort_column = self.sort_column;
            let sort_ascending = self.sort_ascending;

            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::exact(70.0)) // Status
                .column(Column::initial(120.0).at_least(100.0)) // IP
                .column(Column::initial(70.0).at_least(50.0)) // Ping
                .column(Column::initial(160.0).at_least(100.0)) // Hostname
                .column(Column::initial(110.0).at_least(70.0)) // Ports
                .column(Column::initial(140.0).at_least(100.0)) // MAC
                .column(Column::initial(140.0).at_least(100.0)) // Vendor
                .column(Column::remainder()) // Web Title / Banner
                .header(24.0, |mut header| {
                    for (label, column) in SORTABLE_COLUMNS {
                        header.col(|ui| {
                            let text = if column == sort_column {
                                format!("{label} {}", if sort_ascending { "▲" } else { "▼" })
                            } else {
                                label.to_string()
                            };
                            if ui.button(text).clicked() {
                                clicked_sort = Some(column);
                            }
                        });
                    }
                    header.col(|ui| {
                        ui.label(RichText::new("Web Title / Info").strong());
                    });
                })
                .body(|body| {
                    // `rows` only lays out the visible rows, so large scans stay responsive.
                    body.rows(ROW_HEIGHT, visible.len(), |mut row| {
                        let r = &self.results[visible[row.index()]];
                        Self::show_result_row(&mut row, r);
                    });
                });

            if let Some(column) = clicked_sort {
                self.set_sort(column);
            }
        });
    }

    fn show_result_row(row: &mut egui_extras::TableRow<'_, '_>, r: &HostResult) {
        row.col(|ui| {
            let (text, color) = match (r.is_alive, r.open_ports.is_empty()) {
                (true, false) => ("● ALIVE", COLOR_ALIVE_PORTS),
                (true, true) => ("● ALIVE", COLOR_ALIVE),
                (false, _) => ("○ DEAD", COLOR_DEAD),
            };
            ui.label(RichText::new(text).color(color));
        });

        row.col(|ui| {
            let label = ui.selectable_label(false, r.ip.to_string());
            label.context_menu(|ui| {
                if ui.button("Copy IP Address").clicked() {
                    ui.ctx().copy_text(r.ip.to_string());
                    ui.close_menu();
                }
                if let Some(host) = &r.hostname
                    && ui.button("Copy Hostname").clicked()
                {
                    ui.ctx().copy_text(host.clone());
                    ui.close_menu();
                }
                if !r.open_ports.is_empty() {
                    ui.separator();
                    for &port in &r.open_ports {
                        let url = browser_url(r.ip, port);
                        if ui.button(format!("Open in Browser ({url})")).clicked() {
                            let _ = open::that(&url);
                            ui.close_menu();
                        }
                    }
                }
            });
        });

        row.col(|ui| match r.ping_ms {
            Some(ms) => {
                ui.label(format!("{ms:.1}ms"));
            }
            None => {
                ui.label(RichText::new("-").weak());
            }
        });

        row.col(|ui| {
            ui.label(r.hostname.as_deref().unwrap_or("-"));
        });

        row.col(|ui| {
            if r.open_ports.is_empty() {
                ui.label(RichText::new("-").weak());
            } else {
                ui.label(
                    RichText::new(format_ports(&r.open_ports, ", "))
                        .color(COLOR_ALIVE_PORTS)
                        .strong(),
                );
            }
        });

        row.col(|ui| {
            ui.label(r.mac_address.as_deref().unwrap_or("-"));
        });

        row.col(|ui| {
            ui.label(r.vendor.as_deref().unwrap_or("-"));
        });

        row.col(|ui| {
            ui.label(r.web_title.as_deref().unwrap_or("-"));
        });
    }
}

impl eframe::App for HappyIpScannerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.process_scan_events();

        // Keep polling for events until the scan has fully wound down, even after Stop.
        if self.rx.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }

        if self.show_preferences {
            self.show_preferences_window(ctx);
        }
        self.show_top_panel(ctx);
        self.show_bottom_panel(ctx);
        self.show_results_panel(ctx);
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, STORAGE_KEY, &self.preferences);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn host(ip: [u8; 4], alive: bool, hostname: Option<&str>, ports: Vec<u16>) -> HostResult {
        HostResult {
            ip: IpAddr::from(ip),
            is_alive: alive,
            ping_ms: alive.then_some(1.0),
            hostname: hostname.map(str::to_string),
            open_ports: ports,
            mac_address: None,
            vendor: Some("Acme".into()),
            web_title: None,
            comments: None,
        }
    }

    #[test]
    fn filter_matches_ip_hostname_vendor_and_ports() {
        let h = host([192, 168, 1, 5], true, Some("Printer.Local"), vec![9100]);
        assert!(matches_filter(&h, "", false));
        assert!(matches_filter(&h, "1.5", false));
        assert!(matches_filter(&h, "printer", false));
        assert!(matches_filter(&h, "acme", false));
        assert!(matches_filter(&h, "9100", false));
        assert!(!matches_filter(&h, "nas", false));

        let dead = host([192, 168, 1, 6], false, None, vec![]);
        assert!(matches_filter(&dead, "", false));
        assert!(!matches_filter(&dead, "", true));
    }

    #[test]
    fn sorting_toggles_direction_only_on_same_column() {
        let mut app = HappyIpScannerApp {
            results: vec![
                host([10, 0, 0, 2], true, Some("b"), vec![80]),
                host([10, 0, 0, 1], false, None, vec![]),
                host([10, 0, 0, 3], true, Some("a"), vec![80, 443]),
            ],
            ..Default::default()
        };

        app.set_sort(SortColumn::Ports);
        assert!(app.sort_ascending);
        let counts: Vec<usize> = app.results.iter().map(|r| r.open_ports.len()).collect();
        assert_eq!(counts, vec![0, 1, 2]);

        app.set_sort(SortColumn::Ports);
        assert!(!app.sort_ascending);
        let counts: Vec<usize> = app.results.iter().map(|r| r.open_ports.len()).collect();
        assert_eq!(counts, vec![2, 1, 0]);

        app.set_sort(SortColumn::Ip);
        assert!(app.sort_ascending);
        assert_eq!(app.results[0].ip, IpAddr::from([10, 0, 0, 1]));
    }

    #[test]
    fn hosts_without_ping_sort_last_ascending() {
        let mut app = HappyIpScannerApp {
            results: vec![
                host([10, 0, 0, 1], false, None, vec![]),
                host([10, 0, 0, 2], true, None, vec![]),
            ],
            ..Default::default()
        };
        app.set_sort(SortColumn::Ping);
        assert!(app.results[0].ping_ms.is_some());
    }

    #[test]
    fn targets_follow_the_selected_mode() {
        let mut app = HappyIpScannerApp {
            scan_mode: ScanMode::IpRange,
            ip_from: "10.0.0.1".into(),
            ip_to: "10.0.0.4".into(),
            ..Default::default()
        };
        assert_eq!(app.targets().unwrap().len(), 4);

        app.ip_from = "10.0.0.0/30".into();
        app.ip_to.clear();
        assert_eq!(app.targets().unwrap().len(), 2);

        app.ip_from = "not an ip".into();
        app.ip_to = "10.0.0.4".into();
        assert!(app.targets().is_err());

        app.scan_mode = ScanMode::Netmask;
        app.ip_from = "192.168.1.37".into();
        app.selected_netmask = 28;
        assert_eq!(app.targets().unwrap().len(), 14);

        app.scan_mode = ScanMode::Random;
        app.random_count = 7;
        assert_eq!(app.targets().unwrap().len(), 7);
    }

    #[test]
    fn netmask_host_counts_and_urls() {
        assert_eq!(host_count(24), 254);
        assert_eq!(host_count(30), 2);
        assert_eq!(
            browser_url(IpAddr::from([10, 0, 0, 1]), 443),
            "https://10.0.0.1:443"
        );
        assert_eq!(
            browser_url(IpAddr::from([10, 0, 0, 1]), 8080),
            "http://10.0.0.1:8080"
        );
    }
}
