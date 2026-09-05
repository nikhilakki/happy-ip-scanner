# ⚡ Happy IP Scanner

A fast, friendly, cross-platform IP address and port scanner written in **Rust**, inspired by and faithfully porting the classic **Angry IP Scanner**.

Happy IP Scanner features both a **modern Desktop GUI** (powered by `egui`) and an **ultra-fast command-line interface (CLI)**, designed for network administrators, penetration testers, and curious developers.

---

## ✨ Features

- 🖥️ **Modern Desktop GUI**:
  - Clean, responsive interface matching Angry IP Scanner's layout and workflow.
  - Interactive table with real-time streaming results and status indicators (🟢 Alive with open ports, 🔵 Alive, 🔴 Dead).
  - One-click **Local Subnet Auto-Detection** (identifies your active network adapter and auto-populates the `/24` subnet).
  - Quick column sorting (by IP, Ping RTT, Hostname, Ports, MAC Address, Vendor).
  - Instant search and filtering (search by IP, hostname, vendor, or toggle "Show alive only").
  - Right-click context menu: open in web browser (`http://` or `https://`), copy IP or hostname to clipboard.
- ⚡ **Ultra-Fast Asynchronous Engine**:
  - Powered by **Tokio** with configurable worker concurrency (default 64 threads, supports 500+ concurrent probes).
  - Scans typical `/24` subnets (254 hosts) in just a couple of seconds.
- 🎯 **Flexible Target Modes**:
  - **IP Range**: e.g. `192.168.1.1` to `192.168.1.254` or `192.168.1.1-254`.
  - **Netmask / CIDR**: e.g. `192.168.1.0/24`, `/16`, `/28`, etc.
  - **Random IPs**: Scan $N$ random IPv4 addresses across the Internet.
  - **Single IP / Hostnames**: e.g. `example.com` or `127.0.0.1`.
- 🔍 **Liveness Pingers & Probes**:
  - **TCP Port Ping**: Fast, non-root liveness detection that works across all operating systems without requiring root/admin privileges.
  - **Combined Ping**: TCP connection attempt with ICMP ping fallback.
  - **Always Scan**: Force port scanning across all hosts regardless of ping response.
- 🚪 **Port Scanner**:
  - Support for comma-separated lists and ranges (e.g. `80, 443, 22, 8000-8010`).
  - Concurrent TCP port checks.
- 🏷️ **Information Fetchers**:
  - **Reverse DNS**: Asynchronous hostname resolution.
  - **MAC Address & OUI Vendor**: Local ARP cache inspection + built-in vendor identification (Apple, Cisco, Intel, Raspberry Pi, TP-Link, Google, etc.).
  - **Web Title Grabber**: Extracts HTTP `<title>` or `Server:` headers for web servers.
- 💾 **Export Formats**:
  - Export to **CSV**, **JSON**, and **TXT** directly from the GUI or CLI.

---

## 🚀 Getting Started

### Prerequisites

- [Rust toolchain](https://rustup.rs/) (1.80+ recommended)

### Build & Install

```bash
git clone https://github.com/dgeek/happyipscanner.git
cd happyipscanner

# Build optimized release binary
cargo build --release

# The binary will be located at:
# ./target/release/happy-ip-scanner
```

---

## 💻 Desktop GUI Mode

To launch the desktop GUI application, run without arguments:

```bash
cargo run
# or
./target/release/happy-ip-scanner
```

You can also explicitly pass `--gui`:

```bash
./target/release/happy-ip-scanner --gui
```

### GUI Shortcuts & Controls

- **Start / Stop**: Click the green **▶ Start** button (or press Space/Enter). Click **⏹ Stop** at any time to halt an active scan.
- **Local Subnet**: Click **📍 Local Subnet** to auto-fill your current network range.
- **Preferences (⚙)**: Configure thread concurrency, ping timeouts, default ports, and enable/disable fetchers.
- **Export (💾)**: Export results to CSV, JSON, or TXT file via native file dialog.
- **Right-Click Row**: Access options to open open web ports directly in your default browser or copy IP addresses.

---

## 📟 CLI Mode

Happy IP Scanner automatically switches to CLI mode when you pass target arguments:

### Basic Scan

Scan a local `/24` subnet:

```bash
happy-ip-scanner 192.168.1.0/24
```

Scan an IP range:

```bash
happy-ip-scanner 192.168.1.1-254
```

### Custom Ports & Higher Concurrency

Scan specific ports with 128 worker threads and 500ms timeout:

```bash
happy-ip-scanner 192.168.1.0/24 -p 80,443,22,8080,3000 -t 128 --timeout 500
```

### Show Only Alive Hosts

```bash
happy-ip-scanner 192.168.1.0/24 -a
```

### Export to CSV or JSON

```bash
happy-ip-scanner 192.168.1.0/24 -o scan_results.csv -f csv
happy-ip-scanner 192.168.1.0/24 -o scan_results.json -f json
```

### Scan Random Internet IPs

```bash
happy-ip-scanner --random 100 -p 80,443 -a
```

### Full CLI Options

```
Usage: happy-ip-scanner [OPTIONS] [TARGET]

Arguments:
  [TARGET]  Target IP, CIDR (e.g. 192.168.1.0/24), or range (e.g. 192.168.1.1-254)

Options:
      --gui                Launch desktop GUI interface
  -p, --ports <PORTS>      Ports to scan, e.g. "80,443,22,8000-8010" [default: 80,443,22,8080]
  -t, --threads <THREADS>  Maximum concurrent worker threads [default: 64]
      --timeout <TIMEOUT>  Socket timeout per probe in milliseconds [default: 1000]
  -o, --output <OUTPUT>    Save scan results to a file
  -f, --format <FORMAT>    Output format: table, csv, json, txt [default: table]
  -a, --alive-only         Only display / export alive hosts
      --no-dns             Disable reverse DNS hostname resolution
      --no-mac             Disable MAC address / vendor lookup
      --no-banner          Disable HTTP web banner & title grabbing
      --random <RANDOM>    Generate and scan N random IPs
      --scan-dead          Scan ports even on hosts that don't respond to ping
  -h, --help               Print help
  -V, --version            Print version
```

---

## 🛠️ Architecture

```
src/
├── main.rs                 # Application entrypoint (dispatches to GUI or CLI)
├── cli.rs                  # CLI argument parsing, progress bar & colored table output
├── export.rs               # CSV, JSON, and TXT exporter
├── engine/                 # Core scanning engine
│   ├── ip_range.rs         # Range iterator, CIDR parsing & auto-subnet detection
│   ├── pinger.rs           # TCP port & ICMP liveness probes
│   ├── port_scanner.rs     # Concurrent TCP port scan & port range parser
│   ├── arp.rs              # System ARP cache MAC lookup
│   ├── vendor.rs           # IEEE OUI MAC vendor database
│   ├── web_banner.rs       # HTTP web title and server header grabber
│   └── scanner.rs          # Asynchronous scan coordinator & worker pool
└── gui/                    # egui / eframe desktop application
    ├── app.rs              # Main GUI window, controls & results table
    └── preferences.rs      # User settings & scanning preferences
```

---

## 📜 License

MIT License.
