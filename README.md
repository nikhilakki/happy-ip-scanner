# ⚡ Happy IP Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)]()
[![CI](https://github.com/nikhilakki/happy-ip-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/nikhilakki/happy-ip-scanner/actions/workflows/ci.yml)
[![GitHub Repo](https://img.shields.io/badge/GitHub-nikhilakki%2Fhappy--ip--scanner-181717?logo=github)](https://github.com/nikhilakki/happy-ip-scanner)

A blazing-fast, friendly, cross-platform IP address and port scanner written in **Rust**, inspired by and faithfully porting the classic **Angry IP Scanner**.

**Happy IP Scanner** features both a modern, native **Desktop GUI** (powered by [`egui`](https://github.com/emilk/egui)) and a high-performance **Command-Line Interface (CLI)** powered by [`tokio`](https://tokio.rs).

---

## ✨ Key Features

- 🖥️ **Modern Native Desktop GUI**:
  - Clean, responsive interface matching Angry IP Scanner's familiar layout.
  - **Auto Subnet Detection**: Automatically identifies your active network interface on launch and primes your local subnet (e.g. `192.168.1.1` to `192.168.1.254`).
  - **Live Streaming Results Table**: Non-blocking asynchronous updates with color-coded status badges (🟢 Alive with open ports, 🔵 Alive, 🔴 Dead).
  - **Instant Search & Filter**: Filter results in real-time by IP, hostname, vendor, or toggle "Show alive only".
  - **Column Sorting**: Click any header to sort by IP address, ping latency, hostname, open port count, MAC, or vendor.
  - **Context Menu**: Right-click any row to open open web services directly in your browser (`http://` / `https://`) or copy IPs/hostnames to your clipboard.
  - **Preferences Dialog**: Configure concurrency (up to 500 hosts at once), timeouts, default ports, ping method, and individual fetchers. Preferences and window size are remembered between runs.
  - **Exporting**: Save scan reports to **CSV**, **JSON**, or **TXT** using native file dialogs.

- ⚡ **Ultra-Fast Asynchronous Engine**:
  - Multi-threaded asynchronous scanning built on **Tokio** with configurable worker concurrency.
  - Scans an entire `/24` subnet (254 hosts) with port scanning in a few seconds: liveness probes run concurrently, so a dead host costs one timeout, not one per port.
  - A global socket budget (sized from the OS file-descriptor limit, which is raised at startup) keeps full `1-65535` sweeps from exhausting descriptors and silently missing ports.

- 🎯 **Flexible Target Modes**:
  - **IP Range**: e.g. `192.168.1.1` to `192.168.1.254` or short format `192.168.1.1-254`.
  - **Subnet / CIDR**: e.g. `192.168.1.0/24`, `/16`, `/28`, etc.
  - **Random IPs**: Generate and scan $N$ random IPv4 addresses across the Internet.
  - **Single IP / Hostnames**: e.g. `1.1.1.1` or `scanme.nmap.org`.

- 🔍 **Liveness Pingers & Probes**:
  - **TCP Port Ping** (default): Concurrent connection attempts to common ports. An accept *or* a reset proves the host is up. Works without sudo/admin on macOS, Linux, and Windows.
  - **ICMP Ping**: Echo request via the system `ping` command, for hosts that firewall every TCP port (typical for routers).
  - **Combined**: TCP first, ICMP as a fallback.
  - **Always Scan**: Skip the ping and scan ports on every target; a host is alive if any port is open. Use `--scan-dead` to keep the ping result but still scan unresponsive hosts.

- 🚪 **Open Port Scanner**:
  - Support for port lists and hyphenated ranges: `80, 443, 22, 8000-8010, 8080`.
  - Concurrent TCP connect probes per host.

- 🏷️ **Information Fetchers**:
  - **Reverse DNS**: Asynchronous hostname resolution.
  - **MAC Address & OUI Vendor**: Local ARP cache inspection + built-in IEEE OUI vendor identification (Apple, Cisco, Intel, Raspberry Pi, TP-Link, Google, Ubiquiti, etc.).
  - **Web Title & Banner Grabber**: Lightweight HTTP GET parser that extracts HTML `<title>` tags and `Server:` banners from open web ports.

---

## 🚀 Installation & Setup

### Prerequisites

- [Rust toolchain](https://rustup.rs/) 1.88 or newer (the crate uses the 2024 edition and let-chains)
- On Linux, the GUI needs the usual egui/GTK development libraries, e.g. on Debian/Ubuntu:
  `sudo apt-get install libgtk-3-dev libxkbcommon-dev libwayland-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libssl-dev pkg-config`

### Build from Source

```bash
# Clone repository
git clone https://github.com/nikhilakki/happy-ip-scanner.git
cd happy-ip-scanner

# Build optimized release binary
cargo build --release

# The binary will be available at:
./target/release/happy-ip-scanner
```

### Install via Cargo

```bash
cargo install --git https://github.com/nikhilakki/happy-ip-scanner.git
```

---

## 💻 Desktop GUI Mode

To launch the GUI, run `happy-ip-scanner` without arguments or pass `--gui`:

```bash
happy-ip-scanner
# or
happy-ip-scanner --gui
```

### GUI Highlights

| Feature | Description |
|---|---|
| **Start / Stop** | Click **▶ Start** to scan. Turns into **⏹ Stop** to pause or cancel mid-scan. |
| **📍 Local Subnet** | Automatically populates the input fields with your current active network range. |
| **Netmask Dropdown** | Switch between `/24` (254 hosts), `/16` (65534 hosts), `/28` (14 hosts), etc. |
| **⚙ Preferences** | Configure concurrency (1–500 hosts), socket timeouts, ping method, and fetchers. Saved between runs. |
| **💾 Export** | Export results to CSV, JSON, or TXT file via native file dialog. |
| **Right-Click Context** | Open web services in browser (`http://` or `https://`) or copy host details. |

---

## 📟 Command-Line Interface (CLI) Mode

When targets or CLI options are provided, Happy IP Scanner runs in headless CLI mode:

### 1. Scan a Subnet (CIDR)
```bash
happy-ip-scanner 192.168.1.0/24
```

### 2. Scan an IP Range
```bash
happy-ip-scanner 192.168.1.1-254
```

### 3. Custom Ports & Concurrency
Scan specific ports using 128 worker threads and a 500ms timeout:
```bash
happy-ip-scanner 192.168.1.0/24 -p 80,443,22,8080 -t 128 --timeout 500
```

### 4. Show Only Alive Hosts
```bash
happy-ip-scanner 192.168.1.0/24 -a
```

### 5. Export to CSV, JSON, or TXT
The format is taken from `--format`, or guessed from the file extension when only `--output` is given:
```bash
happy-ip-scanner 192.168.1.0/24 -o results.csv
happy-ip-scanner 192.168.1.0/24 -o results.json
happy-ip-scanner 192.168.1.0/24 -o alive.txt -a
```

### 6. Pipe Results to Other Tools
Non-table formats go to stdout when no `--output` is given. Progress and status messages go to stderr, so stdout stays clean:
```bash
happy-ip-scanner 192.168.1.0/24 -f json -a | jq '.[].ip'
happy-ip-scanner 192.168.1.0/24 -f csv > hosts.csv
```

### 7. Find Hosts That Firewall TCP (Routers, Printers)
```bash
happy-ip-scanner 192.168.1.0/24 --ping combined -a
```

### 8. Scan Random Internet Targets
```bash
happy-ip-scanner --random 50 -p 80,443 -a
```

### Sample CLI Output

```
⚡ Happy IP Scanner v0.1.0
🎯 Scanning 1 hosts | Ports: [80, 443] | Concurrency: 64 | Timeout: 1500ms

╭─────────┬────────────┬────────┬─────────────────┬────────────┬─────────────┬────────┬───────────────────────╮
│ Status  ┆ IP Address ┆ Ping   ┆ Hostname        ┆ Open Ports ┆ MAC Address ┆ Vendor ┆ Web / Banner          │
╞═════════╪════════════╪════════╪═════════════════╪════════════╪═════════════╪════════╪═══════════════════════╡
│ ● ALIVE ┆ 1.1.1.1    ┆ 11.4ms ┆ one.one.one.one ┆ 80, 443    ┆ -           ┆ -      ┆ 301 Moved Permanently │
╰─────────┴────────────┴────────┴─────────────────┴────────────┴─────────────┴────────┴───────────────────────╯
```

### CLI Reference

```
A fast, friendly, cross-platform IP and port scanner in Rust (Angry IP Scanner port)

Usage: happy-ip-scanner [OPTIONS] [TARGET]

Arguments:
  [TARGET]  Target: IP, hostname, CIDR (192.168.1.0/24) or range (192.168.1.1-254). Defaults to the local /24 subnet when omitted

Options:
      --gui                Launch the desktop GUI (also the default when run with no arguments)
  -p, --ports <PORTS>      Ports to scan, e.g. "80,443,22,8000-8010" [default: 80,443,22,8080]
  -t, --threads <THREADS>  Maximum number of hosts scanned concurrently [default: 64]
      --timeout <TIMEOUT>  Socket timeout per probe in milliseconds [default: 1000]
      --ping <PING>        Liveness check used before port scanning [default: tcp] [possible values: tcp, icmp, combined, always]
  -o, --output <PATH>      Write results to this file (format from --format, or guessed from the extension)
  -f, --format <FORMAT>    Output format; non-table formats are written to stdout unless --output is given [default: table] [possible values: table, csv, json, txt]
  -a, --alive-only         Only display / export alive hosts
      --no-dns             Disable reverse DNS hostname resolution
      --no-mac             Disable MAC address / vendor lookup
      --no-banner          Disable HTTP web banner & title grabbing
      --random <N>         Generate and scan N random public IPv4 addresses instead of TARGET
      --scan-dead          Scan ports even on hosts that don't respond to ping
  -h, --help               Print help (see more with '--help')
  -V, --version            Print version
```

---

## 🏗️ Architecture

```
src/
├── main.rs                 # Entrypoint: dispatches to GUI or CLI mode
├── cli.rs                  # CLI parser, progress indicator, and table formatting
├── export.rs               # CSV, JSON, and plain text export handlers
├── engine/                 # Scanning engine
│   ├── ip_range.rs         # IP range generator, CIDR parser, local network detector
│   ├── limits.rs           # File-descriptor limit handling & socket budget
│   ├── pinger.rs           # TCP port & ICMP liveness probes
│   ├── port_scanner.rs     # Concurrent TCP port scan & port range parser
│   ├── arp.rs              # System ARP cache MAC discovery
│   ├── vendor.rs           # IEEE OUI MAC vendor lookup database
│   ├── web_banner.rs       # HTTP web title and server header grabber
│   └── scanner.rs          # Asynchronous scan coordinator & worker pool
└── gui/                    # egui / eframe desktop application
    ├── app.rs              # Main GUI window, controls, table & context menu
    └── preferences.rs      # User settings & scanning preferences
```

---

## 🧪 Testing

The same checks run in CI on macOS, Linux, and Windows:

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the project on GitHub: [github.com/nikhilakki/happy-ip-scanner](https://github.com/nikhilakki/happy-ip-scanner)
2. Create your feature branch (`git checkout -b feat/my-new-feature`)
3. Commit your changes (`git commit -am 'feat: add some feature'`)
4. Push to the branch (`git push origin feat/my-new-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 [Nikhil Akki](https://github.com/nikhilakki).
