# 📋 Happy IP Scanner — Roadmap & TODO

This document tracks planned features, enhancements, and backlog items for **Happy IP Scanner** (`github.com/nikhilakki/happy-ip-scanner`).

---

## 🎯 High Priority (Next Release)

- [ ] **Import Targets from File**:
  - [ ] Support reading IP lists or hostnames from `.txt` and `.csv` files via CLI (`-i, --input-file <PATH>`).
  - [ ] Add "Load from File..." button and file picker in Desktop GUI.
- [ ] **Column Customization (Fetcher Selection)**:
  - [ ] Add dialog in GUI to select which columns to show/hide (Angry IP Scanner "Select Fetchers" dialog).
  - [ ] Persist table column visibility and widths across application restarts.
- [ ] **Saved Scan Profiles / Presets**:
  - [ ] Save commonly scanned subnets and port lists as named presets (e.g., "Home Network", "Office Servers", "Web Services").
  - [ ] Quick-select dropdown in top toolbar for saved profiles.
- [ ] **App Packaging & Bundling**:
  - [ ] Create macOS `.app` bundle and `.dmg` installer with custom app icon.
  - [ ] Create Linux `.deb`, `.rpm`, and AppImage packaging.
  - [ ] Create Windows `.msi` / standalone `.exe` installer.

---

## 🔍 Protocol & Engine Enhancements

- [ ] **Native Unprivileged ICMP Echo (Raw/Dgram Sockets)**:
  - [ ] Implement `SOCK_DGRAM` IPPROTO_ICMP on macOS and Linux (`net.ipv4.ping_group_range`) for sub-millisecond ICMP pings without invoking system `ping` binary.
- [ ] **Additional Information Fetchers**:
  - [ ] **NetBIOS / SMB Fetcher**: Query UDP 137 / TCP 445 for Windows / Samba machine names, workgroups, and domain info.
  - [ ] **TLS / SSL Certificate Fetcher**: Extract domain subject, issuer, and expiration date on HTTPS port 443.
  - [ ] **SSH Banner Grabber**: Read SSH version string on port 22 (e.g., `SSH-2.0-OpenSSH_9.0`).
  - [ ] **TTL / OS Detection**: Estimate remote OS (Linux/macOS vs Windows vs Cisco) based on packet TTL values.
  - [ ] **GeoIP & ASN Lookup**: Optional fetcher for public IPs providing country, city, and autonomous system info.
- [ ] **UDP Port Scanning**:
  - [ ] Add probe engine for common UDP services (DNS 53, SNMP 161, NTP 123, mDNS 5353).
- [ ] **Scan Rate Throttling**:
  - [ ] Configurable packet/host delay to prevent network congestion or IDS triggering.
- [ ] **IPv6 Subnet & Multicast Discovery**:
  - [ ] IPv6 Neighbor Discovery Protocol (NDP) and all-nodes multicast ping (`ff02::1`).

---

## 🖥️ Desktop GUI Polish

- [ ] **Theme Switcher**:
  - [ ] Support Light, Dark, and System Auto theme toggling.
- [ ] **Audio / System Notification**:
  - [ ] Optional chime or OS system notification when a long scan finishes.
- [ ] **Real-Time Scanning Animation**:
  - [ ] Display elapsed time counter and dynamic ETA calculation during active scans.
- [ ] **Keyboard Shortcuts**:
  - [ ] `Space` / `Enter`: Start/Stop scan.
  - [ ] `Cmd/Ctrl + F`: Focus filter search input.
  - [ ] `Cmd/Ctrl + E`: Open export dialog.
  - [ ] `Cmd/Ctrl + ,`: Open preferences modal.
  - [ ] `Cmd/Ctrl + C`: Copy selected row(s).

---

## 💾 Export & Interoperability

- [ ] **XML Export**:
  - [ ] Implement Angry IP Scanner compatible XML output format.
- [ ] **HTML Report Generation**:
  - [ ] Export self-contained, responsive HTML report with searchable table and summary charts.
- [ ] **Copy Selection as Markdown / TSV**:
  - [ ] Right-click option to copy selected rows as a GitHub-flavored Markdown table.

---

## 🚀 CI/CD & Distribution

- [ ] **GitHub Actions Workflows**:
  - [x] CI pipeline for `cargo fmt`, `cargo clippy` and `cargo test` on macOS, Ubuntu, and Windows (`.github/workflows/ci.yml`).
  - [ ] Automated release workflow creating multi-architecture release binaries on tag push.
- [ ] **Package Managers**:
  - [ ] Homebrew tap formula (`brew install nikhilakki/tap/happy-ip-scanner`).
  - [ ] Publish crate to [crates.io](https://crates.io).
  - [ ] Arch Linux AUR package (`happy-ip-scanner-bin`).

---

*Suggestions or contributions? Open an issue or PR at [github.com/nikhilakki/happy-ip-scanner](https://github.com/nikhilakki/happy-ip-scanner).*
