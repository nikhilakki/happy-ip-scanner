# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project logo, mascot, and README banner as SVG plus exported PNG icon sizes in `docs/`, with the palette, asset list, and regeneration steps documented in `docs/BRAND.md`.

## [0.1.0] - 2026-09-07

First public release. The entries under Fixed cover problems corrected during
development, before any release was published.

### Added

- Desktop GUI (egui/eframe) with the familiar Angry IP Scanner layout: auto-detected local subnet, netmask dropdown (/30 to /16), Start/Stop control, and a live-updating results table with color-coded status.
- GUI search box that filters by IP, hostname, vendor, or open port, plus a "Show alive only" toggle. Click a column header to sort; click it again to flip the direction.
- Right-click a host's IP address in the GUI for a context menu: copy the IP or hostname to the clipboard, or open any of its open ports in the browser (https for 443 and 8443, http otherwise).
- GUI Preferences dialog for concurrency, timeouts, default ports, ping method, and fetchers. Preferences and window geometry are saved between runs.
- Command-line interface on tokio for headless scanning. Progress goes to stderr and results to stdout, so output pipes cleanly into other tools.
- Target formats: single IP, hostname (including hyphenated names such as `my-nas.local`), CIDR (`192.168.1.0/24`), full range (`192.168.1.1-192.168.1.254`), short range (`192.168.1.1-254`), and `--random N` public IPv4 addresses. With no target the CLI scans the local /24.
- Liveness methods selectable with `--ping`: TCP port ping (default, no root needed), ICMP via the system `ping`, combined (TCP, then ICMP fallback), and always-scan (no ping; alive if any port opens). `--scan-dead` scans ports on hosts that fail the ping.
- Concurrent TCP port scanning with port lists and ranges (`80,443,22,8000-8010`). `-t/--threads` sets how many hosts scan at once and `--timeout` the per-probe timeout.
- Fetchers, each switchable with `--no-dns`, `--no-mac`, or `--no-banner`: reverse DNS, MAC address from the system ARP cache with a built-in vendor lookup for common OUI prefixes, and HTTP title and `Server:` banner grabbing on open web ports.
- Export to CSV, JSON, or TXT from the CLI (`-f`, `-o`, with the format inferred from the file extension) and from the GUI through native file dialogs; the GUI's TXT export contains alive hosts only.
- CSV export prefixes text cells that start with `=`, `+`, `-`, `@`, tab, or carriage return with a single quote, so a hostile hostname or page title cannot become a spreadsheet formula when the file is opened.
- Global socket budget sized from the OS open-file limit, which is raised at startup, so full `1-65535` sweeps do not run out of descriptors and silently miss ports.
- Release profile with LTO and symbol stripping, GitHub Actions CI running fmt, clippy, and tests on Linux, macOS, and Windows, and a release workflow that attaches prebuilt binaries for macOS (Apple Silicon and Intel), Linux (x86_64 and arm64), and Windows x86_64 to tagged releases, each bundled with THIRD_PARTY_LICENSES.md.

### Fixed

- CLI writes CSV, JSON, and TXT to stdout when `--output` is omitted, so results can be piped; previously they were silently dropped.
- `--alive-only` is honored by CSV and JSON exports, not just the table and TXT output.
- Hyphenated hostnames such as `my-nas.local` are accepted as targets instead of being rejected as a malformed range.
- macOS ARP parsing handles unpadded MAC octets (`a:b:c:1:2:3`), which previously broke vendor lookup whenever a short octet fell inside the vendor prefix.
- Windows ARP lookup matches the address column exactly instead of as a substring, so one host no longer picks up another host's MAC.
- macOS `ping -W` is passed milliseconds, and Windows `ping` output must include a TTL, since it exits 0 on "host unreachable".
- GUI no longer hangs on "Stopping scan..." after Stop until the mouse moves.
- GUI sort direction only toggles when the same column is clicked again, and the header shows the current direction.
- Always-scan no longer marks every host alive; a host is alive only when at least one port is open.
- TCP liveness probes run concurrently and stop at the first answer, so a dead host costs one timeout instead of one per port.
- Linux build failed because the ARP cache reader needed the tokio `fs` feature; it is now enabled.

[Unreleased]: https://github.com/nikhilakki/happy-ip-scanner/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nikhilakki/happy-ip-scanner/releases/tag/v0.1.0
