# Contributing to Happy IP Scanner

Thanks for taking the time to contribute. This guide covers how to report problems, set up a development environment, and get a pull request merged. For what the project does and how to use it, see the [README](README.md).

## Filing issues

Open issues at [github.com/nikhilakki/happy-ip-scanner/issues](https://github.com/nikhilakki/happy-ip-scanner/issues). Templates in [`.github/ISSUE_TEMPLATE`](.github/ISSUE_TEMPLATE) will prompt you for the details we need.

- **Bugs**: include your OS and version, how you ran the scanner (GUI or the exact CLI command), what you expected, what happened, and the output of `happy-ip-scanner --version`. Scan targets can be redacted; the shape of the range (`/24`, hostname, random) is enough.
- **Feature requests**: describe the problem you are trying to solve, not only the feature. Check [TODO.md](TODO.md) first; the template asks you to confirm the idea is not already planned. If it is listed there and you want to build it, see [Looking for something to work on?](#looking-for-something-to-work-on) below.
- **Security vulnerabilities**: do not open a public issue. Follow [SECURITY.md](SECURITY.md).
- **Conduct concerns**: see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Development setup

You need Rust 1.88 or newer (the crate uses the 2024 edition and let-chains). Install it with [rustup](https://rustup.rs/), then make sure `rustfmt` and `clippy` are present:

```bash
rustup component add rustfmt clippy
```

**Linux** needs the system libraries used by `eframe` and `rfd`. This is the exact list CI installs on Debian/Ubuntu:

```bash
sudo apt-get install -y libgtk-3-dev libxkbcommon-dev libwayland-dev \
  libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev pkg-config
```

**macOS** needs the Xcode Command Line Tools (`xcode-select --install`) and **Windows** needs the Visual Studio Build Tools with the C++ workload; rustup asks for both during installation. Nothing else is required on either.

## Building and running

```bash
cargo run                              # desktop GUI (no arguments launches it)
cargo run -- --gui                     # same, explicitly
cargo run -- 192.168.1.0/24 -p 80,443  # CLI mode: anything after -- goes to the scanner
cargo build --release                  # optimized binary at target/release/happy-ip-scanner
```

Scanning talks to real hosts. When trying things out, point the CLI at your own network or at `127.0.0.1` rather than at addresses you do not own.

## Checks that must pass

CI runs these three commands on Ubuntu, macOS, and Windows. Run them locally before opening a pull request; a PR that fails any of them will not be merged.

```bash
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

CI also checks that the crate still builds on the minimum supported Rust version (1.88) and runs `cargo deny check`, which fails on known dependency advisories and on licenses outside the allow list in `deny.toml`. Run the latter locally with `cargo install cargo-deny` if you add or update a dependency. `--locked` makes cargo refuse to rewrite `Cargo.lock` silently, so commit the lockfile change together with any `Cargo.toml` change.

`cargo fmt --all` fixes formatting in place. Clippy warnings are errors in CI, so fix the code rather than adding blanket `#[allow]` attributes. If a narrow `allow` is truly needed, add a one-line comment saying why (see `src/engine/limits.rs` for an example).

## Testing

Tests are unit tests that live next to the code they cover, in a `#[cfg(test)] mod tests` block at the bottom of the source file. Add tests in the same place when you change behaviour; parsing helpers (ports, targets, ARP output, ping output, HTML titles) are the easiest to cover and the most likely to regress across platforms.

Rules for tests that touch the network:

- Bind a listener on `127.0.0.1:0` and probe the port you were given. Loopback is the only address guaranteed to exist on every CI runner.
- Never depend on a real network, an outside host, or external DNS. Tests must pass on a machine with no connectivity at all.
- Never run the ICMP path in a test; it shells out to the system `ping` binary and its output differs between operating systems.
- Keep timeouts short so a failure is fast, not a hang.

Useful invocations:

```bash
cargo test                                            # everything
cargo test tcp_ping_reports_loopback_alive_via_listener  # one test by name
cargo test engine::pinger                             # every test in one module
cargo test -- --nocapture                             # show println! output
```

## Pull requests

1. Fork the repository and create a branch from `main` (for example `feat/import-targets` or `fix/windows-arp-parsing`).
2. Keep each PR small and focused on one change. Separate refactors from behaviour changes so they can be reviewed and reverted independently.
3. Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages and the PR title, with the prefixes already used in this repository: `feat:`, `fix:`, `docs:`, `ci:`, `style:`, `chore:`, `refactor:`, `test:`.
4. In the PR description, say what changed and why. If behaviour changes, describe the before and after, and mention which operating systems you tested on.
5. If the change is user-visible (a new flag, a GUI control, a changed default, a new export format), update [README.md](README.md) and add an entry under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) in the same PR.
6. Make sure the three checks above pass. CI runs them on every PR across all three operating systems.

Reviews are done by [@nikhilakki](https://github.com/nikhilakki) in spare time. If a PR has been quiet for a while, a polite ping on it is welcome.

## Project layout

| Path | What it does |
|---|---|
| `src/main.rs` | Entry point: parses arguments, raises the open-file limit, dispatches to GUI or CLI |
| `src/cli.rs` | `clap` argument definitions, progress bar, table rendering, and the headless scan driver |
| `src/export.rs` | CSV, JSON, and TXT writers that work on any `Write`, plus file-creating helpers |
| `src/engine/scanner.rs` | Async scan coordinator: `ScanOptions`, `HostResult`, `ScanEvent`, and the `run_scan` worker pool |
| `src/engine/ip_range.rs` | Target parsing (IP, hostname, CIDR, range), range generation, random IPs, local subnet detection |
| `src/engine/pinger.rs` | Liveness probes: TCP port ping, ICMP via the system `ping` binary, combined, and always-scan |
| `src/engine/port_scanner.rs` | Port list parsing and formatting, concurrent TCP connect scan per host |
| `src/engine/arp.rs` | MAC address lookup from the OS ARP/neighbour cache, with a parser per platform |
| `src/engine/vendor.rs` | Built-in OUI prefix to vendor name lookup |
| `src/engine/web_banner.rs` | HTTP GET on open web ports; extracts the `<title>`, `Server:` header, or status line |
| `src/engine/limits.rs` | Raises the file-descriptor soft limit and sizes the global socket budget from it |
| `src/gui/app.rs` | `eframe` application: toolbar, live results table, filtering, sorting, context menu, export |
| `src/gui/preferences.rs` | `ScannerPreferences`, persisted between runs and converted into `ScanOptions` |

`src/engine/mod.rs` and `src/gui/mod.rs` only declare the modules above (`gui/mod.rs` also re-exports `run_gui`).

## Platform-specific code

A few code paths are gated with `cfg(target_os = ...)`:

- `src/engine/arp.rs` reads the ARP cache differently on each OS: `arp -n` on macOS, `/proc/net/arp` on Linux, and `arp -a` on Windows. Each has its own parser, and other targets return `None`.
- `src/engine/pinger.rs` builds the `ping` command with per-OS flags. The `-W` timeout is in milliseconds on macOS and Windows (`-w`) but in whole seconds on Linux.
- `src/engine/limits.rs` uses `libc::setrlimit` on Unix and is a no-op elsewhere.

CI builds and tests on Ubuntu, macOS, and Windows, so a change that compiles on your machine can still fail on another OS. When you touch gated code, keep every branch compiling (an unused parser on one platform needs `#[cfg_attr(..., allow(dead_code))]`, as the existing ones have), keep the parsers pure so they can be unit-tested with captured output from each OS, and say in the PR which platforms you could actually run it on.

## Releasing (maintainers)

1. Bump `version` in `Cargo.toml` and run `cargo build` so `Cargo.lock` follows.
2. In `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, add a fresh empty `## [Unreleased]` above it, and update the link references at the bottom.
3. Regenerate the bundled license notices: `cargo install cargo-about` once, then `cargo about generate about.hbs -o THIRD_PARTY_LICENSES.md`.
4. Commit as `chore(release): vX.Y.Z`, then tag and push:

   ```bash
   git tag vX.Y.Z
   git push origin main vX.Y.Z
   ```

   The [release workflow](.github/workflows/release.yml) checks that the tag matches the `Cargo.toml` version, builds every target, verifies checksums, and publishes the GitHub release with the archives attached. Add a pre-release suffix (`v0.2.0-rc1`) to mark it as a pre-release.
5. To rehearse without publishing, run the Release workflow manually from the Actions tab (workflow_dispatch). It builds and uploads the archives as workflow artifacts only.

## Looking for something to work on?

[TODO.md](TODO.md) lists planned features and open ideas, from small GUI polish to new fetchers and packaging. Pick one and open a draft pull request early so nobody duplicates the work. Questions are welcome in the draft PR or in a bug or feature request issue.
