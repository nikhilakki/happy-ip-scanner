# Security Policy

Happy IP Scanner talks to every host you point it at and parses whatever comes back. That makes robustness against hostile responses a security concern, not just a bug. This document explains which versions receive fixes, how to report a vulnerability, what counts as one, and how the tool is meant to be used.

## Supported versions

Only the latest tagged release and the `main` branch receive security fixes. Older releases are not patched; upgrade to the latest release instead.

| Version | Supported |
| ------- | --------- |
| `main` | Yes |
| Latest tagged release | Yes |
| Older releases | No |

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability reporting:

https://github.com/nikhilakki/happy-ip-scanner/security/advisories/new

Please do not open a public issue, pull request, or discussion for a security problem until a fix is available. Public reports give attackers a head start and make coordinated fixes harder.

A useful report includes:

- The version or commit you tested (`happy-ip-scanner --version`, or the git commit hash).
- Your operating system and how you ran the tool (GUI or CLI, and the relevant flags or preferences).
- Steps to reproduce. For parser issues, the exact bytes the hostile host sent are ideal (a small script or a captured response is perfect).
- What happened (crash, hang, wrong output, file written somewhere unexpected) and what you expected instead.
- Your assessment of impact, if you have one.

What to expect:

- Acknowledgement within 7 days of your report.
- A fix on a best-effort basis. This is a volunteer-maintained project, so timelines depend on severity and complexity, but you will be kept informed through the advisory.
- Coordinated disclosure. Please give the project a reasonable window (90 days is a common baseline) to ship a fix before publishing details. When the fix is released, the advisory is published and you are credited unless you prefer otherwise.

## Scope

The scanner accepts input from three places it does not control: the network (hosts responding to probes), the operating system (output of `ping`, plus `arp` output on macOS and Windows or `/proc/net/arp` on Linux), and the user (targets, port lists, export paths). Problems in how that input is handled are in scope.

In scope:

- Crashes, panics, hangs, or unbounded memory or CPU use caused by a hostile host responding to a TCP probe or an HTTP banner fetch (`src/engine/web_banner.rs`), including malformed or oversized HTML, headers, or status lines.
- Memory-safety issues anywhere in the codebase, including in the `unsafe` calls that read and raise the file-descriptor limit (`src/engine/limits.rs`).
- Bugs in parsing `ping` output (`src/engine/pinger.rs`) or `arp` and `/proc/net/arp` output (`src/engine/arp.rs`) that lead to crashes or to attacker-controlled content being reported as trusted data.
- Reverse DNS results, HTTP banners, or other remote-supplied strings that escape their intended context, for example leading to command execution, formula injection in CSV exports, or unexpected behaviour in the GUI.
- Export path handling in `src/export.rs`, the CLI's `--output` option (`src/cli.rs`), and the GUI's export dialogs: writing to a location the user did not choose, or clobbering files the user did not intend to overwrite.
- Any way for a scanned host to cause the scanner to execute code, read files, or make connections the user did not ask for.
- Vulnerabilities in a dependency that are reachable from this project's code.

Out of scope:

- The fact that the tool scans networks, probes ports, fetches banners, or looks up MAC addresses. That is what it is for.
- Remote hosts, firewalls, or intrusion-detection systems rate limiting, blocking, logging, or otherwise reacting to a scan.
- Load or disruption caused on a target by scanning it. See "Responsible use" below.
- Bugs in the operating system's `ping` or `arp` binaries themselves. Please report those to the OS vendor.
- Issues that require an attacker who already controls the local user account or its files (for example, a tampered preferences file). At that point they can do anything the user can.
- Dependency advisories with no reachable path from this project. These are still welcome as a regular issue or pull request, just not as a security report.
- Denial of service that only affects the scanner's own process and requires no hostile network input (for example, asking it to scan a very large range with a very short timeout).

If you are unsure whether something is in scope, report it privately anyway. A false alarm costs a few minutes; a missed vulnerability costs more.

## Responsible use

Happy IP Scanner is a network scanner. It sends packets to, and opens connections with, every address in the range you give it.

- Only scan networks and hosts that you own, or that you have explicit written permission to test.
- Unauthorized scanning may violate local laws, the terms of service of your network or hosting provider, and the acceptable-use policies of the networks you traverse. Consequences can include loss of service or legal action, regardless of your intent.
- Scanning can trigger alerts, fill logs, and in rare cases disturb fragile devices. Be considerate with concurrency and timeouts, especially on networks that are not yours.

The software is provided "as is", without warranty of any kind, and the authors and contributors accept no liability for how it is used or for any damage arising from its use, as set out in the MIT license in the `LICENSE` file. You are responsible for making sure your use of this tool is lawful and authorized.
