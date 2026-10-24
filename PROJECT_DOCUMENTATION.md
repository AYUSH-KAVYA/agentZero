# 🛡️ AgentZero — Comprehensive Technical Manual & Architecture Guide

> **Project:** Agent-less macOS System Vulnerability and Network Scanner  
> **Organisation:** National Technical Research Organisation (NTRO)  
> **Target Platform:** Apple macOS (Apple Silicon `arm64` & Intel `x64`, macOS Sonoma 14 / Sequoia 15)  
> **Repository:** [https://github.com/AYUSH-KAVYA/agentZero.git](https://github.com/AYUSH-KAVYA/agentZero.git)

---

## 📑 Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Problem Statement & Background](#2-problem-statement--background)
3. [Technical Architecture](#3-technical-architecture)
4. [The "Agent-less" Mechanism on macOS](#4-the-agent-less-mechanism-on-macos)
5. [System-Level Audit Modules (26 Categories)](#5-system-level-audit-modules-26-categories)
6. [Network-Level Reconnaissance Modules (10 Categories)](#6-network-level-reconnaissance-modules-10-categories)
7. [Vulnerability Engine & Exploit Intelligence](#7-vulnerability-engine--exploit-intelligence)
8. [Consolidated Reporting Subsystem (HTML & PDF)](#8-consolidated-reporting-subsystem-html--pdf)
9. [Complete Tech Stack Breakdown](#9-complete-tech-stack-breakdown)
10. [Local Development & Execution Guide](#10-local-development--execution-guide)
11. [Native macOS Desktop Packaging (.dmg)](#11-native-macos-desktop-packaging-dmg)

---

## 1. Executive Summary

**AgentZero** is an on-demand, agent-less cybersecurity auditing desktop application developed for blue teams, system administrators, and security analysts evaluating macOS hosts. It audits the security posture of Apple macOS subsystems without requiring persistent background daemons or kernel extensions.

When executed, it performs rapid, comprehensive OS-level checks (SIP, FileVault, Gatekeeper, Application Firewall, LaunchDaemons, TCC, SUID permissions), maps local network topology, cross-references host state against an offline macOS CVE database and CIS Apple macOS Benchmarks, identifies weaponized zero-day exploits (BLASTPASS, Operation Triangulation, XNU kernel vulnerabilities), renders an interactive SVG network topology diagram, and generates consolidated executive reports in HTML and PDF formats.

---

## 2. Problem Statement & Background

Traditional vulnerability management agents are heavy, require continuous internet connectivity, and install intrusive background daemons. AgentZero fulfills the requirement for an **agent-less, on-demand auditing framework** that:
- Runs natively on macOS Darwin without permanent installation
- Leverages built-in management tools (`csrutil`, `fdesetup`, `spctl`, `socketfilterfw`, `dscl`, `scutil`, `lsof`)
- Requires zero network calls to third-party cloud servers for offline air-gapped security audits
- Distributes as a standalone macOS `.dmg` installer and `.app` bundle

---

## 3. Technical Architecture

```
┌────────────────────────────────────────────────────────┐
│               Electron Desktop Shell (macOS)           │
│  ┌──────────────────────────────────────────────────┐  │
│  │             React 18 + Vite Cyber UI             │  │
│  │  ┌──────────┐ ┌──────────┐ ┌────────┐ ┌────────┐ │  │
│  │  │Dashboard │ │SystemScan│ │Network │ │VulnScan│ │  │
│  │  └────┬─────┘ └────┬─────┘ └───┬────┘ └───┬────┘ │  │
│  └───────┼────────────┼───────────┼──────────┼──────┘  │
│          └────────────┼───────────┼──────────┘          │
│                 contextBridge IPC                       │
│          ┌────────────┴───────────┴──────────┐          │
│          │   Python 3 Standalone Engine      │          │
│          │  ┌──────────┐ ┌─────────┐ ┌─────┐ │          │
│          │  │System(26)│ │Net (10) │ │Vuln │ │          │
│          │  └──────────┘ └─────────┘ └─────┘ │          │
│          └───────────────────────────────────┘          │
└────────────────────────────────────────────────────────┘
```

---

## 4. The "Agent-less" Mechanism on macOS

Unlike persistent monitoring agents, AgentZero:
- **No Background Daemon:** Does not install LaunchDaemons, LaunchAgents, or background services.
- **Native OS Execution:** Executes read-only queries against macOS Darwin subsystems.
- **Zero Third-Party Kernel Extensions:** Compatible with Apple Silicon Full Security mode.
- **Air-Gapped Offline Operation:** Uses curated offline CVE datasets and CIS benchmark schemas stored locally.

---

## 5. System-Level Audit Modules (26 Categories)

1. `os_info` — macOS Version (`sw_vers`), Kernel, Darwin release, Hardware Model (`sysctl hw.model`), Processor, Uptime.
2. `dotnet_versions` — FileVault 2 Full Disk Encryption status (`fdesetup status`).
3. `amsi_providers` — System Integrity Protection (SIP) state (`csrutil status`).
4. `antivirus` — EDR & System Extensions (`systemextensionsctl list`).
5. `audit_policy` — OpenBSM audit daemon flags (`/etc/security/audit_control`).
6. `autorun` — LaunchDaemons persistence plists in `/Library/LaunchDaemons`.
7. `firewall` — Application Firewall (`socketfilterfw --getglobalstate`, stealth mode).
8. `defender` — Gatekeeper code signing enforcement (`spctl --status`) & XProtect definitions.
9. `certificates` — Keychain Root Certificates in System Keychain (`security find-certificate`).
10. `environment` — Environment variables and `$PATH` directory security.
11. `file_listing` — Sensitive user key files (`~/.ssh`, permissions).
12. `file_info` — SUID/SGID binaries across system directories.
13. `hotfixes` — Rapid Security Responses (RSR) and macOS build version.
14. `installed_products` — Installed applications in `/Applications` & Homebrew packages.
15. `group_policy` — Configuration Profiles & MDM enrollment (`profiles status`).
16. `local_groups` — Members of `admin` and `wheel` directory groups (`dscl`).
17. `local_users` — Local directory users and Guest account status (`dscl`).
18. `ms_updates` — Automatic software update background schedule (`softwareupdate --schedule`).
19. `ntlm_settings` — Local account password policies (`pwpolicy`).
20. `rdp_connections` — Remote Apple Events and sharing services (`systemsetup`).
21. `rdp_sessions` — Screen Sharing & VNC port 5900 listener status.
22. `rdp_settings` — Remote Login (OpenSSH) configuration (`systemsetup -getremotelogin`).
23. `secure_boot` — Apple Silicon Secure Boot policy and kernel boot arguments (`nvram`).
24. `sysmon` — LaunchAgents persistence plists in `/Library/LaunchAgents` and `~/Library/LaunchAgents`.
25. `uac_policies` — Root account direct authentication and sudoers policy.
26. `powershell_history` — Shell command history (`~/.zsh_history`, `~/.bash_history`) credential exposure.

---

## 6. Network-Level Reconnaissance Modules (10 Categories)

1. `interfaces` — Network interface connectors (`en0`, `lo0`, `utun`), IP addresses, MAC addresses.
2. `arp_table` — Local subnet ARP neighbor table with MAC spoofing detection (`arp -a`).
3. `dns_cache` — DNS resolvers and configuration (`scutil --dns`, `/etc/resolv.conf`).
4. `network_profiles` — Active network locations & services (`networksetup -listallnetworkservices`, Wi-Fi SSID).
5. `network_shares` — Mounted and exported SMB/NFS/AFP file systems (`mount`, `sharing -l`).
6. `connections` — Active established TCP/UDP sockets via `lsof -iTCP -sTCP:ESTABLISHED -n -P`.
7. `rpc_endpoints` — Bonjour / mDNS network service advertisements (UDP port 5353).
8. `open_ports` — Listening TCP ports and owning processes (`lsof -iTCP -sTCP:LISTEN -n -P`).
9. `lldp_cdp` — Link layer and default gateway discovery via ARP cache probing.
10. `vlan_devices` — Local broadcast domain & subnet devices scan.
11. `diagram_generator` — Generates interactive SVG network topology diagram.

---

## 7. Vulnerability Engine & Exploit Intelligence

- **CIS Apple macOS Benchmark:** Evaluates 13 critical security controls covering FileVault, SIP, Gatekeeper, Application Firewall, SSH, Screen Sharing, Remote Apple Events, Guest Account, Root Account, and Secure Boot.
- **macOS CVE Snapshot:** Curated offline Apple security vulnerabilities including BLASTPASS (CVE-2023-41064), Operation Triangulation (CVE-2023-38606), WebKit RCE (CVE-2023-42917), and SIP Bypass (CVE-2024-27842).
- **CVSS v3.1 Mathematical Scorer:** Calculates total score (0 to 100), letter grade (A to F), and posture status based on finding severity penalties.

---

## 8. Consolidated Reporting Subsystem (HTML & PDF)

AgentZero features an export engine producing executive reports:
- Standalone HTML report with responsive styling and embedded SVG network diagrams.
- Print-ready PDF report rendering executive summary, severity donut chart, and prioritized remediation tables.

---

## 9. Complete Tech Stack Breakdown

- **Desktop Shell:** Electron 28 (Chromium 120 + Node.js 18)
- **Frontend:** React 18, Vite 5, Tailwind CSS 3, Lucide React, Recharts
- **Scanning Engine:** Python 3.9+ with standard library (`subprocess`, `platform`, `json`, `os`, `re`)
- **Packaging:** electron-builder 24 with native Apple Silicon (`arm64`) target and APFS DMG layout

---

## 10. Local Development & Execution Guide

```bash
# Install dependencies
npm install

# Start Electron desktop development window
npm run dev:electron

# Or execute scans via CLI
python3 python/main.py --scan-type full --output-format json
```

---

## 11. Native macOS Desktop Packaging (.dmg)

```bash
npm run build:mac
```

Generates:
- `release/AgentZero-1.0.0-arm64.dmg` (96 MB DMG installer with drag-to-Applications layout)
- `release/mac-arm64/AgentZero.app` (Standalone application bundle)
- `release/AgentZero-1.0.0-arm64-mac.zip` (Distribution archive)
