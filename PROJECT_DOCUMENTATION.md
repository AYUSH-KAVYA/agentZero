# 🛡️ AgentZero — Comprehensive Technical Manual & Architecture Guide

> **Problem Statement 92:** Agent-less Windows System Vulnerability and Network Scanner  
> **Organisation:** National Technical Research Organisation (NTRO)  
> **Domain / Technology Bucket:** Blockchain & Cybersecurity (Software)  
> **Repository:** [https://github.com/AYUSH-KAVYA/agentZero.git](https://github.com/AYUSH-KAVYA/agentZero.git)

---

## 📑 Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Problem Statement & Background](#2-problem-statement--background)
3. [Technical Architecture](#3-technical-architecture)
4. [The "Agent-less" & AV/EDR Friendly Mechanism](#4-the-agent-less--avedr-friendly-mechanism)
5. [System-Level Audit Modules (26 Categories)](#5-system-level-audit-modules-26-categories)
6. [Network-Level Reconnaissance Modules (10 Categories)](#6-network-level-reconnaissance-modules-10-categories)
7. [Vulnerability Engine & Exploit Crawler](#7-vulnerability-engine--exploit-crawler)
8. [Consolidated Reporting Subsystem (HTML & PDF)](#8-consolidated-reporting-subsystem-html--pdf)
9. [Complete Tech Stack Breakdown](#9-complete-tech-stack-breakdown)
10. [Local Development & Execution Guide](#10-local-development--execution-guide)
11. [Standalone Windows Packaging Guide](#11-standalone-windows-packaging-guide)
12. [Cloud Deployment on Vercel](#12-cloud-deployment-on-vercel)

---

## 1. Executive Summary

**AgentZero** is an on-demand, agent-less cybersecurity auditing tool developed for blue teams, system administrators, and security analysts. It evaluates the security posture of modern Windows 10 and Windows 11 subsystems without installing persistent background agents or services. 

When executed, it performs rapid, comprehensive OS-level queries, sweeps the local network broadcast domain, cross-references discovered parameters against an offline CVE database and the Center for Internet Security (CIS) benchmarks, crawls for weaponized open-source exploits and missing Microsoft KB patches, visualizes the network topology, and generates consolidated executive reports in HTML and PDF formats.

---

## 2. Problem Statement & Background

Most enterprise and individual Windows users fail to update systems promptly or misconfigure critical defensive controls (e.g. disabling User Account Control prompts, granting broad antivirus exclusions, exposing unauthenticated RDP ports, or running outdated runtime environments). 

The National Technical Research Organisation (NTRO) requires a solution that:
- Operates in an **agent-less** manner without persistent daemons.
- Operates in an **AV/EDR-friendly** manner without triggering heuristic behavioral blocks.
- Audits deep system configuration parameters (Registry, WMI, PowerShell, Audit Policies, AMSI).
- Audits the local network perimeter (interfaces, ARP cache, open ports, RPC endpoints, LLDP/CDP, VLAN vectors).
- Correlates findings with known **CVEs**, **publicly available exploits (Exploit-DB, GitHub PoCs)**, and **Microsoft KB patches**.
- Generates an **interactive network diagram** and consolidated **HTML/PDF reports**.

---

## 3. Technical Architecture

AgentZero employs a high-performance **hybrid desktop architecture** separating user interaction from low-level operating system queries:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Electron Desktop Shell                      │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    React 18 + Vite UI                     │  │
│  │  ┌───────────────┐ ┌───────────────┐ ┌─────────────────┐  │  │
│  │  │Dashboard Gauge│ │System Audits  │ │Network Topology │  │  │
│  │  └───────┬───────┘ └───────┬───────┘ └────────┬────────┘  │  │
│  └──────────┼─────────────────┼──────────────────┼───────────┘  │
│             └─────────────────┼──────────────────┘              │
│                     contextBridge IPC Channel                   │
│             ┌─────────────────┴──────────────────┐              │
│             │    Electron Main (ipc-handlers.js) │              │
│             └─────────────────┬──────────────────┘              │
│                 child_process.spawn()                           │
│             ┌─────────────────┴──────────────────┐              │
│             │    Python Extraction Engine (.exe) │              │
│             │  ┌──────────────┐ ┌──────────────┐ │              │
│             │  │System Scanner│ │Net Recon     │ │              │
│             │  │(26 Modules)  │ │(10 Modules)  │ │              │
│             │  └──────┬───────┘ └──────┬───────┘ │              │
│             │  ┌──────┴────────────────┴───────┐ │              │
│             │  │ Vulnerability Engine & Crawler│ │              │
│             │  └───────────────────────────────┘ │              │
│             └────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────────┘
```

- **Renderer Process (React 18, Tailwind CSS, Recharts, Lucide Icons)**: Provides an interactive cybersecurity command center, real-time animated scan progress bars, search/filter controls, and SVG network topology graphs.
- **Main Process (`electron/main.js`, `electron/ipc-handlers.js`)**: Spawns the compiled Python engine silently in the background, streams live stderr diagnostic lines to the UI terminal drawer, and receives structured JSON payloads from stdout.
- **Preload Bridge (`electron/preload.js`)**: Exposes an isolated, secure API to the renderer via `contextBridge`.

---

## 4. The "Agent-less" & AV/EDR Friendly Mechanism

### Agent-less Operation
Traditional security tools require an invasive agent service running continuously in the background, consuming CPU/RAM and creating potential supply-chain attack vectors. AgentZero is **on-demand**:
- It requires no permanent background services, scheduled tasks, or driver installations.
- It executes silently, extracts required telemetry via read-only Windows management interfaces, generates the audit report, and terminates cleanly.

### AV/EDR Friendly Design
To ensure modern Endpoint Detection and Response (EDR) solutions (such as Microsoft Defender for Endpoint, CrowdStrike, SentinelOne) do not flag the audit utility:
- **No In-Memory Injection**: Avoids process hollowing, DLL unhooking, or shellcode execution.
- **Native Administrative Protocols**: Uses Microsoft-approved protocols including Windows Management Instrumentation (WMI), COM (`Microsoft.Update.Session`), and native Winreg APIs.
- **Constrained PowerShell Execution**: All invoked commands use `-NoProfile -NonInteractive` within the current process scope.

---

## 5. System-Level Audit Modules (26 Categories)

Located in `python/core/system_scanner/`:

| Module | Subsystem Audited | Key Data Extracted & Security Checks |
|---|---|---|
| `os_info.py` | Basic OS Information | OS Edition, Build number, Architecture, Domain/Workgroup, Last boot, Uptime |
| `dotnet_versions.py` | .NET Framework & Runtimes | Registry release DWORD mapping, .NET Core/5/6/7/8 runtimes & SDKs |
| `amsi_providers.py` | Antimalware Scan Interface | Registered AMSI providers in registry, CLSID DLL resolution, bypass risk detection |
| `antivirus.py` | Registered Antivirus Products | `root\SecurityCenter2` WMI, `productState` bitmask decoding (Real-time, Up-to-date) |
| `audit_policy.py` | Classic & Advanced Audit Policy | `auditpol` queries, logon/logoff, privilege use, object access, account management |
| `autorun.py` | Persistence & Auto-Run Programs | Registry Run/RunOnce, Startup directories, scheduled tasks, auto-start services |
| `firewall.py` | Windows Firewall Rules | Domain/Private/Public profile status, overly permissive inbound "Allow Any" rules |
| `defender.py` | Microsoft Defender Settings | Real-time, Cloud, Tamper Protection status, path/extension/process exclusions |
| `certificates.py` | Personal & Machine Certificates | Machine/User `My` cert store, expiration dates, non-standard Root CAs, exportable private keys |
| `environment.py` | Environment Variables & PATH | System & User PATH, detection of writable PATH directories (DLL hijacking), SDDL ACLs |
| `file_listing.py` | User Directories Enumeration | Downloads, Documents, Desktop file listing, detection of risky scripts/binaries (`.ps1`, `.vbs`, `.exe`) |
| `file_info.py` | Binary Version & Signatures | Version info and Authenticode digital signature validation for key system binaries |
| `hotfixes.py` | Installed Hotfixes & KBs | WMI `Win32_QuickFixEngineering`, calculation of patch management lag in days |
| `installed_products.py` | Installed Software Inventory | 32-bit & 64-bit Registry Uninstall keys, publishers, display versions |
| `group_policy.py` | Local Group Policy | `gpresult` computer/user evaluation, minimum password length, lockout thresholds |
| `local_groups.py` | Local Security Groups | Non-empty local groups, Administrator and Remote Desktop Users membership |
| `local_users.py` | Local User Accounts | Active vs disabled accounts, password required flag, last logon timestamp |
| `ms_updates.py` | Windows Updates via COM/WMI | `Microsoft.Update.Session` COM object queries, pending critical/security updates |
| `ntlm_settings.py` | NTLM Authentication Policy | `LmCompatibilityLevel`, NTLM minimum client/server security, relay vulnerability check |
| `rdp_connections.py` | Saved RDP Connections | Terminal Server Client registry keys, MRU servers list (lateral movement targets) |
| `rdp_sessions.py` | Incoming RDP Sessions | Active vs disconnected incoming interactive sessions and mapped usernames |
| `rdp_settings.py` | RDP Server Configuration | RDP listening port, Network Level Authentication (NLA) enforcement status |
| `secure_boot.py` | Secure Boot & UEFI Configuration | `Confirm-SecureBootUEFI`, UEFI vs Legacy BIOS verification, bootloader security |
| `sysmon.py` | Sysmon Configuration | Sysmon service status, driver presence, configuration hash tracking |
| `uac_policies.py` | User Account Control Policies | `EnableLUA`, admin consent behavior (`ConsentPromptBehaviorAdmin`), secure desktop status |
| `powershell_history.py` | PowerShell Console History | Scans `ConsoleHost_history.txt` with regex patterns for passwords, tokens, API keys, credentials |

---

## 6. Network-Level Reconnaissance Modules (10 Categories)

Located in `python/core/network_scanner/`:

| Module | Category | Capabilities |
|---|---|---|
| `interfaces.py` | Interface Connectors | Physical and virtual adapters, MAC addresses, IPv4 prefix, unassigned active interfaces |
| `arp_table.py` | ARP Table & Neighbors | Mapped IP-to-MAC associations, duplicate MAC detection (**ARP spoofing / MITM detection**) |
| `dns_cache.py` | DNS Client Cache | Cached DNS resolutions, detection of suspicious top-level domains (.top, .xyz, .buzz) and C2 lookups |
| `network_profiles.py` | Windows Network Profiles | Classification of connected networks (DomainAuthenticated, Private, Public) |
| `network_shares.py` | Exposed Network Shares | Audits exposed SMB shares (`net share`, `Get-SmbShare`), administrative exports (C$, ADMIN$) |
| `connections.py` | Active Sockets & Processes | Maps TCP/UDP sockets to owning process names and PIDs, flags `0.0.0.0` listening services |
| `rpc_endpoints.py` | RPC Endpoints Mapped | TCP port 135 MSRPC Endpoint Mapper audit, interface UUID enumeration (SAMR, LSARPC, Task Scheduler) |
| `open_ports.py` | Rapid Port Scanner | Audits common management and legacy ports (21 FTP, 23 Telnet, 80 HTTP, 135 RPC, 445 SMB, 3389 RDP) |
| `lldp_cdp.py` | LLDP / CDP Discovery | Discovers neighboring managed switches and router infrastructure via LLDP/CDP |
| `vlan_devices.py` | VLAN Vectors Discovery | Sweeps local subnet/VLAN to identify responsive live nodes and lateral attack surfaces |
| `diagram_generator.py` | Topology Graph Generator | Formulates node-link graph data and renders standalone SVG network diagrams |

---

## 7. Vulnerability Engine & Exploit Crawler

Located in `python/core/vuln_engine/`:

- **CVE Database (`cve_database.py`)**: Loads `python/data/cve_snapshot.json` offline with support for live NIST NVD REST API v2.0 enrichment. Correlates OS build numbers, services, and .NET versions with critical Windows vulnerabilities (such as **MadLicense `CVE-2024-38077`**, **Wi-Fi Driver RCE `CVE-2024-30078`**, **PrintNightmare `CVE-2021-34527`**, **Follina `CVE-2022-30190`**, and **BlueKeep `CVE-2019-0708`**).
- **CIS Benchmark Evaluator (`cis_benchmarks.py`)**: Assesses host settings against pre-encoded Center for Internet Security rules (`python/data/cis_windows_benchmarks.json`), reporting compliance percentages, expected values, and Group Policy fix instructions.
- **Open-Source Exploit Crawler (`exploit_crawler.py`)**: Searches Exploit-DB indexes and the GitHub Security Advisory database to identify public Proof-of-Concepts (PoCs) and Metasploit modules matching detected CVEs.
- **Patch Checker (`patch_checker.py`)**: Verifies installed Microsoft KBs against required hotfixes, displaying installation status and direct Microsoft Update Catalog download links.
- **Severity Scorer (`severity_scorer.py`)**: Implements CVSS v3.1 scoring formulas and calculates an aggregate **System Security Posture Rating (0–100)** and letter grade (A through F).

---

## 8. Consolidated Reporting Subsystem (HTML & PDF)

Located in `python/report/`:

- **HTML Report Generator (`html_generator.py`)**: Compiles self-contained executive HTML reports featuring embedded CSS, executive summary statistics, detailed findings by category, and an embedded SVG network diagram.
- **PDF Report Generator (`pdf_generator.py`)**: Converts HTML reports into publication-quality PDFs via WeasyPrint or headless Chromium/Edge (`--headless --print-to-pdf`).
- **CLI Trigger**: Run `python main.py --scan-type report --report-format html` or export directly from the UI.

---

## 9. Complete Tech Stack Breakdown

| Layer | Technologies Used | Purpose |
|---|---|---|
| **Frontend Framework** | React 18, Vite | High-performance single page application |
| **Styling & Icons** | Tailwind CSS, Lucide React | Cybersecurity-themed responsive UI |
| **Data Visualizations** | Recharts, Custom SVG Canvas | CVSS Donut charts, interactive Network Topology Graph |
| **Desktop Shell** | Electron 28+ | Multi-platform desktop wrapper, native window management |
| **IPC Bridge** | Node.js `child_process.spawn()`, `contextBridge` | Secure, asynchronous streaming IPC |
| **Backend Engine** | Python 3.10+ / 3.11+ | System audits, network reconnaissance, CVE analysis |
| **OS Interfaces** | WMI, Windows Registry (`winreg`), PowerShell | Deep Windows subsystem telemetry extraction |
| **Network Probing** | `psutil`, `socket`, `scapy`, `subprocess` | Port scanning, ARP parsing, socket-to-PID mapping |
| **Reporting** | Jinja2, HTML5/CSS3, WeasyPrint | Consolidated HTML and PDF report generation |
| **Packaging** | PyInstaller, electron-builder | Single `.exe` packaging with administrative UAC manifest |

---

## 10. Local Development & Execution Guide

### Prerequisites
- Node.js 18+ / 20+ LTS
- Python 3.10+ / 3.11+
- Git

### 1. Install Dependencies
```bash
# Install frontend packages
npm install

# Setup Python virtual environment
cd python
python3 -m venv venv

# Activate venv:
# On Windows: venv\Scripts\activate
# On macOS/Linux: source venv/bin/activate

pip install -r requirements.txt
cd ..
```

### 2. Run in Development
```bash
# Option A: Run desktop application with live Electron IPC:
npm run dev:electron

# Option B: Run web UI preview in browser:
npm run dev
```

### 3. Run Python CLI Directly
```bash
cd python
python3 main.py --scan-type full
python3 main.py --scan-type report --report-format html
```

---

## 11. Standalone Windows Packaging Guide

To package the tool into a completely standalone application that runs without requiring Node.js or Python to be installed on target machines:

### On a Windows Machine:

#### One-Click Build:
Run the automated script:
```cmd
scripts\build-all.bat
```

#### Manual Build:
```cmd
# 1. Compile Python backend into standalone scanner.exe:
npm run build:python

# 2. Package React + Electron into Windows installers:
npm run build:electron
```

### Generated Binaries:
- **`release/AgentZero Setup 1.0.0.exe`**: Full NSIS installer with administrative UAC elevation.
- **`release/AgentZero 1.0.0.exe`**: **Portable Standalone Executable** (runs on-demand from USB or network shares).
- **`python/dist/scanner.exe`**: Standalone CLI scanner engine.

---

## 12. Cloud Deployment on Vercel

The React frontend of AgentZero can be deployed directly to Vercel as a live interactive demonstration. In cloud mode (where native Electron IPC is not present), AgentZero automatically operates in **Cloud Simulation Mode**, allowing users to explore the live dashboard, trigger simulated scans, view interactive network topology diagrams, and inspect real Windows 11 Enterprise CVE findings.

### Steps to Deploy on Vercel:

#### Method 1: Deploy via Vercel Web Dashboard (Recommended)
1. Push your repository to GitHub: `https://github.com/AYUSH-KAVYA/agentZero.git`.
2. Go to [https://vercel.com](https://vercel.com) and log in.
3. Click **"Add New Project"** and import the `agentZero` repository.
4. Vercel automatically reads [`vercel.json`](file:///Users/ayush___ks/Downloads/agentZero/vercel.json):
   - **Framework Preset**: `Vite`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
5. Click **"Deploy"**. Your live cloud dashboard will be accessible in under 1 minute.

#### Method 2: Deploy via Vercel CLI
```bash
# Install Vercel CLI globally
npm i -g vercel

# Deploy from repository root
vercel
```

---

*Authored for the National Technical Research Organisation (NTRO) • AgentZero Security Audit Team*
