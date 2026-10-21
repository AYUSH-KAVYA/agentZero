# 🛡️ AgentZero

**Agent-less Windows System Vulnerability & Network Scanner**

> A blue team security auditing tool that identifies and maps potential vulnerabilities of Windows OS subsystems to better secure and mitigate against system-level and network-level threats.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Windows 10/11](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6?logo=windows)](https://www.microsoft.com/windows)
[![Electron](https://img.shields.io/badge/Electron-28+-47848F?logo=electron)](https://www.electronjs.org/)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python)](https://www.python.org/)

---

## Overview

AgentZero is an on-demand, standalone desktop application designed for security auditing of Windows 10/11 systems. It operates without a persistent background agent — when executed, it rapidly queries the Windows operating system for misconfigurations, scans the local network for vulnerabilities, cross-references findings against known CVE databases, and compiles everything into comprehensive PDF/HTML reports.

### Key Features

- **🔍 System-Level Scanning** — Audits 25+ Windows configuration areas including Defender settings, firewall rules, UAC policies, AMSI providers, installed hotfixes, and more
- **🌐 Network-Level Scanning** — Maps ARP tables, DNS cache, open ports, RPC endpoints, LLDP/CDP connections, and VLAN-attached devices
- **⚠️ Vulnerability Detection** — Cross-references system state against CVE databases and CIS benchmarks to flag active misconfigurations
- **🕷️ Exploit Crawler** — Searches Exploit-DB and GitHub Advisory Database for publicly available exploits matching detected vulnerabilities
- **📊 Network Topology** — Generates interactive network diagrams from discovered infrastructure
- **📄 Report Generation** — Produces consolidated HTML and PDF reports with severity scoring and remediation guidance
- **🛡️ AV/EDR Friendly** — Designed to operate without triggering antivirus or endpoint detection systems
- **📦 Agent-less** — No installation of persistent services required; runs on demand

## Architecture

```
┌─────────────────────────────────────────────┐
│              Electron Shell                  │
│  ┌───────────────────────────────────────┐  │
│  │           React Dashboard              │  │
│  │  ┌─────────┐ ┌──────────┐ ┌────────┐ │  │
│  │  │ System  │ │ Network  │ │ Vuln   │ │  │
│  │  │ Scan    │ │ Scan     │ │ Report │ │  │
│  │  └────┬────┘ └────┬─────┘ └───┬────┘ │  │
│  └───────┼───────────┼───────────┼──────┘  │
│          └───────────┼───────────┘          │
│                 IPC Bridge                   │
│          ┌───────────┴───────────┐          │
│          │   Python Engine (.exe) │          │
│          │  ┌──────┐ ┌────────┐  │          │
│          │  │System│ │Network │  │          │
│          │  │Scanner│ │Scanner│  │          │
│          │  └──────┘ └────────┘  │          │
│          │  ┌──────────────────┐ │          │
│          │  │  Vuln Engine     │ │          │
│          │  └──────────────────┘ │          │
│          └───────────────────────┘          │
└─────────────────────────────────────────────┘
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18 + Vite + Tailwind CSS |
| Desktop Shell | Electron 28+ |
| Backend Engine | Python 3.11+ |
| System Queries | WMI, winreg, PowerShell |
| Network Scanning | scapy, python-nmap, psutil |
| Vuln Database | NVD API v2.0, Exploit-DB |
| Reports | Jinja2 + Puppeteer (PDF) |
| Packaging | PyInstaller + electron-builder |

## Prerequisites

- **Node.js** 18+ and npm
- **Python** 3.11+
- **Windows 10/11** (for running the scanner)
- **Administrator privileges** (required for WMI/Registry access)

## Development Setup

```bash
# Clone the repository
git clone https://github.com/AYUSH-KAVYA/agentZero.git
cd agentZero

# Install Node dependencies
npm install

# Set up Python environment
cd python
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
cd ..

# Start development
npm run dev
```

## Building

```bash
# Build Python backend
npm run build:python

# Build Electron app
npm run build:electron

# Build everything
npm run build
```

## Project Structure

```
agentZero/
├── electron/          # Electron main process
├── src/               # React frontend
├── python/            # Python scanning engine
│   ├── core/
│   │   ├── system_scanner/   # 25+ system audit modules
│   │   ├── network_scanner/  # Network reconnaissance
│   │   └── vuln_engine/      # CVE/CIS vulnerability analysis
│   ├── report/               # HTML/PDF report generation
│   └── data/                 # Offline CVE/CIS databases
├── assets/            # Icons, logos
├── scripts/           # Build scripts
└── docs/              # Documentation
```

## Organisation

**National Technical Research Organisation (NTRO)**
Domain: Blockchain & Cybersecurity | Category: Software | Year: 2024

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
