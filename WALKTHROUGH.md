# 🚀 AgentZero — Complete macOS Walkthrough & Desktop App Guide

> **National Technical Research Organisation (NTRO)**  
> **Topic:** Agent-less macOS System Vulnerability and Network Scanner  
> **Platform:** Apple macOS (Apple Silicon `arm64` & Intel `x64`, Sonoma 14 / Sequoia 15)

---

## 📖 Walkthrough Overview

This document walks you through the entire AgentZero system:
1. **How the System Works on macOS**
2. **Complete Tech Stack Used & Why**
3. **How to Run the Project (Development, Desktop App, and CLI)**
4. **How to Install and Use the Native `.dmg` Installer**
5. **How to Rebuild the macOS Desktop Application**

---

## 1. How the System Works on macOS

AgentZero is an on-demand, agent-less cybersecurity scanner designed to evaluate macOS systems without installing permanent background daemons.

```
React 18 / Tailwind UI  <──IPC──>  Electron Main  <──child_process──>  Python 3 Engine
  - Security Dashboard               - Preload bridge                    - 26 macOS Checks
  - Network Topology                 - Event streaming                   - 10 Network Checks
  - CVE & Exploit Map                - Resource resolution               - CIS Benchmarks
```

1. **User Interaction**: The user launches the application (or runs the `.dmg` installer) and clicks **Full Audit**, **Audit System**, **Audit Network**, or **Vulnerability Analysis**.
2. **Process Execution**: Electron's main process spawns `python3` targeting the bundled scanning engine (`python/main.py`), passing arguments like `--scan-type system --output-format json`.
3. **Native macOS Audits**: The Python engine invokes native macOS Darwin utilities:
   - `sw_vers`, `uname -r`, `sysctl hw.model` for OS architecture and hardware details
   - `csrutil status` to verify System Integrity Protection (SIP)
   - `fdesetup status` to verify FileVault 2 APFS disk encryption
   - `spctl --status` to audit Gatekeeper code signing enforcement
   - `/usr/libexec/ApplicationFirewall/socketfilterfw` for Application Firewall & stealth mode
   - `nvram` & `bputil` to audit Apple Silicon Secure Boot policy
   - `dscl` for Directory users, groups, and root account status
   - `lsof` for open listening ports, active TCP sockets, and owning process PIDs
   - `scutil --dns` and `networksetup` for DNS and network services
4. **Compliance & Vulnerability Analysis**: Findings are cross-referenced with:
   - **CIS Apple macOS 14/15 Benchmark rules** (13 automated checks)
   - **Offline macOS CVE database** (BLASTPASS, XNU Kernel, WebKit, SIP bypasses)
5. **Real-time Feedback**: Scan progress (0% to 100%) and terminal log lines stream back to the UI in real time via Electron IPC.
6. **Reporting**: One-click generation of consolidated HTML and PDF reports with executive summaries, CVSS severity breakdowns, and remediation commands.

---

## 2. Complete Tech Stack Used & Why

| Layer | Technology | Why It Was Chosen |
|---|---|---|
| **Desktop Shell** | **Electron 28** | Cross-platform desktop shell providing native window management, system IPC, and seamless integration on macOS |
| **Frontend Framework** | **React 18** | High-performance reactive UI with modular component hierarchy and state management |
| **Build Tooling** | **Vite 5** | Instant hot-module replacement (HMR) and optimized production bundle packaging |
| **Styling & Theme** | **Tailwind CSS 3** | Utility-first cyberpunk dark theme styled for security command center environments |
| **Charts & Visuals** | **Recharts** | Interactive SVG charts for CVSS v3.1 severity distribution donut rendering |
| **Icons** | **Lucide React** | Clean, consistent cybersecurity icon set (Shield, Terminal, Network, AlertTriangle) |
| **Scanning Engine** | **Python 3.9+** | Native execution on macOS without external runtimes, leveraging Darwin command-line utilities |
| **Packaging Pipeline**| **electron-builder**| Packages the app into a native Apple Silicon (`arm64`) `.dmg` installer and `.app` bundle |

---

## 3. How to Run the Project

### Option A: Development Mode (Live Reload)
```bash
# Start Vite dev server and launch Electron desktop window
npm run dev:electron
```

### Option B: Standalone Python CLI Scan
You can execute the scanning engine directly from your terminal:
```bash
# Run system audit and output JSON
python3 python/main.py --scan-type system --output-format json

# Run network reconnaissance
python3 python/main.py --scan-type network --output-format json

# Run full consolidated audit
python3 python/main.py --scan-type full --output-format json

# Generate consolidated HTML report
python3 python/main.py --scan-type report --report-format html
```

---

## 4. How to Install and Use the Native `.dmg`

The application is built into a standalone Apple Silicon installer:
- Local Release: `release/AgentZero-1.0.1-arm64.dmg` (88 MB)
- Destination Folder: `/Users/ayush___ks/agentZero Final/AgentZero-1.0.1-arm64.dmg`

1. Double-click `AgentZero-1.0.1-arm64.dmg` or run:
   ```bash
   open "/Users/ayush___ks/agentZero Final/AgentZero-1.0.1-arm64.dmg"
   ```
2. Drag **AgentZero** into the **Applications** shortcut.
3. Launch **AgentZero** from Launchpad or `/Applications`.

*(If Gatekeeper shows an Unidentified Developer notice on first launch, right-click `AgentZero.app` $\rightarrow$ Open $\rightarrow$ Open, or run `xattr -cr /Applications/AgentZero.app`)*.

---

## 5. How to Rebuild the Desktop App

Whenever you modify any code, run:
```bash
npm run build:mac
```
This re-compiles the React frontend, packages the Electron shell, bundles the Python engine, and builds the `.dmg` installer in `release/`.
