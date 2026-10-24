# 🚀 AgentZero — Complete Walkthrough & Deployment Guide

> **National Technical Research Organisation (NTRO)**  
> **Topic:** Agent-less Windows System Vulnerability and Network Scanner (PS92)

---

## 📖 Walkthrough Overview

This document walks you through the entire AgentZero system:
1. **How the System Works**
2. **Complete Tech Stack Used & Why**
3. **How to Run the Project (Development, Desktop Electron, and Standalone CLI)**
4. **How to Deploy on Vercel**
5. **How to Build the Standalone Windows Executable**

---

## 1. How the System Works

AgentZero is an on-demand, agent-less cybersecurity scanner designed to evaluate Windows 10/11 endpoints without installing permanent background services.

```
React 18 / Tailwind UI  <──IPC──>  Electron Main  <──child_process──>  Python Engine (.exe)
  - Live Dashboard                   - Preload bridge                    - 26 System Checks
  - Network Topology                 - Event streaming                   - 10 Network Checks
  - CVE & Exploit Map                - UAC elevation                     - Exploit Crawler
```

1. **User Interaction**: The user launches the application and selects a scan type (Full Audit, System Audit, Network Reconnaissance, or Vulnerability Analysis).
2. **Background Execution**: Electron silently spawns the standalone Python extraction engine using `child_process.spawn()`.
3. **Telemetry Streaming**: Real-time progress updates and log messages are piped from Python's `stderr` back through the `contextBridge` to the React UI.
4. **Analysis & Correlation**:
   - The engine audits 26 Windows subsystem categories (AMSI, Defender exclusions, UAC, firewall, hotfixes, unquoted services, plaintext PowerShell history).
   - It performs network reconnaissance across 10 categories (ARP spoofing detection, listening ports, RPC endpoints, active sockets, VLAN attached devices).
   - It cross-references system state against an offline CVE database and CIS Windows benchmarks.
   - It crawls Exploit-DB and GitHub Security Advisories for weaponized public exploits.
   - It checks Microsoft KB patch status and calculates a CVSS v3.1 Security Posture Score (0–100 / A–F).
5. **Rendering & Export**: Results populate the interactive dashboard, render an SVG/Canvas network topology diagram, and allow 1-click HTML or PDF report generation.

---

## 2. Complete Tech Stack Used

| Layer | Technology | Reason Selected |
|---|---|---|
| **Frontend Framework** | **React 18** + **Vite** | Blazing-fast component rendering, instant HMR, modern hooks |
| **Styling** | **Tailwind CSS** | Dark cybersecurity theme, responsive layout, status badges |
| **Icons** | **Lucide React** | Clean, lightweight SVG security icons |
| **Charts** | **Recharts** | Interactive CVSS severity donut charts and metric visualizations |
| **Desktop Shell** | **Electron 28+** | Native OS integration, window lifecycle, background process control |
| **IPC Bridge** | **contextBridge** + `preload.js` | Secure process isolation preventing direct renderer Node access |
| **Scanning Engine** | **Python 3.10+ / 3.11+** | Rapid data parsing, rich security libraries, Windows COM access |
| **OS Interfaces** | **WMI**, **winreg**, **PowerShell** | Microsoft-approved management APIs without third-party agents |
| **Network Probing** | **socket**, **psutil**, **scapy** | Port scanning, socket-to-PID mapping, ARP table enumeration |
| **Reporting** | **Jinja2** + **WeasyPrint** | Self-contained executive HTML and PDF report generation |
| **Packaging** | **PyInstaller** + **electron-builder** | Single `.exe` deployment with administrative UAC manifest |

---

## 3. How to Run the Project

### A. Run in Development Mode
```bash
# 1. Install Node.js packages
npm install

# 2. Setup Python environment
cd python
python3 -m venv venv
# On macOS/Linux:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate
pip install -r requirements.txt
cd ..

# 3. Launch Desktop Electron Application
npm run dev:electron

# Or launch Web Browser Preview only
npm run dev
```

### B. Run the Python Engine via CLI
```bash
cd python

# Run full audit
python3 main.py --scan-type full

# Run network reconnaissance only
python3 main.py --scan-type network

# Generate standalone HTML report
python3 main.py --scan-type report --report-format html
```

---

## 4. How to Deploy the Web Dashboard on Vercel

AgentZero includes a dedicated cloud demonstration mode. When deployed to Vercel (where native Windows Electron APIs are absent), it automatically operates in **Cloud Simulation Mode**, enabling live interactive testing of the dashboard, network topology graph, and CVE exploit maps.

### Step-by-Step Vercel Deployment:

#### Option A: Deploy via Vercel Web Dashboard (1-Click)
1. Ensure your repository is pushed to GitHub: `https://github.com/AYUSH-KAVYA/agentZero.git`.
2. Visit [https://vercel.com](https://vercel.com) and log in.
3. Click **"Add New Project"** and select **`agentZero`**.
4. Vercel automatically detects the configuration from [`vercel.json`](file:///Users/ayush___ks/Downloads/agentZero/vercel.json):
   - **Framework Preset**: `Vite`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
5. Click **"Deploy"**. The site will be live at `https://agent-zero-xxxx.vercel.app` in under 60 seconds!

#### Option B: Deploy via Vercel CLI
```bash
npm i -g vercel
vercel
```

---

## 5. How to Build the Standalone Windows Executable

To distribute the tool as a **single, portable `.exe`** with zero installation required:

### On a Windows 10/11 Machine:
Run the one-click build script:
```cmd
scripts\build-all.bat
```

Or step-by-step:
```cmd
# Step 1: Compile the Python backend into scanner.exe
npm run build:python

# Step 2: Package React + Electron into Windows installer & portable exe
npm run build:electron
```

The output executables are generated in:
- `release/AgentZero Setup 1.0.0.exe` (Installer requiring admin elevation)
- `release/AgentZero 1.0.0.exe` (Standalone Portable Executable)
- `python/dist/scanner.exe` (Standalone CLI scanner)
