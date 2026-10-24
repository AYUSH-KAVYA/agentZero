# 🛡️ AgentZero — Final Project Handover & Roadmap (`final_task.md`)

> **Problem Statement:** Agent-less macOS System Vulnerability and Network Scanner  
> **Organisation:** National Technical Research Organisation (NTRO)  
> **Target Platform:** Apple macOS (Apple Silicon `arm64` & Intel `x64`, macOS Sonoma 14 / Sequoia 15)  
> **Repository:** [https://github.com/AYUSH-KAVYA/agentZero.git](https://github.com/AYUSH-KAVYA/agentZero.git)  
> **Branch:** `main`  
> **Distribution:** Native macOS Desktop Application (`.dmg` installer + `.app` bundle)

---

## 📌 1. Project Overview & macOS Architecture

AgentZero is an on-demand, agent-less administrative security auditing desktop tool built specifically for macOS. It assesses operating system posture (SIP, FileVault 2, Gatekeeper, XProtect, Application Firewall, LaunchDaemons / LaunchAgents persistence, SUID permissions, root account status) and local network topology using native Darwin management tools (`csrutil`, `fdesetup`, `spctl`, `socketfilterfw`, `dscl`, `scutil`, `systemsetup`, `lsof`).

Findings are evaluated against:
1. **CIS Apple macOS 14 Sonoma & 15 Sequoia Benchmarks**
2. **Curated macOS CVE Database & Weaponized Zero-Day Exploit Mappings**
3. **Interactive SVG Network Topology Generator**
4. **Consolidated Executive HTML and PDF Audit Reports**

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

## 🛠️ 2. Native macOS Packaging (.dmg)

- **DMG Installer:** `release/AgentZero-1.0.1-arm64.dmg` (88 MB)
- **Delivery Path:** `/Users/ayush___ks/agentZero Final/AgentZero-1.0.1-arm64.dmg`
- **UI Theme:** Apple-Grade Executive Sapphire & White-Blue Glassmorphic
- **Key v1.0.1 Features:** Dedicated Full OS Scan Modal, 5-Tab Executive Audit Report Popup, HashRouter routing fix
- **App Bundle:** `release/mac-arm64/AgentZero.app`
- **Application Icon:** `assets/icon.icns` (multi-resolution 16×16 to 1024×1024)
- **Packaged Python Engine:** Bundled into `Contents/Resources/python`

### Building the DMG:
```bash
npm run build:mac
```

---

## 🔍 3. The 26 macOS System Scanner Modules

| # | Module Key | Category | Command / Audit Mechanism |
|---|---|---|---|
| 1 | `os_info` | macOS System Information | `sw_vers`, `uname -r`, `sysctl hw.model`, uptime |
| 2 | `dotnet_versions` | FileVault 2 Disk Encryption | `fdesetup status` (APFS container encryption) |
| 3 | `amsi_providers` | System Integrity Protection (SIP) | `csrutil status` (rootless filesystem protection) |
| 4 | `defender` | Gatekeeper & XProtect | `spctl --status`, XProtect definitions bundle |
| 5 | `firewall` | Application Firewall | `socketfilterfw --getglobalstate`, stealth mode |
| 6 | `secure_boot` | Apple Silicon Secure Boot | `nvram boot-args`, `bputil -d` security mode |
| 7 | `autorun` | LaunchDaemons Persistence | `/Library/LaunchDaemons` world-writable audits |
| 8 | `sysmon` | LaunchAgents Persistence | `~/Library/LaunchAgents`, `/Library/LaunchAgents` |
| 9 | `uac_policies` | Root Account & Sudoers | `dscl root AuthenticationAuthority`, sudoers NOPASSWD |
| 10 | `local_users` | Directory Users & Guest | `dscl . -list /Users`, `com.apple.loginwindow GuestEnabled` |
| 11 | `local_groups` | Admin & Wheel Groups | `dscl . -read /Groups/admin GroupMembership` |
| 12 | `group_policy` | Configuration Profiles & MDM | `profiles status -type enrollment`, mobileconfig |
| 13 | `ms_updates` | Software Update Configuration | `softwareupdate --schedule`, background check |
| 14 | `hotfixes` | Rapid Security Responses (RSR) | `sw_vers -buildVersion`, extra version audit |
| 15 | `rdp_settings` | Remote Login (SSH) Policy | `systemsetup -getremotelogin` |
| 16 | `rdp_sessions` | Screen Sharing & VNC | Listening check on TCP port 5900 via `lsof` |
| 17 | `rdp_connections` | Sharing Services & Apple Events | `systemsetup -getremoteappleevents` |
| 18 | `ntlm_settings` | Account & Password Policies | `pwpolicy getaccountpolicies` |
| 19 | `antivirus` | EDR & System Extensions | `systemextensionsctl list`, active security daemons |
| 20 | `certificates` | Keychain Root Certificates | `security find-certificate -a /Library/Keychains/System.keychain` |
| 21 | `installed_products` | Applications & Homebrew | `/Applications/*.app` and `brew list --versions` |
| 22 | `audit_policy` | Audit Policy Settings | `/etc/security/audit_control`, OpenBSM `auditd` |
| 23 | `powershell_history` | Shell History & Exposed Secrets | Scans `~/.zsh_history` for API keys, tokens, passwords |
| 24 | `environment` | Environment & PATH | Insecure relative entries (`.`) or writable PATH dirs |
| 25 | `file_info` | SUID Binaries & Permissions | Audits setuid binaries across system paths |
| 26 | `file_listing` | User Credential & Key Files | Scans `~/.ssh` for loose private key permissions (`0644`) |

---

## 🌐 4. The 10 macOS Network Scanner Modules

1. **`interfaces`** — Network interface connectors (`en0`, `lo0`, `utun`), IP addresses, MAC addresses.
2. **`arp_table`** — Local subnet ARP neighbor table with MAC spoofing detection (`arp -a`).
3. **`dns_cache`** — DNS resolvers and configuration (`scutil --dns`, `/etc/resolv.conf`).
4. **`network_profiles`** — Active network locations & services (`networksetup -listallnetworkservices`, Wi-Fi SSID).
5. **`network_shares`** — Mounted and exported SMB/NFS/AFP file systems (`mount`, `sharing -l`).
6. **`connections`** — Active established TCP/UDP sockets via `lsof -iTCP -sTCP:ESTABLISHED -n -P`.
7. **`rpc_endpoints`** — Bonjour / mDNS network service advertisements (UDP port 5353).
8. **`open_ports`** — Listening TCP ports and owning processes (`lsof -iTCP -sTCP:LISTEN -n -P`).
9. **`lldp_cdp`** — Link layer and default gateway discovery via ARP cache probing.
10. **`vlan_devices`** — Local broadcast domain & subnet devices scan.
11. **`diagram_generator`** — Generates interactive SVG network topology diagram.

---

## ⚠️ 5. macOS Vulnerability Engine

- **CIS Apple macOS Benchmark Rules:** 13 automated checks evaluating FileVault, SIP, Gatekeeper, Application Firewall, SSH, Screen Sharing, Remote Apple Events, Guest Account, Root Account, and Secure Boot.
- **macOS CVE Snapshot:** Curated offline Apple security vulnerabilities including BLASTPASS (CVE-2023-41064), Operation Triangulation (CVE-2023-38606), WebKit RCE (CVE-2023-42917), and SIP Bypass (CVE-2024-27842).
- **CVSS v3.1 Posture Scorer:** Mathematical weighting calculating overall letter grade (A through F) and posture status.
