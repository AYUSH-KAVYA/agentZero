# AgentZero Architecture

## System Scanner Flow

```
main.py (CLI Entry Point)
    │
    ├── --scan-type system
    │       │
    │       └── SystemScanRunner.run_all()
    │               │
    │               ├── os_info.scan()
    │               ├── dotnet_versions.scan()
    │               ├── amsi_providers.scan()
    │               ├── antivirus.scan()
    │               ├── audit_policy.scan()
    │               ├── autorun.scan()
    │               ├── firewall.scan()
    │               ├── defender.scan()
    │               ├── certificates.scan()
    │               ├── environment.scan()
    │               ├── file_listing.scan()
    │               ├── file_info.scan()
    │               ├── hotfixes.scan()
    │               ├── installed_products.scan()
    │               ├── group_policy.scan()
    │               ├── local_groups.scan()
    │               ├── local_users.scan()
    │               ├── ms_updates.scan()
    │               ├── ntlm_settings.scan()
    │               ├── rdp_connections.scan()
    │               ├── rdp_sessions.scan()
    │               ├── rdp_settings.scan()
    │               ├── secure_boot.scan()
    │               ├── sysmon.scan()
    │               ├── uac_policies.scan()
    │               └── powershell_history.scan()
    │
    ├── --scan-type network
    │       └── NetworkScanRunner.run_all()  [Step 3]
    │
    ├── --scan-type vulnerabilities
    │       └── VulnEngineRunner.run_all()   [Step 4]
    │
    └── --scan-type full
            └── All three runners sequentially

## Module Contract

Every scanner module exposes a single `scan()` function:

```python
def scan() -> dict:
    return {
        "category": "Human Readable Name",
        "status": "pass" | "warn" | "fail" | "info" | "error",
        "data": { ... },        # Raw extracted data
        "findings": [           # Security findings
            {
                "severity": "critical" | "high" | "medium" | "low" | "info",
                "title": "Short title",
                "description": "Detailed description",
                "remediation": "How to fix"   # optional
            }
        ]
    }
```

## IPC Flow (Electron ↔ Python)

```
React Component
    │  ipcRenderer.invoke('scan:system')
    ▼
Electron Main Process (ipc-handlers.js)
    │  child_process.spawn('python', ['main.py', '--scan-type', 'system'])
    ▼
Python Process (main.py)
    │  stderr → progress JSON lines → Main Process → scan:progress event → React
    │  stdout → final results JSON → Main Process → resolve(JSON.parse(stdout))
    ▼
React Component receives results via IPC response
```

## Data Flow

```
Windows OS ──┐
  WMI        │
  Registry   ├──→ Python Scanner ──→ JSON stdout ──→ Electron IPC ──→ React Dashboard
  PowerShell │                   └──→ JSON stderr ──→ Progress Events
  psutil     │
└────────────┘
```
