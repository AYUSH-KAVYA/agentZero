"""
Network Shares Scanner
======================
Audits SMB/CIFS network shares exposed by the host, including default administrative
shares (C$, ADMIN$, IPC$) and customized directory exports.
"""

import platform
import subprocess
import json
import re
from typing import Dict, Any, List


def scan(ip_range: str = None) -> Dict[str, Any]:
    """Scans all active SMB network shares exposed by the machine."""
    result = {
        "category": "Exposed Network Shares",
        "status": "info",
        "data": [],
        "findings": []
    }

    shares = []

    if platform.system() == "Windows":
        cmd = [
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name, Path, Description, Special, ShareState | ConvertTo-Json -Depth 2"
        ]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            if p.returncode == 0 and p.stdout.strip():
                parsed = json.loads(p.stdout)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                shares = parsed
        except Exception:
            pass

    # Fallback to net share command
    if not shares and platform.system() == "Windows":
        try:
            p = subprocess.run(["net", "share"], capture_output=True, text=True, timeout=8)
            if p.returncode == 0:
                lines = p.stdout.splitlines()[4:]
                for line in lines:
                    parts = line.split()
                    if parts and not parts[0].startswith("The command"):
                        shares.append({
                            "Name": parts[0],
                            "Path": parts[1] if len(parts) > 1 else "",
                            "Description": " ".join(parts[2:]) if len(parts) > 2 else ""
                        })
        except Exception:
            pass

    result["data"] = shares

    # Identify non-default custom shares
    custom_shares = [s for s in shares if s.get("Name") not in ("C$", "ADMIN$", "IPC$", "PRINT$") and not s.get("Special", False)]
    if custom_shares:
        result["status"] = "warn"
        for cs in custom_shares:
            name = cs.get("Name")
            path = cs.get("Path", "")
            result["findings"].append({
                "severity": "medium",
                "title": f"Custom SMB Network Share Exposed: {name}",
                "description": f"Share '{name}' exposes path '{path}' over the local network via SMB. If permissions are unconstrained, this provides an unauthorized lateral movement vector.",
                "remediation": "Audit share NTFS and SMB access control lists with Get-SmbShareAccess -Name <share>."
            })

    return result
