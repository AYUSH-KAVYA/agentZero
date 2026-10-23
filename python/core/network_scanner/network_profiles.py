"""
Windows Network Profiles Scanner
================================
Audits network connection profiles (Public, Private, DomainAuthenticated)
to ensure firewall isolation policies match connected network security zones.
"""

import platform
import subprocess
import json
from typing import Dict, Any


def scan(ip_range: str = None) -> Dict[str, Any]:
    """Audits active Windows network connection profiles."""
    result = {
        "category": "Windows Network Profiles",
        "status": "info",
        "data": [],
        "findings": []
    }

    profiles = []

    if platform.system() == "Windows":
        cmd = [
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity, DomainAuthenticationSucceeded | ConvertTo-Json -Depth 2"
        ]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            if p.returncode == 0 and p.stdout.strip():
                parsed = json.loads(p.stdout)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                profiles = parsed
        except Exception:
            pass

    result["data"] = profiles

    for prof in profiles:
        cat = str(prof.get("NetworkCategory", ""))
        alias = prof.get("InterfaceAlias", "Unknown")
        # If connected to a network configured as "Private" on an interface with public gateway
        if cat == "Private" and not prof.get("DomainAuthenticationSucceeded", False):
            result["findings"].append({
                "severity": "low",
                "title": f"Interface {alias} Configured as 'Private' Network Category",
                "description": f"Interface {alias} is operating under the 'Private' firewall category without verified domain authentication. This broadens local discovery and inbound firewall openings.",
                "remediation": "Switch untrusted or guest interfaces to 'Public' using Set-NetConnectionProfile -InterfaceAlias <alias> -NetworkCategory Public."
            })

    return result
