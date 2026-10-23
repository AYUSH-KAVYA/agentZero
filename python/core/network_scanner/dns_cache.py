"""
DNS Client Cache Scanner
========================
Extracts cached DNS query records to detect recent host communication,
C2 domain lookups, and suspicious external resolutions.
"""

import platform
import subprocess
import json
from typing import Dict, Any, List


def scan(ip_range: str = None) -> Dict[str, Any]:
    """Retrieves cached DNS resolution records."""
    result = {
        "category": "DNS Client Cache",
        "status": "info",
        "data": [],
        "findings": []
    }

    records = []

    if platform.system() == "Windows":
        cmd = [
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "Get-DnsClientCache | Select-Object Entry, Name, Type, Status, TimeToLive, Data | ConvertTo-Json -Depth 2"
        ]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            if p.returncode == 0 and p.stdout.strip():
                parsed = json.loads(p.stdout)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                for item in parsed:
                    records.append({
                        "entry": item.get("Entry"),
                        "name": item.get("Name"),
                        "type": item.get("Type"),
                        "data": item.get("Data"),
                        "ttl": item.get("TimeToLive")
                    })
        except Exception:
            pass

    result["data"] = records

    # Look for high-risk TLDs or suspicious dynamic DNS
    suspicious_tlds = [".top", ".xyz", ".buzz", ".cc", ".tk", ".onion"]
    for rec in records:
        name = str(rec.get("name") or rec.get("entry") or "").lower()
        if any(name.endswith(tld) for tld in suspicious_tlds):
            result["findings"].append({
                "severity": "medium",
                "title": f"Suspicious High-Risk Domain in DNS Cache: {name}",
                "description": f"Host recently resolved {name}, which uses a high-risk or commonly abused top-level domain.",
                "remediation": "Check proxy and firewall egress logs to inspect connection timestamps and destination IP addresses."
            })

    return result
