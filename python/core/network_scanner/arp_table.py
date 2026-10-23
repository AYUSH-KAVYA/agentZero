"""
ARP Table & Neighbor Cache Scanner
==================================
Enumerates the host's ARP cache to identify connected local subnet devices,
gateways, and potential ARP spoofing / cache poisoning indicators.
"""

import platform
import subprocess
import re
from typing import Dict, Any, List


def scan(ip_range: str = None) -> Dict[str, Any]:
    """Scans and parses the host ARP table and network neighbors."""
    result = {
        "category": "ARP Table & Network Neighbors",
        "status": "info",
        "data": [],
        "findings": []
    }

    entries = []

    if platform.system() == "Windows":
        cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command",
               "Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias | ConvertTo-Json -Depth 2"]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            if p.returncode == 0 and p.stdout.strip():
                import json
                parsed = json.loads(p.stdout)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                for item in parsed:
                    entries.append({
                        "ip": item.get("IPAddress"),
                        "mac": item.get("LinkLayerAddress"),
                        "state": item.get("State"),
                        "interface": item.get("InterfaceAlias")
                    })
        except Exception:
            pass

    # Fallback to arp -a
    if not entries:
        try:
            p = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=8)
            if p.returncode == 0:
                for line in p.stdout.splitlines():
                    # Parse standard arp -a output: IP, MAC, Type/Interface
                    m = re.search(r"\(?(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?([0-9a-fA-F:-]{11,17})", line)
                    if m:
                        entries.append({
                            "ip": m.group(1),
                            "mac": m.group(2).replace("-", ":").lower(),
                            "type": "Dynamic" if "dynamic" in line.lower() else "Static",
                            "raw": line.strip()
                        })
        except Exception:
            pass

    result["data"] = entries

    # Check for duplicate MAC addresses across different IPs (Indicator of ARP Spoofing/Poisoning)
    mac_to_ips = {}
    for entry in entries:
        mac = entry.get("mac")
        ip = entry.get("ip")
        if mac and mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") and ip:
            mac_to_ips.setdefault(mac, []).append(ip)

    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            result["status"] = "warn"
            result["findings"].append({
                "severity": "high",
                "title": f"Potential ARP Spoofing Detected (MAC: {mac})",
                "description": f"MAC address {mac} is associated with multiple distinct IP addresses: {', '.join(ips)}. This strongly suggests ARP cache poisoning or a rogue gateway MITM device.",
                "remediation": "Investigate network switch port security, enable Dynamic ARP Inspection (DAI), and configure static ARP mappings for critical gateways."
            })

    return result
