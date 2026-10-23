"""
System Interface Connectors Scanner
===================================
Enumerates physical and virtual network adapters, interface configuration,
link speeds, MAC addresses, and IP assignments.
"""

import platform
import subprocess
import json
try:
    import psutil
except ImportError:
    psutil = None
from typing import Dict, Any, List


def scan(ip_range: str = None) -> Dict[str, Any]:
    """Scans all system network interface connectors and configurations."""
    result = {
        "category": "System Interface Connectors",
        "status": "info",
        "data": [],
        "findings": []
    }

    interfaces = []

    if platform.system() == "Windows":
        ps_cmd = (
            "Get-NetAdapter | ForEach-Object { "
            "  $ip = Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue; "
            "  @{ "
            "    Name = $_.Name; "
            "    InterfaceDescription = $_.InterfaceDescription; "
            "    Status = $_.Status; "
            "    MacAddress = $_.MacAddress; "
            "    LinkSpeed = $_.LinkSpeed; "
            "    MediaType = $_.MediaType; "
            "    PhysicalMediaType = $_.PhysicalMediaType; "
            "    IPv4Address = if ($ip) { $ip.IPAddress } else { $null }; "
            "    PrefixLength = if ($ip) { $ip.PrefixLength } else { $null } "
            "  } "
            "} | ConvertTo-Json -Depth 3"
        )
        try:
            p = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=15
            )
            if p.returncode == 0 and p.stdout.strip():
                parsed = json.loads(p.stdout)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                interfaces = parsed
        except Exception:
            pass

    # Fallback to psutil for cross-platform support
    if not interfaces and psutil is not None:
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for iface_name, addr_list in addrs.items():
                ipv4 = next((a.address for a in addr_list if a.family.name == "AF_INET"), None)
                netmask = next((a.netmask for a in addr_list if a.family.name == "AF_INET"), None)
                mac = next((a.address for a in addr_list if a.family.name in ("AF_LINK", "AF_PACKET")), None)
                stat = stats.get(iface_name)

                interfaces.append({
                    "Name": iface_name,
                    "Status": "Up" if (stat and stat.isup) else "Down",
                    "MacAddress": mac,
                    "LinkSpeed": f"{stat.speed} Mbps" if stat else "Unknown",
                    "IPv4Address": ipv4,
                    "Netmask": netmask,
                    "IsVirtual": "vEthernet" in iface_name or "Virtual" in iface_name or "docker" in iface_name or "vmnet" in iface_name
                })
        except Exception:
            pass

    if not interfaces:
        # Basic socket fallback
        try:
            import socket
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            interfaces.append({
                "Name": "Default Adapter",
                "Status": "Up",
                "IPv4Address": local_ip,
                "MacAddress": "00:00:00:00:00:00",
                "LinkSpeed": "Auto"
            })
        except Exception:
            pass

    result["data"] = interfaces

    # Security findings: identify exposed or promiscuous interfaces
    for iface in interfaces:
        name = iface.get("Name", "")
        if "Virtual" not in name and iface.get("Status") == "Up" and not iface.get("IPv4Address"):
            result["findings"].append({
                "severity": "low",
                "title": f"Interface {name} Up Without IPv4 Assignment",
                "description": f"Interface {name} is active without an assigned IPv4 address. Could indicate bridging, packet sniffing, or unconfigured vector."
            })

    return result
