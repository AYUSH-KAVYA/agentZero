"""
VLAN & Subnet Vector Scanner
============================
Discovers active host devices within the local VLAN and network subnet,
mapping IP addresses, hostnames, and potential lateral target vectors.
"""

import platform
import subprocess
import socket
import concurrent.futures
from typing import Dict, Any, List


def _ping_ip(ip: str) -> bool:
    """Quick ICMP or TCP probe to test host liveness."""
    cmd = ["ping", "-n", "1", "-w", "200", ip] if platform.system() == "Windows" else ["ping", "-c", "1", "-W", "1", ip]
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.5)
        return res.returncode == 0
    except Exception:
        return False


def scan(ip_range: str = None) -> Dict[str, Any]:
    """Sweeps local VLAN / subnet vectors to map neighboring alive systems."""
    result = {
        "category": "Attached VLAN Network Vectors",
        "status": "info",
        "data": [],
        "findings": []
    }

    discovered = []

    # Determine local subnet base (e.g. 192.168.1.x)
    base_ip = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        if len(parts) == 4 and parts[0] != "127":
            base_ip = f"{parts[0]}.{parts[1]}.{parts[2]}"
    except Exception:
        base_ip = None

    if base_ip:
        # Sample targeted scan: test common endpoints (.1 gateway, .2-.10, local_ip)
        test_ips = [f"{base_ip}.{i}" for i in [1, 2, 5, 10, 20, 50, 100, 150, 200, 254]]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_ip = {executor.submit(_ping_ip, ip): ip for ip in test_ips}
            for future in concurrent.futures.as_completed(future_to_ip, timeout=5):
                ip = future_to_ip[future]
                try:
                    if future.result():
                        hostname = "Unknown"
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                        except Exception:
                            pass
                        discovered.append({
                            "ip": ip,
                            "hostname": hostname,
                            "status": "Alive / Responsive",
                            "vector_type": "VLAN Node"
                        })
                except Exception:
                    pass

    # Merge with ARP entries
    try:
        p = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
        if p.returncode == 0:
            for line in p.stdout.splitlines():
                if base_ip and base_ip in line:
                    parts = line.split()
                    if parts and not any(d["ip"] == parts[0].strip("()") for d in discovered):
                        discovered.append({
                            "ip": parts[0].strip("()"),
                            "hostname": "ARP Neighbor",
                            "status": "Discovered in ARP Cache",
                            "mac": parts[1] if len(parts) > 1 else ""
                        })
    except Exception:
        pass

    result["data"] = discovered

    if len(discovered) > 5:
        result["findings"].append({
            "severity": "info",
            "title": f"{len(discovered)} Active VLAN Devices Identified",
            "description": f"The host shares its broadcast domain / VLAN with {len(discovered)} active devices. Compromising any endpoint on this VLAN allows layer 2 attacks (ARP spoofing, broadcast poisoning, LLMNR poisoning)."
        })

    return result
