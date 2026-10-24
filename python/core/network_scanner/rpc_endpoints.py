"""
macOS Bonjour & Network Services Scanner
Enumerates local mDNS / Bonjour network advertisements and listening Apple daemons.
"""
import subprocess
from typing import Dict, Any

def scan(ip_range: str = None) -> Dict[str, Any]:
    result = {
        "category": "Bonjour & Network Services",
        "status": "info",
        "data": [],
        "findings": []
    }
    services = []

    try:
        res = subprocess.run(["lsof", "-iUDP:5353", "-n", "-P"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0 and res.stdout.strip():
            for line in res.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 9:
                    services.append({
                        "command": parts[0],
                        "pid": parts[1],
                        "user": parts[2],
                        "protocol": "mDNS / Bonjour (UDP 5353)"
                    })
    except Exception as e:
        result["error"] = str(e)

    result["data"] = services[:15]
    return result
