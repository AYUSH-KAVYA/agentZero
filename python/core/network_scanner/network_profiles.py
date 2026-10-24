"""
macOS Network Services & Profiles Scanner
Audits configured network services (Wi-Fi, Ethernet, Thunderbolt) via networksetup and scutil.
"""
import subprocess
import re
from typing import Dict, Any

def scan(ip_range: str = None) -> Dict[str, Any]:
    result = {
        "category": "macOS Network Services",
        "status": "info",
        "data": [],
        "findings": []
    }
    services = []

    try:
        res = subprocess.run(["networksetup", "-listallnetworkservices"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("An asterisk") and not line.startswith("*"):
                    services.append({"name": line, "status": "configured"})
    except Exception as e:
        result["error"] = str(e)

    # Check Wi-Fi network name if available
    try:
        wifi = subprocess.run(["networksetup", "-getairportnetwork", "en0"], capture_output=True, text=True, timeout=5)
        if wifi.returncode == 0 and "Current Wi-Fi Network:" in wifi.stdout:
            ssid = wifi.stdout.replace("Current Wi-Fi Network:", "").strip()
            services.append({"name": "Active Wi-Fi SSID", "ssid": ssid})
    except Exception:
        pass

    result["data"] = services
    return result
