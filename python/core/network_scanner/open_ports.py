"""
macOS Open Ports & Listening Daemons Scanner
Enumerates all active TCP listening sockets and owning processes via lsof.
"""
import subprocess
from typing import Dict, Any

RISKY_PORTS = {
    21: ("FTP", "critical"),
    22: ("SSH", "medium"),
    23: ("Telnet", "critical"),
    80: ("HTTP (Unencrypted)", "low"),
    445: ("SMB", "high"),
    5900: ("VNC / Screen Sharing", "high"),
    8080: ("HTTP Alternate", "low"),
}

def scan(ip_range: str = None) -> Dict[str, Any]:
    result = {
        "category": "Listening Ports & Services",
        "status": "info",
        "data": [],
        "findings": []
    }
    ports = []

    try:
        res = subprocess.run(["lsof", "-iTCP", "-sTCP:LISTEN", "-n", "-P"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            for line in res.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 9:
                    addr_part = parts[8]
                    port = None
                    if ":" in addr_part:
                        try:
                            port = int(addr_part.split(":")[-1])
                        except ValueError:
                            pass
                    entry = {
                        "command": parts[0],
                        "pid": parts[1],
                        "user": parts[2],
                        "type": parts[4],
                        "address": addr_part,
                        "port": port
                    }
                    ports.append(entry)

                    if port and port in RISKY_PORTS:
                        svc_name, sev = RISKY_PORTS[port]
                        result["findings"].append({
                            "severity": sev,
                            "title": f"Sensitive Port {port} ({svc_name}) Listening",
                            "description": f"Process '{parts[0]}' (PID {parts[1]}) is actively listening on port {port} ({svc_name}).",
                            "remediation": f"Verify whether {svc_name} service is intended to accept incoming network connections."
                        })
    except Exception as e:
        result["error"] = str(e)

    result["data"] = ports
    return result
