"""
macOS Active Network Sockets Scanner
Enumerates established TCP connections and destination endpoints via lsof.
"""
import subprocess
from typing import Dict, Any

def scan(ip_range: str = None) -> Dict[str, Any]:
    result = {
        "category": "Active Network Connections",
        "status": "info",
        "data": [],
        "findings": []
    }
    connections = []

    try:
        res = subprocess.run(["lsof", "-iTCP", "-sTCP:ESTABLISHED", "-n", "-P"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            for line in res.stdout.splitlines()[1:30]:
                parts = line.split()
                if len(parts) >= 9:
                    connections.append({
                        "command": parts[0],
                        "pid": parts[1],
                        "user": parts[2],
                        "connection": parts[8],
                        "state": "ESTABLISHED"
                    })
    except Exception as e:
        result["error"] = str(e)

    result["data"] = connections
    return result
