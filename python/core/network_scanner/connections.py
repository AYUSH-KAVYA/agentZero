"""
TCP/UDP Socket & Process Mapper
===============================
Enumerates active TCP and UDP connections, mapped process identifiers (PIDs),
process names, and socket states (LISTEN, ESTABLISHED, TIME_WAIT).
"""

import platform
import subprocess
try:
    import psutil
except ImportError:
    psutil = None
from typing import Dict, Any, List


def scan(ip_range: str = None) -> Dict[str, Any]:
    """Scans all active TCP and UDP sockets with owning process details."""
    result = {
        "category": "Active TCP and UDP Connections",
        "status": "info",
        "data": [],
        "findings": []
    }

    connections = []

    if psutil is not None:
        try:
            # Cross-platform socket enumeration using psutil
            for conn in psutil.net_connections(kind="inet"):
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                proto = "TCP" if conn.type == 1 else "UDP"

                proc_name = "Unknown"
                if conn.pid:
                    try:
                        proc_name = psutil.Process(conn.pid).name()
                    except Exception:
                        proc_name = "Terminated / Inaccessible"

                connections.append({
                    "proto": proto,
                    "local": laddr,
                    "remote": raddr,
                    "state": conn.status,
                    "pid": conn.pid,
                    "process": proc_name
                })
        except Exception:
            pass

    # Fallback to netstat if psutil not present or returned nothing
    if not connections:
        try:
            cmd = ["netstat", "-ano"] if platform.system() == "Windows" else ["netstat", "-an"]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            if p.returncode == 0:
                for line in p.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[0].upper() in ("TCP", "UDP"):
                        proto = parts[0].upper()
                        local = parts[1]
                        remote = parts[2]
                        state = parts[3] if proto == "TCP" and len(parts) > 3 else "LISTENING"
                        pid = parts[-1] if platform.system() == "Windows" and len(parts) >= 5 else None
                        connections.append({
                            "proto": proto,
                            "local": local,
                            "remote": remote,
                            "state": state,
                            "pid": pid,
                            "process": "System / Service"
                        })
        except Exception:
            pass

    result["data"] = connections

    # Security check: detect high-risk listening services exposed on all interfaces (0.0.0.0)
    for c in connections:
        if c.get("state") == "LISTEN" and "0.0.0.0:" in c.get("local", ""):
            port = c["local"].split(":")[-1]
            if port in ("21", "23", "3389", "445", "5985", "5986"):
                result["findings"].append({
                    "severity": "high" if port in ("21", "23", "445") else "medium",
                    "title": f"Sensitive Service Listening on All Interfaces (Port {port})",
                    "description": f"Process '{c.get('process')}' (PID {c.get('pid')}) is listening on {c.get('local')} without IP binding restrictions.",
                    "remediation": f"Bind port {port} to localhost (127.0.0.1) or restrict inbound firewall rules to authorized subnets."
                })

    return result
