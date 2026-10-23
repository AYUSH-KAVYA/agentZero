"""
Open Ports & Service Listener Scanner
=====================================
Rapid TCP port scanner auditing critical administrative, remote management,
and legacy protocol ports on localhost and local interfaces.
"""

import socket
from typing import Dict, Any, List

COMMON_AUDIT_PORTS = [
    (21, "FTP", "Insecure cleartext file transfer"),
    (22, "SSH", "Secure Shell remote terminal"),
    (23, "Telnet", "Insecure unencrypted remote console"),
    (80, "HTTP", "Cleartext web server"),
    (135, "MSRPC", "Microsoft RPC Endpoint Mapper"),
    (139, "NetBIOS-SSN", "Legacy NetBIOS Session Service"),
    (443, "HTTPS", "Encrypted web server"),
    (445, "SMB", "Server Message Block file & print sharing"),
    (1433, "MSSQL", "Microsoft SQL Server database engine"),
    (3389, "RDP", "Remote Desktop Protocol"),
    (5985, "WinRM-HTTP", "Windows Remote Management (unencrypted HTTP)"),
    (5986, "WinRM-HTTPS", "Windows Remote Management (HTTPS)"),
    (8080, "HTTP-Proxy", "Alternative web service")
]


def scan(ip_range: str = None) -> Dict[str, Any]:
    """Scans and reports open listening ports on the host."""
    result = {
        "category": "Open Ports Status",
        "status": "info",
        "data": [],
        "findings": []
    }

    open_ports = []

    for port, service, desc in COMMON_AUDIT_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        code = s.connect_ex(("127.0.0.1", port))
        s.close()

        if code == 0:
            open_ports.append({
                "port": port,
                "protocol": "TCP",
                "service": service,
                "state": "LISTENING",
                "description": desc
            })

            # Check for legacy high-risk ports
            if port in (21, 23):
                result["status"] = "fail"
                result["findings"].append({
                    "severity": "critical",
                    "title": f"Insecure Legacy Protocol Listening (Port {port} - {service})",
                    "description": f"Port {port} ({service}) transmits authentication credentials and session payloads in unencrypted plaintext.",
                    "remediation": f"Disable the {service} service immediately and migrate to SSH / SFTP."
                })
            elif port == 445:
                result["findings"].append({
                    "severity": "medium",
                    "title": "SMB File Sharing Service Listening (Port 445)",
                    "description": "Port 445 is open. Ensure SMBv1 is disabled and require SMB signing / encryption to prevent relay and interception attacks.",
                    "remediation": "Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol."
                })
            elif port == 3389:
                result["findings"].append({
                    "severity": "medium",
                    "title": "Remote Desktop Protocol Listening (Port 3389)",
                    "description": "RDP is actively listening on standard port 3389. Exposed RDP interfaces are heavily targeted by automated brute-force sprayers.",
                    "remediation": "Enforce Network Level Authentication (NLA) and restrict RDP firewall access to a dedicated VPN / bastion jump box."
                })

    result["data"] = open_ports
    return result
