"""
macOS Network Shares Scanner
Audits mounted SMB, NFS, and AFP network file systems and local sharing exports.
"""
import subprocess
from typing import Dict, Any

def scan(ip_range: str = None) -> Dict[str, Any]:
    result = {
        "category": "Mounted & Shared File Systems",
        "status": "info",
        "data": [],
        "findings": []
    }
    shares = []

    try:
        mount_res = subprocess.run(["mount"], capture_output=True, text=True, timeout=5)
        if mount_res.returncode == 0:
            for line in mount_res.stdout.splitlines():
                if any(fs in line for fs in ["smbfs", "nfs", "afp"]):
                    shares.append({"mount_line": line.strip()})
                    result["findings"].append({
                        "severity": "low",
                        "title": "Remote Network Share Mounted",
                        "description": f"Active remote network file mount detected: {line.strip()}",
                        "remediation": "Verify that remote share credentials and communications use SMB3 with encryption."
                    })
    except Exception as e:
        result["error"] = str(e)

    # Check sharing -l
    try:
        sh_res = subprocess.run(["sharing", "-l"], capture_output=True, text=True, timeout=5)
        if sh_res.returncode == 0 and "No points" not in sh_res.stdout:
            result["data"].append({"sharing_list": sh_res.stdout.strip()[:300]})
    except Exception:
        pass

    result["data"] = shares
    return result
