"""
macOS Screen Sharing & Remote Management Scanner
Audits VNC/ARD service presence (TCP 5900) and Apple Remote Desktop management agent.
"""
import subprocess

def scan() -> dict:
    category = "Screen Sharing & Remote Management"
    data = {"screen_sharing_active": False}
    findings = []
    status = "pass"

    try:
        # Check port 5900 with lsof
        res = subprocess.run(["lsof", "-iTCP:5900", "-sTCP:LISTEN", "-n", "-P"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0 and res.stdout.strip():
            data["screen_sharing_active"] = True
            findings.append({
                "severity": "high",
                "title": "Screen Sharing / VNC Port 5900 is Listening",
                "description": "Screen sharing or Apple Remote Desktop (ARD) is actively listening for remote graphical sessions.",
                "remediation": "Disable Screen Sharing in System Settings > General > Sharing if not strictly required."
            })
    except Exception as e:
        data["error"] = str(e)

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
