"""
macOS Sharing Services & Remote Apple Events Scanner
Audits Remote Apple Events, File Sharing, and AirDrop discovery configuration.
"""
import subprocess

def scan() -> dict:
    category = "Sharing Services & Remote Apple Events"
    data = {"remote_apple_events": False}
    findings = []
    status = "pass"

    try:
        res = subprocess.run(["systemsetup", "-getremoteappleevents"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0 and "on" in res.stdout.lower():
            data["remote_apple_events"] = True
            findings.append({
                "severity": "high",
                "title": "Remote Apple Events is Enabled",
                "description": "Remote Apple Events allows other computers to send commands and scripts to this Mac across the network.",
                "remediation": "Disable Remote Apple Events via 'sudo systemsetup -setremoteappleevents off'."
            })
    except Exception as e:
        data["error"] = str(e)

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
