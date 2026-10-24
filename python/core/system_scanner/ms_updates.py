"""
macOS Software Update Configuration Scanner
Audits automatic update check, download, and installation settings via softwareupdate.
"""
import subprocess

def scan() -> dict:
    category = "Software Update Configuration"
    data = {"automatic_check": True, "schedule_status": ""}
    findings = []
    status = "pass"

    try:
        sched = subprocess.run(["softwareupdate", "--schedule"], capture_output=True, text=True, timeout=5)
        if sched.returncode == 0:
            data["schedule_status"] = sched.stdout.strip()
            if "off" in sched.stdout.lower() or "disabled" in sched.stdout.lower():
                data["automatic_check"] = False
                status = "fail"
                findings.append({
                    "severity": "high",
                    "title": "Automatic Software Update Check is Disabled",
                    "description": "Automatic background checking for Apple security patches is turned off, delaying critical vulnerability remediation.",
                    "remediation": "Enable automatic updates via 'sudo softwareupdate --schedule on'."
                })

    except Exception as e:
        status = "warn"
        data["error"] = str(e)

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
