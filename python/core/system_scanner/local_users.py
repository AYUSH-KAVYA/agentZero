"""
macOS Directory Users Scanner
Lists local user accounts via dscl and audits Guest account status.
"""
import subprocess

def scan() -> dict:
    category = "Directory Users & Guest Account"
    data = {"users": [], "guest_enabled": False}
    findings = []
    status = "pass"

    try:
        res = subprocess.run(["dscl", ".", "-list", "/Users"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                u = line.strip()
                if not u:
                    continue
                # Skip macOS internal service daemons starting with _
                if not u.startswith("_"):
                    data["users"].append(u)

        # Check Guest account status
        guest = subprocess.run(["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"], capture_output=True, text=True, timeout=5)
        if guest.returncode == 0 and guest.stdout.strip() in ["1", "true", "yes"]:
            data["guest_enabled"] = True
            findings.append({
                "severity": "medium",
                "title": "Guest Account is Enabled",
                "description": "The macOS Guest account allows anonymous users to log into the system with guest sessions.",
                "remediation": "Disable the Guest account in System Settings > Users & Groups > Guest User."
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
