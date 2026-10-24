"""
macOS Configuration Profiles & MDM Enrollment Scanner
Inspects installed mobileconfig management profiles and MDM authority.
"""
import subprocess

def scan() -> dict:
    category = "Configuration Profiles & MDM"
    data = {"enrolled": False, "profiles": []}
    findings = []
    status = "info"

    try:
        res = subprocess.run(["profiles", "status", "-type", "enrollment"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            data["enrollment_status"] = res.stdout.strip()
            if "Yes" in res.stdout:
                data["enrolled"] = True

        list_cmd = subprocess.run(["profiles", "list"], capture_output=True, text=True, timeout=5)
        if list_cmd.returncode == 0:
            data["profiles_raw"] = list_cmd.stdout.strip()[:300]

    except Exception as e:
        data["error"] = str(e)

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
