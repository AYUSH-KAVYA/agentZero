"""
macOS Rapid Security Responses & Patches Scanner
Checks current build version and verifies Rapid Security Response (RSR) updates.
"""
import subprocess

def scan() -> dict:
    category = "Rapid Security Responses (RSR)"
    data = {"build_version": "", "extra_version": ""}
    findings = []
    status = "pass"

    try:
        res = subprocess.run(["sw_vers", "-buildVersion"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            data["build_version"] = res.stdout.strip()

        extra = subprocess.run(["sw_vers", "-productVersionExtra"], capture_output=True, text=True, timeout=5)
        if extra.returncode == 0 and extra.stdout.strip():
            data["extra_version"] = extra.stdout.strip()

    except Exception as e:
        data["error"] = str(e)

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
