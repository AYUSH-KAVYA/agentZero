"""
macOS FileVault 2 Disk Encryption Scanner
Verifies full-disk encryption status on the APFS startup container.
"""
import subprocess

def scan() -> dict:
    category = "FileVault Disk Encryption"
    data = {"filevault_enabled": False, "raw": ""}
    findings = []
    status = "pass"

    try:
        res = subprocess.run(["fdesetup", "status"], capture_output=True, text=True, timeout=5)
        data["raw"] = res.stdout.strip()
        if "FileVault is On" in res.stdout:
            data["filevault_enabled"] = True
            status = "pass"
        else:
            data["filevault_enabled"] = False
            status = "fail"
            findings.append({
                "severity": "high",
                "title": "FileVault 2 Disk Encryption is Disabled",
                "description": "The startup volume is not encrypted with FileVault 2. If lost or stolen, physical data on disk can be accessed without credentials.",
                "remediation": "Enable FileVault in System Settings > Privacy & Security > FileVault or execute 'sudo fdesetup enable'."
            })
    except Exception as e:
        status = "warn"
        findings.append({
            "severity": "medium",
            "title": "Failed to Query FileVault Status",
            "description": str(e)
        })

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
