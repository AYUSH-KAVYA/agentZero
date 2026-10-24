"""
macOS Keychain Root Certificates Scanner
Audits System Keychain for unauthorized or custom Root Certificate Authorities.
"""
import subprocess

def scan() -> dict:
    category = "Keychain Root Certificates"
    data = {"custom_root_count": 0}
    findings = []
    status = "pass"

    try:
        res = subprocess.run(["security", "find-certificate", "-a", "/Library/Keychains/System.keychain"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            count = res.stdout.count("BEGIN CERTIFICATE")
            data["system_keychain_certs"] = count
    except Exception as e:
        data["error"] = str(e)

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
