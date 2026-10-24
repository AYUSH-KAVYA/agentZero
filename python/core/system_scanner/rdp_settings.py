"""
macOS Remote Login (SSH) Policy Scanner
Checks whether the built-in OpenSSH daemon is active and listening for network logins.
"""
import subprocess

def scan() -> dict:
    category = "Remote Login (SSH) Policy"
    data = {"remote_login_enabled": False}
    findings = []
    status = "pass"

    try:
        res = subprocess.run(["systemsetup", "-getremotelogin"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0 and "on" in res.stdout.lower():
            data["remote_login_enabled"] = True
            findings.append({
                "severity": "medium",
                "title": "Remote Login (OpenSSH) is Enabled",
                "description": "SSH access is enabled on the system. If SSH is not required for administration, it should be disabled to prevent network brute-force attacks.",
                "remediation": "Turn off Remote Login in System Settings > General > Sharing, or run 'sudo systemsetup -setremotelogin off'."
            })
    except Exception as e:
        data["error"] = str(e)

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
