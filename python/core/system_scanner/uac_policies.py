"""
macOS Root Account & Sudoers Policy Scanner
Audits root user password state and /etc/sudoers configuration for insecure NOPASSWD rules.
"""
import subprocess
import os

def scan() -> dict:
    category = "Root Account & Sudoers Policy"
    data = {"root_enabled": False, "nopasswd_rules": []}
    findings = []
    status = "pass"

    try:
        # Check root account in dscl
        root_chk = subprocess.run(["dscl", ".", "-read", "/Users/root", "AuthenticationAuthority"], capture_output=True, text=True, timeout=5)
        if root_chk.returncode == 0 and "DisabledTags" not in root_chk.stdout and root_chk.stdout.strip():
            data["root_enabled"] = True
            findings.append({
                "severity": "medium",
                "title": "Root Account Has Direct Authentication Authority",
                "description": "The root account appears to have an active password or authentication mechanism configured. macOS best practices recommend leaving root disabled.",
                "remediation": "Disable root account authentication via 'sudo dsenableroot -d'."
            })

        # Check /etc/sudoers for NOPASSWD if readable
        if os.path.exists("/etc/sudoers"):
            try:
                with open("/etc/sudoers", "r", errors="ignore") as f:
                    content = f.read()
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#") and "NOPASSWD" in line:
                            data["nopasswd_rules"].append(line)
                            findings.append({
                                "severity": "high",
                                "title": f"Sudoers NOPASSWD Directive: {line[:50]}",
                                "description": "A sudo rule exists permitting execution of commands as superuser without password prompt.",
                                "remediation": "Audit /etc/sudoers via 'visudo' and enforce password verification."
                            })
            except PermissionError:
                data["sudoers_status"] = "Protected by root permissions (secure)"

    except Exception as e:
        data["error"] = str(e)

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
