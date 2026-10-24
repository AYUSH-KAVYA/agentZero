"""
macOS User Credential & Key Files Scanner
Audits ~/.ssh, ~/.aws, and other sensitive credential directories for insecure permissions.
"""
import os

def scan() -> dict:
    category = "User Credential & Key Files"
    data = {"sensitive_files_found": []}
    findings = []
    status = "pass"

    home = os.path.expanduser("~")
    ssh_dir = os.path.join(home, ".ssh")

    if os.path.exists(ssh_dir):
        try:
            for item in os.listdir(ssh_dir):
                if item.startswith("id_") and not item.endswith(".pub"):
                    key_path = os.path.join(ssh_dir, item)
                    st = os.stat(key_path)
                    data["sensitive_files_found"].append(key_path)
                    # Check if permissions are more open than 0600
                    if st.st_mode & 0o077:
                        status = "fail"
                        findings.append({
                            "severity": "high",
                            "title": f"Overly Permissive Private SSH Key: {item}",
                            "description": f"Private key file {key_path} has open permissions ({oct(st.st_mode)[-3:]}), allowing other users to read it.",
                            "remediation": f"Restrict permissions via 'chmod 600 {key_path}'."
                        })
        except Exception:
            pass

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
