"""
macOS Administrative Groups Scanner
Audits members of the 'admin', 'wheel', and 'sudo' directory groups via dscl.
"""
import subprocess

def scan() -> dict:
    category = "Admin & Wheel Groups"
    data = {"admin_members": [], "wheel_members": []}
    findings = []
    status = "pass"

    try:
        # Check admin group
        adm = subprocess.run(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"], capture_output=True, text=True, timeout=5)
        if adm.returncode == 0 and "GroupMembership:" in adm.stdout:
            parts = adm.stdout.replace("GroupMembership:", "").split()
            data["admin_members"] = parts
            if len(parts) > 4:
                findings.append({
                    "severity": "low",
                    "title": f"High Number of Administrator Accounts ({len(parts)})",
                    "description": f"Found {len(parts)} accounts in the admin group: {', '.join(parts)}. Principle of least privilege recommends minimizing admin accounts.",
                    "remediation": "Demote non-essential administrative users to standard user status."
                })

        # Check wheel group
        wheel = subprocess.run(["dscl", ".", "-read", "/Groups/wheel", "GroupMembership"], capture_output=True, text=True, timeout=5)
        if wheel.returncode == 0 and "GroupMembership:" in wheel.stdout:
            data["wheel_members"] = wheel.stdout.replace("GroupMembership:", "").split()

    except Exception as e:
        status = "warn"
        data["error"] = str(e)

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
