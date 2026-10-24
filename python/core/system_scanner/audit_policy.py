"""
macOS OpenBSM Audit Daemon Scanner
Inspects /etc/security/audit_control and status of the auditd subsystem.
"""
import os

def scan() -> dict:
    category = "Audit Policy Settings"
    data = {"audit_control_present": False, "flags": ""}
    findings = []
    status = "pass"

    path = "/etc/security/audit_control"
    if os.path.exists(path):
        data["audit_control_present"] = True
        try:
            with open(path, "r", errors="ignore") as f:
                for line in f:
                    if line.startswith("flags:"):
                        data["flags"] = line.strip()
        except Exception:
            pass
    else:
        status = "warn"
        findings.append({
            "severity": "medium",
            "title": "Audit Control Configuration Missing",
            "description": "Standard OpenBSM audit_control configuration was not found in /etc/security.",
            "remediation": "Verify auditd configuration and restore default /etc/security/audit_control template."
        })

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
