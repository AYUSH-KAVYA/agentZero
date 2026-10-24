"""
macOS System Integrity Protection (SIP) Scanner
Audits Apple rootless protection / SIP state via csrutil.
"""
import subprocess

def scan() -> dict:
    category = "System Integrity Protection (SIP)"
    data = {"sip_enabled": False, "raw": ""}
    findings = []
    status = "pass"

    try:
        res = subprocess.run(["csrutil", "status"], capture_output=True, text=True, timeout=5)
        data["raw"] = res.stdout.strip()
        if "enabled" in res.stdout.lower():
            data["sip_enabled"] = True
            status = "pass"
        else:
            data["sip_enabled"] = False
            status = "fail"
            findings.append({
                "severity": "critical",
                "title": "System Integrity Protection (SIP) is Disabled",
                "description": "SIP protects critical system files and directories from modification by malware or unauthorized processes, even with root privileges.",
                "remediation": "Boot into Recovery Mode (hold Power button or Command+R), open Terminal, and run 'csrutil enable'."
            })
    except Exception as e:
        status = "warn"
        findings.append({
            "severity": "medium",
            "title": "Failed to Query SIP Status",
            "description": str(e)
        })

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
