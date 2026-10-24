"""
macOS Gatekeeper & XProtect Assessment Scanner
Verifies Gatekeeper code signing enforcement and XProtect antimalware subsystem.
"""
import subprocess
import os

def scan() -> dict:
    category = "Gatekeeper & XProtect Antimalware"
    data = {"gatekeeper_enabled": False, "xprotect_present": False, "raw": ""}
    findings = []
    status = "pass"

    try:
        # Check Gatekeeper
        spctl = subprocess.run(["spctl", "--status"], capture_output=True, text=True, timeout=5)
        data["raw"] = spctl.stdout.strip()
        if "assessments enabled" in spctl.stdout.lower():
            data["gatekeeper_enabled"] = True
        else:
            data["gatekeeper_enabled"] = False
            status = "fail"
            findings.append({
                "severity": "critical",
                "title": "Gatekeeper Assessments are Disabled",
                "description": "Gatekeeper enforces valid Developer ID signatures and Apple notarization. When disabled, untrusted binaries can execute without verification.",
                "remediation": "Re-enable Gatekeeper via 'sudo spctl --master-enable'."
            })

        # Check XProtect bundle presence
        xprotect_path = "/Library/Apple/System/Library/CoreServices/XProtect.bundle"
        if os.path.exists(xprotect_path) or os.path.exists("/System/Library/CoreServices/XProtect.bundle"):
            data["xprotect_present"] = True
        else:
            findings.append({
                "severity": "medium",
                "title": "XProtect Definitions Missing or Relocated",
                "description": "Default macOS XProtect bundle was not found at standard system locations.",
                "remediation": "Run 'softwareupdate --background-critical' to download current security definitions."
            })
    except Exception as e:
        status = "warn"
        findings.append({
            "severity": "medium",
            "title": "Error Auditing Gatekeeper / XProtect",
            "description": str(e)
        })

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
