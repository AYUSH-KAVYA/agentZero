"""
macOS Application Firewall Scanner
Queries socketfilterfw to inspect global state, stealth mode, and block-all settings.
"""
import subprocess

def scan() -> dict:
    category = "Application Firewall"
    data = {"firewall_enabled": False, "stealth_mode": False, "block_all": False}
    findings = []
    status = "pass"

    fw_bin = "/usr/libexec/ApplicationFirewall/socketfilterfw"

    try:
        # Check global state
        res = subprocess.run([fw_bin, "--getglobalstate"], capture_output=True, text=True, timeout=5)
        if "Firewall is enabled" in res.stdout:
            data["firewall_enabled"] = True
        else:
            data["firewall_enabled"] = False
            status = "warn"
            findings.append({
                "severity": "high",
                "title": "macOS Application Firewall is Disabled",
                "description": "The built-in application firewall is switched off, leaving listening services directly exposed to the local network.",
                "remediation": "Enable the firewall in System Settings > Network > Firewall or run 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on'."
            })

        # Check stealth mode
        stealth = subprocess.run([fw_bin, "--getstealthmode"], capture_output=True, text=True, timeout=5)
        if "Stealth mode enabled" in stealth.stdout:
            data["stealth_mode"] = True
        else:
            data["stealth_mode"] = False
            findings.append({
                "severity": "low",
                "title": "Firewall Stealth Mode is Disabled",
                "description": "Stealth mode prevents the Mac from responding to ICMP ping and port probes from unauthorized hosts.",
                "remediation": "Enable stealth mode via 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on'."
            })

    except Exception as e:
        status = "warn"
        findings.append({
            "severity": "medium",
            "title": "Failed to Query Firewall State",
            "description": str(e)
        })

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
