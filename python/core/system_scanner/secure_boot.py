"""
macOS Secure Boot & Boot Arguments Scanner
Audits Apple Silicon / T2 security configuration and checks for dangerous kernel flags.
"""
import subprocess
import platform

def scan() -> dict:
    category = "Secure Boot Policy"
    data = {"arch": platform.machine(), "boot_args": "", "secure_boot_enforced": True}
    findings = []
    status = "pass"

    try:
        # Inspect nvram boot-args
        nvram = subprocess.run(["nvram", "boot-args"], capture_output=True, text=True, timeout=5)
        if nvram.returncode == 0:
            data["boot_args"] = nvram.stdout.strip()
            risky_flags = ["amfi_get_out_of_my_way=1", "cs_enforcement_disable=1", "kext-dev-mode=1"]
            for flag in risky_flags:
                if flag in data["boot_args"]:
                    status = "fail"
                    findings.append({
                        "severity": "critical",
                        "title": f"Dangerous Boot Flag Detected: {flag}",
                        "description": "A kernel boot argument is present that disables core macOS security enforcement (such as AMFI or code signing).",
                        "remediation": "Clear insecure boot arguments by running 'sudo nvram -d boot-args'."
                    })

        # Query bputil on Apple Silicon if available
        if platform.machine() == "arm64":
            bp = subprocess.run(["bputil", "-d"], capture_output=True, text=True, timeout=5)
            if bp.returncode == 0:
                data["bputil_status"] = bp.stdout.strip()[:300]
                if "Reduced Security" in bp.stdout or "Permissive Security" in bp.stdout:
                    findings.append({
                        "severity": "medium",
                        "title": "macOS Running in Reduced Security Mode",
                        "description": "The startup disk is configured with Reduced Security policy, allowing manual kernel extension loading.",
                        "remediation": "Configure Full Security mode in macOS Recovery Startup Security Utility."
                    })

    except Exception as e:
        data["error"] = str(e)

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
