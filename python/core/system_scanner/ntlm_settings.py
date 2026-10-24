"""
macOS Account & Password Policies Scanner
Audits local directory account password policy via pwpolicy.
"""
import subprocess

def scan() -> dict:
    category = "Account & Password Policies"
    data = {"policy_enforced": False, "raw": ""}
    findings = []
    status = "pass"

    try:
        res = subprocess.run(["pwpolicy", "getaccountpolicies"], capture_output=True, text=True, timeout=5)
        data["raw"] = res.stdout.strip()
        if "minChars" in res.stdout:
            data["policy_enforced"] = True
        else:
            findings.append({
                "severity": "medium",
                "title": "No Password Complexity Policy Configured",
                "description": "No global minimum password length or complexity rules are enforced via pwpolicy, allowing weak passwords.",
                "remediation": "Deploy a configuration profile or enforce pwpolicy rules with minimum 14 characters."
            })
    except Exception as e:
        data["error"] = str(e)

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
