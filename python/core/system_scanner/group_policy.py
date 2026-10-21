"""
Group Policy Scanner
====================
Analyzes Local Group Policy settings applied to the machine and current user,
including password policy, account lockout, and audit policy.

Security Relevance:
- Weak password policies (short length, no complexity) make brute-force attacks trivial.
- Missing account lockout thresholds allow unlimited password guessing.
- Missing audit policies prevent detection of security incidents.
- GPOs control many critical security settings; misconfigurations can leave
  the system vulnerable to attack.

Data Sources:
- gpresult /R /SCOPE:COMPUTER
- gpresult /R /SCOPE:USER
- net accounts (password and lockout policy)
- PowerShell: secedit /export for detailed security policy
"""

import platform
import subprocess
import json
import re
import tempfile
import os


def _run_gpresult(scope: str) -> str:
    """Run gpresult for the given scope and return output."""
    try:
        result = subprocess.run(
            ["gpresult", "/R", f"/SCOPE:{scope}"],
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout if result.returncode == 0 else result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return ""


def _parse_gpresult(output: str) -> dict:
    """Parse gpresult /R output into structured data."""
    parsed = {
        "applied_gpos": [],
        "security_settings": [],
        "raw_output": output,
    }

    if not output:
        return parsed

    # Extract applied GPOs
    in_gpo_section = False
    for line in output.splitlines():
        stripped = line.strip()

        if "Applied Group Policy Objects" in line or "Applied GPOs" in line:
            in_gpo_section = True
            continue

        if in_gpo_section:
            if stripped and not stripped.startswith("---"):
                # Check if we've hit the next section
                if any(header in stripped for header in [
                    "The following GPOs", "Resultant Set", "Computer Settings",
                    "User Settings", "The computer is", "The user is",
                ]):
                    in_gpo_section = False
                    continue
                if stripped:
                    parsed["applied_gpos"].append(stripped)

    return parsed


def _get_password_policy() -> dict:
    """Get password and account lockout policy via 'net accounts'."""
    policy = {}
    try:
        result = subprocess.run(
            ["net", "accounts"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.splitlines():
                line = line.strip()
                if ":" in line:
                    key, _, value = line.partition(":")
                    key = key.strip()
                    value = value.strip()

                    if "Minimum password length" in key:
                        try:
                            policy["min_password_length"] = int(value)
                        except ValueError:
                            policy["min_password_length"] = value

                    elif "Maximum password age" in key:
                        policy["max_password_age"] = value

                    elif "Minimum password age" in key:
                        policy["min_password_age"] = value

                    elif "password history" in key.lower():
                        try:
                            policy["password_history_length"] = int(value)
                        except ValueError:
                            policy["password_history_length"] = value

                    elif "Lockout threshold" in key:
                        try:
                            val = value.lower().replace("never", "0")
                            policy["lockout_threshold"] = int(val) if val.isdigit() else value
                        except ValueError:
                            policy["lockout_threshold"] = value

                    elif "Lockout duration" in key:
                        policy["lockout_duration"] = value

                    elif "Lockout observation window" in key:
                        policy["lockout_observation_window"] = value

                    elif "Computer role" in key:
                        policy["computer_role"] = value

            policy["raw_output"] = result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass

    return policy


def _get_security_policy_secedit() -> dict:
    """Export and parse security policy via secedit."""
    policy = {}
    tmp_file = None
    try:
        tmp_file = os.path.join(tempfile.gettempdir(), "agentzero_secedit.cfg")

        result = subprocess.run(
            ["secedit", "/export", "/cfg", tmp_file],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and os.path.exists(tmp_file):
            with open(tmp_file, "r", encoding="utf-16-le", errors="replace") as f:
                content = f.read()

            current_section = ""
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("[") and line.endswith("]"):
                    current_section = line[1:-1]
                    continue

                if "=" in line and current_section:
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip()

                    if current_section == "System Access":
                        if key == "MinimumPasswordLength":
                            try:
                                policy["secedit_min_password_length"] = int(value)
                            except ValueError:
                                policy["secedit_min_password_length"] = value
                        elif key == "PasswordComplexity":
                            policy["password_complexity"] = int(value) if value.isdigit() else value
                        elif key == "LockoutBadCount":
                            try:
                                policy["secedit_lockout_threshold"] = int(value)
                            except ValueError:
                                policy["secedit_lockout_threshold"] = value
                        elif key == "EnableAdminAccount":
                            policy["admin_account_enabled"] = value
                        elif key == "EnableGuestAccount":
                            policy["guest_account_enabled"] = value
                        elif key == "PasswordHistorySize":
                            try:
                                policy["password_history_size"] = int(value)
                            except ValueError:
                                policy["password_history_size"] = value
                        elif key == "ClearTextPassword":
                            policy["cleartext_password_storage"] = value

                    elif current_section == "Event Audit":
                        policy[f"audit_{key}"] = value

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, Exception):
        pass
    finally:
        if tmp_file and os.path.exists(tmp_file):
            try:
                os.remove(tmp_file)
            except OSError:
                pass

    return policy


def _check_password_complexity_powershell() -> dict:
    """Check password complexity requirement via PowerShell."""
    ps_script = """
try {
    $policy = net accounts 2>&1
    $result = @{}
    foreach ($line in $policy) {
        if ($line -match 'Minimum password length\s*:\s*(\d+|None)') {
            $result['min_length'] = $Matches[1]
        }
        if ($line -match 'Lockout threshold\s*:\s*(\d+|Never)') {
            $result['lockout_threshold'] = $Matches[1]
        }
    }
    $result | ConvertTo-Json
} catch {
    @{ 'error' = $_.Exception.Message } | ConvertTo-Json
}
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
    except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception):
        pass
    return {}


def scan() -> dict:
    """
    Scan Group Policy settings, password policy, and account lockout configuration.

    Returns:
        dict with keys: category, status, data, findings
    """
    if platform.system() != "Windows":
        return {
            "category": "Group Policy",
            "status": "error",
            "data": {},
            "findings": [{
                "severity": "info",
                "title": "Not a Windows system",
                "description": "This scanner only runs on Windows.",
            }],
        }

    try:
        findings = []

        # Get gpresult for computer and user
        computer_gpresult = _run_gpresult("COMPUTER")
        user_gpresult = _run_gpresult("USER")

        computer_parsed = _parse_gpresult(computer_gpresult)
        user_parsed = _parse_gpresult(user_gpresult)

        # Get password policy
        password_policy = _get_password_policy()
        security_policy = _get_security_policy_secedit()

        # Merge password policy data
        min_length = (
            security_policy.get("secedit_min_password_length")
            or password_policy.get("min_password_length")
        )
        lockout_threshold = (
            security_policy.get("secedit_lockout_threshold")
            or password_policy.get("lockout_threshold")
        )
        complexity = security_policy.get("password_complexity")
        guest_enabled = security_policy.get("guest_account_enabled")
        cleartext = security_policy.get("cleartext_password_storage")
        password_history = security_policy.get("password_history_size",
                                                password_policy.get("password_history_length"))

        # Check password minimum length
        if min_length is not None:
            try:
                min_len_val = int(min_length)
                if min_len_val == 0:
                    findings.append({
                        "severity": "critical",
                        "title": "No minimum password length required",
                        "description": (
                            "The minimum password length is set to 0, meaning blank passwords "
                            "are allowed. This is extremely dangerous."
                        ),
                        "remediation": (
                            "Set minimum password length to at least 12 characters. "
                            "Use: `net accounts /minpwlen:12` or configure via Group Policy: "
                            "Computer Configuration > Windows Settings > Security Settings > "
                            "Account Policies > Password Policy."
                        ),
                    })
                elif min_len_val < 8:
                    findings.append({
                        "severity": "high",
                        "title": f"Weak minimum password length: {min_len_val} characters",
                        "description": (
                            f"The minimum password length is {min_len_val} characters. "
                            f"Passwords shorter than 8 characters can be brute-forced in minutes."
                        ),
                        "remediation": (
                            "Set minimum password length to at least 12 characters. "
                            "NIST SP 800-63B recommends a minimum of 8, but 12+ is best practice."
                        ),
                    })
                elif min_len_val < 12:
                    findings.append({
                        "severity": "medium",
                        "title": f"Password length could be stronger: {min_len_val} characters",
                        "description": (
                            f"The minimum password length is {min_len_val} characters. "
                            f"While this meets minimum standards, 12+ characters is recommended."
                        ),
                        "remediation": (
                            "Consider increasing minimum password length to 12 or more characters."
                        ),
                    })
            except (ValueError, TypeError):
                pass

        # Check password complexity
        if complexity is not None:
            try:
                if int(complexity) == 0:
                    findings.append({
                        "severity": "high",
                        "title": "Password complexity requirement is disabled",
                        "description": (
                            "Password complexity requirements are not enforced. Users can set "
                            "simple passwords like '12345678' that are trivially guessable."
                        ),
                        "remediation": (
                            "Enable password complexity requirements via Group Policy: "
                            "Computer Configuration > Windows Settings > Security Settings > "
                            "Account Policies > Password Policy > Password must meet complexity requirements."
                        ),
                    })
            except (ValueError, TypeError):
                pass

        # Check account lockout threshold
        if lockout_threshold is not None:
            try:
                threshold_val = str(lockout_threshold).lower().replace("never", "0")
                threshold_int = int(threshold_val) if threshold_val.isdigit() else 0
                if threshold_int == 0:
                    findings.append({
                        "severity": "high",
                        "title": "Account lockout is not configured",
                        "description": (
                            "No account lockout threshold is set. Attackers can attempt unlimited "
                            "password guesses without any account lockout."
                        ),
                        "remediation": (
                            "Set account lockout threshold to 5-10 failed attempts. "
                            "Configure via: `net accounts /lockoutthreshold:5` or Group Policy."
                        ),
                    })
            except (ValueError, TypeError):
                pass

        # Check if Guest account is enabled
        if guest_enabled is not None:
            try:
                if int(guest_enabled) == 1:
                    findings.append({
                        "severity": "high",
                        "title": "Guest account is enabled",
                        "description": (
                            "The built-in Guest account is enabled. This provides anonymous "
                            "access to the system and should be disabled."
                        ),
                        "remediation": (
                            "Disable the Guest account: `net user Guest /active:no` or via "
                            "Computer Management > Local Users and Groups."
                        ),
                    })
            except (ValueError, TypeError):
                pass

        # Check for cleartext password storage
        if cleartext is not None:
            try:
                if int(cleartext) == 1:
                    findings.append({
                        "severity": "critical",
                        "title": "Cleartext password storage is enabled",
                        "description": (
                            "The system is configured to store passwords using reversible "
                            "encryption. This is equivalent to storing passwords in cleartext."
                        ),
                        "remediation": (
                            "Disable 'Store passwords using reversible encryption' in Group Policy: "
                            "Computer Configuration > Windows Settings > Security Settings > "
                            "Account Policies > Password Policy."
                        ),
                    })
            except (ValueError, TypeError):
                pass

        # Check password history
        if password_history is not None:
            try:
                history_val = int(password_history)
                if history_val == 0:
                    findings.append({
                        "severity": "medium",
                        "title": "Password history is not enforced",
                        "description": (
                            "No password history is enforced. Users can reuse the same password "
                            "indefinitely, reducing the effectiveness of password rotation."
                        ),
                        "remediation": (
                            "Set password history to remember at least 24 previous passwords."
                        ),
                    })
            except (ValueError, TypeError):
                pass

        # Determine status
        if any(f["severity"] == "critical" for f in findings):
            status = "fail"
        elif any(f["severity"] == "high" for f in findings):
            status = "fail"
        elif any(f["severity"] == "medium" for f in findings):
            status = "warn"
        elif findings:
            status = "info"
        else:
            status = "pass"

        return {
            "category": "Group Policy",
            "status": status,
            "data": {
                "computer_gpos": computer_parsed.get("applied_gpos", []),
                "user_gpos": user_parsed.get("applied_gpos", []),
                "password_policy": password_policy,
                "security_policy": security_policy,
            },
            "findings": findings,
        }

    except Exception as e:
        return {
            "category": "Group Policy",
            "status": "error",
            "data": {"error": str(e)},
            "findings": [{
                "severity": "info",
                "title": "Scanner error",
                "description": f"An unexpected error occurred while scanning group policy: {e}",
            }],
        }
