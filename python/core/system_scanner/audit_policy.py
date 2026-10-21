"""
Audit Policy Scanner
====================
Reads both classic and advanced Windows audit policy settings to ensure that
critical security events are being logged.

Why it matters:
    Without proper audit policies, security-relevant events (failed logons,
    privilege escalation, process creation, policy changes) are silently
    discarded. Attackers rely on absent logging to operate undetected.
    This module verifies that essential audit categories are configured.

Data sources:
    - ``auditpol /get /category:*`` (authoritative runtime policy)
    - Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa (classic audit)
    - Registry: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit
"""

import json
import platform
import subprocess
import traceback

# Categories considered critical — if any of these show "No Auditing", we flag it.
_CRITICAL_CATEGORIES = {
    "Logon",
    "Logoff",
    "Account Logon",
    "Account Lockout",
    "Credential Validation",
    "Sensitive Privilege Use",
    "Process Creation",
    "Audit Policy Change",
    "Authentication Policy Change",
    "Security State Change",
    "User Account Management",
    "Computer Account Management",
    "Security Group Management",
}


def _run_auditpol() -> dict:
    """Execute ``auditpol /get /category:*`` and parse output."""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "auditpol /get /category:* /r"],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            return {"raw": proc.stderr.strip(), "parsed": [], "error": proc.stderr.strip()}

        lines = [l.strip() for l in proc.stdout.strip().splitlines() if l.strip()]
        # CSV format: Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting
        parsed = []
        if len(lines) > 1:
            for line in lines[1:]:
                parts = line.split(",")
                if len(parts) >= 5:
                    parsed.append({
                        "subcategory": parts[2].strip(),
                        "guid": parts[3].strip(),
                        "setting": parts[4].strip(),
                    })
        return {"raw": proc.stdout.strip(), "parsed": parsed, "error": None}
    except subprocess.TimeoutExpired:
        return {"raw": "", "parsed": [], "error": "auditpol command timed out"}
    except FileNotFoundError:
        return {"raw": "", "parsed": [], "error": "auditpol not found"}
    except Exception as exc:
        return {"raw": "", "parsed": [], "error": str(exc)}


def _read_lsa_registry() -> dict:
    """Read classic audit settings from the LSA registry key."""
    import winreg

    lsa_data = {}
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
        )
        for name in ("AuditBaseObjects", "AuditBaseDirectories", "FullPrivilegeAuditing",
                      "CrashOnAuditFail", "SCENoApplyLegacyAuditPolicy"):
            try:
                value, _ = winreg.QueryValueEx(key, name)
                lsa_data[name] = value
            except FileNotFoundError:
                lsa_data[name] = None
        winreg.CloseKey(key)
    except (FileNotFoundError, PermissionError, OSError) as exc:
        lsa_data["_error"] = str(exc)
    return lsa_data


def _read_advanced_audit_registry() -> dict:
    """Read advanced audit policy configuration from registry."""
    import winreg

    adv = {}
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        index = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, index)
                adv[name] = value
                index += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except (FileNotFoundError, PermissionError, OSError) as exc:
        adv["_error"] = str(exc)
    return adv


def scan() -> dict:
    """
    Scan Windows audit policy configuration.

    Returns:
        dict with keys 'category', 'status', 'data', 'findings'.
    """
    if platform.system() != "Windows":
        return {
            "category": "Audit Policy",
            "status": "error",
            "data": {},
            "findings": [
                {
                    "severity": "info",
                    "title": "Not a Windows system",
                    "description": "Audit policy scanning is only applicable on Windows.",
                }
            ],
        }

    try:
        auditpol = _run_auditpol()
        lsa = _read_lsa_registry()
        advanced = _read_advanced_audit_registry()

        data = {
            "auditpol": auditpol,
            "lsa_registry": lsa,
            "advanced_audit_registry": advanced,
        }

        findings = []

        # --- Analyse auditpol output -------------------------------------------
        if auditpol.get("error"):
            findings.append(
                {
                    "severity": "medium",
                    "title": "Could not retrieve audit policy via auditpol",
                    "description": f"Error: {auditpol['error']}",
                    "remediation": "Run the scanner with elevated (Administrator) privileges.",
                }
            )
        else:
            parsed = auditpol.get("parsed", [])
            not_audited = []
            for entry in parsed:
                subcat = entry.get("subcategory", "")
                setting = entry.get("setting", "")
                # Check if a critical subcategory has no auditing
                if any(crit.lower() in subcat.lower() for crit in _CRITICAL_CATEGORIES):
                    if setting.lower() == "no auditing":
                        not_audited.append(subcat)

            if not_audited:
                findings.append(
                    {
                        "severity": "high",
                        "title": "Critical audit subcategories are not being audited",
                        "description": (
                            "The following critical subcategories have 'No Auditing' "
                            f"configured: {', '.join(not_audited)}. This means security "
                            "events in these areas are not being logged."
                        ),
                        "remediation": (
                            "Configure audit policies using Group Policy or "
                            "`auditpol /set /subcategory:\"<name>\" /success:enable /failure:enable` "
                            "for each missing subcategory."
                        ),
                    }
                )

            # Count how many subcategories are audited at all
            total = len(parsed)
            audited_count = sum(
                1 for e in parsed if e.get("setting", "").lower() != "no auditing"
            )
            data["summary"] = {
                "total_subcategories": total,
                "audited_subcategories": audited_count,
                "unaudited_subcategories": total - audited_count,
            }

            if total > 0 and audited_count == 0:
                findings.append(
                    {
                        "severity": "critical",
                        "title": "No audit subcategories are enabled",
                        "description": (
                            "None of the audit subcategories are configured to log "
                            "events. The system is effectively blind to security events."
                        ),
                        "remediation": (
                            "Apply a comprehensive audit policy via Group Policy. "
                            "At minimum, enable Success and Failure auditing for "
                            "Logon/Logoff, Account Logon, Privilege Use, and "
                            "Policy Change categories."
                        ),
                    }
                )

        # --- Check LSA settings ------------------------------------------------
        sce_no_legacy = lsa.get("SCENoApplyLegacyAuditPolicy")
        if sce_no_legacy is not None and sce_no_legacy == 0:
            findings.append(
                {
                    "severity": "info",
                    "title": "Legacy audit policy may override advanced audit policy",
                    "description": (
                        "SCENoApplyLegacyAuditPolicy is 0, meaning the classic "
                        "audit policy can override the advanced audit policy "
                        "subcategory settings."
                    ),
                }
            )

        crash_on_fail = lsa.get("CrashOnAuditFail")
        if crash_on_fail is not None and crash_on_fail >= 1:
            findings.append(
                {
                    "severity": "info",
                    "title": "CrashOnAuditFail is enabled",
                    "description": (
                        "The system is configured to halt if it cannot write "
                        "audit events. This is a high-security setting."
                    ),
                }
            )

        # --- Determine overall status ------------------------------------------
        severities = [f["severity"] for f in findings]
        if "critical" in severities:
            status = "fail"
        elif "high" in severities:
            status = "fail"
        elif "medium" in severities:
            status = "warn"
        else:
            status = "pass"

        if not findings:
            findings.append(
                {
                    "severity": "info",
                    "title": "Audit policy appears properly configured",
                    "description": "All critical audit subcategories are enabled.",
                }
            )

        return {
            "category": "Audit Policy",
            "status": status,
            "data": data,
            "findings": findings,
        }

    except Exception as exc:
        return {
            "category": "Audit Policy",
            "status": "error",
            "data": {"error": str(exc), "traceback": traceback.format_exc()},
            "findings": [
                {
                    "severity": "info",
                    "title": "Error scanning audit policy",
                    "description": f"An unexpected error occurred: {exc}",
                }
            ],
        }
