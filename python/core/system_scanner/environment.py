"""
Environment Variables & PATH Scanner
=====================================
Audits system and user PATH directories, environment variables, and SDDL
permissions on key system directories.

Security Relevance:
- Writable directories in PATH enable DLL hijacking / binary planting attacks.
  An attacker who can write to a PATH directory can drop a malicious DLL or
  executable that will be loaded by legitimate programs.
- Sensitive data (passwords, API keys, tokens) stored in environment variables
  is accessible to any process running in the same user context.
- Incorrect ACLs (SDDL) on system directories can allow privilege escalation.

Data Sources:
- Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment (system PATH)
- Registry: HKCU\\Environment (user PATH)
- PowerShell: [Environment]::GetEnvironmentVariable
- PowerShell: Get-Acl for SDDL on key system directories
"""

import platform
import subprocess
import json
import re


# Sensitive environment variable name patterns (case-insensitive)
_SENSITIVE_PATTERNS = [
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"passwd", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"access[_-]?key", re.IGNORECASE),
    re.compile(r"private[_-]?key", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
    re.compile(r"connection[_-]?string", re.IGNORECASE),
    re.compile(r"auth[_-]?token", re.IGNORECASE),
    re.compile(r"aws[_-]?secret", re.IGNORECASE),
    re.compile(r"azure[_-]?.*key", re.IGNORECASE),
]

# Well-known writable / risky PATH entries
_RISKY_PATH_PATTERNS = [
    re.compile(r"\\temp\\?$", re.IGNORECASE),
    re.compile(r"\\tmp\\?$", re.IGNORECASE),
    re.compile(r"\\downloads\\?$", re.IGNORECASE),
    re.compile(r"\\desktop\\?$", re.IGNORECASE),
    re.compile(r"^\.\\?$"),  # Current directory
    re.compile(r"\\appdata\\local\\temp", re.IGNORECASE),
]

# Key system directories to check SDDL for
_SYSTEM_DIRS = [
    r"C:\Windows",
    r"C:\Windows\System32",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
]


def _get_env_vars_powershell() -> dict:
    """Get all environment variables via PowerShell."""
    ps_script = """
$result = @{}
$result['system_path'] = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
$result['user_path'] = [Environment]::GetEnvironmentVariable('PATH', 'User')

$sysVars = @{}
[Environment]::GetEnvironmentVariables('Machine').GetEnumerator() | ForEach-Object {
    $sysVars[$_.Key] = $_.Value
}
$result['system_vars'] = $sysVars

$userVars = @{}
[Environment]::GetEnvironmentVariables('User').GetEnumerator() | ForEach-Object {
    $userVars[$_.Key] = $_.Value
}
$result['user_vars'] = $userVars

$result | ConvertTo-Json -Depth 3
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
    except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception):
        pass
    return {}


def _check_path_writable(path_dirs: list) -> list:
    """Check if PATH directories are writable by the current user."""
    if not path_dirs:
        return []

    # Build PowerShell script to test write access
    dir_checks = []
    for d in path_dirs[:50]:  # Limit to 50 directories to avoid timeout
        escaped = d.replace("'", "''")
        dir_checks.append(f"'{escaped}'")

    dirs_array = ",".join(dir_checks)
    ps_script = f"""
$dirs = @({dirs_array})
$results = foreach ($dir in $dirs) {{
    if (Test-Path $dir -PathType Container) {{
        try {{
            $testFile = Join-Path $dir ([System.IO.Path]::GetRandomFileName())
            [System.IO.File]::Create($testFile).Close()
            Remove-Item $testFile -Force -ErrorAction SilentlyContinue
            [PSCustomObject]@{{ Path = $dir; Writable = $true; Exists = $true }}
        }} catch {{
            [PSCustomObject]@{{ Path = $dir; Writable = $false; Exists = $true }}
        }}
    }} else {{
        [PSCustomObject]@{{ Path = $dir; Writable = $false; Exists = $false }}
    }}
}}
$results | ConvertTo-Json -Depth 2
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception):
        pass
    return []


def _get_sddl_info() -> list:
    """Get SDDL information for key system directories."""
    sddl_results = []
    for dir_path in _SYSTEM_DIRS:
        escaped = dir_path.replace("'", "''")
        ps_script = f"""
if (Test-Path '{escaped}') {{
    $acl = Get-Acl '{escaped}' -ErrorAction SilentlyContinue
    if ($acl) {{
        [PSCustomObject]@{{
            Path = '{escaped}'
            Owner = $acl.Owner
            SDDL = $acl.Sddl
            AccessRules = ($acl.Access | ForEach-Object {{
                [PSCustomObject]@{{
                    Identity = $_.IdentityReference.Value
                    AccessType = $_.AccessControlType.ToString()
                    Rights = $_.FileSystemRights.ToString()
                    Inherited = $_.IsInherited
                }}
            }})
        }} | ConvertTo-Json -Depth 3
    }}
}}
"""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                sddl_results.append(data)
        except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception):
            continue
    return sddl_results


def scan() -> dict:
    """
    Scan environment variables, PATH directories, and system directory ACLs.

    Returns:
        dict with keys: category, status, data, findings
    """
    if platform.system() != "Windows":
        return {
            "category": "Environment",
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
        env_data = _get_env_vars_powershell()

        system_path_raw = env_data.get("system_path", "") or ""
        user_path_raw = env_data.get("user_path", "") or ""
        system_vars = env_data.get("system_vars", {}) or {}
        user_vars = env_data.get("user_vars", {}) or {}

        # Parse PATH directories
        system_path_dirs = [d.strip() for d in system_path_raw.split(";") if d.strip()]
        user_path_dirs = [d.strip() for d in user_path_raw.split(";") if d.strip()]
        all_path_dirs = list(dict.fromkeys(system_path_dirs + user_path_dirs))  # dedupe, preserve order

        # Check for risky PATH entries
        for dir_path in all_path_dirs:
            for pattern in _RISKY_PATH_PATTERNS:
                if pattern.search(dir_path):
                    findings.append({
                        "severity": "high",
                        "title": f"Risky directory in PATH: {dir_path}",
                        "description": (
                            f"The directory '{dir_path}' is in the system or user PATH. "
                            f"Temporary or user-writable directories in PATH enable DLL hijacking "
                            f"and binary planting attacks."
                        ),
                        "remediation": (
                            f"Remove '{dir_path}' from the PATH environment variable. "
                            f"Ensure PATH only contains trusted, administrator-protected directories."
                        ),
                    })
                    break

        # Check for writable PATH directories
        writable_check = _check_path_writable(all_path_dirs)
        writable_dirs = [d for d in writable_check if d.get("Writable", False)]
        for wd in writable_dirs:
            path = wd.get("Path", "Unknown")
            # Don't duplicate if already flagged as risky
            already_flagged = any(path.lower() in f.get("title", "").lower() for f in findings)
            if not already_flagged:
                findings.append({
                    "severity": "high",
                    "title": f"Writable PATH directory: {path}",
                    "description": (
                        f"The current user can write to '{path}', which is in the PATH. "
                        f"An attacker could place a malicious executable or DLL in this directory "
                        f"to hijack legitimate program execution."
                    ),
                    "remediation": (
                        f"Restrict write permissions on '{path}' or remove it from PATH. "
                        f"PATH directories should only be writable by administrators."
                    ),
                })

        # Check for sensitive environment variables
        all_vars = {}
        all_vars.update(system_vars)
        all_vars.update(user_vars)

        sensitive_vars_found = []
        for var_name, var_value in all_vars.items():
            for pattern in _SENSITIVE_PATTERNS:
                if pattern.search(var_name):
                    sensitive_vars_found.append({
                        "name": var_name,
                        "value_length": len(str(var_value)) if var_value else 0,
                        "scope": "system" if var_name in system_vars else "user",
                    })
                    break

        if sensitive_vars_found:
            var_names = ", ".join(v["name"] for v in sensitive_vars_found[:10])
            findings.append({
                "severity": "medium",
                "title": f"Sensitive environment variables detected ({len(sensitive_vars_found)} found)",
                "description": (
                    f"Environment variables with potentially sensitive names were found: {var_names}. "
                    f"Secrets stored in environment variables are accessible to any process running "
                    f"in the same user context and may appear in crash dumps or process listings."
                ),
                "remediation": (
                    "Use Windows Credential Manager, Azure Key Vault, or a secrets management "
                    "solution instead of environment variables. Remove sensitive data from "
                    "environment variables where possible."
                ),
            })

        # Get SDDL for system directories
        sddl_info = _get_sddl_info()

        # Check for overly permissive system directory ACLs
        for sddl_entry in sddl_info:
            access_rules = sddl_entry.get("AccessRules", []) or []
            if isinstance(access_rules, dict):
                access_rules = [access_rules]
            for rule in access_rules:
                identity = rule.get("Identity", "")
                rights = rule.get("Rights", "")
                access_type = rule.get("AccessType", "")
                if access_type == "Allow" and identity.lower() in (
                    "everyone", "builtin\\users", "authenticated users",
                    "nt authority\\authenticated users",
                ):
                    if any(perm in rights for perm in ["FullControl", "Modify", "Write"]):
                        findings.append({
                            "severity": "high",
                            "title": f"Overly permissive ACL on {sddl_entry.get('Path', 'Unknown')}",
                            "description": (
                                f"'{identity}' has '{rights}' access to "
                                f"'{sddl_entry.get('Path', 'Unknown')}'. Standard users should not "
                                f"have write access to system directories."
                            ),
                            "remediation": (
                                f"Restrict permissions on '{sddl_entry.get('Path', 'Unknown')}' "
                                f"to SYSTEM and Administrators only. Remove write access for "
                                f"'{identity}'."
                            ),
                        })

        # Determine status
        if any(f["severity"] in ("critical", "high") for f in findings):
            status = "fail"
        elif any(f["severity"] == "medium" for f in findings):
            status = "warn"
        elif findings:
            status = "info"
        else:
            status = "pass"

        # Sanitize env var values for output (don't leak actual secrets)
        safe_system_vars = {k: ("***REDACTED***" if any(p.search(k) for p in _SENSITIVE_PATTERNS) else v)
                           for k, v in system_vars.items()}
        safe_user_vars = {k: ("***REDACTED***" if any(p.search(k) for p in _SENSITIVE_PATTERNS) else v)
                         for k, v in user_vars.items()}

        return {
            "category": "Environment",
            "status": status,
            "data": {
                "system_path_dirs": system_path_dirs,
                "user_path_dirs": user_path_dirs,
                "total_path_dirs": len(all_path_dirs),
                "writable_path_dirs": [d.get("Path") for d in writable_dirs],
                "system_variables": safe_system_vars,
                "user_variables": safe_user_vars,
                "sensitive_variables": sensitive_vars_found,
                "sddl_info": sddl_info,
            },
            "findings": findings,
        }

    except Exception as e:
        return {
            "category": "Environment",
            "status": "error",
            "data": {"error": str(e)},
            "findings": [{
                "severity": "info",
                "title": "Scanner error",
                "description": f"An unexpected error occurred while scanning environment: {e}",
            }],
        }
