"""
PowerShell History Scanner
==========================
Searches PowerShell console history files (PSReadLine ConsoleHost_history.txt)
for all user profiles, looking for sensitive data such as passwords, tokens,
API keys, and credential usage.

Security Relevance:
- PowerShell history persists commands in plaintext on disk by default.
- Administrators often type passwords, tokens, and connection strings directly
  into the PowerShell console, which are saved to history.
- An attacker with file system access can read history files to harvest
  credentials and secrets (credential exposure / lateral movement).
- Usage of ConvertTo-SecureString, -Credential, and Net.WebClient may indicate
  automation scripts that handle secrets insecurely.

Data Sources:
- File: %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt
  for each user profile.
"""

import platform
import subprocess
import json
import re
import os


# Regex patterns for sensitive content in PowerShell history
_SENSITIVE_PATTERNS = [
    {
        "name": "password_parameter",
        "pattern": re.compile(
            r"(?:-|/)(?:password|passwd|pwd)\s+\S+",
            re.IGNORECASE,
        ),
        "description": "Password passed as a command parameter",
        "severity": "high",
    },
    {
        "name": "plaintext_password",
        "pattern": re.compile(
            r"""(?:password|passwd|pwd)\s*[=:]\s*['"]?[^\s'"]{3,}""",
            re.IGNORECASE,
        ),
        "description": "Password assignment in plaintext",
        "severity": "high",
    },
    {
        "name": "secret_token",
        "pattern": re.compile(
            r"""(?:secret|token|apikey|api[_-]?key)\s*[=:]\s*['"]?[^\s'"]{8,}""",
            re.IGNORECASE,
        ),
        "description": "Secret, token, or API key in plaintext",
        "severity": "high",
    },
    {
        "name": "connection_string",
        "pattern": re.compile(
            r"(?:connection\s*string|connstr|Data Source\s*=|Server\s*=).*(?:Password|Pwd)\s*=",
            re.IGNORECASE,
        ),
        "description": "Connection string with embedded credentials",
        "severity": "critical",
    },
    {
        "name": "credential_parameter",
        "pattern": re.compile(
            r"-Credential\s+",
            re.IGNORECASE,
        ),
        "description": "PowerShell -Credential parameter usage",
        "severity": "medium",
    },
    {
        "name": "secure_string_conversion",
        "pattern": re.compile(
            r"ConvertTo-SecureString\s+",
            re.IGNORECASE,
        ),
        "description": "ConvertTo-SecureString usage (may contain plaintext passwords)",
        "severity": "medium",
    },
    {
        "name": "net_webclient",
        "pattern": re.compile(
            r"(?:Net\.WebClient|Invoke-WebRequest|Invoke-RestMethod|wget|curl)\s+",
            re.IGNORECASE,
        ),
        "description": "Web request command (potential data exfiltration or download)",
        "severity": "low",
    },
    {
        "name": "encoded_command",
        "pattern": re.compile(
            r"-(?:EncodedCommand|enc)\s+[A-Za-z0-9+/=]{20,}",
            re.IGNORECASE,
        ),
        "description": "Base64-encoded PowerShell command (obfuscation technique)",
        "severity": "high",
    },
    {
        "name": "aws_credentials",
        "pattern": re.compile(
            r"(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AKIA[0-9A-Z]{16})",
            re.IGNORECASE,
        ),
        "description": "AWS credentials or access key",
        "severity": "critical",
    },
    {
        "name": "azure_credentials",
        "pattern": re.compile(
            r"(?:Connect-AzAccount|Login-AzureRmAccount|az\s+login).*(?:-Credential|-u)",
            re.IGNORECASE,
        ),
        "description": "Azure login with credentials",
        "severity": "high",
    },
    {
        "name": "runas_command",
        "pattern": re.compile(
            r"runas\s+/user:",
            re.IGNORECASE,
        ),
        "description": "RunAs command (privilege escalation attempt or admin action)",
        "severity": "medium",
    },
    {
        "name": "net_use_credentials",
        "pattern": re.compile(
            r"net\s+use\s+.*\s+/user:",
            re.IGNORECASE,
        ),
        "description": "Net use with credentials (network share authentication)",
        "severity": "high",
    },
]


def _find_history_files() -> list:
    """
    Find all PowerShell ConsoleHost_history.txt files for all user profiles.

    Returns:
        List of dicts with 'user', 'path', and 'size' keys.
    """
    ps_script = r"""
$profilesPath = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue).ProfilesDirectory
if (-not $profilesPath) { $profilesPath = 'C:\Users' }

$results = @()
$users = Get-ChildItem $profilesPath -Directory -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -notin @('Public', 'Default', 'Default User', 'All Users')
}

foreach ($user in $users) {
    $histPath = Join-Path $user.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (Test-Path $histPath) {
        $file = Get-Item $histPath -ErrorAction SilentlyContinue
        $results += [PSCustomObject]@{
            User     = $user.Name
            Path     = $histPath
            SizeBytes = $file.Length
            LastModified = $file.LastWriteTime.ToString('o')
        }
    }
}

# Also check current user
$currentHistPath = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
if (Test-Path $currentHistPath) {
    $alreadyFound = $results | Where-Object { $_.Path -eq $currentHistPath }
    if (-not $alreadyFound) {
        $file = Get-Item $currentHistPath -ErrorAction SilentlyContinue
        $results += [PSCustomObject]@{
            User     = $env:USERNAME
            Path     = $currentHistPath
            SizeBytes = $file.Length
            LastModified = $file.LastWriteTime.ToString('o')
        }
    }
}

$results | ConvertTo-Json -Depth 2
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception):
        pass
    return []


def _read_history_file(file_path: str, max_bytes: int = 1_048_576) -> str:
    """
    Read the contents of a PowerShell history file.

    Args:
        file_path: Path to the history file.
        max_bytes: Maximum bytes to read (default 1MB).

    Returns:
        File contents as string.
    """
    escaped = file_path.replace("'", "''")
    ps_script = f"""
try {{
    $content = Get-Content '{escaped}' -Raw -TotalCount 10000 -ErrorAction Stop
    $content
}} catch {{
    ""
}}
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            return result.stdout
    except (subprocess.TimeoutExpired, Exception):
        pass
    return ""


def _scan_content_for_sensitive(content: str, user: str, file_path: str) -> list:
    """
    Scan history content for sensitive patterns.

    Args:
        content: History file content.
        user: Username associated with the history file.
        file_path: Path to the history file.

    Returns:
        List of match dicts.
    """
    matches = []
    if not content:
        return matches

    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("#"):
            continue

        for sp in _SENSITIVE_PATTERNS:
            match = sp["pattern"].search(line_stripped)
            if match:
                # Redact the actual sensitive value in the output
                matched_text = match.group(0)
                # Limit displayed content to avoid leaking full secrets
                display_text = line_stripped[:120] + ("..." if len(line_stripped) > 120 else "")

                matches.append({
                    "user": user,
                    "file": file_path,
                    "line_number": line_num,
                    "pattern_name": sp["name"],
                    "description": sp["description"],
                    "severity": sp["severity"],
                    "context": display_text,
                })
                break  # Only match the first (highest priority) pattern per line

    return matches


def scan() -> dict:
    """
    Scan PowerShell console history files for sensitive data such as
    passwords, tokens, API keys, and credential usage.

    Returns:
        dict with keys: category, status, data, findings
    """
    if platform.system() != "Windows":
        return {
            "category": "PowerShell History",
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
        history_files = _find_history_files()
        all_matches = []
        files_scanned = 0

        for hf in history_files:
            user = hf.get("User", "Unknown")
            file_path = hf.get("Path", "")
            file_size = hf.get("SizeBytes", 0)

            if not file_path:
                continue

            files_scanned += 1
            content = _read_history_file(file_path)

            if content:
                matches = _scan_content_for_sensitive(content, user, file_path)
                all_matches.extend(matches)

        # Aggregate matches by severity and pattern
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        pattern_counts = {}

        for m in all_matches:
            sev = m.get("severity", "low")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            pattern_name = m.get("pattern_name", "unknown")
            if pattern_name not in pattern_counts:
                pattern_counts[pattern_name] = {"count": 0, "description": m.get("description", ""), "severity": sev}
            pattern_counts[pattern_name]["count"] += 1

        # Generate findings
        if severity_counts.get("critical", 0) > 0:
            critical_matches = [m for m in all_matches if m.get("severity") == "critical"]
            sample_contexts = [m.get("context", "")[:80] for m in critical_matches[:3]]
            findings.append({
                "severity": "critical",
                "title": f"Critical secrets found in PowerShell history ({severity_counts['critical']} matches)",
                "description": (
                    f"Critical secrets such as connection strings, AWS credentials, or similar "
                    f"were found in PowerShell history files. These are stored in plaintext and "
                    f"accessible to any user or malware with file system access. "
                    f"Sample matches: {'; '.join(sample_contexts)}"
                ),
                "remediation": (
                    "1. Immediately rotate all exposed credentials.\n"
                    "2. Clear PowerShell history: Remove-Item (Get-PSReadlineOption).HistorySavePath\n"
                    "3. Use a secrets manager instead of typing credentials in the console.\n"
                    "4. Consider disabling PSReadLine history: Set-PSReadLineOption -HistorySaveStyle SaveNothing"
                ),
            })

        if severity_counts.get("high", 0) > 0:
            high_matches = [m for m in all_matches if m.get("severity") == "high"]
            users_affected = list(set(m.get("user", "Unknown") for m in high_matches))
            findings.append({
                "severity": "high",
                "title": f"Sensitive data in PowerShell history ({severity_counts['high']} matches)",
                "description": (
                    f"Passwords, tokens, or API keys were found in PowerShell history for users: "
                    f"{', '.join(users_affected)}. An attacker with local file access could harvest "
                    f"these credentials for lateral movement."
                ),
                "remediation": (
                    "Clear PowerShell history and rotate affected credentials. Use a secrets "
                    "management solution and avoid typing secrets directly in the console."
                ),
            })

        if severity_counts.get("medium", 0) > 0:
            findings.append({
                "severity": "medium",
                "title": f"Credential-related commands in history ({severity_counts['medium']} matches)",
                "description": (
                    f"Usage of -Credential, ConvertTo-SecureString, or RunAs was detected in "
                    f"PowerShell history. While these may be legitimate, they could expose "
                    f"credential handling patterns."
                ),
                "remediation": (
                    "Review the commands to ensure credentials are handled securely. Use "
                    "Windows Credential Manager or Get-Credential instead of inline passwords."
                ),
            })

        if severity_counts.get("low", 0) > 0:
            findings.append({
                "severity": "low",
                "title": f"Potentially interesting commands in history ({severity_counts['low']} matches)",
                "description": (
                    f"Web requests or other potentially interesting commands were found in "
                    f"PowerShell history. These may be benign but should be reviewed."
                ),
            })

        # If no history files found
        if not history_files:
            findings.append({
                "severity": "info",
                "title": "No PowerShell history files found",
                "description": (
                    "No ConsoleHost_history.txt files were found for any user. Either PSReadLine "
                    "is not installed, history saving is disabled, or insufficient permissions "
                    "to access user profiles."
                ),
            })

        # If history files exist but no sensitive data found
        if history_files and not all_matches:
            findings.append({
                "severity": "info",
                "title": f"No sensitive data found in {files_scanned} history files",
                "description": (
                    f"Scanned {files_scanned} PowerShell history files and found no sensitive "
                    f"patterns. This is a good sign."
                ),
            })

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
            "category": "PowerShell History",
            "status": status,
            "data": {
                "history_files_found": len(history_files),
                "files_scanned": files_scanned,
                "total_sensitive_matches": len(all_matches),
                "severity_counts": severity_counts,
                "pattern_counts": pattern_counts,
                "history_files": history_files,
                "sensitive_matches": all_matches[:100],  # Limit output size
            },
            "findings": findings,
        }

    except Exception as e:
        return {
            "category": "PowerShell History",
            "status": "error",
            "data": {"error": str(e)},
            "findings": [{
                "severity": "info",
                "title": "Scanner error",
                "description": f"An unexpected error occurred while scanning PowerShell history: {e}",
            }],
        }
