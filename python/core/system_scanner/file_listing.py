"""
User File Listing Scanner
=========================
Enumerates files in user Downloads, Documents, and Desktop folders across
all user profiles on the system.

Security Relevance:
- Executable files (.exe, .bat, .cmd, .ps1, .vbs, .js, .hta, .scr, .msi) in
  user download folders are a primary malware delivery vector.
- Users frequently download and forget to clean up potentially malicious files.
- Attackers often stage payloads in user-writable locations like Desktop or Downloads.
- Files with double extensions (e.g., report.pdf.exe) are a social engineering trick.

Data Sources:
- PowerShell: Enumerate user profiles and list files in standard folders.
"""

import platform
import subprocess
import json
import re


# Dangerous file extensions that indicate potential executables / scripts
_DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
    ".hta", ".scr", ".msi", ".msp", ".mst", ".com", ".pif",
    ".wsf", ".wsh", ".cpl", ".inf", ".reg",
}

# Additional suspicious extensions
_SUSPICIOUS_EXTENSIONS = {
    ".dll", ".sys", ".drv", ".iso", ".img", ".vhd", ".vhdx",
    ".lnk", ".url",
}


def _enumerate_user_files() -> dict:
    """Enumerate files in user profile folders via PowerShell."""
    ps_script = r"""
$folders = @('Downloads', 'Documents', 'Desktop')
$profilesPath = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue).ProfilesDirectory
if (-not $profilesPath) { $profilesPath = 'C:\Users' }

$allUsers = Get-ChildItem $profilesPath -Directory -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -notin @('Public', 'Default', 'Default User', 'All Users')
}

$results = @()
foreach ($user in $allUsers) {
    foreach ($folder in $folders) {
        $folderPath = Join-Path $user.FullName $folder
        if (Test-Path $folderPath) {
            $files = Get-ChildItem $folderPath -File -ErrorAction SilentlyContinue | Select-Object -First 200 | ForEach-Object {
                [PSCustomObject]@{
                    UserProfile = $user.Name
                    Folder      = $folder
                    FileName    = $_.Name
                    Extension   = $_.Extension.ToLower()
                    SizeBytes   = $_.Length
                    LastModified = $_.LastWriteTime.ToString('o')
                    CreatedTime  = $_.CreationTime.ToString('o')
                    FullPath     = $_.FullName
                    IsReadOnly   = $_.IsReadOnly
                }
            }
            if ($files) {
                $results += $files
            }
        }
    }
}
$results | ConvertTo-Json -Depth 3
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {"files": [], "error": result.stderr.strip() if result.stderr else None}

        data = json.loads(result.stdout)
        if isinstance(data, dict):
            data = [data]
        return {"files": data if isinstance(data, list) else []}
    except json.JSONDecodeError as e:
        return {"files": [], "error": f"JSON parse error: {e}"}
    except subprocess.TimeoutExpired:
        return {"files": [], "error": "PowerShell command timed out"}
    except Exception as e:
        return {"files": [], "error": str(e)}


def _has_double_extension(filename: str) -> bool:
    """Check if a filename has a double extension (e.g., report.pdf.exe)."""
    parts = filename.rsplit(".", 2)
    if len(parts) >= 3:
        apparent_ext = "." + parts[-1].lower()
        if apparent_ext in _DANGEROUS_EXTENSIONS:
            return True
    return False


def scan() -> dict:
    """
    Scan user profile folders (Downloads, Documents, Desktop) for files,
    focusing on potentially dangerous executables.

    Returns:
        dict with keys: category, status, data, findings
    """
    if platform.system() != "Windows":
        return {
            "category": "File Listing",
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
        result = _enumerate_user_files()
        files = result.get("files", [])
        error = result.get("error")

        if error and not files:
            return {
                "category": "File Listing",
                "status": "error",
                "data": {"error": error},
                "findings": [{
                    "severity": "info",
                    "title": "Failed to enumerate user files",
                    "description": f"Could not enumerate user profile files: {error}",
                }],
            }

        # Categorize files
        dangerous_files = []
        suspicious_files = []
        double_ext_files = []
        total_files = len(files)

        # Per-user, per-folder summary
        folder_summary = {}

        for f in files:
            ext = (f.get("Extension", "") or "").lower()
            filename = f.get("FileName", "")
            user = f.get("UserProfile", "Unknown")
            folder = f.get("Folder", "Unknown")

            key = f"{user}/{folder}"
            if key not in folder_summary:
                folder_summary[key] = {"total": 0, "dangerous": 0, "suspicious": 0}
            folder_summary[key]["total"] += 1

            if ext in _DANGEROUS_EXTENSIONS:
                dangerous_files.append(f)
                folder_summary[key]["dangerous"] += 1

            elif ext in _SUSPICIOUS_EXTENSIONS:
                suspicious_files.append(f)
                folder_summary[key]["suspicious"] += 1

            if _has_double_extension(filename):
                double_ext_files.append(f)

        # Generate findings for dangerous files in Downloads
        download_dangerous = [f for f in dangerous_files if f.get("Folder") == "Downloads"]
        if download_dangerous:
            sample_files = [f.get("FileName", "Unknown") for f in download_dangerous[:10]]
            findings.append({
                "severity": "high",
                "title": f"Executable files found in Downloads ({len(download_dangerous)} files)",
                "description": (
                    f"{len(download_dangerous)} potentially dangerous executable files were found "
                    f"in user Downloads folders. Sample files: {', '.join(sample_files)}. "
                    f"Downloaded executables are a primary malware delivery vector."
                ),
                "remediation": (
                    "Review and remove any unauthorized executable files from Downloads folders. "
                    "Implement application whitelisting (AppLocker) to prevent execution from "
                    "user-writable directories. Enable Windows Defender SmartScreen."
                ),
            })

        # Dangerous files in other folders
        other_dangerous = [f for f in dangerous_files if f.get("Folder") != "Downloads"]
        if other_dangerous:
            sample_files = [
                f"{f.get('FileName', '?')} ({f.get('UserProfile', '?')}/{f.get('Folder', '?')})"
                for f in other_dangerous[:10]
            ]
            findings.append({
                "severity": "medium",
                "title": f"Executable files in user folders ({len(other_dangerous)} files)",
                "description": (
                    f"{len(other_dangerous)} executable files found in user Documents/Desktop folders. "
                    f"Sample files: {', '.join(sample_files)}."
                ),
                "remediation": (
                    "Review these files and verify they are legitimate. Consider implementing "
                    "AppLocker rules to restrict execution from user profile directories."
                ),
            })

        # Double extension files
        if double_ext_files:
            sample = [f.get("FileName", "Unknown") for f in double_ext_files[:5]]
            findings.append({
                "severity": "critical",
                "title": f"Files with double extensions detected ({len(double_ext_files)} files)",
                "description": (
                    f"Files with suspicious double extensions were found: {', '.join(sample)}. "
                    f"Double extensions (e.g., report.pdf.exe) are a common social engineering "
                    f"technique used to disguise malware as documents."
                ),
                "remediation": (
                    "Immediately investigate these files — they are very likely malicious. "
                    "Enable 'Show file extensions' in Windows Explorer to make extensions visible. "
                    "Scan these files with an updated antivirus solution."
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
            "category": "File Listing",
            "status": status,
            "data": {
                "total_files_scanned": total_files,
                "dangerous_files_count": len(dangerous_files),
                "suspicious_files_count": len(suspicious_files),
                "double_extension_count": len(double_ext_files),
                "folder_summary": folder_summary,
                "dangerous_files": dangerous_files,
                "suspicious_files": suspicious_files[:50],  # Limit output size
                "double_extension_files": double_ext_files,
            },
            "findings": findings,
        }

    except Exception as e:
        return {
            "category": "File Listing",
            "status": "error",
            "data": {"error": str(e)},
            "findings": [{
                "severity": "info",
                "title": "Scanner error",
                "description": f"An unexpected error occurred while scanning user files: {e}",
            }],
        }
