"""
File Information & Signature Scanner
=====================================
Analyzes file version information and digital signatures for key system files.

Security Relevance:
- System files (cmd.exe, powershell.exe, explorer.exe) that lack valid digital
  signatures may have been tampered with or replaced by malware.
- Rootkits and advanced persistent threats (APTs) sometimes replace system
  binaries with trojaned versions.
- Verifying Authenticode signatures ensures file integrity and authenticity.
- Version information helps identify outdated or patched system binaries.

Data Sources:
- PowerShell: Get-Item for file version metadata
- PowerShell: Get-AuthenticodeSignature for digital signature verification
"""

import platform
import subprocess
import json
import os


# Key system files to verify by default
_DEFAULT_SYSTEM_FILES = [
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    r"C:\Windows\explorer.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\lsass.exe",
    r"C:\Windows\System32\csrss.exe",
    r"C:\Windows\System32\services.exe",
    r"C:\Windows\System32\winlogon.exe",
    r"C:\Windows\System32\taskmgr.exe",
    r"C:\Windows\System32\mshta.exe",
    r"C:\Windows\System32\wscript.exe",
    r"C:\Windows\System32\cscript.exe",
]


def _analyze_file(file_path: str) -> dict:
    """
    Analyze a single file for version info and digital signature.

    Args:
        file_path: Absolute path to the file to analyze.

    Returns:
        Dictionary with file metadata and signature status.
    """
    escaped_path = file_path.replace("'", "''")
    ps_script = f"""
$filePath = '{escaped_path}'
if (-not (Test-Path $filePath)) {{
    [PSCustomObject]@{{
        FilePath = $filePath
        Exists = $false
    }} | ConvertTo-Json -Depth 2
    return
}}

$fileItem = Get-Item $filePath -ErrorAction SilentlyContinue
$versionInfo = $fileItem.VersionInfo
$sig = Get-AuthenticodeSignature $filePath -ErrorAction SilentlyContinue

[PSCustomObject]@{{
    FilePath           = $filePath
    Exists             = $true
    FileName           = $fileItem.Name
    SizeBytes          = $fileItem.Length
    LastModified       = $fileItem.LastWriteTime.ToString('o')
    CreationTime       = $fileItem.CreationTime.ToString('o')
    FileVersion        = $versionInfo.FileVersion
    ProductVersion     = $versionInfo.ProductVersion
    CompanyName        = $versionInfo.CompanyName
    ProductName        = $versionInfo.ProductName
    FileDescription    = $versionInfo.FileDescription
    OriginalFilename   = $versionInfo.OriginalFilename
    InternalName       = $versionInfo.InternalName
    LegalCopyright     = $versionInfo.LegalCopyright
    Language           = $versionInfo.Language
    IsDebug            = $versionInfo.IsDebug
    SignatureStatus    = $sig.Status.ToString()
    SignerCertSubject  = $sig.SignerCertificate.Subject
    SignerCertIssuer   = $sig.SignerCertificate.Issuer
    SignerCertThumbprint = $sig.SignerCertificate.Thumbprint
    SignerCertNotAfter = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.NotAfter.ToString('o') }} else {{ $null }}
    IsOSBinary         = $sig.IsOSBinary
    StatusMessage      = $sig.StatusMessage
    TimeStamperCert    = if ($sig.TimeStamperCertificate) {{ $sig.TimeStamperCertificate.Subject }} else {{ $null }}
}} | ConvertTo-Json -Depth 2
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

    return {
        "FilePath": file_path,
        "Exists": None,
        "error": "Failed to analyze file",
    }


def _analyze_files_batch(file_paths: list) -> list:
    """
    Analyze multiple files in a single PowerShell invocation for efficiency.

    Args:
        file_paths: List of file paths to analyze.

    Returns:
        List of file analysis dictionaries.
    """
    if not file_paths:
        return []

    # Build array of paths
    path_entries = []
    for fp in file_paths:
        escaped = fp.replace("'", "''")
        path_entries.append(f"'{escaped}'")

    paths_array = ",\n".join(path_entries)

    ps_script = f"""
$filePaths = @(
{paths_array}
)

$results = foreach ($filePath in $filePaths) {{
    if (-not (Test-Path $filePath)) {{
        [PSCustomObject]@{{
            FilePath = $filePath
            Exists = $false
        }}
        continue
    }}

    $fileItem = Get-Item $filePath -ErrorAction SilentlyContinue
    $versionInfo = $fileItem.VersionInfo
    $sig = Get-AuthenticodeSignature $filePath -ErrorAction SilentlyContinue

    [PSCustomObject]@{{
        FilePath           = $filePath
        Exists             = $true
        FileName           = $fileItem.Name
        SizeBytes          = $fileItem.Length
        LastModified       = $fileItem.LastWriteTime.ToString('o')
        CreationTime       = $fileItem.CreationTime.ToString('o')
        FileVersion        = $versionInfo.FileVersion
        ProductVersion     = $versionInfo.ProductVersion
        CompanyName        = $versionInfo.CompanyName
        ProductName        = $versionInfo.ProductName
        FileDescription    = $versionInfo.FileDescription
        OriginalFilename   = $versionInfo.OriginalFilename
        SignatureStatus    = $sig.Status.ToString()
        SignerCertSubject  = $sig.SignerCertificate.Subject
        SignerCertIssuer   = $sig.SignerCertificate.Issuer
        SignerCertThumbprint = $sig.SignerCertificate.Thumbprint
        IsOSBinary         = $sig.IsOSBinary
        StatusMessage      = $sig.StatusMessage
    }}
}}

$results | ConvertTo-Json -Depth 3
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception):
        pass

    # Fallback: analyze one at a time
    return [_analyze_file(fp) for fp in file_paths]


def scan() -> dict:
    """
    Verify digital signatures and version information for key system files.

    Returns:
        dict with keys: category, status, data, findings
    """
    if platform.system() != "Windows":
        return {
            "category": "File Information",
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
        file_results = _analyze_files_batch(_DEFAULT_SYSTEM_FILES)

        valid_count = 0
        invalid_count = 0
        missing_count = 0
        non_os_binary_count = 0

        for fr in file_results:
            file_path = fr.get("FilePath", "Unknown")
            file_name = fr.get("FileName", os.path.basename(file_path))
            exists = fr.get("Exists")

            if exists is False:
                missing_count += 1
                findings.append({
                    "severity": "high",
                    "title": f"System file missing: {file_name}",
                    "description": (
                        f"Expected system file '{file_path}' does not exist. "
                        f"This could indicate system corruption, a non-standard Windows "
                        f"installation, or intentional removal."
                    ),
                    "remediation": (
                        "Run 'sfc /scannow' to verify and repair system file integrity. "
                        "If the file should exist, investigate why it was removed."
                    ),
                })
                continue

            if exists is None:
                continue  # Error analyzing file

            sig_status = fr.get("SignatureStatus", "Unknown")
            is_os_binary = fr.get("IsOSBinary", False)

            if sig_status == "Valid":
                valid_count += 1
                if not is_os_binary:
                    non_os_binary_count += 1
                    findings.append({
                        "severity": "high",
                        "title": f"System file is not an OS binary: {file_name}",
                        "description": (
                            f"'{file_path}' has a valid digital signature but IsOSBinary is False. "
                            f"This system file may have been replaced with a non-Microsoft binary. "
                            f"Signer: {fr.get('SignerCertSubject', 'Unknown')}."
                        ),
                        "remediation": (
                            "Investigate this file immediately. Run 'sfc /scannow' to verify "
                            "system file integrity. Compare with a known-good copy."
                        ),
                    })
            elif sig_status in ("NotSigned", ""):
                invalid_count += 1
                findings.append({
                    "severity": "critical",
                    "title": f"System file not digitally signed: {file_name}",
                    "description": (
                        f"'{file_path}' does not have a digital signature. "
                        f"All legitimate Windows system files should be signed by Microsoft. "
                        f"This file may have been tampered with or replaced by malware."
                    ),
                    "remediation": (
                        "IMMEDIATELY investigate this file. Run 'sfc /scannow' and check with "
                        "Windows Defender. Compare the file hash against known-good values. "
                        "Consider isolating this system pending investigation."
                    ),
                })
            elif sig_status == "HashMismatch":
                invalid_count += 1
                findings.append({
                    "severity": "critical",
                    "title": f"System file signature hash mismatch: {file_name}",
                    "description": (
                        f"'{file_path}' has a digital signature but the hash does not match. "
                        f"The file has been modified since it was signed. This is a strong "
                        f"indicator of tampering."
                    ),
                    "remediation": (
                        "CRITICAL: This file has likely been tampered with. Isolate this system "
                        "immediately. Run incident response procedures. Replace the file from "
                        "a known-good Windows installation media."
                    ),
                })
            elif sig_status == "NotTrusted":
                invalid_count += 1
                findings.append({
                    "severity": "high",
                    "title": f"System file has untrusted signature: {file_name}",
                    "description": (
                        f"'{file_path}' is signed by an untrusted certificate: "
                        f"{fr.get('SignerCertSubject', 'Unknown')}. "
                        f"The signing certificate is not in the trusted root store."
                    ),
                    "remediation": (
                        "Verify the signing certificate chain. If this is not an expected "
                        "configuration, investigate the file for potential tampering."
                    ),
                })
            else:
                invalid_count += 1
                findings.append({
                    "severity": "medium",
                    "title": f"System file signature issue: {file_name} ({sig_status})",
                    "description": (
                        f"'{file_path}' has signature status: {sig_status}. "
                        f"Message: {fr.get('StatusMessage', 'N/A')}."
                    ),
                    "remediation": (
                        "Investigate this signature status. Run 'sfc /scannow' to verify "
                        "system file integrity."
                    ),
                })

        # Determine overall status
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
            "category": "File Information",
            "status": status,
            "data": {
                "files_analyzed": len(file_results),
                "valid_signatures": valid_count,
                "invalid_signatures": invalid_count,
                "missing_files": missing_count,
                "non_os_binaries": non_os_binary_count,
                "file_details": file_results,
            },
            "findings": findings,
        }

    except Exception as e:
        return {
            "category": "File Information",
            "status": "error",
            "data": {"error": str(e)},
            "findings": [{
                "severity": "info",
                "title": "Scanner error",
                "description": f"An unexpected error occurred while scanning file information: {e}",
            }],
        }
