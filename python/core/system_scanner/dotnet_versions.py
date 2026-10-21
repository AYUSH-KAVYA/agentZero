"""
.NET Versions Scanner
=====================
Enumerates all installed .NET Framework and .NET Core/5+/6+/7+/8+ versions.

Security Relevance:
- Outdated .NET Framework versions may contain known vulnerabilities (e.g., CVE-2023-36049,
  CVE-2023-36558) that can be exploited for remote code execution or privilege escalation.
- Applications built on unsupported .NET runtimes will not receive security patches.
- Knowing which .NET versions are installed helps assess the attack surface.

Data Sources:
- Registry: HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full (Release DWORD)
- Registry: HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP (sub-keys for v2/v3/v3.5)
- CLI: `dotnet --list-runtimes` and `dotnet --list-sdks` for .NET Core/5+/6+/7+/8+
"""

import platform
import subprocess
import json
import re

# Mapping of .NET Framework Release DWORD values to version strings
# Source: https://learn.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed
_RELEASE_TO_VERSION = {
    528449: "4.8",
    528040: "4.8",
    528372: "4.8",
    528049: "4.8",
    533320: "4.8.1",
    533325: "4.8.1",
    461808: "4.7.2",
    461814: "4.7.2",
    461308: "4.7.1",
    461310: "4.7.1",
    460798: "4.7",
    460805: "4.7",
    394802: "4.6.2",
    394806: "4.6.2",
    394254: "4.6.1",
    394271: "4.6.1",
    393295: "4.6",
    393297: "4.6",
    379893: "4.5.2",
    378675: "4.5.1",
    378758: "4.5.1",
    378389: "4.5",
}

# Known EOL / unsupported .NET Framework versions
_EOL_FRAMEWORK_VERSIONS = {"2.0", "3.0", "3.5", "4.0", "4.5", "4.5.1", "4.5.2", "4.6", "4.6.1"}

# Known EOL .NET Core / .NET runtimes (major.minor)
_EOL_DOTNET_RUNTIMES = {
    "1.0", "1.1", "2.0", "2.1", "2.2", "3.0", "3.1",
    "5.0", "6.0", "7.0",
}


def _resolve_framework_version(release_value: int) -> str:
    """Resolve a .NET Framework Release DWORD to a human-readable version string."""
    if release_value in _RELEASE_TO_VERSION:
        return _RELEASE_TO_VERSION[release_value]
    # Approximate based on range
    if release_value >= 533320:
        return f"4.8.1+ (Release {release_value})"
    if release_value >= 528040:
        return f"4.8 (Release {release_value})"
    if release_value >= 461808:
        return f"4.7.2 (Release {release_value})"
    if release_value >= 461308:
        return f"4.7.1 (Release {release_value})"
    if release_value >= 460798:
        return f"4.7 (Release {release_value})"
    if release_value >= 394802:
        return f"4.6.2 (Release {release_value})"
    if release_value >= 394254:
        return f"4.6.1 (Release {release_value})"
    if release_value >= 393295:
        return f"4.6 (Release {release_value})"
    if release_value >= 378389:
        return f"4.5+ (Release {release_value})"
    return f"Unknown (Release {release_value})"


def _get_framework_versions_registry() -> list:
    """Read .NET Framework versions from the Windows Registry."""
    try:
        import winreg
    except ImportError:
        return []

    versions = []

    # Check .NET Framework 4.x via Release DWORD
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full",
        )
        try:
            release_val, _ = winreg.QueryValueEx(key, "Release")
            version_str = _resolve_framework_version(release_val)
            versions.append({
                "type": ".NET Framework",
                "version": version_str,
                "release_dword": release_val,
                "registry_path": r"HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full",
            })
        except FileNotFoundError:
            pass
        finally:
            winreg.CloseKey(key)
    except (FileNotFoundError, OSError):
        pass

    # Check legacy .NET Framework versions (v2.0, v3.0, v3.5)
    legacy_versions = ["v2.0.50727", "v3.0", "v3.5"]
    for ver_key_name in legacy_versions:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                rf"SOFTWARE\Microsoft\NET Framework Setup\NDP\{ver_key_name}",
            )
            try:
                install_val, _ = winreg.QueryValueEx(key, "Install")
                if install_val == 1:
                    try:
                        version_val, _ = winreg.QueryValueEx(key, "Version")
                    except FileNotFoundError:
                        version_val = ver_key_name.lstrip("v")
                    try:
                        sp_val, _ = winreg.QueryValueEx(key, "SP")
                    except FileNotFoundError:
                        sp_val = 0
                    versions.append({
                        "type": ".NET Framework",
                        "version": version_val,
                        "service_pack": sp_val,
                        "registry_path": rf"HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\{ver_key_name}",
                    })
            except FileNotFoundError:
                pass
            finally:
                winreg.CloseKey(key)
        except (FileNotFoundError, OSError):
            pass

    return versions


def _get_dotnet_runtimes_cli() -> list:
    """Get .NET Core/5+/6+/7+/8+ runtimes via `dotnet --list-runtimes`."""
    runtimes = []
    try:
        result = subprocess.run(
            ["dotnet", "--list-runtimes"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                # Format: "Microsoft.NETCore.App 8.0.4 [C:\Program Files\dotnet\shared\Microsoft.NETCore.App]"
                match = re.match(r"^(\S+)\s+(\S+)\s+\[(.+)\]$", line)
                if match:
                    runtimes.append({
                        "name": match.group(1),
                        "version": match.group(2),
                        "path": match.group(3),
                    })
                else:
                    runtimes.append({"raw": line})
    except FileNotFoundError:
        pass  # dotnet CLI not installed
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    return runtimes


def _get_dotnet_sdks_cli() -> list:
    """Get .NET SDKs via `dotnet --list-sdks`."""
    sdks = []
    try:
        result = subprocess.run(
            ["dotnet", "--list-sdks"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                # Format: "8.0.204 [C:\Program Files\dotnet\sdk]"
                match = re.match(r"^(\S+)\s+\[(.+)\]$", line)
                if match:
                    sdks.append({
                        "version": match.group(1),
                        "path": match.group(2),
                    })
                else:
                    sdks.append({"raw": line})
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    return sdks


def _check_eol_versions(framework_versions: list, runtimes: list, sdks: list) -> list:
    """Check for end-of-life or outdated .NET versions and generate findings."""
    findings = []

    # Check Framework versions
    for fw in framework_versions:
        ver_str = fw.get("version", "")
        # Extract major.minor for EOL comparison
        match = re.match(r"(\d+\.\d+)", ver_str)
        if match:
            major_minor = match.group(1)
            if major_minor in _EOL_FRAMEWORK_VERSIONS:
                findings.append({
                    "severity": "medium",
                    "title": f"End-of-life .NET Framework {ver_str} installed",
                    "description": (
                        f".NET Framework {ver_str} is no longer supported by Microsoft and "
                        f"does not receive security updates. This version may contain known "
                        f"vulnerabilities that can be exploited."
                    ),
                    "remediation": (
                        "Upgrade applications to .NET Framework 4.8 or later, or migrate to "
                        ".NET 8+ (LTS). Remove unsupported framework versions if possible."
                    ),
                })

    # Check .NET Core / .NET runtimes
    for rt in runtimes:
        ver_str = rt.get("version", "")
        match = re.match(r"(\d+\.\d+)", ver_str)
        if match:
            major_minor = match.group(1)
            if major_minor in _EOL_DOTNET_RUNTIMES:
                findings.append({
                    "severity": "medium",
                    "title": f"End-of-life .NET runtime {rt.get('name', 'Unknown')} {ver_str} installed",
                    "description": (
                        f"The .NET runtime {rt.get('name', '')} version {ver_str} is end-of-life "
                        f"and no longer receives security patches. Applications using this runtime "
                        f"are at risk of known vulnerabilities."
                    ),
                    "remediation": (
                        f"Migrate applications to a supported .NET LTS release (e.g., .NET 8). "
                        f"Uninstall the EOL runtime {rt.get('name', '')} {ver_str}."
                    ),
                })

    # Check SDKs
    for sdk in sdks:
        ver_str = sdk.get("version", "")
        match = re.match(r"(\d+\.\d+)", ver_str)
        if match:
            major_minor = match.group(1)
            if major_minor in _EOL_DOTNET_RUNTIMES:
                findings.append({
                    "severity": "low",
                    "title": f"End-of-life .NET SDK {ver_str} installed",
                    "description": (
                        f".NET SDK {ver_str} targets an unsupported .NET version. "
                        f"Development with this SDK may produce applications with known security issues."
                    ),
                    "remediation": (
                        "Update to the latest .NET LTS SDK version (e.g., .NET 8 SDK)."
                    ),
                })

    return findings


def scan() -> dict:
    """
    Scan for installed .NET Framework and .NET Core/5+/6+/7+/8+ versions.

    Returns:
        dict with keys: category, status, data, findings
    """
    if platform.system() != "Windows":
        return {
            "category": ".NET Versions",
            "status": "error",
            "data": {},
            "findings": [{
                "severity": "info",
                "title": "Not a Windows system",
                "description": "This scanner only runs on Windows.",
            }],
        }

    try:
        framework_versions = _get_framework_versions_registry()
        runtimes = _get_dotnet_runtimes_cli()
        sdks = _get_dotnet_sdks_cli()

        findings = _check_eol_versions(framework_versions, runtimes, sdks)

        # Determine overall status
        if any(f["severity"] in ("high", "critical") for f in findings):
            status = "fail"
        elif any(f["severity"] == "medium" for f in findings):
            status = "warn"
        else:
            status = "pass"

        # Add an informational finding if nothing was found
        if not framework_versions and not runtimes and not sdks:
            findings.append({
                "severity": "info",
                "title": "No .NET installations detected",
                "description": "No .NET Framework or .NET Core/5+/8+ installations were found on this system.",
            })
            status = "info"

        return {
            "category": ".NET Versions",
            "status": status,
            "data": {
                "framework_versions": framework_versions,
                "dotnet_runtimes": runtimes,
                "dotnet_sdks": sdks,
                "total_frameworks": len(framework_versions),
                "total_runtimes": len(runtimes),
                "total_sdks": len(sdks),
            },
            "findings": findings,
        }

    except Exception as e:
        return {
            "category": ".NET Versions",
            "status": "error",
            "data": {"error": str(e)},
            "findings": [{
                "severity": "info",
                "title": "Scanner error",
                "description": f"An unexpected error occurred while scanning .NET versions: {e}",
            }],
        }
