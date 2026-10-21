"""
Secure Boot Configuration Scanner
===================================
Checks whether UEFI Secure Boot is enabled and whether the system is booting
in UEFI or Legacy BIOS mode.

Why it matters:
    Secure Boot ensures that only cryptographically signed bootloaders and
    kernel drivers execute during the boot process, protecting against bootkits,
    rootkits, and firmware-level tampering. Legacy BIOS mode lacks this
    protection entirely. A disabled Secure Boot on a UEFI system indicates
    either a misconfiguration or deliberate weakening of the trust chain.

Data sources:
    - PowerShell ``Confirm-SecureBootUEFI`` cmdlet
    - Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State
    - PowerShell environment queries for UEFI vs. Legacy mode
"""

import platform
import subprocess
import traceback


def _check_secure_boot_cmdlet() -> dict:
    """Use PowerShell Confirm-SecureBootUEFI to check Secure Boot status."""
    result = {"secure_boot": None, "error": None, "raw": None}

    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "try { $sb = Confirm-SecureBootUEFI; "
             "@{SecureBoot=$sb; Error=$null} | ConvertTo-Json } "
             "catch { @{SecureBoot=$null; Error=$_.Exception.Message} | ConvertTo-Json }"],
            capture_output=True, text=True, timeout=30,
        )
        result["raw"] = proc.stdout.strip()

        if proc.returncode == 0 and proc.stdout.strip():
            import json
            try:
                data = json.loads(proc.stdout.strip())
                result["secure_boot"] = data.get("SecureBoot")
                result["error"] = data.get("Error")
            except (json.JSONDecodeError, TypeError):
                pass
    except subprocess.TimeoutExpired:
        result["error"] = "Confirm-SecureBootUEFI timed out"
    except FileNotFoundError:
        result["error"] = "PowerShell not found"
    except Exception as exc:
        result["error"] = str(exc)

    return result


def _check_secure_boot_registry() -> dict:
    """Read Secure Boot state from the registry."""
    import winreg

    reg = {"uefi_secure_boot_enabled": None, "error": None}
    key_path = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        try:
            value, _ = winreg.QueryValueEx(key, "UEFISecureBootEnabled")
            reg["uefi_secure_boot_enabled"] = value
        except FileNotFoundError:
            reg["uefi_secure_boot_enabled"] = None
        winreg.CloseKey(key)
    except FileNotFoundError:
        reg["error"] = "SecureBoot\\State key not found — may be Legacy BIOS"
    except PermissionError:
        reg["error"] = "Access denied to SecureBoot\\State key"
    except OSError as exc:
        reg["error"] = str(exc)

    return reg


def _check_firmware_type() -> dict:
    """Determine UEFI vs Legacy BIOS boot mode."""
    fw = {"type": None, "error": None, "raw": None}

    try:
        # Use GetFirmwareType or bcdedit to determine firmware mode
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "try { "
             "  $env_uefi = $env:firmware_type; "
             "  $bcd = bcdedit /enum '{current}' 2>&1 | Select-String 'path'; "
             "  $type = if (Test-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot') { 'UEFI' } else { 'Legacy BIOS (probable)' }; "
             "  @{FirmwareType=$type; BCDPath=$bcd.ToString().Trim(); EnvFirmware=$env_uefi} | ConvertTo-Json "
             "} catch { @{FirmwareType='Unknown'; Error=$_.Exception.Message} | ConvertTo-Json }"],
            capture_output=True, text=True, timeout=30,
        )
        fw["raw"] = proc.stdout.strip()

        if proc.returncode == 0 and proc.stdout.strip():
            import json
            try:
                data = json.loads(proc.stdout.strip())
                fw["type"] = data.get("FirmwareType", "Unknown")
                fw["bcd_path"] = data.get("BCDPath")
            except (json.JSONDecodeError, TypeError):
                pass
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as exc:
        fw["error"] = str(exc)

    return fw


def _check_secure_boot_policy() -> dict:
    """Read additional Secure Boot policy information from registry."""
    import winreg

    policy = {}
    # Check for custom Secure Boot policy
    key_path = r"SYSTEM\CurrentControlSet\Control\SecureBoot"
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        index = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(key, index)
                policy[f"subkey_{index}"] = subkey_name
                index += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except (FileNotFoundError, PermissionError, OSError):
        policy["_note"] = "SecureBoot key not found or not accessible"

    return policy


def scan() -> dict:
    """
    Scan Secure Boot and firmware configuration.

    Returns:
        dict with keys 'category', 'status', 'data', 'findings'.
    """
    if platform.system() != "Windows":
        return {
            "category": "Secure Boot",
            "status": "error",
            "data": {},
            "findings": [
                {
                    "severity": "info",
                    "title": "Not a Windows system",
                    "description": "Secure Boot scanning is only applicable on Windows.",
                }
            ],
        }

    try:
        cmdlet_result = _check_secure_boot_cmdlet()
        registry_result = _check_secure_boot_registry()
        firmware = _check_firmware_type()
        policy = _check_secure_boot_policy()

        data = {
            "cmdlet": cmdlet_result,
            "registry": registry_result,
            "firmware": firmware,
            "policy": policy,
        }

        findings = []

        # Determine Secure Boot state from multiple sources
        sb_cmdlet = cmdlet_result.get("secure_boot")
        sb_registry = registry_result.get("uefi_secure_boot_enabled")
        fw_type = firmware.get("type", "Unknown")

        # Resolve effective Secure Boot status
        # Priority: cmdlet > registry
        secure_boot_enabled = None
        if sb_cmdlet is True:
            secure_boot_enabled = True
        elif sb_cmdlet is False:
            secure_boot_enabled = False
        elif sb_registry == 1:
            secure_boot_enabled = True
        elif sb_registry == 0:
            secure_boot_enabled = False

        data["secure_boot_enabled"] = secure_boot_enabled
        data["firmware_type"] = fw_type

        is_uefi = "uefi" in fw_type.lower() if fw_type else False

        # --- Check 1: Legacy BIOS mode ----------------------------------------
        if not is_uefi and "legacy" in (fw_type or "").lower():
            findings.append(
                {
                    "severity": "high",
                    "title": "System is booting in Legacy BIOS mode",
                    "description": (
                        "The system appears to be running in Legacy BIOS mode. "
                        "Secure Boot is not available in Legacy mode, leaving the "
                        "boot process unprotected against bootkits and firmware "
                        "tampering."
                    ),
                    "remediation": (
                        "If hardware supports it, convert the system to UEFI boot "
                        "mode. Use `mbr2gpt /convert /allowFullOS` (with caution) "
                        "and enable UEFI in the firmware settings."
                    ),
                }
            )

        # --- Check 2: Secure Boot status --------------------------------------
        if secure_boot_enabled is True:
            findings.append(
                {
                    "severity": "info",
                    "title": "Secure Boot is enabled",
                    "description": (
                        "UEFI Secure Boot is active. Only signed bootloaders and "
                        "drivers will execute during boot."
                    ),
                }
            )
        elif secure_boot_enabled is False:
            if is_uefi:
                findings.append(
                    {
                        "severity": "high",
                        "title": "Secure Boot is disabled on a UEFI system",
                        "description": (
                            "The system supports UEFI but Secure Boot is disabled. "
                            "This allows unsigned bootloaders and drivers to execute, "
                            "making the system vulnerable to bootkits and firmware-level "
                            "rootkits."
                        ),
                        "remediation": (
                            "Enable Secure Boot in the system's UEFI firmware settings. "
                            "Ensure all installed drivers and bootloaders are properly "
                            "signed before enabling."
                        ),
                    }
                )
            else:
                findings.append(
                    {
                        "severity": "medium",
                        "title": "Secure Boot is not enabled",
                        "description": (
                            "Secure Boot is not active. The firmware type could not be "
                            "conclusively determined as UEFI."
                        ),
                        "remediation": (
                            "Verify the firmware type and enable Secure Boot if UEFI "
                            "is supported."
                        ),
                    }
                )
        else:
            # Could not determine
            error_msg = cmdlet_result.get("error", "")
            # Confirm-SecureBootUEFI errors on Legacy BIOS with specific message
            if error_msg and ("not supported" in error_msg.lower()
                              or "cmdlet is not supported on this platform" in error_msg.lower()):
                findings.append(
                    {
                        "severity": "high",
                        "title": "Secure Boot is not supported (likely Legacy BIOS)",
                        "description": (
                            f"Confirm-SecureBootUEFI returned: '{error_msg}'. "
                            "This typically indicates the system is running in "
                            "Legacy BIOS mode without Secure Boot capability."
                        ),
                        "remediation": (
                            "If hardware supports UEFI, convert the system to UEFI "
                            "boot mode and enable Secure Boot."
                        ),
                    }
                )
            else:
                findings.append(
                    {
                        "severity": "medium",
                        "title": "Could not determine Secure Boot status",
                        "description": (
                            "Neither the PowerShell cmdlet nor the registry provided "
                            "a conclusive Secure Boot status. "
                            f"Cmdlet error: {error_msg or 'N/A'}. "
                            f"Registry error: {registry_result.get('error', 'N/A')}."
                        ),
                        "remediation": (
                            "Run the scanner with elevated privileges and verify "
                            "Secure Boot status in UEFI firmware settings."
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

        return {
            "category": "Secure Boot",
            "status": status,
            "data": data,
            "findings": findings,
        }

    except Exception as exc:
        return {
            "category": "Secure Boot",
            "status": "error",
            "data": {"error": str(exc), "traceback": traceback.format_exc()},
            "findings": [
                {
                    "severity": "info",
                    "title": "Error scanning Secure Boot configuration",
                    "description": f"An unexpected error occurred: {exc}",
                }
            ],
        }
