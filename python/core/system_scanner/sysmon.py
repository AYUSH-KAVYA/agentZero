"""
Sysmon Configuration Scanner
==============================
Checks whether Sysmon (System Monitor) is installed and reads its
configuration details from the registry.

Why it matters:
    Sysmon is a critical telemetry source that logs process creation, network
    connections, file-creation-time changes, driver/DLL loading, and many other
    events that are essential for threat detection and incident response. If
    Sysmon is absent, the organisation loses visibility into host-level activity
    that Windows native logging doesn't capture. If Sysmon is installed but
    misconfigured or its driver is not loaded, it provides a false sense of
    security.

Registry paths inspected:
    - HKLM\\SYSTEM\\CurrentControlSet\\Services\\Sysmon
    - HKLM\\SYSTEM\\CurrentControlSet\\Services\\Sysmon64
    - HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\
      Microsoft-Windows-Sysmon/Operational
"""

import platform
import subprocess
import traceback


def _check_sysmon_service(service_name: str) -> dict:
    """Read Sysmon service configuration from the registry."""
    import winreg

    info = {"service_name": service_name, "installed": False}
    key_path = rf"SYSTEM\CurrentControlSet\Services\{service_name}"

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        info["installed"] = True

        for name in ("ImagePath", "DisplayName", "Description",
                      "Start", "Type", "ObjectName"):
            try:
                value, _ = winreg.QueryValueEx(key, name)
                info[name] = value
            except FileNotFoundError:
                info[name] = None

        winreg.CloseKey(key)
    except (FileNotFoundError, PermissionError, OSError):
        pass

    return info


def _read_sysmon_config_registry(service_name: str) -> dict:
    """Read Sysmon configuration parameters from the registry."""
    import winreg

    config = {}
    key_path = rf"SYSTEM\CurrentControlSet\Services\{service_name}\Parameters"

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        index = 0
        while True:
            try:
                name, value, vtype = winreg.EnumValue(key, index)
                if isinstance(value, bytes):
                    config[name] = value.hex()
                else:
                    config[name] = value
                index += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except (FileNotFoundError, PermissionError, OSError) as exc:
        config["_error"] = str(exc)

    return config


def _check_sysmon_driver(driver_name: str = "SysmonDrv") -> dict:
    """Check if the Sysmon minifilter driver is installed."""
    import winreg

    driver = {"driver_name": driver_name, "installed": False}
    key_path = rf"SYSTEM\CurrentControlSet\Services\{driver_name}"

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        driver["installed"] = True

        for name in ("ImagePath", "Start", "Type", "Group"):
            try:
                value, _ = winreg.QueryValueEx(key, name)
                driver[name] = value
            except FileNotFoundError:
                driver[name] = None

        winreg.CloseKey(key)
    except (FileNotFoundError, PermissionError, OSError):
        pass

    return driver


def _get_sysmon_version() -> dict:
    """Attempt to determine the Sysmon version via PowerShell."""
    version_info = {"version": None, "error": None}
    try:
        # Try to run sysmon with -? flag, which prints the version
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "try { $s = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue; "
             "$exe = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Sysmon64' -ErrorAction SilentlyContinue).ImagePath; "
             "if (-not $exe) { $exe = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Sysmon' -ErrorAction SilentlyContinue).ImagePath }; "
             "if ($exe) { $exe = $exe -replace '\"',''; $fi = Get-Item $exe -ErrorAction SilentlyContinue; "
             "if ($fi) { $fi.VersionInfo | Select-Object FileVersion,ProductVersion | ConvertTo-Json } } "
             "} catch { @{error=$_.Exception.Message} | ConvertTo-Json }"],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            import json
            try:
                data = json.loads(proc.stdout.strip())
                version_info["version"] = data.get("FileVersion") or data.get("ProductVersion")
            except (json.JSONDecodeError, TypeError):
                version_info["raw"] = proc.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as exc:
        version_info["error"] = str(exc)

    return version_info


def _check_event_channel() -> dict:
    """Check if the Sysmon event log channel exists."""
    import winreg

    channel = {"exists": False}
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational"

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        channel["exists"] = True

        for name in ("Enabled", "MaxSize", "MaxSizeUpper"):
            try:
                value, _ = winreg.QueryValueEx(key, name)
                channel[name] = value
            except FileNotFoundError:
                channel[name] = None

        winreg.CloseKey(key)
    except (FileNotFoundError, PermissionError, OSError):
        pass

    return channel


def scan() -> dict:
    """
    Scan Sysmon installation and configuration.

    Returns:
        dict with keys 'category', 'status', 'data', 'findings'.
    """
    if platform.system() != "Windows":
        return {
            "category": "Sysmon Configuration",
            "status": "error",
            "data": {},
            "findings": [
                {
                    "severity": "info",
                    "title": "Not a Windows system",
                    "description": "Sysmon scanning is only applicable on Windows.",
                }
            ],
        }

    try:
        sysmon64 = _check_sysmon_service("Sysmon64")
        sysmon32 = _check_sysmon_service("Sysmon")
        driver = _check_sysmon_driver("SysmonDrv")
        channel = _check_event_channel()

        # Determine which variant is installed (prefer 64-bit)
        active_sysmon = None
        if sysmon64.get("installed"):
            active_sysmon = sysmon64
            config = _read_sysmon_config_registry("Sysmon64")
        elif sysmon32.get("installed"):
            active_sysmon = sysmon32
            config = _read_sysmon_config_registry("Sysmon")
        else:
            config = {}

        version_info = _get_sysmon_version()

        data = {
            "sysmon64_service": sysmon64,
            "sysmon32_service": sysmon32,
            "driver": driver,
            "config": config,
            "event_channel": channel,
            "version": version_info,
            "is_installed": active_sysmon is not None,
        }

        findings = []

        # --- Check 1: Sysmon installed? ----------------------------------------
        if active_sysmon is None:
            findings.append(
                {
                    "severity": "high",
                    "title": "Sysmon is not installed",
                    "description": (
                        "Neither Sysmon nor Sysmon64 services were found. Without "
                        "Sysmon, the system lacks critical telemetry for detecting "
                        "process creation, network connections, driver loading, and "
                        "other security-relevant events."
                    ),
                    "remediation": (
                        "Install Sysmon from Microsoft Sysinternals: "
                        "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon "
                        "Deploy with a well-tuned configuration such as SwiftOnSecurity's "
                        "sysmon-config or Olaf Hartong's sysmon-modular."
                    ),
                }
            )
            return {
                "category": "Sysmon Configuration",
                "status": "fail",
                "data": data,
                "findings": findings,
            }

        # --- Sysmon IS installed — gather details ------------------------------
        svc_name = active_sysmon.get("service_name", "Sysmon")
        findings.append(
            {
                "severity": "info",
                "title": f"Sysmon is installed ({svc_name})",
                "description": (
                    f"Service: {svc_name}, "
                    f"ImagePath: {active_sysmon.get('ImagePath', 'N/A')}, "
                    f"Version: {version_info.get('version', 'unknown')}"
                ),
            }
        )

        # --- Check 2: Service start type ---------------------------------------
        start_type = active_sysmon.get("Start")
        if start_type is not None:
            # 0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled
            start_labels = {0: "Boot", 1: "System", 2: "Automatic",
                            3: "Manual", 4: "Disabled"}
            label = start_labels.get(start_type, f"Unknown ({start_type})")
            data["service_start_type"] = label

            if start_type == 4:
                findings.append(
                    {
                        "severity": "high",
                        "title": "Sysmon service is disabled",
                        "description": (
                            "The Sysmon service start type is set to Disabled. "
                            "It will not start on boot and is not collecting telemetry."
                        ),
                        "remediation": (
                            "Set the Sysmon service start type to Automatic: "
                            "`sc config Sysmon64 start= auto`"
                        ),
                    }
                )
            elif start_type == 3:
                findings.append(
                    {
                        "severity": "medium",
                        "title": "Sysmon service start type is Manual",
                        "description": (
                            "The Sysmon service is set to Manual start. It may not "
                            "be running after a reboot unless explicitly started."
                        ),
                        "remediation": (
                            "Set start type to Automatic: "
                            "`sc config Sysmon64 start= auto`"
                        ),
                    }
                )

        # --- Check 3: Driver status --------------------------------------------
        if not driver.get("installed"):
            findings.append(
                {
                    "severity": "high",
                    "title": "Sysmon driver (SysmonDrv) is not installed",
                    "description": (
                        "The Sysmon minifilter driver is missing. Without the driver, "
                        "Sysmon cannot intercept system events even if the service is running."
                    ),
                    "remediation": "Reinstall Sysmon to re-register the driver.",
                }
            )

        # --- Check 4: Configuration present ------------------------------------
        config_hash = config.get("HashingAlgorithm") or config.get("ConfigHash")
        if config and not config.get("_error"):
            # Has a config loaded
            config_keys = [k for k in config if not k.startswith("_")]
            if not config_keys:
                findings.append(
                    {
                        "severity": "medium",
                        "title": "Sysmon has no configuration parameters in registry",
                        "description": (
                            "The Sysmon Parameters key exists but contains no values. "
                            "Sysmon may be running with a minimal default configuration."
                        ),
                        "remediation": (
                            "Apply a comprehensive Sysmon configuration XML to ensure "
                            "adequate telemetry coverage."
                        ),
                    }
                )
        elif config.get("_error"):
            findings.append(
                {
                    "severity": "low",
                    "title": "Cannot read Sysmon configuration parameters",
                    "description": f"Error: {config['_error']}",
                }
            )

        # --- Check 5: Event channel -------------------------------------------
        if not channel.get("exists"):
            findings.append(
                {
                    "severity": "medium",
                    "title": "Sysmon event log channel not found",
                    "description": (
                        "The Microsoft-Windows-Sysmon/Operational event log channel "
                        "does not exist in the registry. Events may not be recorded."
                    ),
                    "remediation": "Reinstall Sysmon to re-register the event channel.",
                }
            )
        elif channel.get("Enabled") == 0:
            findings.append(
                {
                    "severity": "high",
                    "title": "Sysmon event log channel is disabled",
                    "description": (
                        "The Sysmon event log channel exists but is disabled. "
                        "Events are being generated but not stored."
                    ),
                    "remediation": (
                        "Enable the channel: "
                        "`wevtutil sl Microsoft-Windows-Sysmon/Operational /e:true`"
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
            "category": "Sysmon Configuration",
            "status": status,
            "data": data,
            "findings": findings,
        }

    except Exception as exc:
        return {
            "category": "Sysmon Configuration",
            "status": "error",
            "data": {"error": str(exc), "traceback": traceback.format_exc()},
            "findings": [
                {
                    "severity": "info",
                    "title": "Error scanning Sysmon configuration",
                    "description": f"An unexpected error occurred: {exc}",
                }
            ],
        }
