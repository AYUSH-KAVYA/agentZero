"""
OS Information Scanner Module
=============================
Collects basic operating system information including OS name, version, build number,
architecture, computer name, domain/workgroup, last boot time, uptime, system drive,
and Windows directory.

Security Relevance:
- Identifies outdated or unsupported OS versions that may lack security patches.
- Reveals architecture info relevant to exploit compatibility.
- Uptime can indicate how long since last reboot (patch application often requires reboot).
"""

import platform
import subprocess
import json
from datetime import datetime, timezone


def scan() -> dict:
    """
    Collects basic OS information from the system.

    Returns:
        dict with keys:
        - 'category': str — Human-readable category name
        - 'status': str — One of 'pass', 'warn', 'fail', 'info', 'error'
        - 'data': dict — Raw extracted data
        - 'findings': list[dict] — Each finding has 'severity', 'title', 'description', and optional 'remediation'
    """
    category = "OS Information"
    data = {}
    findings = []
    status = "info"

    if platform.system() != "Windows":
        return {
            "category": category,
            "status": "error",
            "data": {},
            "findings": [{
                "severity": "info",
                "title": "Not a Windows system",
                "description": f"This module only supports Windows. Detected OS: {platform.system()}"
            }]
        }

    try:
        # Gather basic platform info from the platform module
        data["os_name"] = platform.system()
        data["os_release"] = platform.release()
        data["os_version"] = platform.version()
        data["architecture"] = platform.machine()
        data["platform"] = platform.platform()
        data["processor"] = platform.processor()
        data["node_name"] = platform.node()

        # Use PowerShell Get-ComputerInfo for richer details
        ps_command = """
        $info = Get-ComputerInfo -Property CsName, CsDomain, CsWorkgroup, OsName, OsVersion,
            OsBuildNumber, OsArchitecture, OsLastBootUpTime, OsUptime, OsSystemDrive,
            WindowsDirectory, OsInstallDate, OsProductType, OsStatus,
            WindowsVersion, OsBuildType, CsDomainRole | Select-Object *
        $info | ConvertTo-Json -Depth 3
        """

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_command],
                capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0 and result.stdout.strip():
                computer_info = json.loads(result.stdout.strip())

                data["computer_name"] = computer_info.get("CsName", "Unknown")
                data["domain"] = computer_info.get("CsDomain", "Unknown")
                data["workgroup"] = computer_info.get("CsWorkgroup", "Unknown")
                data["os_full_name"] = computer_info.get("OsName", "Unknown")
                data["os_version_detail"] = computer_info.get("OsVersion", "Unknown")
                data["os_build_number"] = computer_info.get("OsBuildNumber", "Unknown")
                data["os_architecture"] = computer_info.get("OsArchitecture", "Unknown")
                data["system_drive"] = computer_info.get("OsSystemDrive", "Unknown")
                data["windows_directory"] = computer_info.get("WindowsDirectory", "Unknown")
                data["os_install_date"] = str(computer_info.get("OsInstallDate", "Unknown"))
                data["os_product_type"] = computer_info.get("OsProductType", "Unknown")
                data["os_status"] = computer_info.get("OsStatus", "Unknown")
                data["windows_version"] = computer_info.get("WindowsVersion", "Unknown")
                data["os_build_type"] = computer_info.get("OsBuildType", "Unknown")
                data["domain_role"] = computer_info.get("CsDomainRole", "Unknown")

                # Parse last boot time and uptime
                last_boot_raw = computer_info.get("OsLastBootUpTime", {})
                if isinstance(last_boot_raw, dict) and "DateTime" in last_boot_raw:
                    data["last_boot_time"] = last_boot_raw["DateTime"]
                elif isinstance(last_boot_raw, str):
                    data["last_boot_time"] = last_boot_raw
                else:
                    data["last_boot_time"] = str(last_boot_raw)

                uptime_raw = computer_info.get("OsUptime", {})
                if isinstance(uptime_raw, dict):
                    days = uptime_raw.get("Days", 0)
                    hours = uptime_raw.get("Hours", 0)
                    minutes = uptime_raw.get("Minutes", 0)
                    data["uptime_days"] = days
                    data["uptime_formatted"] = f"{days}d {hours}h {minutes}m"
                elif isinstance(uptime_raw, str):
                    data["uptime_formatted"] = uptime_raw
                else:
                    data["uptime_formatted"] = str(uptime_raw)

            else:
                # Fallback: use simpler PowerShell commands
                _collect_fallback_info(data)

        except subprocess.TimeoutExpired:
            data["powershell_error"] = "Get-ComputerInfo timed out"
            _collect_fallback_info(data)
        except json.JSONDecodeError as e:
            data["powershell_error"] = f"Failed to parse Get-ComputerInfo output: {str(e)}"
            _collect_fallback_info(data)

        # Generate findings
        # Check for very old OS versions
        os_release = data.get("os_release", "")
        unsupported_versions = ["6.0", "6.1", "6.2", "6.3", "5.1", "5.2"]
        os_version_str = data.get("os_version_detail", "") or platform.version()

        if os_release in unsupported_versions:
            version_names = {
                "5.1": "Windows XP",
                "5.2": "Windows Server 2003",
                "6.0": "Windows Vista / Server 2008",
                "6.1": "Windows 7 / Server 2008 R2",
                "6.2": "Windows 8 / Server 2012",
                "6.3": "Windows 8.1 / Server 2012 R2",
            }
            old_name = version_names.get(os_release, f"Windows {os_release}")
            findings.append({
                "severity": "critical",
                "title": "End-of-Life Operating System Detected",
                "description": (
                    f"The system is running {old_name} (version {os_release}), "
                    f"which is no longer supported by Microsoft and does not receive security updates."
                ),
                "remediation": "Upgrade to a currently supported version of Windows (Windows 10 22H2+ or Windows 11)."
            })
            status = "fail"

        # Check uptime — long uptime may mean pending reboots for patches
        uptime_days = data.get("uptime_days", 0)
        if isinstance(uptime_days, (int, float)) and uptime_days > 30:
            findings.append({
                "severity": "medium",
                "title": "System Uptime Exceeds 30 Days",
                "description": (
                    f"The system has been running for {uptime_days} days without a reboot. "
                    f"Many security patches require a reboot to take effect."
                ),
                "remediation": "Schedule a maintenance window to reboot the system and apply pending updates."
            })
            if status not in ("fail",):
                status = "warn"

        if not findings:
            status = "info"

    except Exception as e:
        return {
            "category": category,
            "status": "error",
            "data": data,
            "findings": [{
                "severity": "info",
                "title": "OS Information Collection Error",
                "description": f"An unexpected error occurred while collecting OS information: {str(e)}"
            }]
        }

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }


def _collect_fallback_info(data: dict) -> None:
    """Fallback method using simpler PowerShell commands when Get-ComputerInfo is unavailable."""
    try:
        # Computer name and domain
        hostname_result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "$env:COMPUTERNAME"],
            capture_output=True, text=True, timeout=10
        )
        if hostname_result.returncode == 0:
            data["computer_name"] = hostname_result.stdout.strip()

        # System info via WMI
        wmi_cmd = """
        $os = Get-WmiObject Win32_OperatingSystem
        @{
            Caption = $os.Caption
            Version = $os.Version
            BuildNumber = $os.BuildNumber
            OSArchitecture = $os.OSArchitecture
            SystemDrive = $os.SystemDrive
            WindowsDirectory = $os.WindowsDirectory
            LastBootUpTime = $os.ConvertToDateTime($os.LastBootUpTime).ToString('o')
            InstallDate = $os.ConvertToDateTime($os.InstallDate).ToString('o')
        } | ConvertTo-Json
        """
        wmi_result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", wmi_cmd],
            capture_output=True, text=True, timeout=15
        )
        if wmi_result.returncode == 0 and wmi_result.stdout.strip():
            try:
                wmi_data = json.loads(wmi_result.stdout.strip())
                data["os_full_name"] = wmi_data.get("Caption", "Unknown")
                data["os_version_detail"] = wmi_data.get("Version", "Unknown")
                data["os_build_number"] = wmi_data.get("BuildNumber", "Unknown")
                data["os_architecture"] = wmi_data.get("OSArchitecture", "Unknown")
                data["system_drive"] = wmi_data.get("SystemDrive", "Unknown")
                data["windows_directory"] = wmi_data.get("WindowsDirectory", "Unknown")
                data["last_boot_time"] = wmi_data.get("LastBootUpTime", "Unknown")
                data["os_install_date"] = wmi_data.get("InstallDate", "Unknown")

                # Calculate uptime from last boot time
                if wmi_data.get("LastBootUpTime"):
                    try:
                        boot_time = datetime.fromisoformat(wmi_data["LastBootUpTime"])
                        now = datetime.now(boot_time.tzinfo)
                        uptime = now - boot_time
                        data["uptime_days"] = uptime.days
                        hours, remainder = divmod(uptime.seconds, 3600)
                        minutes = remainder // 60
                        data["uptime_formatted"] = f"{uptime.days}d {hours}h {minutes}m"
                    except (ValueError, TypeError):
                        pass
            except json.JSONDecodeError:
                pass

        # Domain/workgroup
        domain_cmd = """
        $cs = Get-WmiObject Win32_ComputerSystem
        @{ Domain = $cs.Domain; Workgroup = $cs.Workgroup; DomainRole = $cs.DomainRole } | ConvertTo-Json
        """
        domain_result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", domain_cmd],
            capture_output=True, text=True, timeout=10
        )
        if domain_result.returncode == 0 and domain_result.stdout.strip():
            try:
                domain_data = json.loads(domain_result.stdout.strip())
                data["domain"] = domain_data.get("Domain", "Unknown")
                data["workgroup"] = domain_data.get("Workgroup", "Unknown")
                data["domain_role"] = domain_data.get("DomainRole", "Unknown")
            except json.JSONDecodeError:
                pass

    except Exception:
        pass
