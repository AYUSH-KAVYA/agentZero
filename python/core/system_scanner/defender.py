"""
Windows Defender Configuration Scanner Module
==============================================
Inspects Windows Defender settings including real-time protection, cloud protection,
behavior monitoring, tamper protection, exclusion lists, and signature status.

Security Relevance:
- Disabled real-time or tamper protection leaves the system exposed to malware.
- Exclusion paths/extensions/processes are a well-known attack vector — attackers
  deliberately place malware in excluded locations to evade detection.
- Outdated signatures mean new threats will not be detected.
"""

import platform
import subprocess
import json


def scan() -> dict:
    """
    Scans Windows Defender configuration and status.

    Returns:
        dict with keys:
        - 'category': str — Human-readable category name
        - 'status': str — One of 'pass', 'warn', 'fail', 'info', 'error'
        - 'data': dict — Raw extracted data
        - 'findings': list[dict] — Each finding has 'severity', 'title', 'description', and optional 'remediation'
    """
    category = "Windows Defender"
    data = {}
    findings = []
    status = "pass"

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
        # Collect Defender preferences (Get-MpPreference)
        prefs_command = r"""
        try {
            $prefs = Get-MpPreference -ErrorAction Stop
            @{
                DisableRealtimeMonitoring = $prefs.DisableRealtimeMonitoring
                DisableBehaviorMonitoring = $prefs.DisableBehaviorMonitoring
                DisableBlockAtFirstSeen = $prefs.DisableBlockAtFirstSeen
                DisableIOAVProtection = $prefs.DisableIOAVProtection
                DisablePrivacyMode = $prefs.DisablePrivacyMode
                DisableScriptScanning = $prefs.DisableScriptScanning
                MAPSReporting = $prefs.MAPSReporting
                SubmitSamplesConsent = $prefs.SubmitSamplesConsent
                CloudBlockLevel = $prefs.CloudBlockLevel
                CloudExtendedTimeout = $prefs.CloudExtendedTimeout
                PUAProtection = $prefs.PUAProtection
                EnableControlledFolderAccess = $prefs.EnableControlledFolderAccess
                EnableNetworkProtection = $prefs.EnableNetworkProtection
                ExclusionPath = @($prefs.ExclusionPath)
                ExclusionExtension = @($prefs.ExclusionExtension)
                ExclusionProcess = @($prefs.ExclusionProcess)
                ExclusionIpAddress = @($prefs.ExclusionIpAddress)
                AttackSurfaceReductionRules_Ids = @($prefs.AttackSurfaceReductionRules_Ids)
                AttackSurfaceReductionRules_Actions = @($prefs.AttackSurfaceReductionRules_Actions)
                error = $null
            } | ConvertTo-Json -Depth 3
        } catch {
            @{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
        }
        """

        prefs_result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", prefs_command],
            capture_output=True, text=True, timeout=30
        )

        prefs_data = {}
        prefs_error = None

        if prefs_result.returncode == 0 and prefs_result.stdout.strip():
            try:
                prefs_data = json.loads(prefs_result.stdout.strip())
                prefs_error = prefs_data.get("error")
            except json.JSONDecodeError as e:
                prefs_error = f"Failed to parse Get-MpPreference output: {str(e)}"
        else:
            prefs_error = prefs_result.stderr.strip() if prefs_result.stderr else "Get-MpPreference failed"

        # Collect Defender computer status (Get-MpComputerStatus)
        status_command = r"""
        try {
            $cs = Get-MpComputerStatus -ErrorAction Stop
            @{
                AMServiceEnabled = $cs.AMServiceEnabled
                AntispywareEnabled = $cs.AntispywareEnabled
                AntivirusEnabled = $cs.AntivirusEnabled
                BehaviorMonitorEnabled = $cs.BehaviorMonitorEnabled
                IoavProtectionEnabled = $cs.IoavProtectionEnabled
                NISEnabled = $cs.NISEnabled
                OnAccessProtectionEnabled = $cs.OnAccessProtectionEnabled
                RealTimeProtectionEnabled = $cs.RealTimeProtectionEnabled
                IsTamperProtected = $cs.IsTamperProtected
                AntivirusSignatureVersion = $cs.AntivirusSignatureVersion
                AntivirusSignatureLastUpdated = if ($cs.AntivirusSignatureLastUpdated) { $cs.AntivirusSignatureLastUpdated.ToString('o') } else { $null }
                AntispywareSignatureVersion = $cs.AntispywareSignatureVersion
                AntispywareSignatureLastUpdated = if ($cs.AntispywareSignatureLastUpdated) { $cs.AntispywareSignatureLastUpdated.ToString('o') } else { $null }
                NISSignatureVersion = $cs.NISSignatureVersion
                NISSignatureLastUpdated = if ($cs.NISSignatureLastUpdated) { $cs.NISSignatureLastUpdated.ToString('o') } else { $null }
                FullScanAge = $cs.FullScanAge
                QuickScanAge = $cs.QuickScanAge
                FullScanEndTime = if ($cs.FullScanEndTime) { $cs.FullScanEndTime.ToString('o') } else { $null }
                QuickScanEndTime = if ($cs.QuickScanEndTime) { $cs.QuickScanEndTime.ToString('o') } else { $null }
                AMEngineVersion = $cs.AMEngineVersion
                AMProductVersion = $cs.AMProductVersion
                DeviceControlState = $cs.DeviceControlState
                error = $null
            } | ConvertTo-Json -Depth 3
        } catch {
            @{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
        }
        """

        status_result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", status_command],
            capture_output=True, text=True, timeout=30
        )

        status_data = {}
        status_error = None

        if status_result.returncode == 0 and status_result.stdout.strip():
            try:
                status_data = json.loads(status_result.stdout.strip())
                status_error = status_data.get("error")
            except json.JSONDecodeError as e:
                status_error = f"Failed to parse Get-MpComputerStatus output: {str(e)}"
        else:
            status_error = status_result.stderr.strip() if status_result.stderr else "Get-MpComputerStatus failed"

        # Check if Defender is not available (e.g., third-party AV)
        if prefs_error and status_error:
            data["defender_available"] = False
            data["preferences_error"] = prefs_error
            data["status_error"] = status_error
            findings.append({
                "severity": "info",
                "title": "Windows Defender Not Available",
                "description": (
                    f"Windows Defender cmdlets are not available. This may indicate a third-party "
                    f"antivirus is installed or Defender is not present. "
                    f"Preferences error: {prefs_error}. Status error: {status_error}"
                )
            })
            return {
                "category": category,
                "status": "info",
                "data": data,
                "findings": findings
            }

        data["defender_available"] = True

        # Organize protection settings
        protection = {}
        protection["real_time_protection_enabled"] = status_data.get("RealTimeProtectionEnabled")
        protection["behavior_monitor_enabled"] = status_data.get("BehaviorMonitorEnabled")
        protection["ioav_protection_enabled"] = status_data.get("IoavProtectionEnabled")
        protection["antivirus_enabled"] = status_data.get("AntivirusEnabled")
        protection["antispyware_enabled"] = status_data.get("AntispywareEnabled")
        protection["on_access_protection_enabled"] = status_data.get("OnAccessProtectionEnabled")
        protection["tamper_protected"] = status_data.get("IsTamperProtected")
        protection["nis_enabled"] = status_data.get("NISEnabled")
        protection["am_service_enabled"] = status_data.get("AMServiceEnabled")
        protection["realtime_monitoring_disabled_pref"] = prefs_data.get("DisableRealtimeMonitoring")
        protection["behavior_monitoring_disabled_pref"] = prefs_data.get("DisableBehaviorMonitoring")
        protection["script_scanning_disabled_pref"] = prefs_data.get("DisableScriptScanning")
        protection["block_at_first_seen_disabled_pref"] = prefs_data.get("DisableBlockAtFirstSeen")
        data["protection_settings"] = protection

        # Cloud protection settings
        cloud = {}
        cloud["maps_reporting"] = prefs_data.get("MAPSReporting")
        cloud["submit_samples_consent"] = prefs_data.get("SubmitSamplesConsent")
        cloud["cloud_block_level"] = prefs_data.get("CloudBlockLevel")
        cloud["cloud_extended_timeout"] = prefs_data.get("CloudExtendedTimeout")
        data["cloud_protection"] = cloud

        # Advanced settings
        advanced = {}
        advanced["pua_protection"] = prefs_data.get("PUAProtection")
        advanced["controlled_folder_access"] = prefs_data.get("EnableControlledFolderAccess")
        advanced["network_protection"] = prefs_data.get("EnableNetworkProtection")
        data["advanced_settings"] = advanced

        # Exclusions
        exclusions = {}
        excl_paths = prefs_data.get("ExclusionPath", [])
        excl_extensions = prefs_data.get("ExclusionExtension", [])
        excl_processes = prefs_data.get("ExclusionProcess", [])
        excl_ips = prefs_data.get("ExclusionIpAddress", [])

        # Filter out null entries from arrays
        excl_paths = [p for p in (excl_paths or []) if p]
        excl_extensions = [e for e in (excl_extensions or []) if e]
        excl_processes = [p for p in (excl_processes or []) if p]
        excl_ips = [i for i in (excl_ips or []) if i]

        exclusions["paths"] = excl_paths
        exclusions["extensions"] = excl_extensions
        exclusions["processes"] = excl_processes
        exclusions["ip_addresses"] = excl_ips
        exclusions["total_count"] = len(excl_paths) + len(excl_extensions) + len(excl_processes) + len(excl_ips)
        data["exclusions"] = exclusions

        # Signature info
        signatures = {}
        signatures["antivirus_version"] = status_data.get("AntivirusSignatureVersion")
        signatures["antivirus_last_updated"] = status_data.get("AntivirusSignatureLastUpdated")
        signatures["antispyware_version"] = status_data.get("AntispywareSignatureVersion")
        signatures["antispyware_last_updated"] = status_data.get("AntispywareSignatureLastUpdated")
        signatures["nis_version"] = status_data.get("NISSignatureVersion")
        signatures["nis_last_updated"] = status_data.get("NISSignatureLastUpdated")
        signatures["engine_version"] = status_data.get("AMEngineVersion")
        signatures["product_version"] = status_data.get("AMProductVersion")
        data["signatures"] = signatures

        # Scan info
        scan_info = {}
        scan_info["full_scan_age_days"] = status_data.get("FullScanAge")
        scan_info["quick_scan_age_days"] = status_data.get("QuickScanAge")
        scan_info["full_scan_end_time"] = status_data.get("FullScanEndTime")
        scan_info["quick_scan_end_time"] = status_data.get("QuickScanEndTime")
        data["scan_info"] = scan_info

        # ASR rules
        asr_ids = prefs_data.get("AttackSurfaceReductionRules_Ids", [])
        asr_actions = prefs_data.get("AttackSurfaceReductionRules_Actions", [])
        asr_ids = [r for r in (asr_ids or []) if r]
        asr_actions = [a for a in (asr_actions or []) if a is not None]
        data["asr_rules"] = {"ids": asr_ids, "actions": asr_actions, "count": len(asr_ids)}

        # ---- Generate Findings ----

        # Real-time protection
        if protection.get("real_time_protection_enabled") is False or prefs_data.get("DisableRealtimeMonitoring") is True:
            findings.append({
                "severity": "critical",
                "title": "Real-Time Protection Is Disabled",
                "description": (
                    "Windows Defender real-time protection is currently disabled. "
                    "Files, downloads, and programs are not being scanned in real-time, "
                    "leaving the system highly vulnerable to malware."
                ),
                "remediation": (
                    "Enable real-time protection: Settings > Windows Security > Virus & threat protection > "
                    "Manage settings > Real-time protection ON. Or via PowerShell: "
                    "Set-MpPreference -DisableRealtimeMonitoring $false"
                )
            })
            status = "fail"

        # Tamper protection
        if protection.get("tamper_protected") is False:
            findings.append({
                "severity": "high",
                "title": "Tamper Protection Is Disabled",
                "description": (
                    "Windows Defender Tamper Protection is disabled. Malware or attackers "
                    "can modify or disable Defender settings without restriction."
                ),
                "remediation": (
                    "Enable Tamper Protection: Settings > Windows Security > Virus & threat protection > "
                    "Manage settings > Tamper Protection ON. Note: This setting cannot be changed via PowerShell "
                    "when properly secured."
                )
            })
            if status != "fail":
                status = "fail"

        # Behavior monitoring
        if protection.get("behavior_monitor_enabled") is False or prefs_data.get("DisableBehaviorMonitoring") is True:
            findings.append({
                "severity": "high",
                "title": "Behavior Monitoring Is Disabled",
                "description": (
                    "Windows Defender behavior monitoring is disabled. This feature detects and blocks "
                    "suspicious process behaviors that signature-based detection might miss."
                ),
                "remediation": "Enable behavior monitoring: Set-MpPreference -DisableBehaviorMonitoring $false"
            })
            if status != "fail":
                status = "warn"

        # Script scanning
        if prefs_data.get("DisableScriptScanning") is True:
            findings.append({
                "severity": "medium",
                "title": "Script Scanning Is Disabled",
                "description": (
                    "Windows Defender script scanning (AMSI integration) is disabled. "
                    "Malicious scripts (PowerShell, VBS, JS) will not be inspected."
                ),
                "remediation": "Enable script scanning: Set-MpPreference -DisableScriptScanning $false"
            })
            if status not in ("fail",):
                status = "warn"

        # Cloud protection
        maps_reporting = prefs_data.get("MAPSReporting")
        if maps_reporting is not None and maps_reporting == 0:
            findings.append({
                "severity": "medium",
                "title": "Cloud-Delivered Protection Disabled",
                "description": (
                    "Microsoft MAPS (cloud-delivered protection) is disabled. "
                    "Cloud protection provides faster response to new threats."
                ),
                "remediation": "Enable cloud protection: Set-MpPreference -MAPSReporting 2"
            })
            if status not in ("fail",):
                status = "warn"

        # Exclusions — always report, these are common attack vectors
        if exclusions["total_count"] > 0:
            excl_details = []
            if excl_paths:
                excl_details.append(f"Paths ({len(excl_paths)}): {', '.join(excl_paths[:10])}")
                if len(excl_paths) > 10:
                    excl_details[-1] += f" ... and {len(excl_paths) - 10} more"
            if excl_extensions:
                excl_details.append(f"Extensions ({len(excl_extensions)}): {', '.join(excl_extensions[:10])}")
                if len(excl_extensions) > 10:
                    excl_details[-1] += f" ... and {len(excl_extensions) - 10} more"
            if excl_processes:
                excl_details.append(f"Processes ({len(excl_processes)}): {', '.join(excl_processes[:10])}")
                if len(excl_processes) > 10:
                    excl_details[-1] += f" ... and {len(excl_processes) - 10} more"
            if excl_ips:
                excl_details.append(f"IP Addresses ({len(excl_ips)}): {', '.join(excl_ips[:10])}")

            severity = "medium"
            # Check for especially dangerous exclusions
            dangerous_patterns = ["c:\\", "c:\\windows", "c:\\users", "*.exe", "*.dll", "*.ps1", "*.bat", "*.cmd"]
            has_dangerous = False
            for path in excl_paths:
                if path.lower().rstrip("\\") in dangerous_patterns:
                    has_dangerous = True
                    break
            for ext in excl_extensions:
                if ext.lower().lstrip(".") in ["exe", "dll", "ps1", "bat", "cmd", "vbs", "js"]:
                    has_dangerous = True
                    break

            if has_dangerous:
                severity = "high"

            findings.append({
                "severity": severity,
                "title": f"Defender Exclusions Configured ({exclusions['total_count']} total)",
                "description": (
                    f"Windows Defender has {exclusions['total_count']} exclusion(s) configured. "
                    f"Exclusions are a common attack vector — malware placed in excluded locations "
                    f"will not be scanned.\n" + "\n".join(excl_details)
                ),
                "remediation": (
                    "Review all exclusions and remove any that are not strictly necessary. "
                    "Avoid excluding executable file types (.exe, .dll, .ps1) or broad directory paths. "
                    "Use Get-MpPreference to review and Remove-MpPreference to remove exclusions."
                )
            })
            if status not in ("fail",):
                status = "warn"

        # Scan age warnings
        full_scan_age = status_data.get("FullScanAge")
        if full_scan_age is not None and isinstance(full_scan_age, (int, float)):
            if full_scan_age > 30:
                findings.append({
                    "severity": "low",
                    "title": f"No Full Scan in {full_scan_age} Days",
                    "description": (
                        f"A full system scan has not been performed in {full_scan_age} days. "
                        f"Regular full scans help detect dormant threats."
                    ),
                    "remediation": "Run a full scan: Start-MpScan -ScanType FullScan"
                })

    except Exception as e:
        return {
            "category": category,
            "status": "error",
            "data": data,
            "findings": [{
                "severity": "info",
                "title": "Defender Scan Error",
                "description": f"An unexpected error occurred while scanning Defender status: {str(e)}"
            }]
        }

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
