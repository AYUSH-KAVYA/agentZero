"""
Autorun / Persistence Mechanism Scanner Module
================================================
Enumerates auto-start programs from multiple persistence locations:
- Registry Run/RunOnce keys (HKLM and HKCU)
- Startup folders (user and common)
- Scheduled tasks
- Auto-start services

Security Relevance:
- Autorun entries are the most common persistence mechanism used by malware.
- Entries pointing to temp directories, AppData, or non-standard paths are suspicious.
- Non-Microsoft scheduled tasks and services may indicate unauthorized persistence.
- Attackers frequently add Run keys or scheduled tasks after initial compromise.
"""

import platform
import subprocess
import json
import os


def scan() -> dict:
    """
    Scans autorun/persistence locations for potentially suspicious entries.

    Returns:
        dict with keys:
        - 'category': str — Human-readable category name
        - 'status': str — One of 'pass', 'warn', 'fail', 'info', 'error'
        - 'data': dict — Raw extracted data
        - 'findings': list[dict] — Each finding has 'severity', 'title', 'description', and optional 'remediation'
    """
    category = "Autorun / Persistence"
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

    suspicious_entries = []

    try:
        # ---- 1. Registry Run Keys ----
        registry_autoruns = _scan_registry_run_keys()
        data["registry_autoruns"] = registry_autoruns

        # Check registry entries for suspicious indicators
        for entry in registry_autoruns:
            suspicion = _check_suspicious(entry.get("value", ""), entry.get("name", ""))
            if suspicion:
                entry["suspicious_reason"] = suspicion
                suspicious_entries.append({
                    "source": f"Registry: {entry.get('key_path', 'Unknown')}",
                    "name": entry.get("name", "Unknown"),
                    "value": entry.get("value", ""),
                    "reason": suspicion,
                })

        # ---- 2. Startup Folders ----
        startup_items = _scan_startup_folders()
        data["startup_folder_items"] = startup_items

        for item in startup_items:
            suspicion = _check_suspicious(item.get("path", ""), item.get("name", ""))
            if suspicion:
                item["suspicious_reason"] = suspicion
                suspicious_entries.append({
                    "source": f"Startup Folder: {item.get('folder', 'Unknown')}",
                    "name": item.get("name", "Unknown"),
                    "value": item.get("path", ""),
                    "reason": suspicion,
                })

        # ---- 3. Scheduled Tasks ----
        scheduled_tasks = _scan_scheduled_tasks()
        data["scheduled_tasks"] = scheduled_tasks.get("tasks", [])
        data["scheduled_tasks_count"] = scheduled_tasks.get("count", 0)
        if scheduled_tasks.get("error"):
            data["scheduled_tasks_error"] = scheduled_tasks["error"]

        # Check scheduled tasks for suspicious entries
        for task in scheduled_tasks.get("tasks", []):
            task_path = task.get("task_to_run", "") or task.get("actions", "")
            author = (task.get("author", "") or "").lower()
            task_name = task.get("task_name", "")

            # Skip known Microsoft tasks
            if author.startswith("microsoft") or task_name.startswith("\\Microsoft\\"):
                task["is_microsoft"] = True
                continue

            task["is_microsoft"] = False
            suspicion = _check_suspicious(task_path, task_name)
            if suspicion:
                task["suspicious_reason"] = suspicion
                suspicious_entries.append({
                    "source": "Scheduled Task",
                    "name": task_name,
                    "value": task_path,
                    "reason": suspicion,
                })

        # ---- 4. Auto-Start Services ----
        autostart_services = _scan_autostart_services()
        data["autostart_services"] = autostart_services.get("services", [])
        data["autostart_services_count"] = autostart_services.get("count", 0)
        if autostart_services.get("error"):
            data["autostart_services_error"] = autostart_services["error"]

        # Check services for suspicious entries
        for svc in autostart_services.get("services", []):
            binary_path = svc.get("binary_path", "")
            display_name = svc.get("display_name", "")

            # Skip Microsoft services (rough heuristic)
            if _is_microsoft_service(svc):
                svc["is_microsoft"] = True
                continue

            svc["is_microsoft"] = False
            suspicion = _check_suspicious(binary_path, display_name)
            if suspicion:
                svc["suspicious_reason"] = suspicion
                suspicious_entries.append({
                    "source": "Auto-Start Service",
                    "name": svc.get("name", "Unknown"),
                    "value": binary_path,
                    "reason": suspicion,
                })

        # ---- Summary ----
        data["suspicious_entries"] = suspicious_entries
        data["suspicious_count"] = len(suspicious_entries)

        # Count non-Microsoft entries
        non_ms_tasks = [t for t in scheduled_tasks.get("tasks", []) if not t.get("is_microsoft", True)]
        non_ms_services = [s for s in autostart_services.get("services", []) if not s.get("is_microsoft", True)]
        data["non_microsoft_scheduled_tasks"] = len(non_ms_tasks)
        data["non_microsoft_autostart_services"] = len(non_ms_services)

        # ---- Generate Findings ----

        # Suspicious autorun entries
        if suspicious_entries:
            entry_details = []
            for entry in suspicious_entries[:10]:
                entry_details.append(
                    f"  - [{entry['source']}] {entry['name']}: {entry['value']}\n    Reason: {entry['reason']}"
                )
            more_text = f"\n  ... and {len(suspicious_entries) - 10} more" if len(suspicious_entries) > 10 else ""

            findings.append({
                "severity": "high",
                "title": f"Suspicious Autorun Entries Detected ({len(suspicious_entries)})",
                "description": (
                    f"Found {len(suspicious_entries)} autorun entry/entries with suspicious characteristics "
                    f"(non-standard paths, scripts in temp directories, etc.):\n"
                    + "\n".join(entry_details) + more_text
                ),
                "remediation": (
                    "Review each suspicious autorun entry:\n"
                    "1. Verify the publisher and digital signature of each executable\n"
                    "2. Remove unauthorized entries from Registry Run keys\n"
                    "3. Delete suspicious files from Startup folders\n"
                    "4. Disable or remove unauthorized scheduled tasks\n"
                    "5. Use tools like Sysinternals Autoruns for detailed analysis"
                )
            })
            status = "warn"

        # Non-Microsoft scheduled tasks (informational)
        if non_ms_tasks:
            task_names = [t.get("task_name", "Unknown") for t in non_ms_tasks[:10]]
            findings.append({
                "severity": "info",
                "title": f"Non-Microsoft Scheduled Tasks ({len(non_ms_tasks)})",
                "description": (
                    f"Found {len(non_ms_tasks)} scheduled task(s) not authored by Microsoft. "
                    f"These should be reviewed for legitimacy.\n"
                    f"Tasks: {', '.join(task_names)}"
                    + (f" ... and {len(non_ms_tasks) - 10} more" if len(non_ms_tasks) > 10 else "")
                ),
                "remediation": "Review non-Microsoft scheduled tasks to ensure they are authorized."
            })

        # Non-Microsoft auto-start services (informational)
        if non_ms_services:
            svc_names = [f"{s.get('name', 'Unknown')} ({s.get('display_name', '')})" for s in non_ms_services[:10]]
            findings.append({
                "severity": "info",
                "title": f"Non-Microsoft Auto-Start Services ({len(non_ms_services)})",
                "description": (
                    f"Found {len(non_ms_services)} auto-start service(s) that appear to be non-Microsoft. "
                    f"Services: {', '.join(svc_names)}"
                    + (f" ... and {len(non_ms_services) - 10} more" if len(non_ms_services) > 10 else "")
                ),
                "remediation": "Review non-Microsoft auto-start services to ensure they are authorized."
            })

        # Registry Run key summary
        if registry_autoruns:
            findings.append({
                "severity": "info",
                "title": f"Registry Autorun Entries ({len(registry_autoruns)})",
                "description": (
                    f"Found {len(registry_autoruns)} entries in Registry Run/RunOnce keys."
                )
            })

    except Exception as e:
        return {
            "category": category,
            "status": "error",
            "data": data,
            "findings": [{
                "severity": "info",
                "title": "Autorun Scan Error",
                "description": f"An unexpected error occurred while scanning autorun entries: {str(e)}"
            }]
        }

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }


def _scan_registry_run_keys() -> list:
    """Scan Registry Run and RunOnce keys for both HKLM and HKCU."""
    entries = []

    try:
        import winreg

        # Define registry paths to check
        run_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\...\\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\...\\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\...\\RunOnce"),
            # 32-bit apps on 64-bit Windows
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\WOW6432Node\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\...\\WOW6432Node\\RunOnce"),
        ]

        for hive, subkey, friendly_name in run_keys:
            try:
                key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                try:
                    index = 0
                    while True:
                        try:
                            name, value, reg_type = winreg.EnumValue(key, index)
                            entries.append({
                                "key_path": friendly_name,
                                "name": name,
                                "value": str(value),
                                "type": reg_type,
                            })
                            index += 1
                        except OSError:
                            break
                finally:
                    winreg.CloseKey(key)
            except FileNotFoundError:
                pass  # Key doesn't exist — that's fine
            except OSError:
                pass  # Access denied or other error

    except ImportError:
        # winreg not available — try PowerShell fallback
        try:
            ps_cmd = r"""
            $entries = @()
            $paths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
            )
            foreach ($path in $paths) {
                if (Test-Path $path) {
                    $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                    if ($props) {
                        $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                            $entries += @{ key_path = $path; name = $_.Name; value = $_.Value.ToString() }
                        }
                    }
                }
            }
            $entries | ConvertTo-Json -Depth 3
            """
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    parsed = json.loads(result.stdout.strip())
                    if isinstance(parsed, dict):
                        parsed = [parsed]
                    entries = parsed or []
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

    return entries


def _scan_startup_folders() -> list:
    """Scan user and common Startup folders."""
    items = []

    try:
        ps_command = r"""
        $items = @()

        # User startup folder
        $userStartup = [Environment]::GetFolderPath('Startup')
        if ($userStartup -and (Test-Path $userStartup)) {
            Get-ChildItem -Path $userStartup -Force -ErrorAction SilentlyContinue | ForEach-Object {
                $items += @{
                    name = $_.Name
                    path = $_.FullName
                    folder = "User Startup"
                    folder_path = $userStartup
                    is_directory = $_.PSIsContainer
                    extension = $_.Extension
                    last_modified = $_.LastWriteTime.ToString('o')
                    size = if (-not $_.PSIsContainer) { $_.Length } else { $null }
                }
            }
        }

        # Common (All Users) startup folder
        $commonStartup = [Environment]::GetFolderPath('CommonStartup')
        if ($commonStartup -and (Test-Path $commonStartup)) {
            Get-ChildItem -Path $commonStartup -Force -ErrorAction SilentlyContinue | ForEach-Object {
                $items += @{
                    name = $_.Name
                    path = $_.FullName
                    folder = "Common Startup"
                    folder_path = $commonStartup
                    is_directory = $_.PSIsContainer
                    extension = $_.Extension
                    last_modified = $_.LastWriteTime.ToString('o')
                    size = if (-not $_.PSIsContainer) { $_.Length } else { $null }
                }
            }
        }

        $items | ConvertTo-Json -Depth 3
        """

        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_command],
            capture_output=True, text=True, timeout=15
        )

        if result.returncode == 0 and result.stdout.strip():
            try:
                parsed = json.loads(result.stdout.strip())
                if isinstance(parsed, dict):
                    parsed = [parsed]
                items = parsed or []
            except json.JSONDecodeError:
                pass

    except Exception:
        pass

    return items


def _scan_scheduled_tasks() -> dict:
    """Scan scheduled tasks for non-Microsoft entries."""
    try:
        ps_command = r"""
        try {
            $tasks = Get-ScheduledTask -ErrorAction Stop |
                Where-Object { $_.State -ne 'Disabled' } |
                Select-Object -First 200 TaskName, TaskPath, Description, Author, State, Date, URI,
                    @{N='Actions'; E={ ($_.Actions | ForEach-Object { if ($_.Execute) { "$($_.Execute) $($_.Arguments)" } }) -join '; ' }},
                    @{N='Triggers'; E={ ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join '; ' }}

            $taskList = @()
            foreach ($t in $tasks) {
                $taskList += @{
                    task_name = $t.TaskPath + $t.TaskName
                    name = $t.TaskName
                    description = $t.Description
                    author = $t.Author
                    state = $t.State.ToString()
                    actions = $t.Actions
                    triggers = $t.Triggers
                    date = $t.Date
                    uri = $t.URI
                }
            }
            @{ tasks = $taskList; count = ($tasks | Measure-Object).Count; error = $null } | ConvertTo-Json -Depth 4 -Compress
        } catch {
            @{ tasks = @(); count = 0; error = $_.Exception.Message } | ConvertTo-Json -Depth 4
        }
        """

        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_command],
            capture_output=True, text=True, timeout=30
        )

        if result.returncode == 0 and result.stdout.strip():
            try:
                parsed = json.loads(result.stdout.strip())
                tasks = parsed.get("tasks", [])
                if isinstance(tasks, dict):
                    tasks = [tasks]
                return {"tasks": tasks, "count": parsed.get("count", len(tasks)), "error": parsed.get("error")}
            except json.JSONDecodeError as e:
                return {"tasks": [], "count": 0, "error": f"JSON parse error: {str(e)}"}
        else:
            return {"tasks": [], "count": 0, "error": result.stderr.strip() if result.stderr else "Failed"}

    except Exception as e:
        return {"tasks": [], "count": 0, "error": str(e)}


def _scan_autostart_services() -> dict:
    """Scan services configured for automatic startup."""
    try:
        ps_command = r"""
        try {
            $services = Get-WmiObject Win32_Service -ErrorAction Stop |
                Where-Object { $_.StartMode -eq 'Auto' } |
                Select-Object Name, DisplayName, State, StartMode, PathName, Description, StartName

            $svcList = @()
            foreach ($s in $services) {
                $svcList += @{
                    name = $s.Name
                    display_name = $s.DisplayName
                    state = $s.State
                    start_mode = $s.StartMode
                    binary_path = $s.PathName
                    description = $s.Description
                    logon_as = $s.StartName
                }
            }
            @{ services = $svcList; count = ($services | Measure-Object).Count; error = $null } | ConvertTo-Json -Depth 4 -Compress
        } catch {
            @{ services = @(); count = 0; error = $_.Exception.Message } | ConvertTo-Json -Depth 4
        }
        """

        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_command],
            capture_output=True, text=True, timeout=30
        )

        if result.returncode == 0 and result.stdout.strip():
            try:
                parsed = json.loads(result.stdout.strip())
                services = parsed.get("services", [])
                if isinstance(services, dict):
                    services = [services]
                return {"services": services, "count": parsed.get("count", len(services)), "error": parsed.get("error")}
            except json.JSONDecodeError as e:
                return {"services": [], "count": 0, "error": f"JSON parse error: {str(e)}"}
        else:
            return {"services": [], "count": 0, "error": result.stderr.strip() if result.stderr else "Failed"}

    except Exception as e:
        return {"services": [], "count": 0, "error": str(e)}


def _check_suspicious(path: str, name: str) -> str:
    """
    Check if an autorun entry path looks suspicious.
    Returns a reason string if suspicious, empty string if not.
    """
    if not path:
        return ""

    path_lower = path.lower().strip().strip('"')
    name_lower = (name or "").lower()

    # Suspicious path patterns
    suspicious_indicators = []

    # Scripts in temp directories
    temp_patterns = ["\\temp\\", "\\tmp\\", "%temp%", "%tmp%", "\\appdata\\local\\temp\\"]
    for pattern in temp_patterns:
        if pattern in path_lower:
            suspicious_indicators.append(f"Path references temp directory ({pattern})")
            break

    # Scripts or executables in user Downloads
    if "\\downloads\\" in path_lower:
        suspicious_indicators.append("Executable in Downloads folder")

    # Script files as autoruns
    script_extensions = [".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".bat", ".cmd"]
    for ext in script_extensions:
        if path_lower.endswith(ext) or f"{ext} " in path_lower or f'{ext}"' in path_lower:
            suspicious_indicators.append(f"Script file autorun ({ext})")
            break

    # PowerShell with encoded commands
    if "powershell" in path_lower and ("-enc" in path_lower or "-encodedcommand" in path_lower):
        suspicious_indicators.append("PowerShell with encoded command")

    # PowerShell with download cradles
    if "powershell" in path_lower and ("downloadstring" in path_lower or "downloadfile" in path_lower or "invoke-webrequest" in path_lower):
        suspicious_indicators.append("PowerShell with download command")

    # mshta, wscript, cscript with URLs
    if any(s in path_lower for s in ["mshta", "wscript", "cscript"]) and ("http" in path_lower or "//" in path_lower):
        suspicious_indicators.append("Script host with remote URL")

    # Executables in Public folder
    if "\\users\\public\\" in path_lower:
        suspicious_indicators.append("Executable in Public user folder")

    # Executables in AppData (not in known safe locations)
    if "\\appdata\\" in path_lower and not any(
        known in path_lower for known in [
            "\\microsoft\\", "\\google\\", "\\mozilla\\", "\\adobe\\",
            "\\dropbox\\", "\\slack\\", "\\zoom\\", "\\teams\\",
            "\\discord\\", "\\spotify\\", "\\vscode\\", "\\code\\",
        ]
    ):
        suspicious_indicators.append("Executable in non-standard AppData location")

    # rundll32 with unusual DLLs
    if "rundll32" in path_lower and "\\temp\\" in path_lower:
        suspicious_indicators.append("rundll32 loading DLL from temp directory")

    # regsvr32 with URLs (Squiblydoo technique)
    if "regsvr32" in path_lower and ("http" in path_lower or "/i:" in path_lower):
        suspicious_indicators.append("regsvr32 with remote script (possible Squiblydoo)")

    return "; ".join(suspicious_indicators) if suspicious_indicators else ""


def _is_microsoft_service(service: dict) -> bool:
    """Heuristically determine if a service is from Microsoft."""
    binary = (service.get("binary_path", "") or "").lower()
    description = (service.get("description", "") or "").lower()
    name = (service.get("name", "") or "").lower()

    # Check if binary is in system directories
    if any(p in binary for p in ["\\windows\\", "\\system32\\", "\\syswow64\\", "\\microsoft\\"]):
        return True

    # Check if service name is a known Windows service prefix
    windows_prefixes = [
        "w32", "wua", "wmi", "bits", "crypto", "dcom", "dhcp", "dns", "event",
        "lanman", "lsa", "mpssvc", "net", "nla", "plug", "rpc", "sam", "schedule",
        "spoo", "srv", "sys", "theme", "uxsms", "win", "wlan", "wer", "wsearch",
        "trust", "audit", "app", "def", "diag", "device", "display", "dot3",
    ]
    if any(name.startswith(p) for p in windows_prefixes):
        return True

    # Check description for Microsoft mentions
    if "microsoft" in description or "windows" in description:
        return True

    return False
