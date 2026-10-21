"""
Hotfix / Patch Status Scanner Module
=====================================
Queries installed Windows hotfixes (KBs) via WMI and evaluates patch currency.

Security Relevance:
- Unpatched systems are the #1 attack vector for known exploits (CVEs).
- If no hotfix has been installed in 30+ days, the system may be missing critical
  security updates that address publicly known vulnerabilities.
- Tracking installed KBs helps identify which patches are applied and which may be missing.
"""

import platform
import subprocess
import json
from datetime import datetime, timedelta


def scan() -> dict:
    """
    Scans installed hotfixes/patches and evaluates patch currency.

    Returns:
        dict with keys:
        - 'category': str — Human-readable category name
        - 'status': str — One of 'pass', 'warn', 'fail', 'info', 'error'
        - 'data': dict — Raw extracted data
        - 'findings': list[dict] — Each finding has 'severity', 'title', 'description', and optional 'remediation'
    """
    category = "Installed Hotfixes"
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
        # Query WMI for installed hotfixes
        ps_command = r"""
        try {
            $hotfixes = Get-WmiObject -Class Win32_QuickFixEngineering -ErrorAction Stop |
                Select-Object HotFixID, Description, InstalledOn, InstalledBy, Caption, CSName, FixComments, ServicePackInEffect, Status |
                Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue

            $hfList = @()
            foreach ($hf in $hotfixes) {
                $installedDate = $null
                if ($hf.InstalledOn) {
                    try {
                        $installedDate = ([DateTime]$hf.InstalledOn).ToString('o')
                    } catch {
                        $installedDate = $hf.InstalledOn.ToString()
                    }
                }
                $hfList += @{
                    HotFixID = $hf.HotFixID
                    Description = $hf.Description
                    InstalledOn = $installedDate
                    InstalledBy = $hf.InstalledBy
                    Caption = $hf.Caption
                    ServicePackInEffect = $hf.ServicePackInEffect
                }
            }
            @{ hotfixes = $hfList; count = ($hotfixes | Measure-Object).Count; error = $null } | ConvertTo-Json -Depth 4
        } catch {
            @{ hotfixes = @(); count = 0; error = $_.Exception.Message } | ConvertTo-Json -Depth 4
        }
        """

        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_command],
            capture_output=True, text=True, timeout=30
        )

        hotfixes = []
        wmi_error = None

        if result.returncode == 0 and result.stdout.strip():
            try:
                parsed = json.loads(result.stdout.strip())
                hotfixes_raw = parsed.get("hotfixes", [])
                if isinstance(hotfixes_raw, dict):
                    hotfixes_raw = [hotfixes_raw]
                hotfixes = hotfixes_raw
                wmi_error = parsed.get("error")
            except json.JSONDecodeError as e:
                wmi_error = f"Failed to parse hotfix output: {str(e)}"
        else:
            wmi_error = result.stderr.strip() if result.stderr else "PowerShell command failed"

        if wmi_error:
            data["wmi_error"] = wmi_error

        # Process hotfix data
        data["total_hotfixes"] = len(hotfixes)

        # Parse dates and compute statistics
        now = datetime.now()
        parsed_hotfixes = []
        most_recent_date = None
        oldest_date = None
        dates_found = []

        for hf in hotfixes:
            parsed_hf = {
                "kb_number": hf.get("HotFixID", "Unknown"),
                "description": hf.get("Description", ""),
                "installed_on": hf.get("InstalledOn"),
                "installed_by": hf.get("InstalledBy", ""),
                "caption": hf.get("Caption", ""),
                "service_pack": hf.get("ServicePackInEffect", ""),
            }

            # Try to parse the installation date
            installed_on = hf.get("InstalledOn")
            if installed_on:
                install_date = _parse_date(installed_on)
                if install_date:
                    # Make naive for comparison
                    if install_date.tzinfo:
                        install_date = install_date.replace(tzinfo=None)
                    days_ago = (now - install_date).days
                    parsed_hf["days_since_install"] = days_ago
                    dates_found.append(install_date)

                    if most_recent_date is None or install_date > most_recent_date:
                        most_recent_date = install_date
                    if oldest_date is None or install_date < oldest_date:
                        oldest_date = install_date

            parsed_hotfixes.append(parsed_hf)

        data["hotfixes"] = parsed_hotfixes

        # Summary statistics
        if most_recent_date:
            days_since_last = (now - most_recent_date).days
            data["most_recent_hotfix_date"] = most_recent_date.isoformat()
            data["days_since_last_hotfix"] = days_since_last
        else:
            data["most_recent_hotfix_date"] = None
            data["days_since_last_hotfix"] = None

        if oldest_date:
            data["oldest_hotfix_date"] = oldest_date.isoformat()

        # Count by type
        type_counts = {}
        for hf in parsed_hotfixes:
            desc = hf.get("description", "Unknown") or "Unknown"
            type_counts[desc] = type_counts.get(desc, 0) + 1
        data["hotfix_types"] = type_counts

        # ---- Generate Findings ----

        if len(hotfixes) == 0 and not wmi_error:
            findings.append({
                "severity": "critical",
                "title": "No Hotfixes Found",
                "description": (
                    "No Windows hotfixes (KBs) were found installed on this system. "
                    "The system may be completely unpatched and vulnerable to numerous known exploits."
                ),
                "remediation": (
                    "Run Windows Update immediately: Settings > Update & Security > Windows Update > Check for updates. "
                    "Consider using WSUS or SCCM for managed patch deployment."
                )
            })
            status = "fail"
        elif most_recent_date:
            days_since_last = (now - most_recent_date).days

            if days_since_last > 90:
                findings.append({
                    "severity": "critical",
                    "title": f"No Hotfixes Installed in {days_since_last} Days",
                    "description": (
                        f"The most recent hotfix was installed {days_since_last} days ago "
                        f"(on {most_recent_date.strftime('%Y-%m-%d')}). The system is likely missing "
                        f"multiple months of critical security patches and is highly vulnerable."
                    ),
                    "remediation": (
                        "Apply all pending Windows updates immediately. Review the Windows Update history "
                        "for failed updates. Consider running: Install-WindowsUpdate -AcceptAll"
                    )
                })
                status = "fail"
            elif days_since_last > 60:
                findings.append({
                    "severity": "high",
                    "title": f"No Hotfixes Installed in {days_since_last} Days",
                    "description": (
                        f"The most recent hotfix was installed {days_since_last} days ago "
                        f"(on {most_recent_date.strftime('%Y-%m-%d')}). The system is likely missing "
                        f"critical security patches from the last two months."
                    ),
                    "remediation": (
                        "Run Windows Update to check for and install pending updates. "
                        "Investigate why updates have not been applied recently."
                    )
                })
                status = "fail"
            elif days_since_last > 30:
                findings.append({
                    "severity": "medium",
                    "title": f"No Hotfixes Installed in {days_since_last} Days",
                    "description": (
                        f"The most recent hotfix was installed {days_since_last} days ago "
                        f"(on {most_recent_date.strftime('%Y-%m-%d')}). Microsoft releases security "
                        f"patches monthly on Patch Tuesday — the system may be missing recent updates."
                    ),
                    "remediation": (
                        "Check Windows Update for pending updates. Ensure automatic updates are enabled "
                        "and the Windows Update service is running."
                    )
                })
                if status != "fail":
                    status = "warn"
            else:
                # Recently patched — good
                findings.append({
                    "severity": "info",
                    "title": f"System Recently Patched ({days_since_last} days ago)",
                    "description": (
                        f"The most recent hotfix was installed {days_since_last} days ago "
                        f"(on {most_recent_date.strftime('%Y-%m-%d')}). {len(hotfixes)} total hotfixes are installed."
                    )
                })

        # Also try to get Windows Update history for more context
        try:
            wu_command = r"""
            try {
                $session = New-Object -ComObject Microsoft.Update.Session
                $searcher = $session.CreateUpdateSearcher()
                $count = $searcher.GetTotalHistoryCount()
                $history = $searcher.QueryHistory(0, [Math]::Min($count, 20))
                $items = @()
                foreach ($h in $history) {
                    $items += @{
                        Title = $h.Title
                        Date = if ($h.Date) { $h.Date.ToString('o') } else { $null }
                        ResultCode = $h.ResultCode
                        Operation = $h.Operation
                    }
                }
                @{ history = $items; totalCount = $count; error = $null } | ConvertTo-Json -Depth 4 -Compress
            } catch {
                @{ history = @(); totalCount = 0; error = $_.Exception.Message } | ConvertTo-Json -Depth 4
            }
            """

            wu_result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", wu_command],
                capture_output=True, text=True, timeout=30
            )

            if wu_result.returncode == 0 and wu_result.stdout.strip():
                try:
                    wu_data = json.loads(wu_result.stdout.strip())
                    history = wu_data.get("history", [])
                    if isinstance(history, dict):
                        history = [history]

                    data["windows_update_history_count"] = wu_data.get("totalCount", 0)
                    data["recent_updates"] = [
                        {
                            "title": h.get("Title", ""),
                            "date": h.get("Date", ""),
                            "result": _result_code_to_string(h.get("ResultCode", -1)),
                        }
                        for h in history[:20]
                    ]

                    # Check for failed updates
                    failed_updates = [h for h in history if h.get("ResultCode") == 4]  # 4 = Failed
                    if failed_updates:
                        data["failed_update_count"] = len(failed_updates)
                        findings.append({
                            "severity": "medium",
                            "title": f"Failed Windows Updates Detected ({len(failed_updates)})",
                            "description": (
                                f"Found {len(failed_updates)} failed Windows Update(s) in recent history. "
                                f"Failed updates may include critical security patches."
                            ),
                            "remediation": (
                                "Investigate failed updates in Windows Update history. "
                                "Try running the Windows Update troubleshooter or manually install failed KBs."
                            )
                        })
                        if status not in ("fail",):
                            status = "warn"

                except json.JSONDecodeError:
                    pass
        except Exception:
            pass  # Windows Update history is supplementary, not critical

    except Exception as e:
        return {
            "category": category,
            "status": "error",
            "data": data,
            "findings": [{
                "severity": "info",
                "title": "Hotfix Scan Error",
                "description": f"An unexpected error occurred while scanning hotfixes: {str(e)}"
            }]
        }

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }


def _parse_date(date_str: str) -> datetime:
    """Try to parse a date string in various formats."""
    if not date_str:
        return None

    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%m/%d/%Y",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%d",
        "%Y-%m-%d %H:%M:%S",
        "%d/%m/%Y",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(date_str.strip(), fmt)
        except (ValueError, TypeError):
            continue

    # Try Python's fromisoformat as last resort
    try:
        return datetime.fromisoformat(date_str.strip().replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError):
        pass

    return None


def _result_code_to_string(code: int) -> str:
    """Convert Windows Update result code to human-readable string."""
    codes = {
        0: "Not Started",
        1: "In Progress",
        2: "Succeeded",
        3: "Succeeded With Errors",
        4: "Failed",
        5: "Aborted",
    }
    return codes.get(code, f"Unknown ({code})")
