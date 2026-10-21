"""
Microsoft Updates Scanner
=========================
Enumerates installed and pending Windows updates via COM and WMI.

Security Relevance:
- Missing security updates leave the system vulnerable to known exploits.
- Systems not updated recently are at high risk for ransomware, worms, and
  other automated attacks that target known vulnerabilities.
- Pending security updates that haven't been installed indicate patch
  management failures.
- Cross-referencing COM and WMI update data provides a comprehensive view
  of patch status.

Data Sources:
- PowerShell: Microsoft.Update.Session COM object (installed + pending)
- WMI: Win32_QuickFixEngineering (installed hotfixes)
"""

import platform
import subprocess
import json
from datetime import datetime, timezone, timedelta
from typing import Optional


def _get_updates_via_com() -> dict:
    """
    Query installed and pending updates via the Microsoft.Update.Session COM object.
    Returns a dict with 'installed' and 'pending' lists.
    """
    ps_script = r"""
try {
    $session = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
    $searcher = $session.CreateUpdateSearcher()

    # Get installed updates (search for already installed)
    $installed = @()
    try {
        $historyCount = $searcher.GetTotalHistoryCount()
        if ($historyCount -gt 0) {
            $history = $searcher.QueryHistory(0, [math]::Min($historyCount, 500))
            foreach ($entry in $history) {
                $installed += [PSCustomObject]@{
                    Title       = $entry.Title
                    Date        = if ($entry.Date) { $entry.Date.ToString('o') } else { $null }
                    ResultCode  = switch ($entry.ResultCode) {
                        0 { 'NotStarted' }
                        1 { 'InProgress' }
                        2 { 'Succeeded' }
                        3 { 'SucceededWithErrors' }
                        4 { 'Failed' }
                        5 { 'Aborted' }
                        default { $entry.ResultCode }
                    }
                    Operation   = switch ($entry.Operation) {
                        1 { 'Installation' }
                        2 { 'Uninstallation' }
                        default { $entry.Operation }
                    }
                    UpdateID    = $entry.UpdateIdentity.UpdateID
                    SupportUrl  = $entry.SupportUrl
                }
            }
        }
    } catch {}

    # Get pending updates (search for not-yet-installed)
    $pending = @()
    try {
        $searchResult = $searcher.Search("IsInstalled=0")
        foreach ($update in $searchResult.Updates) {
            $categories = @()
            foreach ($cat in $update.Categories) {
                $categories += $cat.Name
            }
            $kbs = @()
            foreach ($kb in $update.KBArticleIDs) {
                $kbs += "KB$kb"
            }
            $pending += [PSCustomObject]@{
                Title         = $update.Title
                KBArticleIDs  = ($kbs -join ', ')
                Description   = $update.Description
                IsMandatory   = $update.IsMandatory
                IsDownloaded  = $update.IsDownloaded
                Categories    = ($categories -join ', ')
                MsrcSeverity  = $update.MsrcSeverity
                RebootRequired = $update.RebootRequired
                MaxDownloadSize = $update.MaxDownloadSize
            }
        }
    } catch {}

    [PSCustomObject]@{
        InstalledHistory = $installed
        PendingUpdates   = $pending
    } | ConvertTo-Json -Depth 4
} catch {
    [PSCustomObject]@{
        Error = $_.Exception.Message
    } | ConvertTo-Json
}
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=120,  # COM queries can be slow
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
    except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception):
        pass
    return {"InstalledHistory": [], "PendingUpdates": [], "Error": "Failed to query COM object"}


def _get_hotfixes_wmi() -> list:
    """
    Query installed hotfixes via Win32_QuickFixEngineering (WMI).
    This is faster and more reliable than COM but provides less detail.
    """
    ps_script = """
try {
    $hotfixes = Get-WmiObject -Class Win32_QuickFixEngineering -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            HotFixID    = $_.HotFixID
            Description = $_.Description
            InstalledBy = $_.InstalledBy
            InstalledOn = $_.InstalledOn
            Caption     = $_.Caption
        }
    }
    $hotfixes | ConvertTo-Json -Depth 2
} catch {
    @() | ConvertTo-Json
}
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception):
        pass
    return []


def _get_last_update_date(installed_history: list, hotfixes: list) -> Optional[datetime]:
    """Determine the most recent update installation date."""
    latest = None

    # Check COM history
    for entry in installed_history:
        if entry.get("ResultCode") == "Succeeded":
            date_str = entry.get("Date")
            if date_str:
                try:
                    dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    if latest is None or dt > latest:
                        latest = dt
                except (ValueError, TypeError):
                    pass

    # Check WMI hotfixes
    for hf in hotfixes:
        date_str = hf.get("InstalledOn", "")
        if date_str:
            for fmt in ["%m/%d/%Y", "%Y-%m-%dT%H:%M:%S", "%Y%m%d"]:
                try:
                    dt = datetime.strptime(date_str.strip(), fmt).replace(tzinfo=timezone.utc)
                    if latest is None or dt > latest:
                        latest = dt
                    break
                except (ValueError, TypeError):
                    continue

    return latest


def scan() -> dict:
    """
    Scan for installed and pending Microsoft updates.

    Returns:
        dict with keys: category, status, data, findings
    """
    if platform.system() != "Windows":
        return {
            "category": "Microsoft Updates",
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

        # Query updates via COM and WMI
        com_data = _get_updates_via_com()
        hotfixes = _get_hotfixes_wmi()

        installed_history = com_data.get("InstalledHistory", []) or []
        pending_updates = com_data.get("PendingUpdates", []) or []
        com_error = com_data.get("Error")

        if isinstance(installed_history, dict):
            installed_history = [installed_history]
        if isinstance(pending_updates, dict):
            pending_updates = [pending_updates]

        # Categorize pending updates
        pending_security = []
        pending_critical = []
        pending_other = []

        for update in pending_updates:
            categories = (update.get("Categories", "") or "").lower()
            severity = (update.get("MsrcSeverity", "") or "").lower()
            title = update.get("Title", "")

            if severity in ("critical",) or "critical" in categories:
                pending_critical.append(update)
            elif severity in ("important", "moderate") or "security" in categories:
                pending_security.append(update)
            else:
                pending_other.append(update)

        # Finding: Pending critical updates
        if pending_critical:
            titles = [u.get("Title", "Unknown") for u in pending_critical[:5]]
            findings.append({
                "severity": "critical",
                "title": f"{len(pending_critical)} critical updates pending",
                "description": (
                    f"There are {len(pending_critical)} critical updates that have not been installed. "
                    f"These updates address severe vulnerabilities that may be actively exploited. "
                    f"Examples: {'; '.join(titles)}"
                ),
                "remediation": (
                    "Install critical updates immediately. Run Windows Update or use: "
                    "`Install-WindowsUpdate -AcceptAll -AutoReboot` (requires PSWindowsUpdate module). "
                    "Schedule a maintenance window if immediate patching is not possible."
                ),
            })

        # Finding: Pending security updates
        if pending_security:
            titles = [u.get("Title", "Unknown") for u in pending_security[:5]]
            findings.append({
                "severity": "high",
                "title": f"{len(pending_security)} security updates pending",
                "description": (
                    f"There are {len(pending_security)} security updates that have not been installed. "
                    f"Examples: {'; '.join(titles)}"
                ),
                "remediation": (
                    "Install security updates as soon as possible. Prioritize based on MSRC severity."
                ),
            })

        # Finding: Other pending updates
        if pending_other:
            findings.append({
                "severity": "low",
                "title": f"{len(pending_other)} other updates pending",
                "description": (
                    f"There are {len(pending_other)} non-security updates available."
                ),
                "remediation": (
                    "Install pending updates during the next maintenance window."
                ),
            })

        # Check when the system was last updated
        last_update_date = _get_last_update_date(installed_history, hotfixes)
        now = datetime.now(timezone.utc)

        if last_update_date:
            days_since_update = (now - last_update_date).days
            if days_since_update > 90:
                findings.append({
                    "severity": "critical",
                    "title": f"System not updated in {days_since_update} days",
                    "description": (
                        f"The last successful update was installed {days_since_update} days ago "
                        f"on {last_update_date.strftime('%Y-%m-%d')}. Systems not updated for more "
                        f"than 90 days are at extreme risk of exploitation."
                    ),
                    "remediation": (
                        "Immediately investigate why updates are not being applied. Check Windows "
                        "Update service status, WSUS connectivity, and disk space. Apply all "
                        "pending updates."
                    ),
                })
            elif days_since_update > 30:
                findings.append({
                    "severity": "high",
                    "title": f"System not updated in {days_since_update} days",
                    "description": (
                        f"The last successful update was installed {days_since_update} days ago "
                        f"on {last_update_date.strftime('%Y-%m-%d')}. Microsoft releases security "
                        f"updates monthly on Patch Tuesday."
                    ),
                    "remediation": (
                        "Check Windows Update configuration and apply pending updates."
                    ),
                })
        else:
            if not hotfixes and not installed_history:
                findings.append({
                    "severity": "high",
                    "title": "Unable to determine last update date",
                    "description": (
                        "No update history was found. The system may never have been updated "
                        "or update history has been cleared."
                    ),
                    "remediation": (
                        "Verify Windows Update is functioning correctly and run a manual update check."
                    ),
                })

        # Cross-reference: list installed KB numbers
        installed_kbs = set()
        for hf in hotfixes:
            kb = hf.get("HotFixID", "")
            if kb:
                installed_kbs.add(kb.upper())

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
            "category": "Microsoft Updates",
            "status": status,
            "data": {
                "installed_history_count": len(installed_history),
                "pending_updates_count": len(pending_updates),
                "pending_critical_count": len(pending_critical),
                "pending_security_count": len(pending_security),
                "pending_other_count": len(pending_other),
                "hotfixes_count": len(hotfixes),
                "installed_kbs": sorted(installed_kbs),
                "last_update_date": last_update_date.isoformat() if last_update_date else None,
                "hotfixes": hotfixes,
                "pending_updates": pending_updates,
                "recent_history": installed_history[:50],  # Limit output
            },
            "findings": findings,
        }

    except Exception as e:
        return {
            "category": "Microsoft Updates",
            "status": "error",
            "data": {"error": str(e)},
            "findings": [{
                "severity": "info",
                "title": "Scanner error",
                "description": f"An unexpected error occurred while scanning updates: {e}",
            }],
        }
