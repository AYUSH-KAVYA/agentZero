"""
Local Groups Scanner
====================
Enumerates all local groups and their members, with special attention to
security-sensitive groups.

Security Relevance:
- The Administrators group grants full system control; unexpected members
  indicate potential privilege escalation or unauthorized access.
- Remote Desktop Users membership controls who can RDP into the system.
- Backup Operators can read any file on the system regardless of ACLs.
- Hyper-V Administrators have full control over virtual machines.
- Distributed COM Users and Network Configuration Operators also have
  elevated privileges that may be exploited.

Data Sources:
- PowerShell: Get-LocalGroup
- PowerShell: Get-LocalGroupMember
"""

import platform
import subprocess
import json


# Security-sensitive groups to pay special attention to
_SENSITIVE_GROUPS = {
    "Administrators": "critical",
    "Remote Desktop Users": "high",
    "Backup Operators": "high",
    "Hyper-V Administrators": "medium",
    "Power Users": "medium",
    "Network Configuration Operators": "medium",
    "Distributed COM Users": "low",
    "Remote Management Users": "medium",
    "Access Control Assistance Operators": "low",
    "Event Log Readers": "low",
    "Performance Log Users": "low",
    "Performance Monitor Users": "low",
    "Replicator": "medium",
}

# Built-in / expected administrator accounts
_EXPECTED_ADMIN_SIDS = {
    "S-1-5-21-*-500",  # Built-in Administrator
}
_EXPECTED_ADMIN_NAMES = {
    "administrator",
    "domain admins",
}


def _get_all_groups() -> list:
    """Get all local groups via PowerShell."""
    ps_script = """
$groups = Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        Name        = $_.Name
        SID         = $_.SID.Value
        Description = $_.Description
        ObjectClass = $_.ObjectClass
    }
}
$groups | ConvertTo-Json -Depth 2
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


def _get_group_members(group_name: str) -> list:
    """Get members of a specific local group via PowerShell."""
    escaped = group_name.replace("'", "''")
    ps_script = f"""
try {{
    $members = Get-LocalGroupMember -Group '{escaped}' -ErrorAction Stop | ForEach-Object {{
        [PSCustomObject]@{{
            Name        = $_.Name
            SID         = $_.SID.Value
            ObjectClass = $_.ObjectClass
            PrincipalSource = $_.PrincipalSource.ToString()
        }}
    }}
    $members | ConvertTo-Json -Depth 2
}} catch {{
    @() | ConvertTo-Json
}}
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception):
        pass
    return []


def _get_all_groups_with_members() -> list:
    """
    Efficiently get all groups and their members in a single PowerShell call.
    Falls back to individual queries if the batch approach fails.
    """
    ps_script = """
$allGroups = @()
$groups = Get-LocalGroup -ErrorAction SilentlyContinue

foreach ($group in $groups) {
    $members = @()
    try {
        $members = Get-LocalGroupMember -Group $group.Name -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Name            = $_.Name
                SID             = $_.SID.Value
                ObjectClass     = $_.ObjectClass
                PrincipalSource = $_.PrincipalSource.ToString()
            }
        }
    } catch {
        # Some groups may fail (e.g., orphaned SIDs)
    }

    $allGroups += [PSCustomObject]@{
        GroupName    = $group.Name
        GroupSID     = $group.SID.Value
        Description  = $group.Description
        MemberCount  = @($members).Count
        Members      = @($members)
    }
}

$allGroups | ConvertTo-Json -Depth 4
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

    # Fallback: get groups first, then members individually
    groups = _get_all_groups()
    result_list = []
    for group in groups:
        name = group.get("Name", "")
        members = _get_group_members(name) if name else []
        result_list.append({
            "GroupName": name,
            "GroupSID": group.get("SID", ""),
            "Description": group.get("Description", ""),
            "MemberCount": len(members),
            "Members": members,
        })
    return result_list


def _is_expected_admin(member_name: str, member_sid: str) -> bool:
    """Check if a member is an expected administrator."""
    name_lower = member_name.lower().split("\\")[-1] if member_name else ""
    if name_lower in _EXPECTED_ADMIN_NAMES:
        return True
    # Check for built-in Administrator SID (ends in -500)
    if member_sid and member_sid.endswith("-500"):
        return True
    return False


def scan() -> dict:
    """
    Enumerate all local groups and their members, flagging security concerns.

    Returns:
        dict with keys: category, status, data, findings
    """
    if platform.system() != "Windows":
        return {
            "category": "Local Groups",
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
        groups_data = _get_all_groups_with_members()

        non_empty_groups = []
        sensitive_group_findings = {}

        for group in groups_data:
            group_name = group.get("GroupName", "")
            members = group.get("Members", [])
            member_count = group.get("MemberCount", len(members))

            if isinstance(members, dict):
                members = [members]

            if member_count > 0:
                non_empty_groups.append(group)

            # Check sensitive groups
            if group_name in _SENSITIVE_GROUPS:
                severity = _SENSITIVE_GROUPS[group_name]

                if group_name == "Administrators":
                    # Flag unexpected admin members
                    unexpected_admins = []
                    for member in members:
                        member_name = member.get("Name", "")
                        member_sid = member.get("SID", "")
                        if not _is_expected_admin(member_name, member_sid):
                            unexpected_admins.append(member_name)

                    if unexpected_admins:
                        findings.append({
                            "severity": "critical",
                            "title": f"Unexpected Administrators group members ({len(unexpected_admins)})",
                            "description": (
                                f"The following accounts are in the Administrators group but are not "
                                f"standard built-in accounts: {', '.join(unexpected_admins)}. "
                                f"Unauthorized administrator accounts are a significant privilege "
                                f"escalation risk."
                            ),
                            "remediation": (
                                "Review each account in the Administrators group. Remove any accounts "
                                "that do not require administrative privileges. Follow the principle "
                                "of least privilege."
                            ),
                        })

                    if member_count > 3:
                        findings.append({
                            "severity": "high",
                            "title": f"Too many Administrators: {member_count} members",
                            "description": (
                                f"The Administrators group has {member_count} members. Having many "
                                f"administrator accounts increases the attack surface significantly."
                            ),
                            "remediation": (
                                "Reduce the number of administrator accounts to the minimum necessary. "
                                "Use standard user accounts for daily work and elevate only when needed."
                            ),
                        })

                elif group_name == "Remote Desktop Users":
                    if members:
                        member_names = [m.get("Name", "Unknown") for m in members]
                        findings.append({
                            "severity": "high",
                            "title": f"Remote Desktop Users has {member_count} members",
                            "description": (
                                f"The Remote Desktop Users group contains: {', '.join(member_names)}. "
                                f"These accounts can establish RDP sessions to this system. "
                                f"RDP is a common attack vector for ransomware and lateral movement."
                            ),
                            "remediation": (
                                "Review RDP access requirements. Remove users who don't need remote "
                                "access. If RDP is required, enforce Network Level Authentication (NLA), "
                                "use MFA, and restrict source IPs via Windows Firewall."
                            ),
                        })

                elif group_name == "Backup Operators":
                    if members:
                        member_names = [m.get("Name", "Unknown") for m in members]
                        findings.append({
                            "severity": "high",
                            "title": f"Backup Operators has {member_count} members",
                            "description": (
                                f"Backup Operators group contains: {', '.join(member_names)}. "
                                f"Members can read any file on the system regardless of ACLs, "
                                f"which can be abused to extract sensitive data including SAM/SYSTEM hives."
                            ),
                            "remediation": (
                                "Limit Backup Operators membership to dedicated backup service accounts. "
                                "Monitor for suspicious file access by these accounts."
                            ),
                        })

                elif group_name == "Hyper-V Administrators":
                    if members:
                        member_names = [m.get("Name", "Unknown") for m in members]
                        findings.append({
                            "severity": "medium",
                            "title": f"Hyper-V Administrators has {member_count} members",
                            "description": (
                                f"Hyper-V Administrators group contains: {', '.join(member_names)}. "
                                f"Members have full control over all virtual machines on this host."
                            ),
                            "remediation": (
                                "Ensure only authorized VM administrators are in this group."
                            ),
                        })

                elif members:
                    # Generic sensitive group finding
                    member_names = [m.get("Name", "Unknown") for m in members]
                    findings.append({
                        "severity": severity,
                        "title": f"Sensitive group '{group_name}' has {member_count} members",
                        "description": (
                            f"The '{group_name}' group contains: {', '.join(member_names)}. "
                            f"Membership in this group grants elevated privileges."
                        ),
                        "remediation": (
                            f"Review membership of '{group_name}' and remove any unauthorized accounts."
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
            "category": "Local Groups",
            "status": status,
            "data": {
                "total_groups": len(groups_data),
                "non_empty_groups": len(non_empty_groups),
                "groups": groups_data,
            },
            "findings": findings,
        }

    except Exception as e:
        return {
            "category": "Local Groups",
            "status": "error",
            "data": {"error": str(e)},
            "findings": [{
                "severity": "info",
                "title": "Scanner error",
                "description": f"An unexpected error occurred while scanning local groups: {e}",
            }],
        }
