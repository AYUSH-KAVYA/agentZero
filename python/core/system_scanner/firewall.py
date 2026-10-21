"""
Firewall Configuration Scanner Module
======================================
Inspects Windows Firewall profile status (Domain, Private, Public) and enumerates
firewall rules to identify non-standard or overly permissive configurations.

Security Relevance:
- A disabled firewall profile exposes the system to unauthorized network access.
- Overly permissive inbound rules (Allow Any from Any) can be exploited by attackers.
- Non-standard/custom rules may indicate intentional backdoors or misconfigurations.
"""

import platform
import subprocess
import json


def scan() -> dict:
    """
    Scans Windows Firewall profiles and rules.

    Returns:
        dict with keys:
        - 'category': str — Human-readable category name
        - 'status': str — One of 'pass', 'warn', 'fail', 'info', 'error'
        - 'data': dict — Raw extracted data
        - 'findings': list[dict] — Each finding has 'severity', 'title', 'description', and optional 'remediation'
    """
    category = "Firewall Configuration"
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
        # ---- Step 1: Get Firewall Profiles ----
        profile_command = r"""
        try {
            $profiles = Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogFileName, LogMaxSizeKilobytes, LogAllowed, LogBlocked, NotifyOnListen
            $profileList = @()
            foreach ($p in $profiles) {
                $profileList += @{
                    Name = $p.Name
                    Enabled = [bool]$p.Enabled
                    DefaultInboundAction = $p.DefaultInboundAction.ToString()
                    DefaultOutboundAction = $p.DefaultOutboundAction.ToString()
                    LogFileName = $p.LogFileName
                    LogMaxSizeKilobytes = $p.LogMaxSizeKilobytes
                    LogAllowed = [bool]$p.LogAllowed
                    LogBlocked = [bool]$p.LogBlocked
                    NotifyOnListen = [bool]$p.NotifyOnListen
                }
            }
            @{ profiles = $profileList; error = $null } | ConvertTo-Json -Depth 4
        } catch {
            @{ profiles = @(); error = $_.Exception.Message } | ConvertTo-Json -Depth 4
        }
        """

        profile_result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", profile_command],
            capture_output=True, text=True, timeout=30
        )

        profiles = []
        if profile_result.returncode == 0 and profile_result.stdout.strip():
            try:
                parsed = json.loads(profile_result.stdout.strip())
                profiles_raw = parsed.get("profiles", [])
                if isinstance(profiles_raw, dict):
                    profiles_raw = [profiles_raw]
                profiles = profiles_raw
                if parsed.get("error"):
                    data["profile_error"] = parsed["error"]
            except json.JSONDecodeError as e:
                data["profile_error"] = f"Failed to parse profile output: {str(e)}"
        else:
            data["profile_error"] = profile_result.stderr.strip() if profile_result.stderr else "Failed to get firewall profiles"

        data["profiles"] = profiles

        # Check for disabled profiles
        for profile in profiles:
            profile_name = profile.get("Name", "Unknown")
            enabled = profile.get("Enabled", True)
            if not enabled:
                findings.append({
                    "severity": "critical",
                    "title": f"Firewall Profile Disabled: {profile_name}",
                    "description": (
                        f"The Windows Firewall '{profile_name}' profile is disabled. "
                        f"All inbound and outbound traffic on this network type is unfiltered."
                    ),
                    "remediation": (
                        f"Enable the firewall profile: Set-NetFirewallProfile -Profile {profile_name} -Enabled True"
                    )
                })
                status = "fail"

            # Check default inbound action
            default_inbound = profile.get("DefaultInboundAction", "")
            if enabled and default_inbound.lower() in ("allow", "2"):
                findings.append({
                    "severity": "high",
                    "title": f"Default Inbound Action is Allow: {profile_name}",
                    "description": (
                        f"The '{profile_name}' profile has default inbound action set to Allow. "
                        f"All inbound traffic is permitted unless explicitly blocked by a rule."
                    ),
                    "remediation": (
                        f"Set default inbound to Block: Set-NetFirewallProfile -Profile {profile_name} -DefaultInboundAction Block"
                    )
                })
                if status != "fail":
                    status = "fail"

        # ---- Step 2: Enumerate Firewall Rules ----
        rules_command = r"""
        try {
            $rules = Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.Enabled -eq 'True' } |
                Select-Object -First 500 DisplayName, Description, Direction, Action, Profile, Enabled, DisplayGroup, Owner
            $ruleList = @()
            foreach ($r in $rules) {
                # Get port/address filters
                $portFilter = $null
                $addressFilter = $null
                try {
                    $portFilter = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                    $addressFilter = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
                } catch {}

                $ruleList += @{
                    DisplayName = $r.DisplayName
                    Description = $r.Description
                    Direction = $r.Direction.ToString()
                    Action = $r.Action.ToString()
                    Profile = $r.Profile.ToString()
                    Enabled = [bool]$r.Enabled
                    DisplayGroup = $r.DisplayGroup
                    Owner = $r.Owner
                    LocalPort = if ($portFilter) { $portFilter.LocalPort } else { $null }
                    RemotePort = if ($portFilter) { $portFilter.RemotePort } else { $null }
                    Protocol = if ($portFilter) { $portFilter.Protocol } else { $null }
                    LocalAddress = if ($addressFilter) { $addressFilter.LocalAddress } else { $null }
                    RemoteAddress = if ($addressFilter) { $addressFilter.RemoteAddress } else { $null }
                    IsCustom = ($r.DisplayGroup -eq $null -or $r.DisplayGroup -eq '' -or $r.Owner -ne $null)
                }
            }
            @{ rules = $ruleList; totalEnabled = ($rules | Measure-Object).Count; error = $null } | ConvertTo-Json -Depth 4 -Compress
        } catch {
            @{ rules = @(); totalEnabled = 0; error = $_.Exception.Message } | ConvertTo-Json -Depth 4
        }
        """

        rules_result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", rules_command],
            capture_output=True, text=True, timeout=30
        )

        rules = []
        total_enabled = 0
        custom_rules = []
        permissive_rules = []

        if rules_result.returncode == 0 and rules_result.stdout.strip():
            try:
                parsed = json.loads(rules_result.stdout.strip())
                rules_raw = parsed.get("rules", [])
                if isinstance(rules_raw, dict):
                    rules_raw = [rules_raw]
                rules = rules_raw
                total_enabled = parsed.get("totalEnabled", len(rules))
                if parsed.get("error"):
                    data["rules_error"] = parsed["error"]
            except json.JSONDecodeError as e:
                data["rules_error"] = f"Failed to parse rules output: {str(e)}"
        else:
            data["rules_error"] = rules_result.stderr.strip() if rules_result.stderr else "Failed to enumerate rules"

        # Analyze rules
        microsoft_groups = set()
        for rule in rules:
            display_group = rule.get("DisplayGroup", "") or ""
            is_custom = rule.get("IsCustom", False)
            direction = str(rule.get("Direction", "")).lower()
            action = str(rule.get("Action", "")).lower()
            local_port = str(rule.get("LocalPort", "") or "")
            remote_address = str(rule.get("RemoteAddress", "") or "")
            remote_port = str(rule.get("RemotePort", "") or "")
            protocol = str(rule.get("Protocol", "") or "")

            # Identify custom/non-standard rules
            if is_custom or not display_group:
                custom_rules.append(rule)

            # Identify overly permissive inbound allow rules
            if direction in ("inbound", "1") and action in ("allow", "2"):
                is_permissive = False
                if local_port.lower() == "any" and remote_address.lower() == "any":
                    is_permissive = True
                elif local_port.lower() == "any" and protocol.lower() in ("tcp", "udp", "any", "6", "17"):
                    is_permissive = True

                if is_permissive:
                    permissive_rules.append(rule)

        data["total_enabled_rules"] = total_enabled
        data["custom_rules_count"] = len(custom_rules)
        data["permissive_inbound_rules_count"] = len(permissive_rules)

        # Store limited rule details to avoid huge data payloads
        data["custom_rules"] = [
            {
                "name": r.get("DisplayName", "Unknown"),
                "direction": r.get("Direction", "Unknown"),
                "action": r.get("Action", "Unknown"),
                "local_port": r.get("LocalPort", "Any"),
                "remote_address": r.get("RemoteAddress", "Any"),
                "protocol": r.get("Protocol", "Any"),
            }
            for r in custom_rules[:50]  # Limit to 50 entries
        ]

        data["permissive_inbound_rules"] = [
            {
                "name": r.get("DisplayName", "Unknown"),
                "local_port": r.get("LocalPort", "Any"),
                "remote_address": r.get("RemoteAddress", "Any"),
                "protocol": r.get("Protocol", "Any"),
                "group": r.get("DisplayGroup", ""),
            }
            for r in permissive_rules[:30]
        ]

        # Findings for permissive rules
        if permissive_rules:
            rule_names = [r.get("DisplayName", "Unknown") for r in permissive_rules[:5]]
            more_text = f" and {len(permissive_rules) - 5} more" if len(permissive_rules) > 5 else ""
            findings.append({
                "severity": "high",
                "title": f"Overly Permissive Inbound Rules Found ({len(permissive_rules)})",
                "description": (
                    f"Found {len(permissive_rules)} inbound firewall rule(s) that allow traffic from any source "
                    f"on any port. These rules significantly expand the attack surface.\n"
                    f"Examples: {', '.join(rule_names)}{more_text}"
                ),
                "remediation": (
                    "Review and restrict overly permissive inbound rules. Limit rules to specific ports, "
                    "protocols, and source addresses. Remove rules that are no longer needed."
                )
            })
            if status != "fail":
                status = "warn"

        # Findings for custom rules
        if custom_rules:
            findings.append({
                "severity": "info",
                "title": f"Custom/Non-Standard Firewall Rules Detected ({len(custom_rules)})",
                "description": (
                    f"Found {len(custom_rules)} custom or non-standard firewall rule(s) that are not part of "
                    f"the default Windows firewall configuration. These should be reviewed for legitimacy."
                ),
                "remediation": "Review custom firewall rules to ensure they are authorized and necessary."
            })

    except Exception as e:
        return {
            "category": category,
            "status": "error",
            "data": data,
            "findings": [{
                "severity": "info",
                "title": "Firewall Scan Error",
                "description": f"An unexpected error occurred while scanning firewall configuration: {str(e)}"
            }]
        }

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
