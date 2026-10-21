"""
Local Users Scanner Module
===========================
Enumerates local user accounts, their status (enabled/disabled), password policies,
and identifies potential security weaknesses in user configurations.

Security Relevance:
- Users with no password requirement are trivial to compromise.
- The built-in Administrator account, if enabled, is a high-value target for attackers.
- Enabled accounts that have never logged in may be orphaned/forgotten and represent
  unnecessary attack surface.
- Accounts with passwords that never expire violate password rotation best practices.
"""

import platform
import subprocess
import json


def scan() -> dict:
    """
    Scans local user accounts and their security configuration.

    Returns:
        dict with keys:
        - 'category': str — Human-readable category name
        - 'status': str — One of 'pass', 'warn', 'fail', 'info', 'error'
        - 'data': dict — Raw extracted data
        - 'findings': list[dict] — Each finding has 'severity', 'title', 'description', and optional 'remediation'
    """
    category = "Local Users"
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
        # Use Get-LocalUser for comprehensive user info
        ps_command = r"""
        try {
            $users = Get-LocalUser -ErrorAction Stop
            $userList = @()
            foreach ($u in $users) {
                $userList += @{
                    Name = $u.Name
                    FullName = $u.FullName
                    Description = $u.Description
                    Enabled = $u.Enabled
                    LastLogon = if ($u.LastLogon) { $u.LastLogon.ToString('o') } else { $null }
                    PasswordLastSet = if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString('o') } else { $null }
                    PasswordExpires = if ($u.PasswordExpires) { $u.PasswordExpires.ToString('o') } else { $null }
                    PasswordRequired = $u.PasswordRequired
                    PasswordChangeableDate = if ($u.PasswordChangeableDate) { $u.PasswordChangeableDate.ToString('o') } else { $null }
                    UserMayChangePassword = $u.UserMayChangePassword
                    AccountExpires = if ($u.AccountExpires) { $u.AccountExpires.ToString('o') } else { $null }
                    SID = $u.SID.Value
                    PrincipalSource = $u.PrincipalSource.ToString()
                    ObjectClass = $u.ObjectClass
                }
            }
            @{ users = $userList; count = ($users | Measure-Object).Count; error = $null } | ConvertTo-Json -Depth 4
        } catch {
            @{ users = @(); count = 0; error = $_.Exception.Message } | ConvertTo-Json -Depth 4
        }
        """

        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_command],
            capture_output=True, text=True, timeout=30
        )

        users = []
        cmd_error = None

        if result.returncode == 0 and result.stdout.strip():
            try:
                parsed = json.loads(result.stdout.strip())
                users_raw = parsed.get("users", [])
                if isinstance(users_raw, dict):
                    users_raw = [users_raw]
                users = users_raw
                cmd_error = parsed.get("error")
            except json.JSONDecodeError as e:
                cmd_error = f"Failed to parse Get-LocalUser output: {str(e)}"
        else:
            cmd_error = result.stderr.strip() if result.stderr else "Get-LocalUser command failed"
            # Fallback to net user if Get-LocalUser is not available
            users, cmd_error = _fallback_net_user()

        if cmd_error and not users:
            data["error"] = cmd_error

        # Also get local group memberships for Administrators group
        admin_members = _get_admin_group_members()
        data["administrators_group_members"] = admin_members

        # Process users
        processed_users = []
        enabled_count = 0
        disabled_count = 0
        no_password_required = []
        never_logged_in_but_enabled = []
        password_never_expires = []
        builtin_admin_enabled = False
        builtin_guest_enabled = False

        for user in users:
            username = user.get("Name", "Unknown")
            enabled = user.get("Enabled", False)
            password_required = user.get("PasswordRequired", True)
            last_logon = user.get("LastLogon")
            password_expires = user.get("PasswordExpires")
            sid = user.get("SID", "")

            processed_user = {
                "username": username,
                "full_name": user.get("FullName", ""),
                "description": user.get("Description", ""),
                "enabled": enabled,
                "last_logon": last_logon,
                "password_last_set": user.get("PasswordLastSet"),
                "password_expires": password_expires,
                "password_required": password_required,
                "password_changeable": user.get("PasswordChangeableDate"),
                "user_may_change_password": user.get("UserMayChangePassword"),
                "account_expires": user.get("AccountExpires"),
                "sid": sid,
                "principal_source": user.get("PrincipalSource", ""),
                "is_admin": username in admin_members,
            }

            if enabled:
                enabled_count += 1
            else:
                disabled_count += 1

            # Check for no password required
            if enabled and password_required is False:
                no_password_required.append(username)

            # Check for enabled but never logged in
            if enabled and not last_logon:
                never_logged_in_but_enabled.append(username)

            # Check for password never expires
            if enabled and not password_expires:
                password_never_expires.append(username)

            # Check for built-in Administrator (SID ends with -500)
            if sid and sid.endswith("-500"):
                processed_user["is_builtin_admin"] = True
                if enabled:
                    builtin_admin_enabled = True

            # Check for built-in Guest (SID ends with -501)
            if sid and sid.endswith("-501"):
                processed_user["is_builtin_guest"] = True
                if enabled:
                    builtin_guest_enabled = True

            processed_users.append(processed_user)

        data["users"] = processed_users
        data["total_users"] = len(processed_users)
        data["enabled_count"] = enabled_count
        data["disabled_count"] = disabled_count
        data["no_password_required_count"] = len(no_password_required)
        data["never_logged_in_enabled_count"] = len(never_logged_in_but_enabled)
        data["password_never_expires_count"] = len(password_never_expires)
        data["builtin_admin_enabled"] = builtin_admin_enabled
        data["builtin_guest_enabled"] = builtin_guest_enabled

        # ---- Generate Findings ----

        # CRITICAL: Users with no password required
        if no_password_required:
            findings.append({
                "severity": "critical",
                "title": f"User Accounts Without Password Requirement ({len(no_password_required)})",
                "description": (
                    f"The following enabled user account(s) do not require a password: "
                    f"{', '.join(no_password_required)}. These accounts can be accessed without "
                    f"any authentication, making them trivial to compromise."
                ),
                "remediation": (
                    "Set passwords for all accounts and require password authentication:\n"
                    "For each user: Set-LocalUser -Name '<username>' -PasswordNeverExpires $false\n"
                    "Then set a strong password: net user <username> <password>"
                )
            })
            status = "fail"

        # HIGH: Built-in Administrator enabled
        if builtin_admin_enabled:
            findings.append({
                "severity": "high",
                "title": "Built-in Administrator Account Is Enabled",
                "description": (
                    "The built-in Administrator account (SID *-500) is enabled. This is a well-known "
                    "account name that attackers target for brute-force attacks. It also typically runs "
                    "without UAC protection (Admin Approval Mode)."
                ),
                "remediation": (
                    "Disable the built-in Administrator account and use a named admin account instead:\n"
                    "Disable-LocalUser -Name 'Administrator'\n"
                    "If needed, rename it: Rename-LocalUser -Name 'Administrator' -NewName '<new_name>'"
                )
            })
            if status != "fail":
                status = "fail"

        # MEDIUM: Built-in Guest enabled
        if builtin_guest_enabled:
            findings.append({
                "severity": "medium",
                "title": "Built-in Guest Account Is Enabled",
                "description": (
                    "The built-in Guest account is enabled. Guest accounts provide unauthenticated "
                    "access with limited privileges but can be used as a foothold for lateral movement."
                ),
                "remediation": "Disable the Guest account: Disable-LocalUser -Name 'Guest'"
            })
            if status not in ("fail",):
                status = "warn"

        # MEDIUM: Enabled accounts that never logged in
        if never_logged_in_but_enabled:
            # Filter out common system accounts
            system_accounts = {"defaultaccount", "wdagutilityaccount", "guest"}
            suspicious = [u for u in never_logged_in_but_enabled if u.lower() not in system_accounts]
            if suspicious:
                findings.append({
                    "severity": "medium",
                    "title": f"Enabled Accounts With No Login History ({len(suspicious)})",
                    "description": (
                        f"The following enabled account(s) have never logged in: "
                        f"{', '.join(suspicious)}. Unused but enabled accounts expand the attack "
                        f"surface and may represent forgotten or orphaned accounts."
                    ),
                    "remediation": (
                        "Review these accounts and disable any that are not needed:\n"
                        "Disable-LocalUser -Name '<username>'"
                    )
                })
                if status not in ("fail",):
                    status = "warn"

        # LOW: Passwords that never expire
        if password_never_expires:
            # Filter system accounts
            system_accounts = {"defaultaccount", "wdagutilityaccount", "guest", "administrator"}
            user_never_expire = [u for u in password_never_expires if u.lower() not in system_accounts]
            if user_never_expire:
                findings.append({
                    "severity": "low",
                    "title": f"Accounts With Non-Expiring Passwords ({len(user_never_expire)})",
                    "description": (
                        f"The following account(s) have passwords that never expire: "
                        f"{', '.join(user_never_expire)}. Password rotation is a security best practice."
                    ),
                    "remediation": (
                        "Consider implementing a password expiration policy:\n"
                        "Set-LocalUser -Name '<username>' -PasswordNeverExpires $false"
                    )
                })

        # INFO: Admin group membership summary
        if admin_members:
            findings.append({
                "severity": "info",
                "title": f"Local Administrators Group ({len(admin_members)} members)",
                "description": f"Administrators group members: {', '.join(admin_members)}"
            })

    except Exception as e:
        return {
            "category": category,
            "status": "error",
            "data": data,
            "findings": [{
                "severity": "info",
                "title": "Local Users Scan Error",
                "description": f"An unexpected error occurred while scanning local users: {str(e)}"
            }]
        }

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }


def _get_admin_group_members() -> list:
    """Get members of the local Administrators group."""
    try:
        ps_command = r"""
        try {
            $members = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
            $members | ForEach-Object { $_.Name } | ConvertTo-Json
        } catch {
            try {
                $members = net localgroup Administrators 2>$null
                $inMembers = $false
                $memberList = @()
                foreach ($line in $members) {
                    if ($line -match '^---') { $inMembers = $true; continue }
                    if ($line -match '^The command completed') { break }
                    if ($inMembers -and $line.Trim()) { $memberList += $line.Trim() }
                }
                $memberList | ConvertTo-Json
            } catch {
                "[]"
            }
        }
        """
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_command],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0 and result.stdout.strip():
            try:
                members = json.loads(result.stdout.strip())
                if isinstance(members, str):
                    members = [members]
                return members or []
            except json.JSONDecodeError:
                return []
    except Exception:
        pass
    return []


def _fallback_net_user() -> tuple:
    """Fallback method using 'net user' command."""
    users = []
    error = None
    try:
        # Get list of usernames
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "net user | Select-String -Pattern '^\\w' | ForEach-Object { $_.Line }"],
            capture_output=True, text=True, timeout=15
        )

        if result.returncode != 0:
            return [], result.stderr.strip() if result.stderr else "net user failed"

        # Parse usernames from net user output
        usernames = []
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if line and not line.startswith("User accounts") and not line.startswith("---") and not line.startswith("The command"):
                # net user outputs names in columns
                parts = line.split()
                usernames.extend(parts)

        # Get details for each user
        for username in usernames:
            try:
                detail_result = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     f'net user "{username}" 2>$null'],
                    capture_output=True, text=True, timeout=10
                )
                if detail_result.returncode == 0:
                    user_info = _parse_net_user_output(detail_result.stdout, username)
                    users.append(user_info)
            except Exception:
                users.append({"Name": username, "Enabled": None})

    except Exception as e:
        error = f"Fallback net user failed: {str(e)}"

    return users, error


def _parse_net_user_output(output: str, username: str) -> dict:
    """Parse the output of 'net user <username>' into a dict."""
    info = {"Name": username}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Full Name"):
            info["FullName"] = line.split(None, 2)[-1].strip() if len(line.split(None, 2)) > 2 else ""
        elif line.startswith("Comment"):
            info["Description"] = line.split(None, 1)[-1].strip() if len(line.split(None, 1)) > 1 else ""
        elif line.startswith("Account active"):
            active_str = line.split()[-1].strip().lower()
            info["Enabled"] = active_str == "yes"
        elif line.startswith("Password required"):
            req_str = line.split()[-1].strip().lower()
            info["PasswordRequired"] = req_str == "yes"
        elif line.startswith("Last logon"):
            val = line.replace("Last logon", "").strip()
            info["LastLogon"] = val if val.lower() != "never" else None
        elif line.startswith("Password last set"):
            val = line.replace("Password last set", "").strip()
            info["PasswordLastSet"] = val
        elif line.startswith("Password expires"):
            val = line.replace("Password expires", "").strip()
            info["PasswordExpires"] = val if val.lower() != "never" else None
    return info
