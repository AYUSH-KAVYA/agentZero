"""
UAC (User Account Control) Policy Scanner Module
==================================================
Reads UAC-related registry values from
HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System
to determine the UAC configuration state.

Security Relevance:
- UAC is a critical defense-in-depth mechanism against privilege escalation.
- Disabling UAC (EnableLUA=0) allows all programs to run with full admin privileges.
- Auto-approving admin prompts (ConsentPromptBehaviorAdmin=0) removes the UAC elevation prompt.
- Disabling the secure desktop allows UI spoofing attacks during elevation prompts.
- FilterAdministratorToken controls whether the built-in Administrator gets a filtered token.
"""

import platform


def scan() -> dict:
    """
    Scans UAC system policies via the Windows Registry.

    Returns:
        dict with keys:
        - 'category': str — Human-readable category name
        - 'status': str — One of 'pass', 'warn', 'fail', 'info', 'error'
        - 'data': dict — Raw extracted data
        - 'findings': list[dict] — Each finding has 'severity', 'title', 'description', and optional 'remediation'
    """
    category = "UAC Policies"
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
        import winreg

        reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

        # Define all UAC-related registry values to check
        uac_values = {
            "EnableLUA": {
                "description": "UAC Enabled",
                "default": 1,
                "type": winreg.REG_DWORD,
            },
            "ConsentPromptBehaviorAdmin": {
                "description": "Admin Consent Prompt Behavior",
                "default": 5,
                "type": winreg.REG_DWORD,
            },
            "ConsentPromptBehaviorUser": {
                "description": "Standard User Consent Prompt Behavior",
                "default": 3,
                "type": winreg.REG_DWORD,
            },
            "PromptOnSecureDesktop": {
                "description": "Prompt on Secure Desktop",
                "default": 1,
                "type": winreg.REG_DWORD,
            },
            "EnableVirtualization": {
                "description": "File/Registry Virtualization",
                "default": 1,
                "type": winreg.REG_DWORD,
            },
            "FilterAdministratorToken": {
                "description": "Filter Built-in Administrator Token",
                "default": 0,
                "type": winreg.REG_DWORD,
            },
            "EnableInstallerDetection": {
                "description": "Installer Detection",
                "default": 1,
                "type": winreg.REG_DWORD,
            },
            "ValidateAdminCodeSignatures": {
                "description": "Validate Admin Code Signatures",
                "default": 0,
                "type": winreg.REG_DWORD,
            },
            "EnableSecureUIAPaths": {
                "description": "Secure UIAccess Applications",
                "default": 1,
                "type": winreg.REG_DWORD,
            },
        }

        # ConsentPromptBehaviorAdmin value meanings
        admin_prompt_behaviors = {
            0: "Elevate without prompting (auto-approve)",
            1: "Prompt for credentials on secure desktop",
            2: "Prompt for consent on secure desktop",
            3: "Prompt for credentials",
            4: "Prompt for consent",
            5: "Prompt for consent for non-Windows binaries (default)",
        }

        # ConsentPromptBehaviorUser value meanings
        user_prompt_behaviors = {
            0: "Automatically deny elevation requests",
            1: "Prompt for credentials on secure desktop",
            3: "Prompt for credentials (default)",
        }

        # Read all registry values
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_READ)
        except OSError as e:
            return {
                "category": category,
                "status": "error",
                "data": {"registry_error": str(e)},
                "findings": [{
                    "severity": "info",
                    "title": "Cannot Access UAC Registry Key",
                    "description": f"Failed to open registry key HKLM\\{reg_path}: {str(e)}"
                }]
            }

        registry_values = {}
        for value_name, value_info in uac_values.items():
            try:
                value, reg_type = winreg.QueryValueEx(key, value_name)
                registry_values[value_name] = {
                    "value": value,
                    "description": value_info["description"],
                    "default": value_info["default"],
                    "is_default": (value == value_info["default"]),
                }
            except FileNotFoundError:
                # Value doesn't exist — use default
                registry_values[value_name] = {
                    "value": value_info["default"],
                    "description": value_info["description"],
                    "default": value_info["default"],
                    "is_default": True,
                    "not_present": True,
                }
            except OSError as e:
                registry_values[value_name] = {
                    "value": None,
                    "description": value_info["description"],
                    "default": value_info["default"],
                    "error": str(e),
                }

        try:
            winreg.CloseKey(key)
        except Exception:
            pass

        data["registry_values"] = registry_values

        # Add human-readable interpretations
        admin_behavior = registry_values.get("ConsentPromptBehaviorAdmin", {}).get("value")
        if admin_behavior is not None:
            data["admin_prompt_behavior_text"] = admin_prompt_behaviors.get(
                admin_behavior, f"Unknown ({admin_behavior})"
            )

        user_behavior = registry_values.get("ConsentPromptBehaviorUser", {}).get("value")
        if user_behavior is not None:
            data["user_prompt_behavior_text"] = user_prompt_behaviors.get(
                user_behavior, f"Unknown ({user_behavior})"
            )

        # Compute overall UAC level (similar to Windows Security slider)
        enable_lua = registry_values.get("EnableLUA", {}).get("value", 1)
        consent_admin = registry_values.get("ConsentPromptBehaviorAdmin", {}).get("value", 5)
        secure_desktop = registry_values.get("PromptOnSecureDesktop", {}).get("value", 1)

        if enable_lua == 0:
            data["uac_level"] = "Disabled (Never notify)"
        elif consent_admin == 0:
            data["uac_level"] = "Never notify (auto-elevate)"
        elif consent_admin == 5 and secure_desktop == 0:
            data["uac_level"] = "Notify without secure desktop"
        elif consent_admin == 5 and secure_desktop == 1:
            data["uac_level"] = "Notify for non-Windows programs (default)"
        elif consent_admin == 2 and secure_desktop == 1:
            data["uac_level"] = "Always notify (highest)"
        else:
            data["uac_level"] = f"Custom (Admin={consent_admin}, SecureDesktop={secure_desktop})"

        # ---- Generate Findings ----

        # CRITICAL: UAC disabled entirely
        if enable_lua == 0:
            findings.append({
                "severity": "critical",
                "title": "UAC Is Completely Disabled",
                "description": (
                    "User Account Control (EnableLUA) is disabled (value=0). All programs run "
                    "with full administrative privileges without any elevation prompt. This removes "
                    "a fundamental security boundary and allows any malware to gain admin access instantly."
                ),
                "remediation": (
                    "Enable UAC immediately:\n"
                    "1. Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA = 1\n"
                    "2. Or via Group Policy: Computer Configuration > Windows Settings > Security Settings > "
                    "Local Policies > Security Options > 'User Account Control: Run all administrators in "
                    "Admin Approval Mode' = Enabled\n"
                    "3. A reboot is required for this change to take effect."
                )
            })
            status = "fail"

        # HIGH: Admin auto-approve (no prompt)
        if consent_admin == 0 and enable_lua != 0:
            findings.append({
                "severity": "high",
                "title": "Admin Elevation Without Prompting",
                "description": (
                    "ConsentPromptBehaviorAdmin is set to 0 (elevate without prompting). "
                    "Administrative users will never see a UAC prompt, allowing any program "
                    "to silently elevate to admin privileges."
                ),
                "remediation": (
                    "Set ConsentPromptBehaviorAdmin to 5 (default) or higher:\n"
                    "Registry: HKLM\\...\\Policies\\System\\ConsentPromptBehaviorAdmin = 5\n"
                    "Group Policy: 'User Account Control: Behavior of the elevation prompt for administrators "
                    "in Admin Approval Mode' = 'Prompt for consent for non-Windows binaries'"
                )
            })
            if status != "fail":
                status = "fail"

        # MEDIUM: Secure desktop disabled
        if secure_desktop == 0 and enable_lua != 0:
            findings.append({
                "severity": "medium",
                "title": "Secure Desktop Disabled for UAC Prompts",
                "description": (
                    "PromptOnSecureDesktop is set to 0. UAC elevation prompts appear on the "
                    "normal user desktop instead of the secure desktop. This makes it possible "
                    "for malware to programmatically interact with and auto-approve UAC prompts."
                ),
                "remediation": (
                    "Enable secure desktop:\n"
                    "Registry: HKLM\\...\\Policies\\System\\PromptOnSecureDesktop = 1\n"
                    "Group Policy: 'User Account Control: Switch to the secure desktop when prompting "
                    "for elevation' = Enabled"
                )
            })
            if status not in ("fail",):
                status = "warn"

        # INFO: Virtualization disabled
        enable_virt = registry_values.get("EnableVirtualization", {}).get("value", 1)
        if enable_virt == 0:
            findings.append({
                "severity": "low",
                "title": "File/Registry Virtualization Disabled",
                "description": (
                    "EnableVirtualization is set to 0. UAC file and registry virtualization is disabled. "
                    "This feature redirects writes to protected areas for legacy applications."
                ),
                "remediation": (
                    "Consider enabling virtualization for legacy application compatibility:\n"
                    "Registry: HKLM\\...\\Policies\\System\\EnableVirtualization = 1"
                )
            })

        # INFO: Built-in admin not filtered
        filter_admin = registry_values.get("FilterAdministratorToken", {}).get("value", 0)
        if filter_admin == 0:
            findings.append({
                "severity": "low",
                "title": "Built-in Administrator Token Not Filtered",
                "description": (
                    "FilterAdministratorToken is 0 (default). The built-in Administrator account "
                    "runs with a full administrator token and is not subject to UAC prompts. "
                    "If the built-in Administrator is enabled, this is a security concern."
                ),
                "remediation": (
                    "If the built-in Administrator account is active, consider setting "
                    "FilterAdministratorToken = 1 to enable Admin Approval Mode for this account."
                )
            })

        # HIGH: Standard user auto-deny might indicate restrictive but also unusual config
        if user_behavior == 0:
            findings.append({
                "severity": "info",
                "title": "Standard User Elevation Auto-Denied",
                "description": (
                    "ConsentPromptBehaviorUser is set to 0. Standard users are automatically denied "
                    "any elevation requests. This is a restrictive but secure configuration."
                )
            })

        # Code signature validation
        validate_sigs = registry_values.get("ValidateAdminCodeSignatures", {}).get("value", 0)
        if validate_sigs == 1:
            findings.append({
                "severity": "info",
                "title": "Admin Code Signature Validation Enabled",
                "description": (
                    "ValidateAdminCodeSignatures is enabled. Only signed and validated executables "
                    "can be elevated. This is a hardened configuration."
                )
            })

    except ImportError:
        return {
            "category": category,
            "status": "error",
            "data": {},
            "findings": [{
                "severity": "info",
                "title": "winreg Module Not Available",
                "description": "The winreg module is not available on this platform."
            }]
        }
    except Exception as e:
        return {
            "category": category,
            "status": "error",
            "data": data,
            "findings": [{
                "severity": "info",
                "title": "UAC Policy Scan Error",
                "description": f"An unexpected error occurred while scanning UAC policies: {str(e)}"
            }]
        }

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
