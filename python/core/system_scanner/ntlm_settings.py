"""
NTLM Authentication Settings Scanner
======================================
Reads LAN Manager / NTLM authentication configuration from the registry.

Why it matters:
    Weak NTLM settings allow downgrade attacks to NTLMv1 or even LM, which
    are trivially crackable. Pass-the-hash and NTLM relay attacks are among
    the most common Active Directory compromise techniques. Proper hardening
    requires NTLMv2-only responses and maximum session security.

Registry paths inspected:
    - HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa
        * LmCompatibilityLevel
        * NtlmMinClientSec
        * NtlmMinServerSec
        * RestrictSendingNTLMTraffic
        * RestrictReceivingNTLMTraffic
        * NoLMHash
    - HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters
        * RequireSignOrSeal
        * RequireStrongKey
        * SealSecureChannel
        * SignSecureChannel
"""

import platform
import traceback

# LmCompatibilityLevel descriptions (0-5)
_LM_COMPAT_LEVELS = {
    0: "Send LM & NTLM responses (least secure)",
    1: "Send LM & NTLM — use NTLMv2 session security if negotiated",
    2: "Send NTLM response only",
    3: "Send NTLMv2 response only",
    4: "Send NTLMv2 response only — refuse LM",
    5: "Send NTLMv2 response only — refuse LM & NTLM (most secure)",
}

# Minimum session security bit flags
_SESSION_SEC_FLAGS = {
    0x00000001: "NTLMv2 session security",
    0x00000002: "Negotiate 56-bit encryption",
    0x00000004: "Negotiate 128-bit encryption",
    0x00000008: "NTLMv2 session integrity",
    0x00000010: "NTLMv2 session confidentiality",
    0x00080000: "Require NTLMv2 session security",
    0x20000000: "Require 128-bit encryption",
}


def _read_lsa_settings() -> dict:
    """Read NTLM-related values from the LSA registry key."""
    import winreg

    lsa = {}
    key_path = r"SYSTEM\CurrentControlSet\Control\Lsa"

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        for name in ("LmCompatibilityLevel", "NtlmMinClientSec",
                      "NtlmMinServerSec", "NoLMHash",
                      "RestrictSendingNTLMTraffic",
                      "RestrictReceivingNTLMTraffic",
                      "UseMachineId", "AuditReceivingNTLMTraffic"):
            try:
                value, _ = winreg.QueryValueEx(key, name)
                lsa[name] = value
            except FileNotFoundError:
                lsa[name] = None
        winreg.CloseKey(key)
    except (FileNotFoundError, PermissionError, OSError) as exc:
        lsa["_error"] = str(exc)
    return lsa


def _read_lsa_msr_settings() -> dict:
    """Read NTLM restriction settings from Lsa\\MSV1_0."""
    import winreg

    msv = {}
    key_path = r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        for name in ("RestrictSendingNTLMTraffic", "RestrictReceivingNTLMTraffic",
                      "AuditReceivingNTLMTraffic", "NTLMMinClientSec",
                      "NTLMMinServerSec", "AllowNullSessionFallback"):
            try:
                value, _ = winreg.QueryValueEx(key, name)
                msv[name] = value
            except FileNotFoundError:
                msv[name] = None
        winreg.CloseKey(key)
    except (FileNotFoundError, PermissionError, OSError) as exc:
        msv["_error"] = str(exc)
    return msv


def _read_netlogon_settings() -> dict:
    """Read secure-channel settings from the Netlogon\\Parameters key."""
    import winreg

    netlogon = {}
    key_path = r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        for name in ("RequireSignOrSeal", "RequireStrongKey",
                      "SealSecureChannel", "SignSecureChannel",
                      "DisablePasswordChange", "MaximumPasswordAge",
                      "RefusePasswordChange"):
            try:
                value, _ = winreg.QueryValueEx(key, name)
                netlogon[name] = value
            except FileNotFoundError:
                netlogon[name] = None
        winreg.CloseKey(key)
    except (FileNotFoundError, PermissionError, OSError) as exc:
        netlogon["_error"] = str(exc)
    return netlogon


def _decode_session_security(value: int) -> list:
    """Decode a session security bitmask into flag descriptions."""
    if value is None:
        return []
    flags = []
    for bit, desc in _SESSION_SEC_FLAGS.items():
        if value & bit:
            flags.append(desc)
    return flags


def scan() -> dict:
    """
    Scan NTLM / LAN Manager authentication settings.

    Returns:
        dict with keys 'category', 'status', 'data', 'findings'.
    """
    if platform.system() != "Windows":
        return {
            "category": "NTLM Settings",
            "status": "error",
            "data": {},
            "findings": [
                {
                    "severity": "info",
                    "title": "Not a Windows system",
                    "description": "NTLM settings scanning is only applicable on Windows.",
                }
            ],
        }

    try:
        lsa = _read_lsa_settings()
        msv = _read_lsa_msr_settings()
        netlogon = _read_netlogon_settings()

        data = {
            "lsa": lsa,
            "msv1_0": msv,
            "netlogon": netlogon,
        }

        findings = []

        # --- Check 1: LmCompatibilityLevel ------------------------------------
        lm_level = lsa.get("LmCompatibilityLevel")
        if lm_level is not None:
            desc = _LM_COMPAT_LEVELS.get(lm_level, f"Unknown ({lm_level})")
            data["lm_compatibility_description"] = desc

            if lm_level < 3:
                findings.append(
                    {
                        "severity": "critical",
                        "title": f"LmCompatibilityLevel is {lm_level} — allows weak NTLM/LM",
                        "description": (
                            f"LmCompatibilityLevel = {lm_level}: {desc}. "
                            "Values below 3 allow NTLMv1 or LM responses which are "
                            "trivially crackable. This enables pass-the-hash and "
                            "downgrade attacks."
                        ),
                        "remediation": (
                            "Set LmCompatibilityLevel to 5 (Send NTLMv2 only, refuse "
                            "LM & NTLM) via Group Policy → Computer Configuration → "
                            "Windows Settings → Security Settings → Local Policies → "
                            "Security Options → 'Network security: LAN Manager "
                            "authentication level'."
                        ),
                    }
                )
            elif lm_level < 5:
                findings.append(
                    {
                        "severity": "medium",
                        "title": f"LmCompatibilityLevel is {lm_level} — could be hardened",
                        "description": (
                            f"LmCompatibilityLevel = {lm_level}: {desc}. "
                            "While NTLMv1/LM responses are not sent, the server may "
                            "still accept them. Level 5 provides maximum protection."
                        ),
                        "remediation": (
                            "Consider raising LmCompatibilityLevel to 5 after testing "
                            "compatibility with legacy systems."
                        ),
                    }
                )
            else:
                findings.append(
                    {
                        "severity": "info",
                        "title": "LmCompatibilityLevel is 5 (most secure)",
                        "description": desc,
                    }
                )
        else:
            # Default on modern Windows is typically 3, but not having it
            # explicitly set is worth noting
            findings.append(
                {
                    "severity": "low",
                    "title": "LmCompatibilityLevel not explicitly configured",
                    "description": (
                        "The LmCompatibilityLevel registry value is not set. "
                        "Modern Windows defaults vary by version. Explicitly set "
                        "it to 5 to ensure maximum NTLM hardening."
                    ),
                    "remediation": (
                        "Set LmCompatibilityLevel to 5 via Group Policy."
                    ),
                }
            )

        # --- Check 2: NoLMHash -------------------------------------------------
        no_lm = lsa.get("NoLMHash")
        if no_lm is not None and no_lm != 1:
            findings.append(
                {
                    "severity": "high",
                    "title": "LM password hashes are being stored",
                    "description": (
                        f"NoLMHash = {no_lm}. LM hashes are extremely weak and "
                        "can be cracked in minutes. They should never be stored."
                    ),
                    "remediation": (
                        "Set NoLMHash to 1: Group Policy → 'Network security: "
                        "Do not store LAN Manager hash value on next password change'."
                    ),
                }
            )

        # --- Check 3: Minimum session security ---------------------------------
        for label, key_name in [("Client", "NtlmMinClientSec"),
                                 ("Server", "NtlmMinServerSec")]:
            val = lsa.get(key_name)
            if val is not None:
                flags = _decode_session_security(val)
                data[f"{key_name}_flags"] = flags

                # Check if 128-bit encryption is required
                if not (val & 0x20000000):
                    findings.append(
                        {
                            "severity": "medium",
                            "title": f"NTLM {label} does not require 128-bit encryption",
                            "description": (
                                f"{key_name} = 0x{val:08X}. 128-bit encryption is not "
                                "enforced for NTLM sessions, allowing weaker encryption."
                            ),
                            "remediation": (
                                f"Set {key_name} to at minimum 0x20080000 to require "
                                "NTLMv2 session security and 128-bit encryption."
                            ),
                        }
                    )

        # --- Check 4: NTLM traffic restrictions --------------------------------
        restrict_send = msv.get("RestrictSendingNTLMTraffic")
        if restrict_send is not None:
            if restrict_send == 0:
                findings.append(
                    {
                        "severity": "medium",
                        "title": "Outbound NTLM traffic is unrestricted",
                        "description": (
                            "RestrictSendingNTLMTraffic = 0. No restrictions on "
                            "sending NTLM credentials to remote servers."
                        ),
                        "remediation": (
                            "Set RestrictSendingNTLMTraffic to 1 (Audit) or 2 (Deny all) "
                            "to limit NTLM relay attack surface."
                        ),
                    }
                )
            elif restrict_send == 2:
                findings.append(
                    {
                        "severity": "info",
                        "title": "Outbound NTLM traffic is denied",
                        "description": "RestrictSendingNTLMTraffic = 2 — all outbound NTLM is blocked.",
                    }
                )

        # --- Check 5: Netlogon secure channel ----------------------------------
        sign_or_seal = netlogon.get("RequireSignOrSeal")
        if sign_or_seal is not None and sign_or_seal != 1:
            findings.append(
                {
                    "severity": "high",
                    "title": "Netlogon secure channel signing/sealing not required",
                    "description": (
                        f"RequireSignOrSeal = {sign_or_seal}. Unsigned secure channel "
                        "traffic can be tampered with (related to Zerologon mitigations)."
                    ),
                    "remediation": (
                        "Set RequireSignOrSeal to 1 to enforce signing and sealing "
                        "on the Netlogon secure channel."
                    ),
                }
            )

        strong_key = netlogon.get("RequireStrongKey")
        if strong_key is not None and strong_key != 1:
            findings.append(
                {
                    "severity": "high",
                    "title": "Netlogon secure channel does not require strong keys",
                    "description": (
                        f"RequireStrongKey = {strong_key}. Weak session keys on the "
                        "secure channel increase the risk of Zerologon-style attacks."
                    ),
                    "remediation": "Set RequireStrongKey to 1.",
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

        if not findings:
            findings.append(
                {
                    "severity": "info",
                    "title": "NTLM settings appear properly configured",
                    "description": "No NTLM hardening issues detected.",
                }
            )

        return {
            "category": "NTLM Settings",
            "status": status,
            "data": data,
            "findings": findings,
        }

    except Exception as exc:
        return {
            "category": "NTLM Settings",
            "status": "error",
            "data": {"error": str(exc), "traceback": traceback.format_exc()},
            "findings": [
                {
                    "severity": "info",
                    "title": "Error scanning NTLM settings",
                    "description": f"An unexpected error occurred: {exc}",
                }
            ],
        }
