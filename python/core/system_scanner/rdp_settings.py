"""
Remote Desktop Settings Scanner
================================
Reads RDP server and client configuration from the registry to assess the
attack surface and security posture of Remote Desktop services.

Why it matters:
    RDP is one of the most commonly exploited remote-access vectors. Weak
    configuration — such as disabled Network Level Authentication (NLA),
    non-standard ports (security-through-obscurity vs. actual protection),
    or RDP being enabled when unnecessary — significantly increases risk.

Registry paths inspected:
    - HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server
    - HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp
"""

import platform
import traceback


def _read_terminal_server_settings() -> dict:
    """Read top-level Terminal Server registry values."""
    import winreg

    ts = {}
    key_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        for name in ("fDenyTSConnections", "fSingleSessionPerUser",
                      "TSEnabled", "TSUserEnabled", "AllowTSConnections"):
            try:
                value, _ = winreg.QueryValueEx(key, name)
                ts[name] = value
            except FileNotFoundError:
                ts[name] = None
        winreg.CloseKey(key)
    except (FileNotFoundError, PermissionError, OSError) as exc:
        ts["_error"] = str(exc)
    return ts


def _read_rdp_tcp_settings() -> dict:
    """Read RDP-Tcp WinStation configuration."""
    import winreg

    rdp_tcp = {}
    key_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        for name in ("PortNumber", "SecurityLayer", "UserAuthentication",
                      "MinEncryptionLevel", "fInheritMaxIdleTime",
                      "MaxIdleTime", "MaxConnectionTime",
                      "MaxDisconnectionTime", "fInheritAutoReconnect",
                      "Shadow", "fEnableWinStation"):
            try:
                value, _ = winreg.QueryValueEx(key, name)
                rdp_tcp[name] = value
            except FileNotFoundError:
                rdp_tcp[name] = None
        winreg.CloseKey(key)
    except (FileNotFoundError, PermissionError, OSError) as exc:
        rdp_tcp["_error"] = str(exc)
    return rdp_tcp


# Human-readable maps
_SECURITY_LAYER_MAP = {
    0: "RDP Security Layer (least secure)",
    1: "Negotiate",
    2: "TLS (SSL)",
}

_ENCRYPTION_LEVEL_MAP = {
    1: "Low",
    2: "Client Compatible",
    3: "High",
    4: "FIPS Compliant",
}


def scan() -> dict:
    """
    Scan Remote Desktop (RDP) server/client settings.

    Returns:
        dict with keys 'category', 'status', 'data', 'findings'.
    """
    if platform.system() != "Windows":
        return {
            "category": "RDP Settings",
            "status": "error",
            "data": {},
            "findings": [
                {
                    "severity": "info",
                    "title": "Not a Windows system",
                    "description": "RDP settings scanning is only applicable on Windows.",
                }
            ],
        }

    try:
        ts = _read_terminal_server_settings()
        rdp_tcp = _read_rdp_tcp_settings()

        data = {
            "terminal_server": ts,
            "rdp_tcp": rdp_tcp,
        }

        findings = []

        # --- Check 1: Is RDP enabled? ------------------------------------------
        f_deny = ts.get("fDenyTSConnections")
        if f_deny is not None:
            rdp_enabled = f_deny == 0
            data["rdp_enabled"] = rdp_enabled

            if rdp_enabled:
                findings.append(
                    {
                        "severity": "medium",
                        "title": "Remote Desktop (RDP) is enabled",
                        "description": (
                            "fDenyTSConnections = 0 — RDP connections are accepted. "
                            "RDP is a common attack vector for brute-force, credential "
                            "stuffing, and BlueKeep-class exploits."
                        ),
                        "remediation": (
                            "Disable RDP if not required: Set fDenyTSConnections to 1. "
                            "If RDP is needed, restrict access via firewall rules, use "
                            "an RDP gateway, enable NLA, and enforce strong passwords/MFA."
                        ),
                    }
                )
            else:
                findings.append(
                    {
                        "severity": "info",
                        "title": "Remote Desktop (RDP) is disabled",
                        "description": "fDenyTSConnections = 1 — RDP connections are denied.",
                    }
                )
        else:
            data["rdp_enabled"] = None
            findings.append(
                {
                    "severity": "info",
                    "title": "Could not determine RDP enabled state",
                    "description": "fDenyTSConnections registry value not found.",
                }
            )

        # --- Check 2: Network Level Authentication (NLA) -----------------------
        nla = rdp_tcp.get("UserAuthentication")
        if nla is not None:
            data["nla_enabled"] = nla == 1
            if nla != 1:
                findings.append(
                    {
                        "severity": "high",
                        "title": "Network Level Authentication (NLA) is disabled",
                        "description": (
                            f"UserAuthentication = {nla}. Without NLA, the RDP login "
                            "screen is presented before authentication, exposing the "
                            "system to pre-auth exploits (e.g., BlueKeep CVE-2019-0708) "
                            "and resource exhaustion attacks."
                        ),
                        "remediation": (
                            "Enable NLA: Set UserAuthentication to 1 under "
                            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\"
                            "WinStations\\RDP-Tcp, or via Group Policy → Remote Desktop "
                            "Session Host → Security → Require NLA."
                        ),
                    }
                )
            else:
                findings.append(
                    {
                        "severity": "info",
                        "title": "Network Level Authentication (NLA) is enabled",
                        "description": "UserAuthentication = 1 — NLA is enforced for RDP.",
                    }
                )

        # --- Check 3: Security Layer -------------------------------------------
        sec_layer = rdp_tcp.get("SecurityLayer")
        if sec_layer is not None:
            layer_desc = _SECURITY_LAYER_MAP.get(sec_layer, f"Unknown ({sec_layer})")
            data["security_layer"] = layer_desc

            if sec_layer == 0:
                findings.append(
                    {
                        "severity": "high",
                        "title": "RDP using native RDP Security Layer (weakest)",
                        "description": (
                            f"SecurityLayer = {sec_layer} ({layer_desc}). The native "
                            "RDP security layer does not use TLS and is vulnerable to "
                            "man-in-the-middle attacks."
                        ),
                        "remediation": (
                            "Set SecurityLayer to 2 (TLS/SSL) for maximum protection, "
                            "or 1 (Negotiate) at minimum."
                        ),
                    }
                )
            elif sec_layer == 1:
                findings.append(
                    {
                        "severity": "low",
                        "title": "RDP security layer set to Negotiate",
                        "description": (
                            f"SecurityLayer = {sec_layer} ({layer_desc}). The server "
                            "negotiates the highest available layer, which may fall back "
                            "to native RDP security if the client doesn't support TLS."
                        ),
                        "remediation": (
                            "Consider setting SecurityLayer to 2 (TLS/SSL) to enforce "
                            "TLS for all connections."
                        ),
                    }
                )

        # --- Check 4: Port number -----------------------------------------------
        port = rdp_tcp.get("PortNumber")
        if port is not None:
            data["rdp_port"] = port
            if port != 3389:
                findings.append(
                    {
                        "severity": "info",
                        "title": f"RDP is configured on non-standard port {port}",
                        "description": (
                            f"PortNumber = {port} (default is 3389). While this adds "
                            "a minor layer of obscurity, it does not constitute a "
                            "security control. Automated scanners will discover it."
                        ),
                    }
                )
            else:
                data["rdp_port_standard"] = True

        # --- Check 5: Encryption level -----------------------------------------
        enc_level = rdp_tcp.get("MinEncryptionLevel")
        if enc_level is not None:
            enc_desc = _ENCRYPTION_LEVEL_MAP.get(enc_level, f"Unknown ({enc_level})")
            data["encryption_level"] = enc_desc

            if enc_level == 1:
                findings.append(
                    {
                        "severity": "medium",
                        "title": "RDP encryption level set to Low",
                        "description": (
                            f"MinEncryptionLevel = {enc_level} ({enc_desc}). Only "
                            "data sent from client to server is encrypted; server-to-"
                            "client traffic may be unprotected."
                        ),
                        "remediation": (
                            "Set MinEncryptionLevel to 3 (High) or 4 (FIPS Compliant)."
                        ),
                    }
                )

        # --- Check 6: Single-session policy ------------------------------------
        single = ts.get("fSingleSessionPerUser")
        if single is not None:
            data["single_session_per_user"] = single == 1
            if single != 1:
                findings.append(
                    {
                        "severity": "low",
                        "title": "Multiple simultaneous RDP sessions per user allowed",
                        "description": (
                            "fSingleSessionPerUser = 0. Multiple concurrent sessions "
                            "per user account are allowed, which can make it harder "
                            "to detect credential sharing or compromised accounts."
                        ),
                        "remediation": (
                            "Set fSingleSessionPerUser to 1 to limit each user to "
                            "a single RDP session."
                        ),
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

        return {
            "category": "RDP Settings",
            "status": status,
            "data": data,
            "findings": findings,
        }

    except Exception as exc:
        return {
            "category": "RDP Settings",
            "status": "error",
            "data": {"error": str(exc), "traceback": traceback.format_exc()},
            "findings": [
                {
                    "severity": "info",
                    "title": "Error scanning RDP settings",
                    "description": f"An unexpected error occurred: {exc}",
                }
            ],
        }
