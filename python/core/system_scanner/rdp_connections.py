"""
Saved RDP Connections Scanner
=============================
Enumerates saved Remote Desktop connection entries from the current user's
registry and the Default.rdp file.

Why it matters:
    Saved RDP endpoints reveal the lateral-movement landscape — which servers
    the current user has connected to in the past. An attacker who compromises
    this account immediately gains a target list. Stale credentials or saved
    passwords in these entries compound the risk.

Registry paths inspected:
    - HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers\\<hostname>
    - HKCU\\Software\\Microsoft\\Terminal Server Client\\Default\\MRU*
"""

import os
import platform
import traceback


def _enumerate_saved_servers() -> list:
    """Read per-server RDP entries from HKCU."""
    import winreg

    servers = []
    base_path = r"Software\Microsoft\Terminal Server Client\Servers"

    try:
        base_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_path)
    except (FileNotFoundError, PermissionError):
        return servers

    index = 0
    while True:
        try:
            hostname = winreg.EnumKey(base_key, index)
            server_info = {"hostname": hostname, "username_hint": None}

            try:
                srv_key = winreg.OpenKey(base_key, hostname)
                try:
                    val, _ = winreg.QueryValueEx(srv_key, "UsernameHint")
                    server_info["username_hint"] = val
                except (FileNotFoundError, OSError):
                    pass
                # Grab any additional interesting values
                try:
                    val, _ = winreg.QueryValueEx(srv_key, "CertHash")
                    server_info["cert_hash"] = val.hex() if isinstance(val, bytes) else str(val)
                except (FileNotFoundError, OSError):
                    pass
                winreg.CloseKey(srv_key)
            except (FileNotFoundError, PermissionError, OSError):
                pass

            servers.append(server_info)
            index += 1
        except OSError:
            break

    winreg.CloseKey(base_key)
    return servers


def _read_mru_entries() -> list:
    """Read MRU (Most Recently Used) RDP connection list."""
    import winreg

    mru = []
    key_path = r"Software\Microsoft\Terminal Server Client\Default"

    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
    except (FileNotFoundError, PermissionError):
        return mru

    index = 0
    while True:
        try:
            name, value, _ = winreg.EnumValue(key, index)
            if name.upper().startswith("MRU"):
                mru.append({"name": name, "value": value})
            index += 1
        except OSError:
            break

    winreg.CloseKey(key)
    return mru


def _read_default_rdp_file() -> dict:
    """Parse the Default.rdp file in the user's Documents folder."""
    docs = os.path.join(os.environ.get("USERPROFILE", ""), "Documents", "Default.rdp")
    result = {"path": docs, "exists": False, "settings": {}}

    if not os.path.isfile(docs):
        return result

    result["exists"] = True
    try:
        with open(docs, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith(";"):
                    continue
                parts = line.split(":", 2)
                if len(parts) == 3:
                    key, dtype, value = parts
                    result["settings"][key.strip()] = value.strip()
                elif len(parts) == 2:
                    result["settings"][parts[0].strip()] = parts[1].strip()
    except (IOError, OSError) as exc:
        result["error"] = str(exc)

    return result


def scan() -> dict:
    """
    Scan saved RDP connections and recently-used servers.

    Returns:
        dict with keys 'category', 'status', 'data', 'findings'.
    """
    if platform.system() != "Windows":
        return {
            "category": "Saved RDP Connections",
            "status": "error",
            "data": {},
            "findings": [
                {
                    "severity": "info",
                    "title": "Not a Windows system",
                    "description": "RDP connection scanning is only applicable on Windows.",
                }
            ],
        }

    try:
        servers = _enumerate_saved_servers()
        mru = _read_mru_entries()
        default_rdp = _read_default_rdp_file()

        data = {
            "saved_servers": servers,
            "mru_entries": mru,
            "default_rdp": default_rdp,
            "total_saved_servers": len(servers),
            "total_mru_entries": len(mru),
        }

        findings = []

        # --- Informational listing of saved servers ----------------------------
        if servers:
            hostnames = [s["hostname"] for s in servers]
            findings.append(
                {
                    "severity": "info",
                    "title": f"{len(servers)} saved RDP server(s) found",
                    "description": (
                        "The following RDP endpoints are saved in the current user's "
                        f"registry: {', '.join(hostnames)}. These may be lateral "
                        "movement targets if this account is compromised."
                    ),
                }
            )

            # Flag servers with saved username hints
            with_creds = [s for s in servers if s.get("username_hint")]
            if with_creds:
                user_list = ", ".join(
                    f"{s['hostname']} ({s['username_hint']})" for s in with_creds
                )
                findings.append(
                    {
                        "severity": "low",
                        "title": "Saved RDP entries contain username hints",
                        "description": (
                            "The following saved servers have stored username hints, "
                            f"reducing the effort for an attacker: {user_list}."
                        ),
                        "remediation": (
                            "Consider clearing saved RDP credentials via "
                            "`cmdkey /delete:TERMSRV/<hostname>` or Group Policy."
                        ),
                    }
                )

        # --- MRU entries -------------------------------------------------------
        if mru:
            mru_values = [m["value"] for m in mru if isinstance(m.get("value"), str)]
            findings.append(
                {
                    "severity": "info",
                    "title": f"{len(mru)} recent RDP connection(s) in MRU list",
                    "description": (
                        f"Recent connections: {', '.join(mru_values) if mru_values else 'N/A'}"
                    ),
                }
            )

        # --- Default.rdp file --------------------------------------------------
        if default_rdp.get("exists"):
            settings = default_rdp.get("settings", {})
            findings.append(
                {
                    "severity": "info",
                    "title": "Default.rdp file exists",
                    "description": (
                        f"Found Default.rdp at {default_rdp['path']} with "
                        f"{len(settings)} setting(s)."
                    ),
                }
            )
            # Warn if password is saved in file
            if "password 51" in {k.lower() for k in settings}:
                findings.append(
                    {
                        "severity": "medium",
                        "title": "Default.rdp contains a saved password blob",
                        "description": (
                            "A password entry exists in the Default.rdp file. "
                            "While it is encrypted with DPAPI, it can be decrypted "
                            "by any process running as the current user."
                        ),
                        "remediation": (
                            "Remove the saved password from Default.rdp and use a "
                            "credential manager or just-in-time access instead."
                        ),
                    }
                )

        # --- No data at all ----------------------------------------------------
        if not servers and not mru and not default_rdp.get("exists"):
            findings.append(
                {
                    "severity": "info",
                    "title": "No saved RDP connections found",
                    "description": "No saved servers, MRU entries, or Default.rdp file detected.",
                }
            )

        # Determine status
        severities = [f["severity"] for f in findings]
        if "high" in severities or "critical" in severities:
            status = "fail"
        elif "medium" in severities:
            status = "warn"
        else:
            status = "info"

        return {
            "category": "Saved RDP Connections",
            "status": status,
            "data": data,
            "findings": findings,
        }

    except Exception as exc:
        return {
            "category": "Saved RDP Connections",
            "status": "error",
            "data": {"error": str(exc), "traceback": traceback.format_exc()},
            "findings": [
                {
                    "severity": "info",
                    "title": "Error scanning saved RDP connections",
                    "description": f"An unexpected error occurred: {exc}",
                }
            ],
        }
