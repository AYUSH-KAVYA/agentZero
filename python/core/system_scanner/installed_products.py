"""
Installed Products Scanner
==========================
Enumerates installed software from the Windows Registry Uninstall keys.

Security Relevance:
- Outdated software with known vulnerabilities is a primary attack vector.
- Software not managed by IT may lack security patches (shadow IT).
- Certain installed tools (e.g., remote access, password dumpers) may indicate
  compromise or policy violations.
- Understanding installed software helps assess the attack surface.

Data Sources:
- Registry: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall
- Registry: HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall
- Registry: HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall
"""

import platform
import subprocess
import json
import re


# Known potentially risky software patterns (for flagging)
_RISKY_SOFTWARE_PATTERNS = [
    # Remote access tools
    (re.compile(r"TeamViewer", re.IGNORECASE), "remote_access", "medium"),
    (re.compile(r"AnyDesk", re.IGNORECASE), "remote_access", "medium"),
    (re.compile(r"LogMeIn", re.IGNORECASE), "remote_access", "low"),
    (re.compile(r"VNC|RealVNC|TightVNC|UltraVNC", re.IGNORECASE), "remote_access", "medium"),
    (re.compile(r"Ammyy", re.IGNORECASE), "remote_access", "high"),
    (re.compile(r"ScreenConnect|ConnectWise Control", re.IGNORECASE), "remote_access", "medium"),
    # Hacking / pentest tools (may indicate compromise if unauthorized)
    (re.compile(r"Mimikatz", re.IGNORECASE), "hacking_tool", "critical"),
    (re.compile(r"Cain.*Abel", re.IGNORECASE), "hacking_tool", "critical"),
    (re.compile(r"Nmap", re.IGNORECASE), "pentest_tool", "low"),
    (re.compile(r"Wireshark", re.IGNORECASE), "network_tool", "low"),
    (re.compile(r"Metasploit", re.IGNORECASE), "hacking_tool", "critical"),
    (re.compile(r"Cobalt\s*Strike", re.IGNORECASE), "hacking_tool", "critical"),
    # Torrent clients
    (re.compile(r"BitTorrent|uTorrent|qBittorrent|Vuze|Deluge", re.IGNORECASE), "torrent_client", "low"),
]

# Known vulnerable software patterns with version checks
_KNOWN_VULNERABLE = [
    {
        "pattern": re.compile(r"Adobe Flash Player", re.IGNORECASE),
        "severity": "critical",
        "reason": "Adobe Flash Player is end-of-life and has numerous unpatched CVEs.",
    },
    {
        "pattern": re.compile(r"Java\s+(?:\d|SE)", re.IGNORECASE),
        "max_major_version": 8,
        "severity": "high",
        "reason": "Legacy Java versions contain numerous known vulnerabilities.",
    },
    {
        "pattern": re.compile(r"Adobe Reader\s+(X|XI|9|10|11|2015)", re.IGNORECASE),
        "severity": "medium",
        "reason": "Older Adobe Reader versions have known security vulnerabilities.",
    },
    {
        "pattern": re.compile(r"Silverlight", re.IGNORECASE),
        "severity": "medium",
        "reason": "Microsoft Silverlight is end-of-life and no longer receives security updates.",
    },
    {
        "pattern": re.compile(r"Internet Explorer", re.IGNORECASE),
        "severity": "high",
        "reason": "Internet Explorer is end-of-life and should not be installed.",
    },
    {
        "pattern": re.compile(r"WinRAR", re.IGNORECASE),
        "severity": "medium",
        "reason": "WinRAR versions before 6.23 have known RCE vulnerabilities (CVE-2023-38831).",
    },
    {
        "pattern": re.compile(r"7-Zip", re.IGNORECASE),
        "severity": "low",
        "reason": "Ensure 7-Zip is updated; older versions had security vulnerabilities.",
    },
]


def _get_installed_products_registry() -> list:
    """Read installed products from the Windows Registry."""
    try:
        import winreg
    except ImportError:
        return []

    products = []
    reg_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    for hive, path in reg_paths:
        try:
            key = winreg.OpenKey(hive, path)
        except (FileNotFoundError, OSError):
            continue

        try:
            subkey_count = winreg.QueryInfoKey(key)[0]
            for i in range(subkey_count):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)

                    product = {"registry_key": subkey_name}

                    for value_name in ["DisplayName", "DisplayVersion", "Publisher",
                                       "InstallDate", "UninstallString", "InstallLocation",
                                       "URLInfoAbout", "Comments"]:
                        try:
                            val, _ = winreg.QueryValueEx(subkey, value_name)
                            product[value_name] = str(val) if val else ""
                        except (FileNotFoundError, OSError):
                            product[value_name] = ""

                    # Check for SystemComponent flag
                    try:
                        sys_comp, _ = winreg.QueryValueEx(subkey, "SystemComponent")
                        product["SystemComponent"] = bool(sys_comp)
                    except (FileNotFoundError, OSError):
                        product["SystemComponent"] = False

                    winreg.CloseKey(subkey)

                    # Skip entries without a display name
                    if not product.get("DisplayName"):
                        continue

                    # Skip Windows updates (KB entries)
                    display_name = product["DisplayName"]
                    if re.match(r"^(KB\d+|Update for|Security Update for|Hotfix for)", display_name, re.IGNORECASE):
                        continue

                    # Determine registry source
                    if hive == winreg.HKEY_CURRENT_USER:
                        product["scope"] = "user"
                    elif "WOW6432Node" in path:
                        product["scope"] = "machine_x86"
                    else:
                        product["scope"] = "machine_x64"

                    products.append(product)

                except (FileNotFoundError, OSError):
                    continue
        finally:
            winreg.CloseKey(key)

    # Deduplicate by DisplayName + DisplayVersion
    seen = set()
    unique_products = []
    for p in products:
        key = (p.get("DisplayName", "").lower(), p.get("DisplayVersion", "").lower())
        if key not in seen:
            seen.add(key)
            unique_products.append(p)

    return unique_products


def _check_risky_software(products: list) -> list:
    """Check installed products against known risky software patterns."""
    findings = []

    for product in products:
        display_name = product.get("DisplayName", "")
        if not display_name:
            continue

        # Check for risky software
        for pattern, category, severity in _RISKY_SOFTWARE_PATTERNS:
            if pattern.search(display_name):
                findings.append({
                    "severity": severity,
                    "title": f"Potentially risky software: {display_name}",
                    "description": (
                        f"'{display_name}' (version: {product.get('DisplayVersion', 'Unknown')}, "
                        f"publisher: {product.get('Publisher', 'Unknown')}) is installed. "
                        f"Category: {category.replace('_', ' ')}. This software may pose a "
                        f"security risk or violate organizational policy."
                    ),
                    "remediation": (
                        f"Verify that '{display_name}' is authorized for use on this system. "
                        f"If unauthorized, uninstall it immediately."
                    ),
                })
                break

        # Check for known vulnerable software
        for vuln in _KNOWN_VULNERABLE:
            if vuln["pattern"].search(display_name):
                findings.append({
                    "severity": vuln["severity"],
                    "title": f"Known vulnerable software: {display_name}",
                    "description": (
                        f"'{display_name}' (version: {product.get('DisplayVersion', 'Unknown')}) "
                        f"is installed. {vuln['reason']}"
                    ),
                    "remediation": (
                        f"Update or remove '{display_name}'. If the software is end-of-life, "
                        f"migrate to a supported alternative."
                    ),
                })
                break

    return findings


def scan() -> dict:
    """
    Enumerate installed products from the Windows Registry and flag
    potentially risky or vulnerable software.

    Returns:
        dict with keys: category, status, data, findings
    """
    if platform.system() != "Windows":
        return {
            "category": "Installed Products",
            "status": "error",
            "data": {},
            "findings": [{
                "severity": "info",
                "title": "Not a Windows system",
                "description": "This scanner only runs on Windows.",
            }],
        }

    try:
        products = _get_installed_products_registry()
        findings = _check_risky_software(products)

        # Add informational summary
        if not products:
            findings.append({
                "severity": "info",
                "title": "No installed products found",
                "description": (
                    "No software was found in the Windows Registry Uninstall keys. "
                    "This may indicate insufficient permissions or a minimal installation."
                ),
            })

        # Sort products by name
        products.sort(key=lambda p: p.get("DisplayName", "").lower())

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
            "category": "Installed Products",
            "status": status,
            "data": {
                "total_products": len(products),
                "products": products,
            },
            "findings": findings,
        }

    except Exception as e:
        return {
            "category": "Installed Products",
            "status": "error",
            "data": {"error": str(e)},
            "findings": [{
                "severity": "info",
                "title": "Scanner error",
                "description": f"An unexpected error occurred while scanning installed products: {e}",
            }],
        }
