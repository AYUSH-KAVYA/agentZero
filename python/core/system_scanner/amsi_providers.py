"""
AMSI (Antimalware Scan Interface) Providers Scanner
=====================================================
Enumerates all registered AMSI providers via the Windows Registry.

Why it matters:
    AMSI is a critical defence layer that allows antimalware products to inspect
    script content (PowerShell, VBScript, JScript, etc.) at runtime. If no AMSI
    provider is registered — or if an attacker has replaced the legitimate
    provider with a rogue DLL — malicious scripts can execute without inspection.
    This module detects missing, tampered, or non-standard AMSI registrations.

Registry paths inspected:
    - HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers   (list of provider CLSIDs)
    - HKCR\\CLSID\\{guid}\\InprocServer32           (DLL path for each provider)
"""

import platform
import traceback

# Well-known Windows Defender AMSI provider CLSID
_DEFENDER_AMSI_CLSID = "{2781761E-28E0-4109-99FE-B9D127C57AFE}"


def _read_amsi_providers_registry() -> dict:
    """Read AMSI provider CLSIDs and resolve each to its DLL path."""
    import winreg

    providers = []
    amsi_key_path = r"SOFTWARE\Microsoft\AMSI\Providers"

    try:
        amsi_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, amsi_key_path)
    except FileNotFoundError:
        return {"providers": [], "amsi_key_exists": False}
    except PermissionError:
        return {"providers": [], "amsi_key_exists": None, "error": "Access denied to AMSI Providers key"}

    index = 0
    while True:
        try:
            clsid = winreg.EnumKey(amsi_key, index)
            provider_info = {"clsid": clsid, "dll_path": None, "description": None}

            # Resolve CLSID → InprocServer32 DLL path
            try:
                inproc_path = rf"CLSID\{clsid}\InprocServer32"
                inproc_key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, inproc_path)
                dll_path, _ = winreg.QueryValueEx(inproc_key, "")
                provider_info["dll_path"] = dll_path
                winreg.CloseKey(inproc_key)
            except (FileNotFoundError, OSError):
                provider_info["dll_path"] = "UNRESOLVED"

            # Try to get a friendly description from the CLSID key
            try:
                clsid_key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, rf"CLSID\{clsid}")
                desc, _ = winreg.QueryValueEx(clsid_key, "")
                provider_info["description"] = desc
                winreg.CloseKey(clsid_key)
            except (FileNotFoundError, OSError):
                pass

            provider_info["is_defender"] = clsid.upper() == _DEFENDER_AMSI_CLSID.upper()
            providers.append(provider_info)
            index += 1
        except OSError:
            break

    winreg.CloseKey(amsi_key)
    return {"providers": providers, "amsi_key_exists": True}


def scan() -> dict:
    """
    Scan registered AMSI providers and assess security posture.

    Returns:
        dict with keys 'category', 'status', 'data', 'findings'.
    """
    if platform.system() != "Windows":
        return {
            "category": "AMSI Providers",
            "status": "error",
            "data": {},
            "findings": [
                {
                    "severity": "info",
                    "title": "Not a Windows system",
                    "description": "AMSI provider scanning is only applicable on Windows.",
                }
            ],
        }

    try:
        result = _read_amsi_providers_registry()
        findings = []

        providers = result.get("providers", [])
        amsi_key_exists = result.get("amsi_key_exists")

        # --- Check 1: AMSI key missing entirely --------------------------------
        if amsi_key_exists is False:
            findings.append(
                {
                    "severity": "critical",
                    "title": "AMSI Providers registry key does not exist",
                    "description": (
                        "The HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers key is missing. "
                        "This means no antimalware product is registered to inspect "
                        "script content via AMSI, leaving the system vulnerable to "
                        "fileless malware and script-based attacks."
                    ),
                    "remediation": (
                        "Ensure Windows Defender or a compatible third-party AV is "
                        "installed and that its AMSI provider is properly registered."
                    ),
                }
            )
            return {
                "category": "AMSI Providers",
                "status": "fail",
                "data": result,
                "findings": findings,
            }

        # --- Check 2: Access denied -------------------------------------------
        if amsi_key_exists is None:
            findings.append(
                {
                    "severity": "medium",
                    "title": "Cannot read AMSI Providers registry key",
                    "description": result.get("error", "Access denied"),
                    "remediation": "Run the scanner with elevated (Administrator) privileges.",
                }
            )
            return {
                "category": "AMSI Providers",
                "status": "error",
                "data": result,
                "findings": findings,
            }

        # --- Check 3: No providers registered ----------------------------------
        if len(providers) == 0:
            findings.append(
                {
                    "severity": "critical",
                    "title": "No AMSI providers registered",
                    "description": (
                        "The AMSI Providers key exists but contains no registered "
                        "providers. AMSI cannot inspect script content, which is a "
                        "common indicator of an AMSI bypass attack."
                    ),
                    "remediation": (
                        "Investigate why no AMSI providers are registered. Reinstall "
                        "Windows Defender or your endpoint protection product."
                    ),
                }
            )
            return {
                "category": "AMSI Providers",
                "status": "fail",
                "data": result,
                "findings": findings,
            }

        # --- Check 4: Defender provider presence -------------------------------
        defender_present = any(p.get("is_defender") for p in providers)
        if not defender_present:
            findings.append(
                {
                    "severity": "info",
                    "title": "Windows Defender AMSI provider not found",
                    "description": (
                        f"The default Windows Defender AMSI CLSID ({_DEFENDER_AMSI_CLSID}) "
                        "is not registered. A third-party antimalware product may be "
                        "providing AMSI coverage instead."
                    ),
                }
            )

        # --- Check 5: Non-standard / unknown providers -------------------------
        for prov in providers:
            if prov.get("is_defender"):
                continue
            findings.append(
                {
                    "severity": "medium",
                    "title": f"Non-standard AMSI provider detected: {prov['clsid']}",
                    "description": (
                        f"CLSID {prov['clsid']} is registered as an AMSI provider "
                        f"with DLL path: {prov.get('dll_path', 'UNKNOWN')}. "
                        "Verify this is a legitimate antimalware product and not a "
                        "rogue provider planted by an attacker."
                    ),
                    "remediation": (
                        "Confirm the DLL is signed by a trusted vendor. Remove any "
                        "unrecognised AMSI provider registrations."
                    ),
                }
            )

        # --- Check 6: Unresolved DLL paths ------------------------------------
        for prov in providers:
            if prov.get("dll_path") == "UNRESOLVED":
                findings.append(
                    {
                        "severity": "high",
                        "title": f"AMSI provider CLSID {prov['clsid']} has no resolvable DLL",
                        "description": (
                            "The InprocServer32 key for this CLSID could not be found "
                            "or read. The provider may be broken or tampered with."
                        ),
                        "remediation": (
                            "Re-register the AMSI provider or reinstall the associated "
                            "antimalware product."
                        ),
                    }
                )

        # Determine overall status
        severities = [f["severity"] for f in findings]
        if "critical" in severities:
            status = "fail"
        elif "high" in severities:
            status = "fail"
        elif "medium" in severities:
            status = "warn"
        else:
            status = "pass"

        # If everything looks good, add an informational finding
        if not findings:
            findings.append(
                {
                    "severity": "info",
                    "title": "AMSI providers are properly registered",
                    "description": (
                        f"{len(providers)} AMSI provider(s) registered, including "
                        "the Windows Defender provider."
                    ),
                }
            )

        return {
            "category": "AMSI Providers",
            "status": status,
            "data": result,
            "findings": findings,
        }

    except Exception as exc:
        return {
            "category": "AMSI Providers",
            "status": "error",
            "data": {"error": str(exc), "traceback": traceback.format_exc()},
            "findings": [
                {
                    "severity": "info",
                    "title": "Error scanning AMSI providers",
                    "description": f"An unexpected error occurred: {exc}",
                }
            ],
        }
