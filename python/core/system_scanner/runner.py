"""
System Scanner Runner — Orchestrates all system-level scanner modules.

This is the central coordinator that imports and executes each individual
scanner module, collects results, tracks progress, and consolidates findings
into a unified report structure.
"""

import time
import traceback
from typing import Callable, Optional

# Import all scanner modules
from . import (
    os_info,
    dotnet_versions,
    amsi_providers,
    antivirus,
    audit_policy,
    autorun,
    firewall,
    defender,
    certificates,
    environment,
    file_listing,
    file_info,
    hotfixes,
    installed_products,
    group_policy,
    local_groups,
    local_users,
    ms_updates,
    ntlm_settings,
    rdp_connections,
    rdp_sessions,
    rdp_settings,
    secure_boot,
    sysmon,
    uac_policies,
    powershell_history,
)


# Ordered list of all scanner modules with metadata
SCANNER_MODULES = [
    {"key": "os_info", "module": os_info, "label": "Basic OS Information"},
    {"key": "dotnet_versions", "module": dotnet_versions, "label": ".NET Versions"},
    {"key": "amsi_providers", "module": amsi_providers, "label": "AMSI Providers"},
    {"key": "antivirus", "module": antivirus, "label": "Registered Antivirus"},
    {"key": "audit_policy", "module": audit_policy, "label": "Audit Policy Settings"},
    {"key": "autorun", "module": autorun, "label": "Auto-Run Programs"},
    {"key": "firewall", "module": firewall, "label": "Firewall Rules"},
    {"key": "defender", "module": defender, "label": "Windows Defender"},
    {"key": "certificates", "module": certificates, "label": "Certificate Files"},
    {"key": "environment", "module": environment, "label": "Environment & PATH"},
    {"key": "file_listing", "module": file_listing, "label": "User File Listing"},
    {"key": "file_info", "module": file_info, "label": "System File Info"},
    {"key": "hotfixes", "module": hotfixes, "label": "Installed Hotfixes"},
    {"key": "installed_products", "module": installed_products, "label": "Installed Products"},
    {"key": "group_policy", "module": group_policy, "label": "Group Policy Settings"},
    {"key": "local_groups", "module": local_groups, "label": "Local Groups"},
    {"key": "local_users", "module": local_users, "label": "Local Users"},
    {"key": "ms_updates", "module": ms_updates, "label": "Microsoft Updates"},
    {"key": "ntlm_settings", "module": ntlm_settings, "label": "NTLM Settings"},
    {"key": "rdp_connections", "module": rdp_connections, "label": "Saved RDP Connections"},
    {"key": "rdp_sessions", "module": rdp_sessions, "label": "Active RDP Sessions"},
    {"key": "rdp_settings", "module": rdp_settings, "label": "RDP Server/Client Settings"},
    {"key": "secure_boot", "module": secure_boot, "label": "Secure Boot Configuration"},
    {"key": "sysmon", "module": sysmon, "label": "Sysmon Configuration"},
    {"key": "uac_policies", "module": uac_policies, "label": "UAC Policies"},
    {"key": "powershell_history", "module": powershell_history, "label": "PowerShell History"},
]


class SystemScanRunner:
    """Orchestrates the execution of all system scanner modules."""

    def __init__(self, progress_callback: Optional[Callable] = None):
        """
        Args:
            progress_callback: Function(progress: int, module: str, status: str)
                              called to report scan progress.
        """
        self.progress_callback = progress_callback or (lambda *a, **kw: None)

    def _emit_progress(self, progress: int, module: str, status: str = "scanning"):
        """Emit a progress update."""
        try:
            self.progress_callback(progress, module, status)
        except Exception:
            pass  # Never let progress reporting crash the scan

    def run_module(self, module_info: dict) -> dict:
        """
        Run a single scanner module safely.

        Args:
            module_info: Dict with 'key', 'module', and 'label' keys.

        Returns:
            The module's scan result dict, or an error dict if it crashed.
        """
        try:
            result = module_info["module"].scan()
            # Validate the result structure
            if not isinstance(result, dict):
                return {
                    "category": module_info["label"],
                    "status": "error",
                    "data": {},
                    "findings": [
                        {
                            "severity": "info",
                            "title": "Invalid module output",
                            "description": f"Module {module_info['key']} returned {type(result).__name__} instead of dict",
                        }
                    ],
                }
            return result
        except Exception as e:
            return {
                "category": module_info["label"],
                "status": "error",
                "data": {"error": str(e), "traceback": traceback.format_exc()},
                "findings": [
                    {
                        "severity": "info",
                        "title": f"Module {module_info['key']} failed",
                        "description": str(e),
                    }
                ],
            }

    def run_all(self) -> dict:
        """
        Run all system scanner modules sequentially and return consolidated results.

        Returns:
            dict with keys:
            - scan_type: "system"
            - timestamp: ISO format timestamp
            - modules: dict mapping module key -> module result
            - summary: dict with counts and statistics
        """
        self._emit_progress(0, "System Scanner", "starting")

        total = len(SCANNER_MODULES)
        results = {
            "scan_type": "system",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "modules": {},
            "summary": {
                "total_modules": total,
                "completed": 0,
                "errors": 0,
                "findings_by_severity": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                },
                "status_counts": {
                    "pass": 0,
                    "warn": 0,
                    "fail": 0,
                    "info": 0,
                    "error": 0,
                },
            },
        }

        for i, module_info in enumerate(SCANNER_MODULES):
            progress = int((i / total) * 100)
            self._emit_progress(progress, module_info["label"], "scanning")

            # Run the module
            module_result = self.run_module(module_info)
            results["modules"][module_info["key"]] = module_result

            # Update summary statistics
            status = module_result.get("status", "error")
            results["summary"]["completed"] += 1

            if status == "error":
                results["summary"]["errors"] += 1

            if status in results["summary"]["status_counts"]:
                results["summary"]["status_counts"][status] += 1

            # Count findings by severity
            for finding in module_result.get("findings", []):
                severity = finding.get("severity", "info")
                if severity in results["summary"]["findings_by_severity"]:
                    results["summary"]["findings_by_severity"][severity] += 1

        self._emit_progress(100, "System Scanner", "complete")
        return results

    def run_selected(self, module_keys: list) -> dict:
        """
        Run only selected scanner modules.

        Args:
            module_keys: List of module key strings to run.

        Returns:
            Same structure as run_all() but only with selected modules.
        """
        selected = [m for m in SCANNER_MODULES if m["key"] in module_keys]
        if not selected:
            return {
                "scan_type": "system",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "modules": {},
                "summary": {"error": "No valid modules selected"},
            }

        # Temporarily replace the module list
        original = SCANNER_MODULES.copy()
        total = len(selected)
        results = {
            "scan_type": "system",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "modules": {},
            "summary": {
                "total_modules": total,
                "completed": 0,
                "errors": 0,
                "findings_by_severity": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                },
                "status_counts": {
                    "pass": 0,
                    "warn": 0,
                    "fail": 0,
                    "info": 0,
                    "error": 0,
                },
            },
        }

        for i, module_info in enumerate(selected):
            progress = int((i / total) * 100)
            self._emit_progress(progress, module_info["label"], "scanning")

            module_result = self.run_module(module_info)
            results["modules"][module_info["key"]] = module_result

            status = module_result.get("status", "error")
            results["summary"]["completed"] += 1

            if status == "error":
                results["summary"]["errors"] += 1

            if status in results["summary"]["status_counts"]:
                results["summary"]["status_counts"][status] += 1

            for finding in module_result.get("findings", []):
                severity = finding.get("severity", "info")
                if severity in results["summary"]["findings_by_severity"]:
                    results["summary"]["findings_by_severity"][severity] += 1

        self._emit_progress(100, "System Scanner", "complete")
        return results
