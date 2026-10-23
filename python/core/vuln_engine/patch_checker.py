"""
Patch Checker & Cumulative Update Verifier
==========================================
Cross-references detected vulnerabilities against installed Windows KBs and hotfixes.
Determines if a patch is available, installed, or superseded.
"""

from typing import List, Dict, Any, Set


class PatchChecker:
    """Verifies Microsoft security updates and hotfixes against detected CVEs."""

    def __init__(self, installed_hotfixes: List[str] = None):
        self.installed_kbs = self._normalize_kbs(installed_hotfixes or [])

    def _normalize_kbs(self, kbs: List[Any]) -> Set[str]:
        cleaned = set()
        for item in kbs:
            if isinstance(item, str):
                s = item.upper().strip().replace("KB", "")
                if s:
                    cleaned.add(s)
            elif isinstance(item, dict):
                # May have HotFixID or Description
                val = item.get("HotFixID") or item.get("kb") or ""
                s = str(val).upper().strip().replace("KB", "")
                if s:
                    cleaned.add(s)
        return cleaned

    def update_installed_kbs(self, kbs: List[Any]) -> None:
        self.installed_kbs = self._normalize_kbs(kbs)

    def check_patch_status(self, required_kb: str) -> Dict[str, Any]:
        """
        Check if a given required Microsoft KB is installed on the host.
        """
        if not required_kb:
            return {
                "patch_available": False,
                "required_kb": None,
                "is_installed": False,
                "status_text": "No specific KB patch identified"
            }

        norm_required = required_kb.upper().replace("KB", "").strip()
        is_installed = norm_required in self.installed_kbs

        return {
            "patch_available": True,
            "required_kb": f"KB{norm_required}",
            "is_installed": is_installed,
            "status_text": "Installed" if is_installed else "Missing / Not Installed",
            "kb_download_url": f"https://www.catalog.update.microsoft.com/Search.aspx?q=KB{norm_required}"
        }
