"""
CVE Database & Query Engine
============================
Loads offline curated CVE dataset and enriches vulnerabilities with NVD API v2.0 queries.
Maps system findings (OS build, services, .NET versions, installed hotfixes) to CVE entries.
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional

try:
    import requests
except ImportError:
    requests = None

logger = logging.getLogger(__name__)


class CVEDatabase:
    """Manages offline CVE cache and online NVD API enrichment."""

    def __init__(self, data_path: Optional[str] = None):
        if data_path is None:
            data_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "data",
                "cve_snapshot.json",
            )
        self.data_path = data_path
        self.cve_entries = []
        self.load_snapshot()

    def load_snapshot(self) -> None:
        """Load curated offline CVE snapshot."""
        if os.path.exists(self.data_path):
            try:
                with open(self.data_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.cve_entries = data.get("entries", [])
            except Exception as e:
                logger.warning(f"Failed to load CVE snapshot from {self.data_path}: {e}")
                self.cve_entries = []
        else:
            self.cve_entries = []

    def get_all_cves(self) -> List[Dict[str, Any]]:
        return self.cve_entries

    def find_by_cve_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        for entry in self.cve_entries:
            if entry.get("cve_id", "").upper() == cve_id.upper():
                return entry
        return None

    def query_nvd_online(self, cve_id: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
        """
        Query NIST NVD REST API v2.0 for live CVE metadata if network connectivity exists.
        Falls back cleanly to offline data when rate limited or offline.
        """
        if requests is None:
            return None

        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        try:
            resp = requests.get(url, timeout=timeout, headers={"User-Agent": "AgentZero-VulnerabilityScanner/1.0"})
            if resp.status_code == 200:
                payload = resp.json()
                vulnerabilities = payload.get("vulnerabilities", [])
                if vulnerabilities:
                    cve_data = vulnerabilities[0].get("cve", {})
                    metrics = cve_data.get("metrics", {})
                    cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    
                    descriptions = cve_data.get("descriptions", [])
                    desc_en = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
                    
                    return {
                        "cve_id": cve_id,
                        "description": desc_en,
                        "cvss_score": cvss_v31.get("baseScore", 0.0),
                        "cvss_vector": cvss_v31.get("vectorString", ""),
                        "severity": cvss_v31.get("baseSeverity", "UNKNOWN").lower(),
                        "source": "NVD API v2.0",
                    }
        except Exception:
            pass
        return None

    def match_system_state(
        self,
        os_info: Dict[str, Any],
        hotfixes_installed: List[str],
        dotnet_versions: List[str],
        services_running: List[str],
    ) -> List[Dict[str, Any]]:
        """
        Cross-reference system parameters against known CVE criteria.
        Returns list of matched potential vulnerabilities.
        """
        matched_vulnerabilities = []
        os_build = 0
        try:
            build_str = str(os_info.get("build_number") or os_info.get("WindowsBuildLabEx") or "0")
            os_build = int("".join(filter(str.isdigit, build_str.split(".")[0])))
        except Exception:
            os_build = 0

        installed_kbs = {str(kb).upper().replace("KB", "") for kb in hotfixes_installed if kb}

        for cve in self.cve_entries:
            conds = cve.get("affected_conditions", {})
            required_kb = cve.get("required_hotfix_kb", "").upper().replace("KB", "")

            # If required hotfix KB is already installed, this CVE is mitigated
            if required_kb and required_kb in installed_kbs:
                continue

            is_match = False

            # Build range check
            min_b = conds.get("min_build")
            max_b = conds.get("max_build")
            if min_b is not None or max_b is not None:
                if os_build > 0:
                    in_range = True
                    if min_b and os_build < min_b:
                        in_range = False
                    if max_b and os_build > max_b:
                        in_range = False
                    if in_range:
                        is_match = True

            # macOS version check
            max_ver = conds.get("max_version")
            min_ver = conds.get("min_version")
            curr_ver = os_info.get("productversion") or os_info.get("os_version")
            if curr_ver and (max_ver or min_ver):
                try:
                    def vtuple(v):
                        return tuple(int(x) for x in v.split(".") if x.isdigit())
                    c_t = vtuple(curr_ver)
                    in_v_range = True
                    if min_ver and c_t < vtuple(min_ver):
                        in_v_range = False
                    if max_ver and c_t > vtuple(max_ver):
                        in_v_range = False
                    if in_v_range:
                        is_match = True
                except Exception:
                    pass

            # Services check
            aff_services = conds.get("services", [])
            if aff_services and services_running:
                for s in aff_services:
                    if any(s.lower() in str(srv).lower() for srv in services_running):
                        is_match = True
                        break

            # .NET versions check
            aff_dotnets = conds.get("dotnet_versions", [])
            if aff_dotnets and dotnet_versions:
                for d in aff_dotnets:
                    if any(d in str(inst) for inst in dotnet_versions):
                        is_match = True
                        break

            if is_match or not conds:
                matched_vulnerabilities.append(cve)

        return matched_vulnerabilities
