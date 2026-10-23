"""
Vulnerability Engine Runner
===========================
Orchestrates CVE matching, CIS benchmark evaluations, open-source exploit crawling,
patch verification, and security posture scoring.
"""

import time
import json
import logging
from typing import Dict, Any, Optional, Callable, List

from .cve_database import CVEDatabase
from .cis_benchmarks import CISBenchmarkEvaluator
from .exploit_crawler import ExploitCrawler
from .patch_checker import PatchChecker
from .severity_scorer import SeverityScorer

logger = logging.getLogger(__name__)


class VulnEngineRunner:
    """Coordinates vulnerability detection, exploit crawling, and posture analysis."""

    def __init__(
        self,
        progress_callback: Optional[Callable[[int, str, str], None]] = None,
        search_online_exploits: bool = False,
    ):
        self.progress_callback = progress_callback or (lambda *a, **kw: None)
        self.search_online_exploits = search_online_exploits
        self.cve_db = CVEDatabase()
        self.cis_eval = CISBenchmarkEvaluator()
        self.crawler = ExploitCrawler()
        self.scorer = SeverityScorer()

    def _emit(self, progress: int, module: str, status: str = "scanning") -> None:
        try:
            self.progress_callback(progress, module, status)
        except Exception:
            pass

    def run_all(self, system_scan_results: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute complete vulnerability assessment pipeline.
        Can run on live scan results or fallback gracefully.
        """
        self._emit(5, "Vulnerability Engine", "initializing")

        # 1. Extract system facts from system scan results
        system_modules = {}
        if system_scan_results and "modules" in system_scan_results:
            system_modules = system_scan_results["modules"]

        # Hotfixes
        hotfix_module = system_modules.get("hotfixes", {})
        hotfix_list = hotfix_module.get("data", {}).get("hotfixes", [])
        patch_checker = PatchChecker(hotfix_list)

        # OS Info
        os_info = system_modules.get("os_info", {}).get("data", {})

        # DotNet versions
        dotnet_module = system_modules.get("dotnet_versions", {})
        dotnet_list = []
        if isinstance(dotnet_module.get("data"), dict):
            dotnet_list = [str(k) for k in dotnet_module.get("data", {}).keys()]

        # Services
        autorun_module = system_modules.get("autorun", {})
        services = autorun_module.get("data", {}).get("services", [])

        self._emit(25, "CVE Database Matcher", "matching")

        # 2. Match potential CVEs
        raw_cves = self.cve_db.match_system_state(
            os_info=os_info,
            hotfixes_installed=list(patch_checker.installed_kbs),
            dotnet_versions=dotnet_list,
            services_running=services,
        )

        self._emit(50, "Exploit & Patch Crawler", "crawling")

        # 3. Enrich CVE findings with live patch verification & exploit crawling
        findings = []
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        info_count = 0

        for cve in raw_cves:
            cve_id = cve.get("cve_id")
            req_kb = cve.get("required_hotfix_kb", "")
            patch_status = patch_checker.check_patch_status(req_kb)
            
            # Crawl for open-source exploits
            exploits = self.crawler.crawl_for_cve(
                cve_id, search_online=self.search_online_exploits
            )

            severity = cve.get("severity", "medium").lower()
            if severity == "critical":
                critical_count += 1
            elif severity == "high":
                high_count += 1
            elif severity == "medium":
                medium_count += 1
            elif severity == "low":
                low_count += 1
            else:
                info_count += 1

            findings.append({
                "cve": cve_id,
                "title": cve.get("title"),
                "category": cve.get("category"),
                "description": cve.get("description"),
                "cvss_score": cve.get("cvss_score", 0.0),
                "cvss_vector": cve.get("cvss_vector", ""),
                "severity": severity,
                "patch_available": patch_status["patch_available"],
                "patch_kb": patch_status["required_kb"],
                "patch_installed": patch_status["is_installed"],
                "patch_status_text": patch_status["status_text"],
                "patch_url": patch_status.get("kb_download_url"),
                "exploit_available": len(exploits) > 0 or cve.get("exploit_available", False),
                "exploit_source": exploits[0]["source"] if exploits else cve.get("exploit_source", "Public Index"),
                "exploit_url": exploits[0]["url"] if exploits else cve.get("exploit_url", ""),
                "exploit_type": exploits[0]["type"] if exploits else cve.get("exploit_type", "PoC"),
                "exploits": exploits,
                "remediation": cve.get("remediation"),
            })

        self._emit(75, "CIS Benchmark Evaluation", "evaluating")

        # 4. Evaluate CIS Windows Benchmarks
        cis_results = self.cis_eval.evaluate(system_modules)

        self._emit(90, "Security Posture Scoring", "calculating")

        # 5. Calculate overall posture score
        posture = self.scorer.calculate_posture_score(
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            cis_score=cis_results.get("score", 100.0),
        )

        self._emit(100, "Vulnerability Engine", "complete")

        return {
            "scan_type": "vulnerabilities",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "total": len(findings),
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "info": info_count,
            "posture": posture,
            "cis_benchmark": cis_results,
            "findings": findings,
        }
