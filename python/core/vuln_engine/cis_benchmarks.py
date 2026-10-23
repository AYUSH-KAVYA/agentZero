"""
CIS Benchmarks Evaluator
========================
Evaluates system scanner audit results against the Center for Internet Security (CIS)
Microsoft Windows 10/11 Benchmark recommendations.
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class CISBenchmarkEvaluator:
    """Evaluates CIS Benchmark compliance from system scan results."""

    def __init__(self, benchmark_path: Optional[str] = None):
        if benchmark_path is None:
            benchmark_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "data",
                "cis_windows_benchmarks.json",
            )
        self.benchmark_path = benchmark_path
        self.rules = []
        self.load_benchmarks()

    def load_benchmarks(self) -> None:
        if os.path.exists(self.benchmark_path):
            try:
                with open(self.benchmark_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.rules = data.get("rules", [])
            except Exception as e:
                logger.warning(f"Failed to load CIS benchmarks: {e}")
                self.rules = []
        else:
            self.rules = []

    def evaluate(self, system_modules: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate system scan modules against all loaded CIS rules.
        Returns compliance summary and list of rule assessment results.
        """
        results = []
        passed_count = 0
        failed_count = 0
        warn_count = 0

        for rule in self.rules:
            rule_id = rule.get("id")
            module_key = rule.get("module")
            check_key = rule.get("check_key")
            operator = rule.get("operator", "eq")
            target = rule.get("target_value")
            severity = rule.get("severity", "medium")

            module_data = system_modules.get(module_key, {})
            raw_data = module_data.get("data", {})
            findings = module_data.get("findings", [])

            # Extract actual value from module data
            actual_val = self._extract_value(raw_data, check_key)
            status = "FAIL"
            detail = ""

            # If module errored or not found
            if module_data.get("status") == "error":
                status = "WARN"
                detail = f"Could not audit ({module_data.get('category', module_key)} returned error)"
                warn_count += 1
            elif actual_val is None:
                # Check if failure is noted in module findings
                has_finding = any(check_key.lower() in f.get("title", "").lower() or check_key.lower() in f.get("description", "").lower() for f in findings)
                if has_finding:
                    status = "FAIL"
                    failed_count += 1
                    detail = f"Misconfiguration detected in {module_key} findings"
                else:
                    status = "WARN"
                    warn_count += 1
                    detail = "Parameter not explicitly reported by OS subsystem"
            else:
                passed = self._compare(actual_val, operator, target)
                if passed:
                    status = "PASS"
                    passed_count += 1
                    detail = f"Compliant: current value is {actual_val}"
                else:
                    status = "FAIL"
                    failed_count += 1
                    detail = f"Non-compliant: actual value '{actual_val}', expected '{operator} {target}'"

            results.append({
                "rule_id": rule_id,
                "title": rule.get("title"),
                "category": rule.get("category"),
                "severity": severity,
                "status": status,
                "actual_value": actual_val,
                "expected_value": target,
                "detail": detail,
                "description": rule.get("description"),
                "remediation": rule.get("remediation"),
            })

        total_rules = len(self.rules)
        score = round((passed_count / total_rules * 100), 1) if total_rules > 0 else 0.0

        return {
            "score": score,
            "total_rules": total_rules,
            "passed": passed_count,
            "failed": failed_count,
            "warnings": warn_count,
            "rule_evaluations": results,
        }

    def _extract_value(self, data: Any, key: str) -> Any:
        if not isinstance(data, dict):
            return None
        if key in data:
            return data[key]
        for k, v in data.items():
            if isinstance(v, dict):
                res = self._extract_value(v, key)
                if res is not None:
                    return res
        return None

    def _compare(self, actual: Any, operator: str, target: Any) -> bool:
        try:
            if operator == "eq":
                return actual == target
            elif operator == "neq":
                return actual != target
            elif operator == "gte":
                return float(actual) >= float(target)
            elif operator == "lte":
                return float(actual) <= float(target)
            elif operator == "lte_positive":
                val = float(actual)
                return 0 < val <= float(target)
            elif operator == "in":
                return actual in target
        except Exception:
            return False
        return False
