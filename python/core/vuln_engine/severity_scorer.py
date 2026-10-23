"""
Severity Scorer & Security Posture Calculator
=============================================
Calculates risk scores, CVSS distributions, and the overall System Security Posture Rating (0-100).
"""

from typing import List, Dict, Any


class SeverityScorer:
    """Computes vulnerability severity metrics and host posture grade."""

    @staticmethod
    def categorize_cvss(score: float) -> str:
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score > 0.0:
            return "low"
        return "info"

    @classmethod
    def calculate_posture_score(
        cls,
        critical_count: int,
        high_count: int,
        medium_count: int,
        low_count: int,
        cis_score: float = 100.0,
    ) -> Dict[str, Any]:
        """
        Compute an aggregate security posture score between 0 and 100.
        Deducts points according to vulnerability severities and weights CIS compliance.
        """
        base = 100.0

        # Penalties:
        # Each critical vulnerability with missing patch: -20 points
        # Each high vulnerability: -10 points
        # Each medium vulnerability: -3 points
        # Each low vulnerability: -1 point
        penalty = (critical_count * 20.0) + (high_count * 10.0) + (medium_count * 3.0) + (low_count * 1.0)
        
        # Factor in CIS compliance (30% weight to CIS benchmark score, 70% to CVE absence)
        cve_score = max(0.0, base - penalty)
        weighted_score = round((cve_score * 0.7) + (cis_score * 0.3), 1)

        grade = "A"
        if weighted_score < 50.0:
            grade = "F"
        elif weighted_score < 65.0:
            grade = "D"
        elif weighted_score < 75.0:
            grade = "C"
        elif weighted_score < 88.0:
            grade = "B"

        status_text = "Secure"
        if grade in ("D", "F"):
            status_text = "At Immediate Risk"
        elif grade == "C":
            status_text = "Moderate Risk / Hardening Needed"
        elif grade == "B":
            status_text = "Good / Minor Misconfigurations"

        return {
            "score": weighted_score,
            "grade": grade,
            "status": status_text,
            "penalties": {
                "critical": critical_count * 20.0,
                "high": high_count * 10.0,
                "medium": medium_count * 3.0,
                "low": low_count * 1.0,
            }
        }
