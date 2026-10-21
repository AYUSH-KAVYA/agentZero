"""
HTML Report Generator for AgentZero.

Generates a self-contained HTML report from scan results using Jinja2 templates.
(Stub — will be fully implemented in Step 6)
"""

import os
import json
from datetime import datetime

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:
    Environment = None
    FileSystemLoader = None


class HTMLReportGenerator:
    """Generates HTML reports from AgentZero scan results."""

    def __init__(self, template_dir: str = None):
        if template_dir is None:
            template_dir = os.path.join(os.path.dirname(__file__), "templates")
        self.template_dir = template_dir

    def generate(self, scan_results: dict, output_path: str) -> str:
        """
        Generate an HTML report from scan results.

        Args:
            scan_results: Combined scan results dict.
            output_path: Path to write the HTML file.

        Returns:
            Path to the generated HTML file.
        """
        if Environment is None:
            raise ImportError("jinja2 is required for report generation. Install with: pip install jinja2")

        env = Environment(loader=FileSystemLoader(self.template_dir))
        template = env.get_template("report_template.html")

        # Load CSS
        css_path = os.path.join(self.template_dir, "styles.css")
        with open(css_path, "r") as f:
            css = f.read()

        # Prepare template context
        context = {
            "css": css,
            "timestamp": scan_results.get("timestamp", datetime.now().isoformat()),
            "scan_type": scan_results.get("scan_type", "unknown"),
            "hostname": scan_results.get("system", {}).get("modules", {}).get("os_info", {}).get("data", {}).get("hostname", "Unknown"),
            "summary": self._compute_summary(scan_results),
            "system_results": scan_results.get("system"),
            "network_results": scan_results.get("network"),
            "vuln_results": scan_results.get("vulnerabilities"),
            "network_diagram": scan_results.get("network_diagram"),
        }

        html = template.render(**context)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        return output_path

    def _compute_summary(self, scan_results: dict) -> dict:
        """Compute severity counts across all scan results."""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for section in ["system", "network"]:
            section_data = scan_results.get(section, {})
            for module in section_data.get("modules", {}).values():
                for finding in module.get("findings", []):
                    severity = finding.get("severity", "info")
                    if severity in summary:
                        summary[severity] += 1

        vuln_data = scan_results.get("vulnerabilities", {})
        for finding in vuln_data.get("findings", []):
            severity = finding.get("severity", "info")
            if severity in summary:
                summary[severity] += 1

        return summary
