"""
HTML Report Generator for AgentZero.
Generates an executive, self-contained HTML audit report from scan results.
Features embedded CSS styling, SVG network topology, CVSS severity matrix, and CIS benchmarks.
"""

import os
import json
import html
from datetime import datetime
from typing import Dict, Any, Optional

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:
    Environment = None
    FileSystemLoader = None


class HTMLReportGenerator:
    """Generates standalone HTML reports from AgentZero scan payloads."""

    def __init__(self, template_dir: Optional[str] = None):
        if template_dir is None:
            template_dir = os.path.join(os.path.dirname(__file__), "templates")
        self.template_dir = template_dir

    def generate(self, scan_results: Dict[str, Any], output_path: str) -> str:
        """
        Generate a self-contained HTML report from scan results.
        Uses Jinja2 if available, or a native fallback HTML compiler.
        """
        css_path = os.path.join(self.template_dir, "styles.css")
        css = ""
        if os.path.exists(css_path):
            with open(css_path, "r", encoding="utf-8") as f:
                css = f.read()

        context = {
            "css": css,
            "timestamp": scan_results.get("timestamp", datetime.now().isoformat()),
            "scan_type": scan_results.get("scan_type", "Comprehensive Security Audit"),
            "hostname": (
                scan_results.get("system", {}).get("modules", {}).get("os_info", {}).get("data", {}).get("hostname")
                or scan_results.get("hostname")
                or "Windows-Host"
            ),
            "summary": self._compute_summary(scan_results),
            "system_results": scan_results.get("system") or (scan_results if "modules" in scan_results and "os_info" in scan_results.get("modules", {}) else None),
            "network_results": scan_results.get("network"),
            "vuln_results": scan_results.get("vulnerabilities") or (scan_results if "cis_benchmark" in scan_results else None),
            "network_diagram": scan_results.get("network_diagram_svg") or scan_results.get("network", {}).get("network_diagram_svg"),
        }

        if Environment is not None and os.path.exists(os.path.join(self.template_dir, "report_template.html")):
            env = Environment(loader=FileSystemLoader(self.template_dir))
            template = env.get_template("report_template.html")
            rendered_html = template.render(**context)
        else:
            rendered_html = self._render_fallback_html(context)

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(rendered_html)

        return output_path

    def _compute_summary(self, scan_results: Dict[str, Any]) -> Dict[str, int]:
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        # Check vulnerability section
        vuln_data = scan_results.get("vulnerabilities") or (scan_results if "findings" in scan_results and "total" in scan_results else {})
        for finding in vuln_data.get("findings", []):
            sev = finding.get("severity", "info").lower()
            if sev in summary:
                summary[sev] += 1

        # Check system section
        sys_data = scan_results.get("system") or (scan_results if "modules" in scan_results else {})
        for mod in sys_data.get("modules", {}).values():
            for f in mod.get("findings", []):
                sev = f.get("severity", "info").lower()
                if sev in summary:
                    summary[sev] += 1

        return summary

    def _render_fallback_html(self, ctx: Dict[str, Any]) -> str:
        """Stand-in HTML generator when jinja2 is not installed."""
        summary = ctx["summary"]
        h_name = html.escape(str(ctx["hostname"]))
        ts = html.escape(str(ctx["timestamp"]))

        vuln_html = ""
        vuln_res = ctx.get("vuln_results") or {}
        for f in vuln_res.get("findings", []):
            vuln_html += f"""
            <div class="vuln-card severity-{f.get('severity', 'info')}">
                <h3>{html.escape(f.get('title', 'Finding'))} ({html.escape(f.get('cve', 'Misconfiguration'))})</h3>
                <p>{html.escape(f.get('description', ''))}</p>
                <p><strong>Remediation:</strong> {html.escape(f.get('remediation', 'None'))}</p>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AgentZero Audit Report - {h_name}</title>
    <style>{ctx['css']}</style>
</head>
<body>
    <header class="report-header">
        <div>
            <h1>🛡️ AgentZero Security Report</h1>
            <p>Agent-less Windows Vulnerability and Network Scanner</p>
        </div>
        <div class="scan-meta">
            <p><strong>Host:</strong> {h_name}</p>
            <p><strong>Timestamp:</strong> {ts}</p>
        </div>
    </header>

    <section class="executive-summary">
        <h2>Executive Summary</h2>
        <div class="severity-grid">
            <div class="severity-card critical"><span class="count">{summary['critical']}</span><span class="label">Critical</span></div>
            <div class="severity-card high"><span class="count">{summary['high']}</span><span class="label">High</span></div>
            <div class="severity-card medium"><span class="count">{summary['medium']}</span><span class="label">Medium</span></div>
            <div class="severity-card low"><span class="count">{summary['low']}</span><span class="label">Low</span></div>
        </div>
    </section>

    <section class="findings-section">
        <h2>Vulnerabilities & Attack Vectors</h2>
        {vuln_html or '<p class="no-findings">No active critical CVEs flagged.</p>'}
    </section>

    <footer>
        <p>National Technical Research Organisation (NTRO) • AgentZero Security Audit</p>
    </footer>
</body>
</html>"""
