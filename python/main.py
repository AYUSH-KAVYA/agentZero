#!/usr/bin/env python3
"""
AgentZero — Agent-less Windows System Vulnerability & Network Scanner
Main CLI entry point.

This script is the single entry point for all scanning operations.
It is invoked by the Electron main process via child_process.spawn().

Usage:
    python main.py --scan-type system --output-format json
    python main.py --scan-type network --output-format json
    python main.py --scan-type vulnerabilities --output-format json
    python main.py --scan-type full --output-format json
"""

import argparse
import json
import os
import sys
import time
import traceback

from core.system_scanner.runner import SystemScanRunner
from core.network_scanner.runner import NetworkScanRunner
from core.vuln_engine.runner import VulnEngineRunner
from report.html_generator import HTMLReportGenerator
from report.pdf_generator import PDFReportGenerator


def emit_progress(progress: int, module: str, status: str = "scanning"):
    """Emit a progress update to stderr (read by Electron main process)."""
    update = {"progress": progress, "module": module, "status": status}
    print(json.dumps(update), file=sys.stderr, flush=True)


def run_system_scan() -> dict:
    """Execute all system-level scanner modules."""
    runner = SystemScanRunner(progress_callback=emit_progress)
    return runner.run_all()


def run_network_scan(ip_range: str = None) -> dict:
    """Execute all network-level scanner modules."""
    runner = NetworkScanRunner(progress_callback=emit_progress, ip_range=ip_range)
    return runner.run_all()


def run_vuln_scan(system_results: dict = None) -> dict:
    """Execute vulnerability analysis on existing scan results."""
    if system_results is None:
        # Run system scan facts if not provided
        system_results = run_system_scan()
    runner = VulnEngineRunner(progress_callback=emit_progress)
    return runner.run_all(system_scan_results=system_results)


def run_full_scan(ip_range: str = None) -> dict:
    """Execute system scan, network scan, and vulnerability analysis."""
    emit_progress(0, "Full Scan", "starting")

    system_results = run_system_scan()
    network_results = run_network_scan(ip_range)
    vuln_results = run_vuln_scan(system_results=system_results)

    return {
        "scan_type": "full",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "system": system_results,
        "network": network_results,
        "vulnerabilities": vuln_results,
    }


def generate_scan_report(format_type: str = "html", data: dict = None, output_file: str = None) -> dict:
    """Generate consolidated HTML or PDF report."""
    emit_progress(10, "Report Engine", "generating")
    if data is None:
        data = run_full_scan()

    ts = time.strftime("%Y%m%d_%H%M%S")
    reports_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
    os.makedirs(reports_dir, exist_ok=True)

    if not output_file:
        ext = "html" if format_type.lower() == "html" else "pdf"
        output_file = os.path.join(reports_dir, f"AgentZero_Report_{ts}.{ext}")

    html_gen = HTMLReportGenerator()
    temp_html = output_file if format_type.lower() == "html" else output_file.replace(".pdf", "_temp.html")
    html_path = html_gen.generate(data, temp_html)

    final_path = html_path
    if format_type.lower() == "pdf":
        emit_progress(60, "PDF Generator", "rendering")
        pdf_gen = PDFReportGenerator()
        final_path = pdf_gen.generate(html_path, output_file)
        if os.path.exists(temp_html) and temp_html != final_path:
            try:
                os.remove(temp_html)
            except Exception:
                pass

    emit_progress(100, "Report Engine", "complete")
    return {
        "status": "success",
        "format": format_type,
        "reportPath": os.path.abspath(final_path),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z")
    }


def main():
    parser = argparse.ArgumentParser(
        description="AgentZero — Agent-less Windows Vulnerability Scanner"
    )
    parser.add_argument(
        "--scan-type",
        choices=["system", "network", "vulnerabilities", "full", "report"],
        required=True,
        help="Type of scan to perform",
    )
    parser.add_argument(
        "--output-format",
        choices=["json", "html", "pdf"],
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--report-format",
        choices=["html", "pdf"],
        default="html",
        help="Report export format",
    )
    parser.add_argument(
        "--report-output",
        default=None,
        help="Output file destination for report",
    )
    parser.add_argument(
        "--ip-range",
        default=None,
        help="IP range for network scanning (e.g., 192.168.1.0/24)",
    )

    args = parser.parse_args()

    try:
        if args.scan_type == "system":
            results = run_system_scan()
        elif args.scan_type == "network":
            results = run_network_scan(args.ip_range)
        elif args.scan_type == "vulnerabilities":
            results = run_vuln_scan()
        elif args.scan_type == "full":
            results = run_full_scan(args.ip_range)
        elif args.scan_type == "report":
            results = generate_scan_report(
                format_type=args.report_format,
                output_file=args.report_output
            )

        # Output results to stdout (read by Electron)
        print(json.dumps(results, indent=2, default=str))

    except Exception as e:
        error_result = {
            "scan_type": args.scan_type,
            "error": str(e),
            "traceback": traceback.format_exc(),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        print(json.dumps(error_result, indent=2), file=sys.stdout)
        sys.exit(1)


if __name__ == "__main__":
    main()
