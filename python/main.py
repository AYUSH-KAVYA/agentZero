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
import sys
import time
import traceback

from core.system_scanner.runner import SystemScanRunner
from core.network_scanner.runner import NetworkScanRunner
from core.vuln_engine.runner import VulnEngineRunner


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


def run_vuln_scan() -> dict:
    """Execute vulnerability analysis on existing scan results."""
    runner = VulnEngineRunner(progress_callback=emit_progress)
    return runner.run_all()


def run_full_scan(ip_range: str = None) -> dict:
    """Execute system scan, network scan, and vulnerability analysis."""
    emit_progress(0, "Full Scan", "starting")

    system_results = run_system_scan()
    network_results = run_network_scan(ip_range)
    vuln_results = run_vuln_scan()

    return {
        "scan_type": "full",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "system": system_results,
        "network": network_results,
        "vulnerabilities": vuln_results,
    }


def main():
    parser = argparse.ArgumentParser(
        description="AgentZero — Agent-less Windows Vulnerability Scanner"
    )
    parser.add_argument(
        "--scan-type",
        choices=["system", "network", "vulnerabilities", "full"],
        required=True,
        help="Type of scan to perform",
    )
    parser.add_argument(
        "--output-format",
        choices=["json"],
        default="json",
        help="Output format (default: json)",
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
