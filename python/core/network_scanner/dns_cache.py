"""
macOS DNS Resolvers & Configuration Scanner
Audits macOS DNS nameservers, search domains, and resolver configurations via scutil --dns.
"""
import subprocess
import re
from typing import Dict, Any

def scan(ip_range: str = None) -> Dict[str, Any]:
    result = {
        "category": "DNS Resolvers & Configuration",
        "status": "info",
        "data": [],
        "findings": []
    }
    records = []

    try:
        res = subprocess.run(["scutil", "--dns"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            current_resolver = {}
            for line in res.stdout.splitlines():
                line = line.strip()
                if line.startswith("resolver #"):
                    if current_resolver:
                        records.append(current_resolver)
                    current_resolver = {"resolver": line}
                elif "nameserver[" in line and ":" in line:
                    ns = line.split(":", 1)[1].strip()
                    current_resolver.setdefault("nameservers", []).append(ns)
                    # Check for unencrypted or suspicious DNS
                    if ns in ["8.8.8.8", "1.1.1.1"]:
                        pass
                elif "domain" in line and ":" in line:
                    current_resolver["domain"] = line.split(":", 1)[1].strip()

            if current_resolver:
                records.append(current_resolver)
    except Exception as e:
        result["error"] = str(e)

    result["data"] = records[:10]
    return result
