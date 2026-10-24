"""
macOS Shell History & Exposed Secrets Scanner
Inspects ~/.zsh_history and ~/.bash_history for leaked API keys, tokens, or credentials.
"""
import os
import re

PATTERNS = [
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{4,})", "Hardcoded Password in Command"),
    (r"(?i)(AKIA[0-9A-Z]{16})", "AWS Access Key ID"),
    (r"(?i)ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"(?i)(bearer\s+[a-zA-Z0-9_\-\.]{20,})", "Bearer Auth Token"),
]

def scan() -> dict:
    category = "Shell History & Exposed Secrets"
    data = {"history_files_checked": [], "matches_count": 0}
    findings = []
    status = "pass"

    home = os.path.expanduser("~")
    hist_files = [os.path.join(home, ".zsh_history"), os.path.join(home, ".bash_history")]

    for fpath in hist_files:
        if not os.path.exists(fpath):
            continue
        data["history_files_checked"].append(fpath)
        try:
            with open(fpath, "r", errors="ignore") as f:
                lines = f.readlines()[-300:] # Inspect last 300 entries
                for idx, line in enumerate(lines):
                    for pat, label in PATTERNS:
                        m = re.search(pat, line)
                        if m:
                            data["matches_count"] += 1
                            status = "fail"
                            findings.append({
                                "severity": "critical",
                                "title": f"Secret Exposed in Shell History: {label}",
                                "description": f"Detected potential plaintext secret in {os.path.basename(fpath)} on line {idx + 1}.",
                                "remediation": f"Remove sensitive commands from {fpath} and revoke compromised credentials immediately."
                            })
                            break
        except Exception:
            pass

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
