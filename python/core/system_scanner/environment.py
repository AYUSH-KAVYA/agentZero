"""
macOS Environment & PATH Variables Scanner
Inspects system and user environment variables, analyzing PATH for unsafe relative or writable entries.
"""
import os

def scan() -> dict:
    category = "Environment & PATH"
    data = {"path_entries": [], "insecure_entries": []}
    findings = []
    status = "pass"

    raw_path = os.environ.get("PATH", "")
    data["path_entries"] = raw_path.split(":")

    for p in data["path_entries"]:
        if p == "." or p == "":
            data["insecure_entries"].append(p)
            status = "warn"
            findings.append({
                "severity": "high",
                "title": "Current Working Directory ('.') in PATH",
                "description": "Including '.' in $PATH allows binary hijacking if executing commands inside attacker-controlled directories.",
                "remediation": "Remove '.' from PATH in ~/.zshrc or ~/.bash_profile."
            })
        elif os.path.exists(p):
            try:
                st = os.stat(p)
                if st.st_mode & 0o002: # World-writable
                    data["insecure_entries"].append(p)
                    findings.append({
                        "severity": "medium",
                        "title": f"World-Writable Directory in PATH: {p}",
                        "description": f"The directory {p} is writable by other users, allowing malicious replacement of standard commands.",
                        "remediation": f"Fix permissions with 'chmod 755 {p}'."
                    })
            except Exception:
                pass

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
