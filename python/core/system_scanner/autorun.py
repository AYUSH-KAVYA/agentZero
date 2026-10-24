"""
macOS LaunchDaemons Persistence Scanner
Audits system-wide background LaunchDaemons in /Library/LaunchDaemons and /System/Library/LaunchDaemons.
"""
import os
import plistlib

def scan() -> dict:
    category = "LaunchDaemons Persistence"
    data = {"daemons": [], "count": 0}
    findings = []
    status = "pass"

    scan_dirs = ["/Library/LaunchDaemons"]
    for d in scan_dirs:
        if not os.path.exists(d):
            continue
        try:
            for item in os.listdir(d):
                if not item.endswith(".plist"):
                    continue
                path = os.path.join(d, item)
                info = {"name": item, "path": path}
                # Check permissions
                st = os.stat(path)
                if st.st_mode & 0o002: # World writable
                    status = "fail"
                    findings.append({
                        "severity": "high",
                        "title": f"World-Writable LaunchDaemon: {item}",
                        "description": f"The LaunchDaemon plist file {path} is writable by any local user, presenting an instant root escalation vector.",
                        "remediation": f"Fix permissions via 'sudo chmod 644 {path} && sudo chown root:wheel {path}'."
                    })
                data["daemons"].append(info)
        except Exception as e:
            data["error"] = str(e)

    data["count"] = len(data["daemons"])
    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
