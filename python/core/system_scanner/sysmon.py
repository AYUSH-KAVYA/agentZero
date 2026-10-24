"""
macOS LaunchAgents Persistence Scanner
Audits user-level and system-wide LaunchAgents in /Library/LaunchAgents and ~/Library/LaunchAgents.
"""
import os

def scan() -> dict:
    category = "LaunchAgents Persistence"
    data = {"agents": [], "count": 0}
    findings = []
    status = "pass"

    dirs = ["/Library/LaunchAgents", os.path.expanduser("~/Library/LaunchAgents")]
    for d in dirs:
        if not os.path.exists(d):
            continue
        try:
            for item in os.listdir(d):
                if item.endswith(".plist"):
                    path = os.path.join(d, item)
                    data["agents"].append({"name": item, "path": path, "location": d})
        except Exception:
            pass

    data["count"] = len(data["agents"])
    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
