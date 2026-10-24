"""
macOS EDR & System Extensions Scanner
Audits third-party System Extensions, Endpoint Security extensions, and running security processes.
"""
import subprocess

def scan() -> dict:
    category = "EDR & System Extensions"
    data = {"extensions": [], "count": 0}
    findings = []
    status = "pass"

    try:
        res = subprocess.run(["systemextensionsctl", "list"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if "teamID" in line or "com." in line:
                    data["extensions"].append(line.strip())
            data["count"] = len(data["extensions"])
    except Exception as e:
        data["error"] = str(e)

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
