"""
macOS Installed Applications & Homebrew Scanner
Enumerates third-party applications in /Applications and installed Homebrew packages.
"""
import os
import subprocess

def scan() -> dict:
    category = "Applications & Homebrew"
    data = {"applications": [], "brew_packages": []}
    findings = []
    status = "info"

    try:
        if os.path.exists("/Applications"):
            for item in sorted(os.listdir("/Applications")):
                if item.endswith(".app"):
                    data["applications"].append(item)

        # Check brew
        brew = subprocess.run(["brew", "list", "--versions"], capture_output=True, text=True, timeout=5)
        if brew.returncode == 0:
            for line in brew.stdout.splitlines()[:50]:
                data["brew_packages"].append(line.strip())

    except Exception as e:
        data["error"] = str(e)

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
