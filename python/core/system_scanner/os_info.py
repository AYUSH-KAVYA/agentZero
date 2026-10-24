"""
macOS System Information Scanner
Collects OS version, build, kernel, hardware model, architecture, uptime, and computer name.
"""
import platform
import subprocess
import os
import time

def scan() -> dict:
    category = "macOS System Information"
    data = {}
    findings = []
    status = "pass"

    try:
        # sw_vers
        sw = subprocess.run(["sw_vers"], capture_output=True, text=True, timeout=5)
        for line in sw.stdout.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                data[k.strip().lower().replace(" ", "_")] = v.strip()

        data["platform"] = platform.platform()
        data["architecture"] = platform.machine()
        data["kernel_version"] = platform.release()
        data["node_name"] = platform.node()

        # sysctl hw.model
        model = subprocess.run(["sysctl", "-n", "hw.model"], capture_output=True, text=True, timeout=5)
        if model.returncode == 0:
            data["hardware_model"] = model.stdout.strip()

        # sysctl machdep.cpu.brand_string
        cpu = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True, timeout=5)
        if cpu.returncode == 0 and cpu.stdout.strip():
            data["processor"] = cpu.stdout.strip()
        else:
            data["processor"] = f"Apple Silicon ({platform.machine()})"

        # uptime
        uptime = subprocess.run(["uptime"], capture_output=True, text=True, timeout=5)
        if uptime.returncode == 0:
            data["uptime_raw"] = uptime.stdout.strip()

        ver_str = data.get("productversion", "")
        if ver_str:
            major = int(ver_str.split(".")[0])
            if major < 13:
                status = "warn"
                findings.append({
                    "severity": "high",
                    "title": "Legacy or Unsupported macOS Version",
                    "description": f"macOS version {ver_str} is no longer receiving standard security updates from Apple.",
                    "remediation": "Upgrade to macOS 14 (Sonoma) or macOS 15 (Sequoia)."
                })

    except Exception as e:
        status = "error"
        findings.append({
            "severity": "medium",
            "title": "Error Collecting OS Information",
            "description": str(e)
        })

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
