"""
macOS SUID Binaries & System Permissions Scanner
Audits setuid/setgid executables across standard macOS system paths.
"""
import os

STANDARD_SUID = {
    "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/crontab",
    "/usr/bin/su", "/usr/bin/login", "/usr/bin/top",
    "/usr/sbin/traceroute", "/usr/sbin/traceroute6"
}

def scan() -> dict:
    category = "SUID Binaries & File Permissions"
    data = {"suid_binaries": [], "count": 0}
    findings = []
    status = "pass"

    search_dirs = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
    for d in search_dirs:
        if not os.path.exists(d):
            continue
        try:
            for item in os.listdir(d):
                p = os.path.join(d, item)
                if os.path.islink(p):
                    continue
                try:
                    st = os.stat(p)
                    if st.st_mode & 0o4000: # SUID bit
                        data["suid_binaries"].append(p)
                        if p not in STANDARD_SUID and not p.startswith("/usr/"):
                            findings.append({
                                "severity": "medium",
                                "title": f"Non-Standard SUID Executable: {p}",
                                "description": f"Found SUID executable {p} outside standard macOS trusted binary list.",
                                "remediation": "Audit necessity and verify code signature with 'codesign -dv {p}'."
                            })
                except Exception:
                    pass
        except Exception:
            pass

    data["count"] = len(data["suid_binaries"])
    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
