"""
Active RDP Sessions Scanner
============================
Enumerates current incoming Remote Desktop sessions using ``qwinsta``
(Query Session).

Why it matters:
    Active or disconnected RDP sessions may indicate:
    - Unauthorized remote access by an attacker
    - Stale disconnected sessions that retain user tokens, which can be
      hijacked via session-stealing techniques (e.g., ``tscon``)
    - Shadow / monitoring sessions

Data source:
    - PowerShell ``qwinsta`` / ``query session`` command output
"""

import platform
import re
import subprocess
import traceback


def _parse_qwinsta_output(raw: str) -> list:
    """
    Parse the output of ``qwinsta`` into a list of session dicts.

    The output format is fixed-width columns:
        SESSIONNAME  USERNAME  ID  STATE  TYPE  DEVICE
    """
    sessions = []
    lines = raw.strip().splitlines()
    if not lines:
        return sessions

    # First line is the header — use it to identify column positions
    header = lines[0]

    # Try to find column start positions from the header keywords
    col_names = ["SESSIONNAME", "USERNAME", "ID", "STATE", "TYPE", "DEVICE"]
    col_positions = []
    for col in col_names:
        pos = header.upper().find(col)
        col_positions.append(pos if pos >= 0 else None)

    for line in lines[1:]:
        if not line.strip():
            continue

        session = {}
        # Extract each field based on column positions
        for i, col in enumerate(col_names):
            start = col_positions[i]
            if start is None:
                session[col.lower()] = ""
                continue
            # End is the start of next column, or end of line
            end = None
            for j in range(i + 1, len(col_positions)):
                if col_positions[j] is not None:
                    end = col_positions[j]
                    break
            val = line[start:end].strip() if end else line[start:].strip()
            session[col.lower()] = val

        # The leading '>' marks the current session
        if session.get("sessionname", "").startswith(">"):
            session["sessionname"] = session["sessionname"][1:].strip()
            session["is_current"] = True
        else:
            session["is_current"] = False

        # Parse ID as integer if possible
        try:
            session["id"] = int(session.get("id", ""))
        except (ValueError, TypeError):
            pass

        sessions.append(session)

    return sessions


def _run_qwinsta() -> dict:
    """Execute ``qwinsta`` and return raw + parsed output."""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "qwinsta 2>&1"],
            capture_output=True, text=True, timeout=30,
        )
        raw = proc.stdout.strip()
        if proc.returncode != 0 and not raw:
            raw = proc.stderr.strip()
            return {"raw": raw, "sessions": [], "error": raw}

        sessions = _parse_qwinsta_output(raw)
        return {"raw": raw, "sessions": sessions, "error": None}

    except subprocess.TimeoutExpired:
        return {"raw": "", "sessions": [], "error": "qwinsta command timed out"}
    except FileNotFoundError:
        return {"raw": "", "sessions": [], "error": "qwinsta / query session not found"}
    except Exception as exc:
        return {"raw": "", "sessions": [], "error": str(exc)}


def scan() -> dict:
    """
    Scan current RDP / terminal sessions.

    Returns:
        dict with keys 'category', 'status', 'data', 'findings'.
    """
    if platform.system() != "Windows":
        return {
            "category": "RDP Sessions",
            "status": "error",
            "data": {},
            "findings": [
                {
                    "severity": "info",
                    "title": "Not a Windows system",
                    "description": "RDP session scanning is only applicable on Windows.",
                }
            ],
        }

    try:
        result = _run_qwinsta()
        sessions = result.get("sessions", [])
        findings = []

        data = {
            "raw_output": result.get("raw", ""),
            "sessions": sessions,
            "error": result.get("error"),
        }

        if result.get("error"):
            findings.append(
                {
                    "severity": "medium",
                    "title": "Could not enumerate RDP sessions",
                    "description": f"Error running qwinsta: {result['error']}",
                    "remediation": "Run the scanner with elevated (Administrator) privileges.",
                }
            )
            return {
                "category": "RDP Sessions",
                "status": "warn",
                "data": data,
                "findings": findings,
            }

        # Classify sessions
        active_sessions = [
            s for s in sessions
            if s.get("state", "").lower() == "active"
            and s.get("username")
        ]
        disconnected_sessions = [
            s for s in sessions
            if s.get("state", "").lower() in ("disc", "disconnected", "disc.")
            and s.get("username")
        ]
        rdp_active = [
            s for s in active_sessions
            if s.get("sessionname", "").lower().startswith("rdp")
        ]
        rdp_disconnected = [
            s for s in disconnected_sessions
            if s.get("sessionname", "").lower().startswith("rdp")
            or s.get("type", "").lower() == "rdpwd"
        ]

        data["summary"] = {
            "total_sessions": len(sessions),
            "active_sessions": len(active_sessions),
            "disconnected_sessions": len(disconnected_sessions),
            "active_rdp_sessions": len(rdp_active),
            "disconnected_rdp_sessions": len(rdp_disconnected),
        }

        # --- Active RDP sessions -----------------------------------------------
        if rdp_active:
            users = ", ".join(
                f"{s.get('username', '?')} (ID {s.get('id', '?')})" for s in rdp_active
            )
            findings.append(
                {
                    "severity": "medium",
                    "title": f"{len(rdp_active)} active RDP session(s) detected",
                    "description": (
                        f"Active RDP sessions: {users}. Verify these are "
                        "authorised users. Unexpected sessions may indicate "
                        "unauthorised remote access."
                    ),
                    "remediation": (
                        "Verify the identity of all active RDP users. Use "
                        "`logoff <session-id>` to terminate suspicious sessions."
                    ),
                }
            )

        # --- Disconnected RDP sessions -----------------------------------------
        if rdp_disconnected:
            users = ", ".join(
                f"{s.get('username', '?')} (ID {s.get('id', '?')})" for s in rdp_disconnected
            )
            findings.append(
                {
                    "severity": "high",
                    "title": f"{len(rdp_disconnected)} disconnected RDP session(s) still alive",
                    "description": (
                        f"Disconnected sessions: {users}. These sessions retain "
                        "the user's security token and can be hijacked by a local "
                        "administrator using `tscon <id> /dest:console`."
                    ),
                    "remediation": (
                        "Log off disconnected sessions using `logoff <session-id>`. "
                        "Configure Group Policy to set an idle session time limit: "
                        "Computer Configuration > Administrative Templates > "
                        "Windows Components > Remote Desktop Services > "
                        "Session Time Limits."
                    ),
                }
            )

        # --- All active sessions listing (informational) -----------------------
        if active_sessions:
            all_users = ", ".join(
                f"{s.get('username', '?')} via {s.get('sessionname', '?')}"
                for s in active_sessions
            )
            findings.append(
                {
                    "severity": "info",
                    "title": f"{len(active_sessions)} total active session(s)",
                    "description": f"Active sessions: {all_users}",
                }
            )

        if not findings:
            findings.append(
                {
                    "severity": "info",
                    "title": "No interactive RDP sessions detected",
                    "description": "No active or disconnected RDP user sessions found.",
                }
            )

        # Determine overall status
        severities = [f["severity"] for f in findings]
        if "critical" in severities:
            status = "fail"
        elif "high" in severities:
            status = "fail"
        elif "medium" in severities:
            status = "warn"
        else:
            status = "pass"

        return {
            "category": "RDP Sessions",
            "status": status,
            "data": data,
            "findings": findings,
        }

    except Exception as exc:
        return {
            "category": "RDP Sessions",
            "status": "error",
            "data": {"error": str(exc), "traceback": traceback.format_exc()},
            "findings": [
                {
                    "severity": "info",
                    "title": "Error scanning RDP sessions",
                    "description": f"An unexpected error occurred: {exc}",
                }
            ],
        }
