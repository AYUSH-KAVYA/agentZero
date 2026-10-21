"""
Certificate Store Scanner
=========================
Enumerates certificates in the Windows Local Machine and Current User personal
stores, as well as the Trusted Root CA store.

Security Relevance:
- Expired certificates can cause service outages and may indicate abandoned infrastructure.
- Certificates with exportable private keys are at higher risk of key theft.
- Non-standard root CAs in the Trusted Root store can enable man-in-the-middle attacks
  (e.g., corporate SSL inspection, adware, or attacker-installed CAs).
- Rogue root certificates have been used in real-world attacks (Superfish, eDellRoot).

Data Sources:
- PowerShell: Get-ChildItem Cert:\\LocalMachine\\My
- PowerShell: Get-ChildItem Cert:\\CurrentUser\\My
- PowerShell: Get-ChildItem Cert:\\LocalMachine\\Root (Trusted Root CAs)
"""

import platform
import subprocess
import json
from datetime import datetime, timezone


# Well-known Microsoft / standard root CA thumbprints are too numerous to embed.
# Instead we check for non-Microsoft issuers in the root store.
_KNOWN_ROOT_ISSUERS = {
    "Microsoft",
    "VeriSign",
    "DigiCert",
    "GlobalSign",
    "Comodo",
    "Sectigo",
    "GoDaddy",
    "Entrust",
    "GeoTrust",
    "thawte",
    "Baltimore",
    "Starfield",
    "Symantec",
    "QuoVadis",
    "USERTrust",
    "AAA Certificate Services",
    "AddTrust",
    "Buypass",
    "Certum",
    "ISRG Root",  # Let's Encrypt
    "Amazon",
    "Actalis",
    "T-TeleSec",
    "D-TRUST",
    "CFCA",
    "SwissSign",
    "IdenTrust",
    "Trustwave",
    "SSL.com",
    "Hongkong Post",
    "TWCA",
    "Certigna",
    "emSign",
    "Staat der Nederlanden",
}


def _query_cert_store(store_path: str) -> list:
    """
    Query a Windows certificate store via PowerShell and return certificate details.

    Args:
        store_path: Certificate store path (e.g., 'Cert:\\LocalMachine\\My')

    Returns:
        List of certificate dictionaries.
    """
    ps_script = f"""
$certs = Get-ChildItem -Path '{store_path}' -ErrorAction SilentlyContinue | ForEach-Object {{
    [PSCustomObject]@{{
        Subject       = $_.Subject
        Issuer        = $_.Issuer
        Thumbprint    = $_.Thumbprint
        NotBefore     = $_.NotBefore.ToString('o')
        NotAfter      = $_.NotAfter.ToString('o')
        HasPrivateKey = $_.HasPrivateKey
        KeyUsage      = ($_.Extensions | Where-Object {{ $_ -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension] }} | ForEach-Object {{ $_.KeyUsages.ToString() }}) -join ','
        EnhancedKeyUsage = ($_.EnhancedKeyUsageList | ForEach-Object {{ $_.FriendlyName }}) -join ','
        FriendlyName  = $_.FriendlyName
        SerialNumber  = $_.SerialNumber
        SignatureAlgorithm = $_.SignatureAlgorithm.FriendlyName
    }}
}}
$certs | ConvertTo-Json -Depth 3
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        if isinstance(data, dict):
            data = [data]
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception):
        return []


def _is_known_root_issuer(issuer: str) -> bool:
    """Check if a root certificate issuer matches a well-known CA."""
    issuer_upper = issuer.upper()
    for known in _KNOWN_ROOT_ISSUERS:
        if known.upper() in issuer_upper:
            return True
    return False


def _check_exportable_private_keys(store_path: str) -> list:
    """Check if certificates have exportable private keys."""
    ps_script = f"""
$certs = Get-ChildItem -Path '{store_path}' -ErrorAction SilentlyContinue | Where-Object {{ $_.HasPrivateKey }}
$results = foreach ($cert in $certs) {{
    try {{
        $key = $cert.PrivateKey
        $exportable = $false
        if ($key -and $key.CspKeyContainerInfo) {{
            $exportable = $key.CspKeyContainerInfo.Exportable
        }}
        [PSCustomObject]@{{
            Thumbprint = $cert.Thumbprint
            Subject    = $cert.Subject
            Exportable = $exportable
        }}
    }} catch {{
        # Cannot access private key details
    }}
}}
$results | ConvertTo-Json -Depth 2
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []
        data = json.loads(result.stdout)
        if isinstance(data, dict):
            data = [data]
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception):
        return []


def scan() -> dict:
    """
    Scan certificate stores for expired certs, non-standard root CAs,
    and certificates with exportable private keys.

    Returns:
        dict with keys: category, status, data, findings
    """
    if platform.system() != "Windows":
        return {
            "category": "Certificates",
            "status": "error",
            "data": {},
            "findings": [{
                "severity": "info",
                "title": "Not a Windows system",
                "description": "This scanner only runs on Windows.",
            }],
        }

    try:
        findings = []

        # Query certificate stores
        machine_personal = _query_cert_store("Cert:\\LocalMachine\\My")
        user_personal = _query_cert_store("Cert:\\CurrentUser\\My")
        machine_root = _query_cert_store("Cert:\\LocalMachine\\Root")

        now = datetime.now(timezone.utc)

        # Check for expired certificates in personal stores
        for store_name, certs in [("LocalMachine\\My", machine_personal), ("CurrentUser\\My", user_personal)]:
            for cert in certs:
                try:
                    not_after_str = cert.get("NotAfter", "")
                    if not_after_str:
                        not_after = datetime.fromisoformat(not_after_str.replace("+00:00", "+00:00"))
                        if not_after.tzinfo is None:
                            not_after = not_after.replace(tzinfo=timezone.utc)
                        if not_after < now:
                            findings.append({
                                "severity": "medium",
                                "title": f"Expired certificate in {store_name}",
                                "description": (
                                    f"Certificate '{cert.get('Subject', 'Unknown')}' "
                                    f"(Thumbprint: {cert.get('Thumbprint', 'N/A')}) "
                                    f"expired on {not_after_str}."
                                ),
                                "remediation": (
                                    "Renew or remove the expired certificate. Expired certificates "
                                    "can cause service failures and may indicate abandoned infrastructure."
                                ),
                            })
                except (ValueError, TypeError):
                    pass

        # Check for non-standard root CAs
        non_standard_roots = []
        for cert in machine_root:
            issuer = cert.get("Issuer", "")
            subject = cert.get("Subject", "")
            if not _is_known_root_issuer(issuer) and not _is_known_root_issuer(subject):
                non_standard_roots.append({
                    "subject": subject,
                    "issuer": issuer,
                    "thumbprint": cert.get("Thumbprint", ""),
                    "not_after": cert.get("NotAfter", ""),
                })

        if non_standard_roots:
            for root in non_standard_roots:
                findings.append({
                    "severity": "high",
                    "title": "Non-standard root CA detected",
                    "description": (
                        f"A non-standard certificate authority is installed in the Trusted Root store: "
                        f"Subject='{root['subject']}', Issuer='{root['issuer']}', "
                        f"Thumbprint={root['thumbprint']}. This could enable TLS interception "
                        f"or man-in-the-middle attacks."
                    ),
                    "remediation": (
                        "Verify this root CA is legitimate and authorized by your organization. "
                        "If not recognized, remove it from Cert:\\LocalMachine\\Root immediately. "
                        "Known malicious root CAs include Superfish and eDellRoot."
                    ),
                })

        # Check for exportable private keys
        for store_path, store_label in [
            ("Cert:\\LocalMachine\\My", "LocalMachine\\My"),
            ("Cert:\\CurrentUser\\My", "CurrentUser\\My"),
        ]:
            exportable_certs = _check_exportable_private_keys(store_path)
            for ec in exportable_certs:
                if ec.get("Exportable", False):
                    findings.append({
                        "severity": "medium",
                        "title": f"Certificate with exportable private key in {store_label}",
                        "description": (
                            f"Certificate '{ec.get('Subject', 'Unknown')}' "
                            f"(Thumbprint: {ec.get('Thumbprint', 'N/A')}) has an exportable "
                            f"private key. An attacker with access to this machine could export "
                            f"the key and impersonate this certificate."
                        ),
                        "remediation": (
                            "Re-import the certificate with the private key marked as non-exportable, "
                            "or use a Hardware Security Module (HSM) / TPM to protect the key."
                        ),
                    })

        # Determine status
        if any(f["severity"] in ("critical", "high") for f in findings):
            status = "fail"
        elif any(f["severity"] == "medium" for f in findings):
            status = "warn"
        elif findings:
            status = "info"
        else:
            status = "pass"

        return {
            "category": "Certificates",
            "status": status,
            "data": {
                "local_machine_personal_count": len(machine_personal),
                "current_user_personal_count": len(user_personal),
                "trusted_root_ca_count": len(machine_root),
                "non_standard_root_cas": len(non_standard_roots),
                "local_machine_personal": machine_personal,
                "current_user_personal": user_personal,
                "trusted_root_cas": machine_root,
            },
            "findings": findings,
        }

    except Exception as e:
        return {
            "category": "Certificates",
            "status": "error",
            "data": {"error": str(e)},
            "findings": [{
                "severity": "info",
                "title": "Scanner error",
                "description": f"An unexpected error occurred while scanning certificates: {e}",
            }],
        }
