"""
Antivirus Status Scanner Module
================================
Queries the WMI SecurityCenter2 namespace to discover registered antivirus products,
their enabled state, definition update status, and real-time protection status.

Security Relevance:
- Systems without registered antivirus are at high risk of malware infection.
- Disabled antivirus or outdated definitions significantly reduce protection.
- The productState bitmask reveals the true operational state of each AV product.
"""

import platform
import subprocess
import json


def _parse_product_state(product_state: int) -> dict:
    """
    Parse the WMI AntiVirusProduct productState bitmask.

    The productState is a 3-byte value:
    - Byte 1 (bits 16-23): Product owner / provider
    - Byte 2 (bits 8-15): Scanner status
      - Bit 12 (0x1000): Real-time protection enabled
    - Byte 3 (bits 0-7): Definition status
      - 0x00: Up to date
      - 0x10: Out of date

    Common productState values:
    - 266240 (0x41000): Enabled, up to date
    - 262144 (0x40000): Disabled, up to date
    - 393472 (0x60100): Enabled, out of date
    - 393216 (0x60000): Disabled, out of date
    """
    result = {
        "raw_state": product_state,
        "hex_state": hex(product_state) if isinstance(product_state, int) else str(product_state),
    }

    try:
        state = int(product_state)

        # Byte 2: Check if real-time protection is enabled (bit 12)
        scanner_byte = (state >> 8) & 0xFF
        result["real_time_protection"] = bool(scanner_byte & 0x10)
        result["enabled"] = bool(scanner_byte & 0x10)

        # Byte 3: Check definition status
        definition_byte = state & 0xFF
        result["definitions_up_to_date"] = (definition_byte == 0x00)

    except (ValueError, TypeError):
        result["real_time_protection"] = None
        result["enabled"] = None
        result["definitions_up_to_date"] = None

    return result


def scan() -> dict:
    """
    Scans for registered antivirus products via WMI SecurityCenter2.

    Returns:
        dict with keys:
        - 'category': str — Human-readable category name
        - 'status': str — One of 'pass', 'warn', 'fail', 'info', 'error'
        - 'data': dict — Raw extracted data
        - 'findings': list[dict] — Each finding has 'severity', 'title', 'description', and optional 'remediation'
    """
    category = "Antivirus Status"
    data = {}
    findings = []
    status = "pass"

    if platform.system() != "Windows":
        return {
            "category": category,
            "status": "error",
            "data": {},
            "findings": [{
                "severity": "info",
                "title": "Not a Windows system",
                "description": f"This module only supports Windows. Detected OS: {platform.system()}"
            }]
        }

    try:
        # Query WMI SecurityCenter2 for antivirus products
        ps_command = r"""
        try {
            $avProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction Stop
            if ($avProducts -eq $null) {
                @{ products = @(); error = $null } | ConvertTo-Json -Depth 5
            } else {
                $productList = @()
                foreach ($av in $avProducts) {
                    $productList += @{
                        displayName = $av.displayName
                        instanceGuid = $av.instanceGuid
                        pathToSignedProductExe = $av.pathToSignedProductExe
                        pathToSignedReportingExe = $av.pathToSignedReportingExe
                        productState = $av.productState
                        timestamp = $av.timestamp
                    }
                }
                @{ products = $productList; error = $null } | ConvertTo-Json -Depth 5
            }
        } catch {
            @{ products = @(); error = $_.Exception.Message } | ConvertTo-Json -Depth 5
        }
        """

        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_command],
            capture_output=True, text=True, timeout=30
        )

        products = []
        wmi_error = None

        if result.returncode == 0 and result.stdout.strip():
            try:
                parsed = json.loads(result.stdout.strip())
                wmi_error = parsed.get("error")
                raw_products = parsed.get("products", [])

                # Ensure raw_products is a list (single item comes as dict)
                if isinstance(raw_products, dict):
                    raw_products = [raw_products]

                for product in raw_products:
                    product_state = product.get("productState", 0)
                    state_info = _parse_product_state(product_state)

                    products.append({
                        "display_name": product.get("displayName", "Unknown"),
                        "instance_guid": product.get("instanceGuid", ""),
                        "exe_path": product.get("pathToSignedProductExe", ""),
                        "reporting_exe_path": product.get("pathToSignedReportingExe", ""),
                        "product_state": product_state,
                        "timestamp": product.get("timestamp", ""),
                        "real_time_protection": state_info.get("real_time_protection"),
                        "enabled": state_info.get("enabled"),
                        "definitions_up_to_date": state_info.get("definitions_up_to_date"),
                        "state_hex": state_info.get("hex_state"),
                    })

            except json.JSONDecodeError as e:
                wmi_error = f"Failed to parse WMI output: {str(e)}"
        else:
            wmi_error = result.stderr.strip() if result.stderr else "PowerShell command failed"

        data["products"] = products
        data["product_count"] = len(products)
        if wmi_error:
            data["wmi_error"] = wmi_error

        # Analyze findings

        # No antivirus registered at all
        if len(products) == 0:
            if wmi_error and ("invalid namespace" in wmi_error.lower() or "not supported" in wmi_error.lower()):
                # SecurityCenter2 not available (e.g., Windows Server)
                findings.append({
                    "severity": "info",
                    "title": "SecurityCenter2 Not Available",
                    "description": (
                        "The WMI SecurityCenter2 namespace is not available on this system. "
                        "This is normal for Windows Server editions. Antivirus status should be "
                        "verified through the specific AV product's management console."
                    ),
                    "remediation": "Verify antivirus status through the installed AV product's management interface or Group Policy."
                })
                status = "info"
            else:
                findings.append({
                    "severity": "critical",
                    "title": "No Antivirus Product Registered",
                    "description": (
                        "No antivirus product is registered with Windows Security Center. "
                        "The system may be unprotected against malware, ransomware, and other threats."
                    ),
                    "remediation": (
                        "Install and activate a reputable antivirus solution. Windows Defender is included "
                        "with Windows 10/11 and should be enabled at minimum."
                    )
                })
                status = "fail"

        # Check each registered product
        for product in products:
            name = product.get("display_name", "Unknown AV")

            # Check if AV is disabled
            if product.get("enabled") is False:
                findings.append({
                    "severity": "high",
                    "title": f"Antivirus Disabled: {name}",
                    "description": (
                        f"The antivirus product '{name}' is registered but real-time protection "
                        f"is disabled (productState: {product.get('state_hex', 'N/A')}). "
                        f"The system is not actively protected."
                    ),
                    "remediation": f"Enable real-time protection in {name} settings immediately."
                })
                status = "fail"

            # Check if definitions are outdated
            if product.get("definitions_up_to_date") is False:
                findings.append({
                    "severity": "high",
                    "title": f"Antivirus Definitions Outdated: {name}",
                    "description": (
                        f"The antivirus product '{name}' has outdated virus definitions "
                        f"(productState: {product.get('state_hex', 'N/A')}). "
                        f"New threats will not be detected."
                    ),
                    "remediation": f"Update virus definitions for {name}. Ensure automatic updates are enabled."
                })
                if status != "fail":
                    status = "warn"

            # Check if real-time protection is off
            if product.get("real_time_protection") is False and product.get("enabled") is not False:
                findings.append({
                    "severity": "high",
                    "title": f"Real-Time Protection Off: {name}",
                    "description": (
                        f"Real-time protection is disabled for '{name}'. Files and downloads "
                        f"are not being scanned in real-time."
                    ),
                    "remediation": f"Enable real-time protection in {name}."
                })
                if status != "fail":
                    status = "fail"

    except Exception as e:
        return {
            "category": category,
            "status": "error",
            "data": data,
            "findings": [{
                "severity": "info",
                "title": "Antivirus Scan Error",
                "description": f"An unexpected error occurred while scanning antivirus status: {str(e)}"
            }]
        }

    return {
        "category": category,
        "status": status,
        "data": data,
        "findings": findings
    }
