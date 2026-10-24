"""
Network Scanner Runner — Orchestrates all network reconnaissance modules.
Coordinates interface enumeration, ARP sweep, port checks, RPC endpoint mapping,
LLDP/CDP neighbor discovery, and network topology diagram generation.
"""

import time
import traceback
from typing import Callable, Optional, Dict, Any

from . import (
    interfaces,
    arp_table,
    dns_cache,
    network_profiles,
    network_shares,
    connections,
    rpc_endpoints,
    open_ports,
    lldp_cdp,
    vlan_devices,
)
from .diagram_generator import NetworkDiagramGenerator


MODULES = [
    {"key": "interfaces", "module": interfaces, "label": "System Interface Connectors"},
    {"key": "arp_table", "module": arp_table, "label": "ARP Table & Adapter Info"},
    {"key": "dns_cache", "module": dns_cache, "label": "DNS Cache & Resolvers"},
    {"key": "network_profiles", "module": network_profiles, "label": "macOS Network Services & Profiles"},
    {"key": "network_shares", "module": network_shares, "label": "Mounted & Shared File Systems"},
    {"key": "connections", "module": connections, "label": "Active TCP Sockets"},
    {"key": "rpc_endpoints", "module": rpc_endpoints, "label": "Bonjour & Network Services"},
    {"key": "open_ports", "module": open_ports, "label": "Listening Ports & Services"},
    {"key": "lldp_cdp", "module": lldp_cdp, "label": "LLDP/CDP Infrastructure"},
    {"key": "vlan_devices", "module": vlan_devices, "label": "Attached VLAN Vectors"},
]


class NetworkScanRunner:
    """Orchestrates the execution of all network scanner modules."""

    def __init__(self, progress_callback: Optional[Callable] = None, ip_range: Optional[str] = None):
        self.progress_callback = progress_callback or (lambda *a, **kw: None)
        self.ip_range = ip_range

    def _emit(self, progress: int, module: str, status: str = "scanning") -> None:
        try:
            self.progress_callback(progress, module, status)
        except Exception:
            pass

    def run_all(self) -> Dict[str, Any]:
        """Run all network reconnaissance modules sequentially."""
        self._emit(0, "Network Scanner", "starting")

        total = len(MODULES)
        results = {
            "scan_type": "network",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "modules": {},
            "topology_nodes": [],
            "topology_links": [],
            "network_diagram_svg": "",
            "summary": {
                "total_modules": total,
                "completed": 0,
                "errors": 0,
            },
        }

        for i, mod_info in enumerate(MODULES):
            progress = int((i / total) * 90)
            self._emit(progress, mod_info["label"], "scanning")

            try:
                mod_result = mod_info["module"].scan(ip_range=self.ip_range)
                results["modules"][mod_info["key"]] = mod_result
                results["summary"]["completed"] += 1
            except Exception as e:
                results["modules"][mod_info["key"]] = {
                    "category": mod_info["label"],
                    "status": "error",
                    "data": {"error": str(e), "traceback": traceback.format_exc()},
                    "findings": []
                }
                results["summary"]["errors"] += 1

        self._emit(92, "Formulating Network Topology", "processing")

        # Formulate network topology diagram
        try:
            ifaces = results["modules"].get("interfaces", {}).get("data", [])
            arp_data = results["modules"].get("arp_table", {}).get("data", [])
            conn_data = results["modules"].get("connections", {}).get("data", [])
            vlan_data = results["modules"].get("vlan_devices", {}).get("data", [])

            topo = NetworkDiagramGenerator.generate_topology_model(
                interfaces=ifaces,
                arp_entries=arp_data,
                connections=conn_data,
                vlan_devices=vlan_data,
            )
            results["topology_nodes"] = topo["topology_nodes"]
            results["topology_links"] = topo["topology_links"]
            results["network_diagram_svg"] = NetworkDiagramGenerator.generate_svg(topo)
        except Exception as e:
            results["topology_error"] = str(e)

        self._emit(100, "Network Scanner", "complete")
        return results
