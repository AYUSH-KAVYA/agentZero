"""
Network Diagram & Topology Generator
====================================
Formulates interactive topology graph models and SVG network diagrams
from discovered interfaces, ARP tables, open ports, and VLAN vectors.
"""

from typing import Dict, Any, List


class NetworkDiagramGenerator:
    """Generates structured network topology graph models and SVG renders."""

    @staticmethod
    def generate_topology_model(
        interfaces: List[Dict[str, Any]],
        arp_entries: List[Dict[str, Any]],
        connections: List[Dict[str, Any]],
        vlan_devices: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Formulate node-link graph model for React / D3 rendering and report embedding.
        """
        nodes = []
        links = []
        added_node_ids = set()

        # 1. Central Host Node
        host_ip = "127.0.0.1"
        for iface in interfaces:
            ip = iface.get("IPv4Address")
            if ip and not ip.startswith("127."):
                host_ip = ip
                break

        nodes.append({
            "id": "host",
            "label": "Audit Host (Local)",
            "ip": host_ip,
            "type": "target",
            "status": "normal",
            "x": 400,
            "y": 220
        })
        added_node_ids.add("host")

        # 2. Gateway / Router Node
        gw_found = False
        for entry in arp_entries:
            ip = entry.get("ip", "")
            if ip.endswith(".1") or entry.get("type") == "Gateway Router":
                nodes.append({
                    "id": "gw",
                    "label": "Default Gateway Switch",
                    "ip": ip,
                    "type": "router",
                    "status": "normal",
                    "mac": entry.get("mac", ""),
                    "x": 160,
                    "y": 120
                })
                links.append({
                    "source": "host",
                    "target": "gw",
                    "protocol": "Default Route / ARP",
                    "active": True
                })
                added_node_ids.add("gw")
                gw_found = True
                break

        if not gw_found:
            nodes.append({
                "id": "gw",
                "label": "Network Gateway",
                "ip": "192.168.1.1",
                "type": "router",
                "status": "normal",
                "x": 160,
                "y": 120
            })
            links.append({"source": "host", "target": "gw", "protocol": "Default Gateway", "active": True})
            added_node_ids.add("gw")

        # 3. Add VLAN devices as nodes
        vlan_count = 0
        positions = [
            (640, 120), (640, 320), (160, 320), (400, 70), (400, 370)
        ]

        for dev in vlan_devices:
            dev_ip = dev.get("ip")
            if dev_ip and dev_ip != host_ip and dev_ip != "192.168.1.1":
                nid = f"vlan_{vlan_count}"
                if nid not in added_node_ids:
                    pos = positions[vlan_count % len(positions)]
                    nodes.append({
                        "id": nid,
                        "label": dev.get("hostname") or f"Host {dev_ip}",
                        "ip": dev_ip,
                        "type": "server" if dev_ip.endswith(".20") else "client",
                        "status": "normal",
                        "x": pos[0],
                        "y": pos[1]
                    })
                    links.append({
                        "source": "host",
                        "target": nid,
                        "protocol": "VLAN Neighbor / NetBIOS",
                        "active": False
                    })
                    added_node_ids.add(nid)
                    vlan_count += 1
                    if vlan_count >= 5:
                        break

        # 4. Add established remote connection nodes
        for c in connections:
            remote = c.get("remote", "")
            if remote and ":" in remote and not remote.startswith("0.0.0.0") and not remote.startswith("127."):
                r_ip = remote.split(":")[0]
                if r_ip and r_ip != host_ip and r_ip not in [n["ip"] for n in nodes]:
                    nid = f"remote_{len(nodes)}"
                    nodes.append({
                        "id": nid,
                        "label": f"Active Peer ({c.get('process', 'Socket')})",
                        "ip": r_ip,
                        "type": "client",
                        "status": "active",
                        "x": 160,
                        "y": 320
                    })
                    links.append({
                        "source": nid,
                        "target": "host",
                        "protocol": f"{c.get('proto', 'TCP')} :{c.get('local', '').split(':')[-1]}",
                        "active": True
                    })
                    break

        return {
            "topology_nodes": nodes,
            "topology_links": links
        }

    @staticmethod
    def generate_svg(topology_model: Dict[str, Any]) -> str:
        """Render self-contained SVG network diagram for report embedding."""
        nodes = topology_model.get("topology_nodes", [])
        links = topology_model.get("topology_links", [])

        svg_lines = [
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 450" width="100%" height="100%" style="background-color: #060911;">',
            '  <defs>',
            '    <linearGradient id="linkGrad" x1="0%" y1="0%" x2="100%" y2="100%">',
            '      <stop offset="0%" stop-color="#00ff88" stop-opacity="0.8"/>',
            '      <stop offset="100%" stop-color="#38bdf8" stop-opacity="0.8"/>',
            '    </linearGradient>',
            '  </defs>'
        ]

        # Draw links
        for link in links:
            s_node = next((n for n in nodes if n["id"] == link["source"]), None)
            t_node = next((n for n in nodes if n["id"] == link["target"]), None)
            if s_node and t_node:
                stroke = "url(#linkGrad)" if link.get("active") else "#374151"
                dash = 'stroke-dasharray="4 2"' if link.get("active") else ''
                svg_lines.append(
                    f'  <line x1="{s_node["x"]}" y1="{s_node["y"]}" x2="{t_node["x"]}" y2="{t_node["y"]}" '
                    f'stroke="{stroke}" stroke-width="2" {dash} />'
                )

        # Draw nodes
        for node in nodes:
            is_host = node["type"] == "target"
            color = "#00ff88" if is_host else "#38bdf8"
            bg = "#111827"
            svg_lines.append(f'  <g transform="translate({node["x"] - 60}, {node["y"] - 25})">')
            svg_lines.append(f'    <rect width="120" height="50" rx="8" fill="{bg}" stroke="{color}" stroke-width="1.5"/>')
            svg_lines.append(f'    <text x="60" y="20" fill="#ffffff" font-size="11" font-family="sans-serif" font-weight="bold" text-anchor="middle">{node["label"][:16]}</text>')
            svg_lines.append(f'    <text x="60" y="38" fill="#38bdf8" font-size="10" font-family="monospace" text-anchor="middle">{node["ip"]}</text>')
            svg_lines.append('  </g>')

        svg_lines.append('</svg>')
        return "\n".join(svg_lines)
