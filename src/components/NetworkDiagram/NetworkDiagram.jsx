import React, { useState } from 'react';
import { Shield, Server, Router, HardDrive, Laptop, Globe, CheckCircle, AlertTriangle, XCircle } from 'lucide-react';

export default function NetworkDiagram({ topologyData }) {
  const [selectedNode, setSelectedNode] = useState(null);
  const [filterType, setFilterType] = useState('all');

  const defaultNodes = [
    { id: 'host', label: 'Local Windows Host', ip: '192.168.1.105', type: 'target', status: 'warning', role: 'Audit Target', x: 400, y: 220 },
    { id: 'gw', label: 'Default Gateway Router', ip: '192.168.1.1', type: 'router', status: 'normal', role: 'Cisco Core Switch', x: 150, y: 100 },
    { id: 'dc', label: 'Domain Controller (DC01)', ip: '192.168.1.20', type: 'server', status: 'normal', role: 'Active Directory / DNS', x: 650, y: 100 },
    { id: 'nas', label: 'Storage NAS', ip: '192.168.1.45', type: 'storage', status: 'normal', role: 'SMB File Server', x: 650, y: 340 },
    { id: 'client', label: 'VLAN Workstation', ip: '192.168.1.150', type: 'client', status: 'active', role: 'Inbound RDP Client', x: 150, y: 340 },
  ];

  const defaultLinks = [
    { source: 'host', target: 'gw', label: 'Default Route / ARP', active: true },
    { source: 'host', target: 'dc', label: 'Kerberos :88 / DNS :53', active: true },
    { source: 'host', target: 'nas', label: 'SMB Share :445', active: false },
    { source: 'client', target: 'host', label: 'RDP :3389 [ESTABLISHED]', active: true },
  ];

  const nodes = topologyData?.topology_nodes?.map((n, idx) => {
    const fallback = defaultNodes[idx] || { x: 200 + (idx * 100), y: 150 + (idx * 50) };
    return { ...fallback, ...n };
  }) || defaultNodes;

  const links = topologyData?.topology_links || defaultLinks;

  const getNodeIcon = (type) => {
    switch (type) {
      case 'target':
        return <Shield className="w-5 h-5 text-cyber-accent" />;
      case 'router':
        return <Router className="w-5 h-5 text-blue-400" />;
      case 'server':
        return <Server className="w-5 h-5 text-purple-400" />;
      case 'storage':
        return <HardDrive className="w-5 h-5 text-amber-400" />;
      default:
        return <Laptop className="w-5 h-5 text-emerald-400" />;
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'warning':
        return <AlertTriangle className="w-3.5 h-3.5 text-cyber-warning" />;
      case 'danger':
        return <XCircle className="w-3.5 h-3.5 text-cyber-danger" />;
      default:
        return <CheckCircle className="w-3.5 h-3.5 text-cyber-accent" />;
    }
  };

  const filteredNodes = nodes.filter((n) => filterType === 'all' || n.type === filterType);

  return (
    <div className="cyber-card relative overflow-hidden">
      <div className="flex items-center justify-between mb-4 border-b border-cyber-border/70 pb-3">
        <div>
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <Globe className="w-4 h-4 text-cyber-accent" />
            Interactive Network Topology
          </h3>
          <p className="text-xs text-gray-400">
            Discovered nodes, VLAN devices, and mapped inbound/outbound connection vectors
          </p>
        </div>
        <div className="flex gap-2">
          {['all', 'target', 'router', 'server', 'client'].map((t) => (
            <button
              key={t}
              onClick={() => setFilterType(t)}
              className={`px-2.5 py-1 text-xs rounded font-medium uppercase tracking-wider transition-colors ${
                filterType === t
                  ? 'bg-cyber-accent text-cyber-dark'
                  : 'bg-cyber-darker text-gray-400 hover:text-white border border-cyber-border'
              }`}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      <div className="relative w-full h-[420px] bg-cyber-darker rounded-lg border border-cyber-border overflow-hidden">
        {/* Background Grid */}
        <div
          className="absolute inset-0 opacity-15"
          style={{
            backgroundImage: 'radial-gradient(#38bdf8 1px, transparent 1px)',
            backgroundSize: '24px 24px',
          }}
        />

        {/* SVG Connections Canvas */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none">
          <defs>
            <linearGradient id="cyberLine" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#00ff88" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.8" />
            </linearGradient>
          </defs>
          {links.map((link, idx) => {
            const src = nodes.find((n) => n.id === link.source) || defaultNodes[0];
            const tgt = nodes.find((n) => n.id === link.target) || defaultNodes[1];
            return (
              <g key={idx}>
                <line
                  x1={src.x || 200}
                  y1={src.y || 150}
                  x2={tgt.x || 300}
                  y2={tgt.y || 200}
                  stroke={link.active ? 'url(#cyberLine)' : '#374151'}
                  strokeWidth={link.active ? 2 : 1}
                  strokeDasharray={link.active ? '4 2' : 'none'}
                />
                <circle
                  cx={(src.x + tgt.x) / 2}
                  cy={(src.y + tgt.y) / 2}
                  r="3"
                  fill="#00ff88"
                  className={link.active ? 'animate-pulse' : 'hidden'}
                />
              </g>
            );
          })}
        </svg>

        {/* Node Badges */}
        {filteredNodes.map((node) => {
          const isSelected = selectedNode?.id === node.id;
          return (
            <div
              key={node.id}
              onClick={() => setSelectedNode(node)}
              style={{ left: `${node.x - 70}px`, top: `${node.y - 35}px` }}
              className={`absolute cursor-pointer transition-all duration-300 w-[140px] p-2.5 rounded-lg border flex flex-col items-center text-center shadow-lg backdrop-blur-md ${
                isSelected
                  ? 'bg-cyber-card/95 border-cyber-accent ring-2 ring-cyber-accent/40 scale-105 z-20'
                  : 'bg-cyber-card/85 border-cyber-border hover:border-cyber-accent/60 hover:scale-102 z-10'
              }`}
            >
              <div className="flex items-center justify-between w-full mb-1">
                <div className="p-1 rounded bg-white/5">{getNodeIcon(node.type)}</div>
                {getStatusBadge(node.status)}
              </div>
              <p className="text-xs font-semibold text-white truncate w-full">{node.label}</p>
              <p className="text-[11px] font-mono text-cyan-400 mt-0.5">{node.ip}</p>
            </div>
          );
        })}

        {/* Selected Node Inspector Drawer */}
        {selectedNode && (
          <div className="absolute right-3 top-3 bottom-3 w-72 bg-cyber-card/95 border border-cyber-border rounded-lg p-4 shadow-xl z-30 flex flex-col justify-between backdrop-blur-md">
            <div>
              <div className="flex items-center justify-between border-b border-cyber-border pb-2 mb-3">
                <div className="flex items-center gap-2">
                  {getNodeIcon(selectedNode.type)}
                  <span className="text-sm font-bold text-white truncate max-w-[170px]">
                    {selectedNode.label}
                  </span>
                </div>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="text-gray-400 hover:text-white text-xs px-1.5 py-0.5 rounded bg-white/5"
                >
                  ✕
                </button>
              </div>

              <div className="space-y-2 text-xs">
                <div>
                  <span className="text-gray-400">IP Address:</span>
                  <p className="font-mono text-cyan-400">{selectedNode.ip}</p>
                </div>
                <div>
                  <span className="text-gray-400">Node Role:</span>
                  <p className="text-white">{selectedNode.role || 'Network Endpoint'}</p>
                </div>
                <div>
                  <span className="text-gray-400">Subsystem Status:</span>
                  <p className="capitalize text-cyber-accent">{selectedNode.status || 'Active'}</p>
                </div>
                <div>
                  <span className="text-gray-400">Audit Status:</span>
                  <p className="text-gray-300">
                    {selectedNode.type === 'target'
                      ? 'Local Host Under Full Audit'
                      : 'Neighbor Vector via ARP / Netstat'}
                  </p>
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-cyber-border">
              <span className="text-[11px] text-gray-500">AgentZero Network Graph Engine</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
