import React, { useState } from 'react';
import { useScan } from '../../context/ScanContext';
import NetworkDiagram from '../NetworkDiagram/NetworkDiagram';
import { Network, Activity, Radio, Share2, Layers, AlertCircle, Play } from 'lucide-react';

export default function NetworkScan() {
  const { networkResults, isScanning, startScan } = useScan();
  const [activeTab, setActiveTab] = useState('topology');

  const modules = networkResults?.modules || {};

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-cyber-card p-5 rounded-xl border border-cyber-border">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-tight">Network Reconnaissance & Vectors</h2>
          <p className="text-xs text-gray-400 mt-1">
            Maps VLAN attached vectors, open RPC endpoints, active socket connections, and exposed shares
          </p>
        </div>

        <button
          onClick={() => startScan('network')}
          disabled={isScanning}
          className="cyber-btn-primary text-xs flex items-center gap-2 self-start md:self-auto disabled:opacity-50"
        >
          {isScanning ? 'Probing Network...' : '▶ Audit Network'}
        </button>
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-cyber-border pb-3">
        {[
          { id: 'topology', label: 'Network Diagram', icon: Network },
          { id: 'ports', label: 'Open Ports & Services', icon: Radio },
          { id: 'connections', label: 'Active Connections', icon: Activity },
          { id: 'arp', label: 'ARP Table & Neighbors', icon: Layers },
          { id: 'shares', label: 'Network Shares', icon: Share2 },
        ].map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold transition-all ${
                activeTab === tab.id
                  ? 'bg-cyber-accent text-cyber-dark shadow'
                  : 'bg-cyber-card text-gray-400 hover:text-white border border-cyber-border'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Content */}
      {activeTab === 'topology' && (
        <NetworkDiagram topologyData={networkResults} />
      )}

      {activeTab === 'ports' && (
        <div className="cyber-card">
          <div className="flex items-center justify-between mb-4 border-b border-cyber-border pb-2">
            <h3 className="text-sm font-semibold text-white">Listening Ports & Associated Services</h3>
            <span className="text-xs text-gray-400 font-mono">
              {modules.open_ports?.data?.length || 0} Ports Monitored
            </span>
          </div>

          {modules.open_ports?.data ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-cyber-darker text-gray-400 uppercase text-[10px] font-mono">
                  <tr>
                    <th className="p-3">Port</th>
                    <th className="p-3">Protocol</th>
                    <th className="p-3">State</th>
                    <th className="p-3">Service Name</th>
                    <th className="p-3">Process</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-border text-gray-300">
                  {modules.open_ports.data.map((p, idx) => (
                    <tr key={idx} className="hover:bg-white/5 transition-colors">
                      <td className="p-3 font-mono font-bold text-cyber-accent">{p.port}</td>
                      <td className="p-3 font-mono">{p.protocol}</td>
                      <td className="p-3">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          {p.state}
                        </span>
                      </td>
                      <td className="p-3 font-medium text-white">{p.service}</td>
                      <td className="p-3 font-mono text-gray-400">{p.process || 'Unknown'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-12 text-xs text-gray-500">
              No port scan data available. Run network scan to enumerate endpoints.
            </div>
          )}
        </div>
      )}

      {activeTab === 'connections' && (
        <div className="cyber-card">
          <div className="flex items-center justify-between mb-4 border-b border-cyber-border pb-2">
            <h3 className="text-sm font-semibold text-white">Established & Listening Sockets</h3>
            <span className="text-xs text-gray-400 font-mono">
              {modules.connections?.data?.length || 0} Sockets
            </span>
          </div>

          {modules.connections?.data ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-cyber-darker text-gray-400 uppercase text-[10px] font-mono">
                  <tr>
                    <th className="p-3">Proto</th>
                    <th className="p-3">Local Address</th>
                    <th className="p-3">Foreign Address</th>
                    <th className="p-3">State</th>
                    <th className="p-3">PID / Process</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-border text-gray-300 font-mono">
                  {modules.connections.data.map((c, idx) => (
                    <tr key={idx} className="hover:bg-white/5 transition-colors">
                      <td className="p-3 text-cyan-400 font-bold">{c.proto}</td>
                      <td className="p-3">{c.local}</td>
                      <td className="p-3">{c.remote}</td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] ${
                          c.state === 'ESTABLISHED'
                            ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                            : 'bg-gray-500/20 text-gray-400'
                        }`}>
                          {c.state}
                        </span>
                      </td>
                      <td className="p-3 text-gray-400">{c.process || c.pid}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-12 text-xs text-gray-500">
              No connection records found.
            </div>
          )}
        </div>
      )}

      {activeTab === 'arp' && (
        <div className="cyber-card">
          <div className="flex items-center justify-between mb-4 border-b border-cyber-border pb-2">
            <h3 className="text-sm font-semibold text-white">ARP Cache & Neighbor Vectors</h3>
            <span className="text-xs text-gray-400 font-mono">VLAN Devices</span>
          </div>

          {modules.arp_table?.data ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-cyber-darker text-gray-400 uppercase text-[10px] font-mono">
                  <tr>
                    <th className="p-3">IP Address</th>
                    <th className="p-3">MAC Address</th>
                    <th className="p-3">Device / Node Type</th>
                    <th className="p-3">Hardware Vendor</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-border text-gray-300">
                  {modules.arp_table.data.map((a, idx) => (
                    <tr key={idx} className="hover:bg-white/5 transition-colors">
                      <td className="p-3 font-mono font-bold text-white">{a.ip}</td>
                      <td className="p-3 font-mono text-cyan-400">{a.mac}</td>
                      <td className="p-3">{a.type || 'Dynamic Neighbor'}</td>
                      <td className="p-3 text-gray-400">{a.vendor || 'Unknown'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-12 text-xs text-gray-500">
              No ARP entries recorded.
            </div>
          )}
        </div>
      )}

      {activeTab === 'shares' && (
        <div className="cyber-card">
          <div className="flex items-center justify-between mb-4 border-b border-cyber-border pb-2">
            <h3 className="text-sm font-semibold text-white">Exposed Network Shares</h3>
            <span className="text-xs text-gray-400 font-mono">SMB Endpoints</span>
          </div>

          {modules.network_shares?.data ? (
            <div className="space-y-2.5">
              {modules.network_shares.data.map((s, idx) => (
                <div key={idx} className="p-3 bg-cyber-dark rounded-lg border border-cyber-border flex items-center justify-between">
                  <div>
                    <span className="text-xs font-bold text-white font-mono">{s.name}</span>
                    <p className="text-[11px] text-gray-400 font-mono mt-0.5">{s.path || 'Virtual Pipe'}</p>
                  </div>
                  <span className="text-xs text-gray-400">{s.remark || 'Active Share'}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12 text-xs text-gray-500">
              No network shares detected.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
