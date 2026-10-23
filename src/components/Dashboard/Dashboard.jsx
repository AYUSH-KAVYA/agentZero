import React, { useState } from 'react';
import { useScan } from '../../context/ScanContext';
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  Terminal,
  AlertTriangle,
  Play,
  RotateCcw,
  Sparkles,
  Server,
  Network,
  Bug,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';

export default function Dashboard() {
  const {
    isScanning,
    progress,
    currentModule,
    systemResults,
    networkResults,
    vulnResults,
    posture,
    lastScanTime,
    isAdmin,
    error,
    logs,
    isMockData,
    startScan,
    cancelScan,
    loadMockData,
    clearError,
    clearLogs,
  } = useScan();

  const [showTerminal, setShowTerminal] = useState(true);

  // Compute stats
  const totalSystemModules = systemResults?.modules ? Object.keys(systemResults.modules).length : 0;
  const totalFindings = vulnResults?.total ?? (
    (systemResults?.summary?.findings_by_severity?.critical || 0) +
    (systemResults?.summary?.findings_by_severity?.high || 0) +
    (systemResults?.summary?.findings_by_severity?.medium || 0)
  );
  const criticalCount = vulnResults?.critical ?? systemResults?.summary?.findings_by_severity?.critical ?? 0;
  const highCount = vulnResults?.high ?? systemResults?.summary?.findings_by_severity?.high ?? 0;
  const mediumCount = vulnResults?.medium ?? systemResults?.summary?.findings_by_severity?.medium ?? 0;
  const lowCount = vulnResults?.low ?? systemResults?.summary?.findings_by_severity?.low ?? 0;

  const exploitsAvailableCount = (vulnResults?.findings || []).filter((f) => f.exploit_available).length;
  const cisScore = vulnResults?.cis_benchmark?.score ?? 0;

  const severityChartData = [
    { name: 'Critical', value: criticalCount, color: '#ef4444' },
    { name: 'High', value: highCount, color: '#f97316' },
    { name: 'Medium', value: mediumCount, color: '#eab308' },
    { name: 'Low', value: lowCount, color: '#3b82f6' },
  ].filter((d) => d.value > 0);

  const postureScore = posture?.score ?? (totalFindings > 0 ? Math.max(10, 100 - totalFindings * 12) : 100);
  const postureGrade = posture?.grade ?? (postureScore > 85 ? 'A' : postureScore > 70 ? 'B' : postureScore > 50 ? 'C' : 'F');

  return (
    <div className="space-y-6 pb-8">
      {/* Top Banner & Scan Triggers */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-cyber-card p-5 rounded-xl border border-cyber-border shadow-lg">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-2xl font-bold text-white tracking-tight">Security Command Center</h2>
            {isMockData && (
              <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                Evaluation Demo Profile
              </span>
            )}
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Agent-less Windows host vulnerability & network reconnaissance engine
            {lastScanTime && ` • Last audit: ${new Date(lastScanTime).toLocaleString()}`}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={loadMockData}
            title="Load sample Windows 11 Enterprise findings for macOS development & UI testing"
            className="cyber-btn-secondary text-xs flex items-center gap-1.5"
          >
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            Load Sample Profile
          </button>

          {isScanning ? (
            <button onClick={cancelScan} className="cyber-btn-danger flex items-center gap-2 text-xs">
              <RotateCcw className="w-4 h-4 animate-spin" />
              Cancel Scan
            </button>
          ) : (
            <button
              onClick={() => startScan('full')}
              className="cyber-btn-primary flex items-center gap-2 text-xs font-semibold px-4 py-2"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              Run Full Audit
            </button>
          )}
        </div>
      </div>

      {/* Alerts */}
      {error && (
        <div className="flex items-center justify-between bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-xs">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span className="text-red-400 font-medium">{error}</span>
          </div>
          <button onClick={clearError} className="text-red-400 hover:text-red-300">
            Dismiss
          </button>
        </div>
      )}

      {!isAdmin && (
        <div className="flex items-center gap-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3 text-xs text-yellow-300">
          <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0" />
          <span>
            Operating in standard privilege mode. Launching as Administrator ensures full WMI SecurityCenter2, Registry, and driver access.
          </span>
        </div>
      )}

      {/* Progress Card */}
      {isScanning && (
        <div className="cyber-card scan-pulse border-cyber-accent/40">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-full bg-cyber-accent animate-ping" />
              <span className="text-sm font-semibold text-cyber-accent font-mono">
                {currentModule}
              </span>
            </div>
            <span className="text-xs font-mono text-gray-400">{Math.round(progress)}% Completed</span>
          </div>
          <div className="w-full bg-gray-900 rounded-full h-2.5 overflow-hidden border border-cyber-border">
            <div
              className="bg-gradient-to-r from-cyan-500 to-cyber-accent h-full transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Posture Score & Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Posture Gauge */}
        <div className="cyber-card flex flex-col justify-between items-center text-center p-5 relative overflow-hidden">
          <div className="w-full flex items-center justify-between text-xs text-gray-400">
            <span>Security Posture Index</span>
            <Activity className="w-4 h-4 text-cyber-accent" />
          </div>
          <div className="my-3">
            <div
              className={`w-20 h-20 rounded-full flex flex-col items-center justify-center border-4 ${
                postureGrade === 'A'
                  ? 'border-green-500 text-green-400'
                  : postureGrade === 'B'
                  ? 'border-cyan-400 text-cyan-400'
                  : postureGrade === 'C'
                  ? 'border-yellow-500 text-yellow-400'
                  : 'border-red-500 text-red-500'
              }`}
            >
              <span className="text-3xl font-black font-mono">{postureGrade}</span>
              <span className="text-[10px] text-gray-400">{Math.round(postureScore)}/100</span>
            </div>
          </div>
          <p className="text-xs font-medium text-gray-300">{posture?.status || 'Overall Rating'}</p>
        </div>

        {/* System Checks Stat */}
        <div className="cyber-card p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span>OS Subsystems Audited</span>
            <Server className="w-4 h-4 text-blue-400" />
          </div>
          <div className="my-2">
            <p className="text-3xl font-extrabold text-white font-mono">
              {totalSystemModules} <span className="text-xs font-normal text-gray-500">/ 26 categories</span>
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span className="text-green-400">✓ {systemResults?.summary?.status_counts?.pass || 0} Pass</span>
            <span className="text-yellow-400">⚠ {systemResults?.summary?.status_counts?.warn || 0} Warn</span>
            <span className="text-red-400">✗ {systemResults?.summary?.status_counts?.fail || 0} Fail</span>
          </div>
        </div>

        {/* Vulnerabilities Stat */}
        <div className="cyber-card p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span>Vulnerability Matches</span>
            <Bug className="w-4 h-4 text-red-400" />
          </div>
          <div className="my-2">
            <p className="text-3xl font-extrabold text-red-400 font-mono">{totalFindings}</p>
          </div>
          <p className="text-xs text-gray-400">
            <span className="text-red-400 font-semibold">{criticalCount} Critical</span> •{' '}
            <span className="text-orange-400 font-semibold">{highCount} High</span>
          </p>
        </div>

        {/* Exploits & CIS Stat */}
        <div className="cyber-card p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span>Exploit & CIS Status</span>
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          </div>
          <div className="my-2 space-y-1">
            <div className="flex justify-between items-center text-xs">
              <span className="text-gray-400">Public Exploits:</span>
              <span className="font-mono font-bold text-red-400">{exploitsAvailableCount} Weaponized</span>
            </div>
            <div className="flex justify-between items-center text-xs">
              <span className="text-gray-400">CIS Compliance:</span>
              <span className="font-mono font-bold text-cyber-accent">{cisScore}%</span>
            </div>
          </div>
          <p className="text-[11px] text-gray-500">Based on CIS Windows 10/11 Benchmark</p>
        </div>
      </div>

      {/* Visual Analytics & Fast Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution Donut */}
        <div className="cyber-card p-5">
          <h3 className="text-sm font-semibold text-white mb-2 flex items-center justify-between">
            <span>Severity Distribution</span>
            <span className="text-xs text-gray-500">CVSS v3.1</span>
          </h3>
          <div className="h-48 w-full flex items-center justify-center">
            {severityChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityChartData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={75}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {severityChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '8px' }}
                    itemStyle={{ color: '#fff', fontSize: '12px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-center text-xs text-gray-500">
                <ShieldCheck className="w-10 h-10 mx-auto text-gray-600 mb-1" />
                No active vulnerabilities reported
              </div>
            )}
          </div>
          <div className="flex justify-around text-xs mt-1">
            <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-full bg-red-500" /><span className="text-gray-400">Crit ({criticalCount})</span></div>
            <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-full bg-orange-500" /><span className="text-gray-400">High ({highCount})</span></div>
            <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-full bg-yellow-500" /><span className="text-gray-400">Med ({mediumCount})</span></div>
          </div>
        </div>

        {/* Actionable Attack Vectors */}
        <div className="cyber-card p-5 lg:col-span-2 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3 border-b border-cyber-border pb-2">
              <h3 className="text-sm font-semibold text-white">Priority Attack Surface Vectors</h3>
              <span className="text-xs text-gray-400 font-mono">Top Threat Remediations</span>
            </div>

            <div className="space-y-2.5">
              {(vulnResults?.findings || []).slice(0, 3).map((v, i) => (
                <div key={i} className="p-3 bg-cyber-dark rounded-lg border border-red-500/20 flex items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="status-badge bg-red-500/20 text-red-400 text-[10px] font-bold">
                        {v.severity.toUpperCase()}
                      </span>
                      <span className="text-xs font-semibold text-white">{v.title}</span>
                    </div>
                    <p className="text-[11px] text-gray-400 mt-1 line-clamp-1">{v.description}</p>
                  </div>
                  {v.exploit_available && (
                    <span className="shrink-0 px-2 py-0.5 rounded text-[10px] font-medium bg-red-500/10 text-red-400 border border-red-500/30">
                      Exploit Public
                    </span>
                  )}
                </div>
              ))}

              {(!vulnResults?.findings || vulnResults.findings.length === 0) && (
                <div className="text-center py-8 text-xs text-gray-500">
                  Execute a scan or load the sample profile to inspect active attack vectors.
                </div>
              )}
            </div>
          </div>

          <div className="grid grid-cols-3 gap-3 pt-4 border-t border-cyber-border">
            <button
              onClick={() => startScan('system')}
              disabled={isScanning}
              className="cyber-card p-2.5 hover:border-cyber-accent/60 transition-colors text-left disabled:opacity-50"
            >
              <div className="flex items-center gap-2 text-white font-medium text-xs">
                <Server className="w-3.5 h-3.5 text-cyber-accent" />
                Audit System
              </div>
              <p className="text-[10px] text-gray-500 mt-0.5">26 Windows checks</p>
            </button>

            <button
              onClick={() => startScan('network')}
              disabled={isScanning}
              className="cyber-card p-2.5 hover:border-blue-500/60 transition-colors text-left disabled:opacity-50"
            >
              <div className="flex items-center gap-2 text-white font-medium text-xs">
                <Network className="w-3.5 h-3.5 text-blue-400" />
                Audit Network
              </div>
              <p className="text-[10px] text-gray-500 mt-0.5">ARP, ports & topology</p>
            </button>

            <button
              onClick={() => startScan('vulnerabilities')}
              disabled={isScanning}
              className="cyber-card p-2.5 hover:border-red-500/60 transition-colors text-left disabled:opacity-50"
            >
              <div className="flex items-center gap-2 text-white font-medium text-xs">
                <Bug className="w-3.5 h-3.5 text-red-400" />
                Vulnerabilities
              </div>
              <p className="text-[10px] text-gray-500 mt-0.5">CVE & CIS mapper</p>
            </button>
          </div>
        </div>
      </div>

      {/* Real-Time Scan Console Terminal Drawer */}
      <div className="cyber-card border-cyber-border overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2.5 bg-cyber-darker border-b border-cyber-border">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyber-accent" />
            <span className="text-xs font-semibold text-white font-mono">Live Execution Console</span>
            <span className="text-[10px] text-gray-500 font-mono">({logs.length} events logged)</span>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={clearLogs}
              className="text-[11px] text-gray-400 hover:text-gray-200 transition-colors"
            >
              Clear
            </button>
            <button
              onClick={() => setShowTerminal(!showTerminal)}
              className="text-gray-400 hover:text-white"
            >
              {showTerminal ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {showTerminal && (
          <div className="p-3 bg-cyber-dark font-mono text-xs text-gray-300 max-h-48 overflow-y-auto space-y-1">
            {logs.length > 0 ? (
              logs.map((log, idx) => (
                <div key={idx} className="flex items-start gap-2 leading-relaxed">
                  <span className="text-gray-500 select-none">{log.time || '>'}</span>
                  <span className={log.text?.includes('ERROR') ? 'text-red-400' : log.text?.includes('complete') ? 'text-cyber-accent' : 'text-gray-300'}>
                    {log.text}
                  </span>
                </div>
              ))
            ) : (
              <p className="text-gray-600 italic">No output logged yet. Initiate a scan to stream live diagnostic output.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
