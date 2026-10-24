import React, { useState } from 'react';
import { useScan } from '../../context/ScanContext';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Activity,
  Play,
  RotateCcw,
  Sparkles,
  Server,
  Network,
  Bug,
  Lock,
  Cpu,
  FileText,
  ChevronRight,
  ExternalLink,
  Layers,
  CheckCircle2,
  AlertCircle
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';
import AuditReportModal from '../ReportModal/AuditReportModal';

export default function Dashboard() {
  const {
    isScanning,
    progress,
    systemResults,
    networkResults,
    vulnResults,
    posture,
    lastScanTime,
    isAdmin,
    isMockData,
    startScan,
    cancelScan,
    loadMockData,
  } = useScan();

  const navigate = useNavigate();
  const [isReportOpen, setIsReportOpen] = useState(false);

  // Extract core numbers
  const osData = systemResults?.modules?.os_info?.data || {};
  const sysMods = systemResults?.modules || {};
  const findings = vulnResults?.findings || [];
  const cisScore = vulnResults?.cis_benchmark?.score ?? 76.9;
  const cisPassed = vulnResults?.cis_benchmark?.passed ?? 10;
  const cisTotal = vulnResults?.cis_benchmark?.total_rules ?? 13;

  const criticalCount = vulnResults?.critical ?? 0;
  const highCount = vulnResults?.high ?? (findings.filter(f => f.severity === 'high').length);
  const mediumCount = vulnResults?.medium ?? (findings.filter(f => f.severity === 'medium').length);
  const lowCount = vulnResults?.low ?? (findings.filter(f => f.severity === 'low').length);

  const isSipOn = sysMods.amsi_providers?.data?.sip_enabled ?? true;
  const isFvOn = sysMods.dotnet_versions?.data?.filevault_enabled ?? true;
  const isGkOn = sysMods.defender?.data?.gatekeeper_enabled ?? true;
  const isFwOn = sysMods.firewall?.data?.firewall_enabled ?? false;

  const score = posture?.score ?? 93.1;
  const grade = posture?.grade ?? 'A';

  const severityChartData = [
    { name: 'Critical', value: criticalCount, color: '#ef4444' },
    { name: 'High', value: highCount, color: '#f97316' },
    { name: 'Medium', value: mediumCount, color: '#f59e0b' },
    { name: 'Low', value: lowCount, color: '#38bdf8' },
  ].filter((d) => d.value > 0);

  const handleStartFullScan = () => {
    startScan('full');
    setIsReportOpen(true);
  };

  return (
    <div className="space-y-6 pb-12 max-w-7xl mx-auto">
      
      {/* Hero Glassmorphic Header */}
      <div className="cyber-card p-6 md:p-8 bg-gradient-to-r from-slate-900/90 via-slate-900/80 to-blue-950/40 relative overflow-hidden">
        {/* Subtle decorative glow */}
        <div className="absolute -right-20 -top-20 w-80 h-80 rounded-full bg-sky-500/10 filter blur-3xl pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div className="space-y-2 max-w-2xl">
            <div className="flex items-center gap-3">
              <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold bg-sky-500/15 text-sky-400 border border-sky-400/30">
                macOS Darwin v1.0.1
              </span>
              {isMockData && (
                <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-blue-500/15 text-blue-300 border border-blue-400/30">
                  Evaluation Demo Active
                </span>
              )}
            </div>
            <h2 className="text-3xl font-extrabold text-white tracking-tight">
              macOS Security Command Center
            </h2>
            <p className="text-sm text-slate-300 leading-relaxed font-normal">
              Agent-less administrative cybersecurity engine auditing System Integrity Protection (SIP), FileVault 2, Gatekeeper, CIS benchmarks, and local network attack surfaces.
            </p>
            {lastScanTime && (
              <p className="text-xs text-slate-400 font-mono">
                Last completed audit: {new Date(lastScanTime).toLocaleString()}
              </p>
            )}
          </div>

          {/* Action Button Suite */}
          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <button
              onClick={handleStartFullScan}
              disabled={isScanning}
              className="cyber-btn-primary px-6 py-3 text-sm shadow-skeuo-btn flex items-center gap-2 font-bold"
            >
              <Play className="w-4 h-4 fill-white" />
              Run Full OS Audit
            </button>

            <button
              onClick={() => setIsReportOpen(true)}
              className="cyber-btn-secondary px-4 py-3 text-sm flex items-center gap-2"
            >
              <FileText className="w-4 h-4 text-sky-400" />
              View Audit Report
            </button>

            <button
              onClick={loadMockData}
              title="Load sample macOS Sonoma evaluation profile"
              className="p-3 text-slate-400 hover:text-sky-300 hover:bg-white/5 rounded-xl border border-white/10 transition-colors"
            >
              <Sparkles className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* 4 Key Executive Posture Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* Metric 1: Posture Grade */}
        <div className="cyber-card p-5 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Overall Posture</span>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-black font-mono text-white">{score}</span>
              <span className="text-xs font-bold text-sky-400">/ 100</span>
            </div>
            <p className="text-xs text-emerald-400 font-semibold">{posture?.status || 'Secure Baseline'}</p>
          </div>
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-slate-800 to-slate-950 border border-sky-400/30 shadow-skeuo flex flex-col items-center justify-center">
            <span className="text-lg font-black text-white font-mono">{grade}</span>
            <span className="text-[9px] uppercase font-bold text-sky-400">GRADE</span>
          </div>
        </div>

        {/* Metric 2: CIS Compliance */}
        <div className="cyber-card p-5 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">CIS Apple Benchmark</span>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-black font-mono text-white">{cisScore}%</span>
            </div>
            <p className="text-xs text-slate-300 font-mono">{cisPassed} / {cisTotal} Controls Passed</p>
          </div>
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-slate-800 to-slate-950 border border-blue-400/30 shadow-skeuo flex items-center justify-center">
            <Layers className="w-6 h-6 text-sky-400" />
          </div>
        </div>

        {/* Metric 3: Core macOS Pillars */}
        <div className="cyber-card p-5 space-y-2">
          <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Core macOS Security</span>
          <div className="grid grid-cols-2 gap-2 pt-1 text-[11px] font-medium">
            <div className="flex items-center gap-1.5 text-slate-300">
              <CheckCircle2 className={`w-3.5 h-3.5 ${isSipOn ? 'text-sky-400' : 'text-red-400'}`} />
              SIP: {isSipOn ? 'ON' : 'OFF'}
            </div>
            <div className="flex items-center gap-1.5 text-slate-300">
              <CheckCircle2 className={`w-3.5 h-3.5 ${isFvOn ? 'text-sky-400' : 'text-red-400'}`} />
              FileVault: {isFvOn ? 'ON' : 'OFF'}
            </div>
            <div className="flex items-center gap-1.5 text-slate-300">
              <CheckCircle2 className={`w-3.5 h-3.5 ${isGkOn ? 'text-sky-400' : 'text-red-400'}`} />
              Gatekeeper: {isGkOn ? 'ON' : 'OFF'}
            </div>
            <div className="flex items-center gap-1.5 text-slate-300">
              <AlertCircle className={`w-3.5 h-3.5 ${isFwOn ? 'text-sky-400' : 'text-amber-400'}`} />
              Firewall: {isFwOn ? 'ON' : 'OFF'}
            </div>
          </div>
        </div>

        {/* Metric 4: Host Specs */}
        <div className="cyber-card p-5 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Audited Hardware</span>
            <p className="text-sm font-bold text-white truncate max-w-[130px]">{osData.processor || 'Apple Silicon'}</p>
            <p className="text-xs text-slate-400 font-mono truncate">{osData.hardware_model || 'Mac16,1'} • {osData.architecture || 'arm64'}</p>
          </div>
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-slate-800 to-slate-950 border border-indigo-400/30 shadow-skeuo flex items-center justify-center">
            <Cpu className="w-6 h-6 text-indigo-400" />
          </div>
        </div>

      </div>

      {/* Main Visual Section: Clean Donut + Fast Drills */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Severity Distribution Donut */}
        <div className="cyber-card p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-white/10 pb-3 mb-4">
              <h3 className="text-sm font-bold text-white tracking-tight">Threat Severity Profile</h3>
              <span className="text-xs font-mono text-sky-400">CVSS v3.1</span>
            </div>

            <div className="h-44 w-full flex items-center justify-center">
              {severityChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityChartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={48}
                      outerRadius={70}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {severityChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: 'rgba(255,255,255,0.15)', borderRadius: '10px' }}
                      itemStyle={{ color: '#fff', fontSize: '12px' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="text-center text-xs text-slate-500 py-6">
                  <ShieldCheck className="w-10 h-10 mx-auto text-emerald-400/80 mb-2" />
                  No active threat vectors flagged
                </div>
              )}
            </div>
          </div>

          <div className="flex justify-around text-xs mt-3 pt-3 border-t border-white/10">
            <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-full bg-red-500" /><span className="text-slate-400">Crit ({criticalCount})</span></div>
            <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-full bg-orange-500" /><span className="text-slate-400">High ({highCount})</span></div>
            <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-full bg-amber-500" /><span className="text-slate-400">Med ({mediumCount})</span></div>
          </div>
        </div>

        {/* Drill-down Navigation Cards (Uncluttered) */}
        <div className="cyber-card p-6 lg:col-span-2 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-white/10 pb-3 mb-4">
              <div>
                <h3 className="text-sm font-bold text-white tracking-tight">Audit Domains & Fast Navigation</h3>
                <p className="text-xs text-slate-400 mt-0.5">Explore subsystem inspections and network topology</p>
              </div>
              <button
                onClick={() => setIsReportOpen(true)}
                className="text-xs text-sky-400 hover:text-sky-300 font-semibold flex items-center gap-1"
              >
                Open Full Report <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              
              <div
                onClick={() => navigate('/system')}
                className="p-4 rounded-xl bg-slate-950/50 border border-white/10 hover:border-sky-500/40 cursor-pointer transition-all hover:-translate-y-0.5 space-y-2 group"
              >
                <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-400/20 flex items-center justify-center text-sky-400 group-hover:bg-sky-500/20">
                  <Server className="w-4 h-4" />
                </div>
                <h4 className="text-sm font-bold text-white">System Audit</h4>
                <p className="text-xs text-slate-400 leading-relaxed">
                  26 modules auditing SIP, FileVault, Gatekeeper, LaunchDaemons, and SUID permissions.
                </p>
                <span className="inline-flex items-center text-[11px] font-semibold text-sky-400 pt-1">
                  Explore Checks →
                </span>
              </div>

              <div
                onClick={() => navigate('/network')}
                className="p-4 rounded-xl bg-slate-950/50 border border-white/10 hover:border-blue-500/40 cursor-pointer transition-all hover:-translate-y-0.5 space-y-2 group"
              >
                <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-400/20 flex items-center justify-center text-blue-400 group-hover:bg-blue-500/20">
                  <Network className="w-4 h-4" />
                </div>
                <h4 className="text-sm font-bold text-white">Network Recon</h4>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Interactive topology map, listening ports, established sockets, and ARP neighbor table.
                </p>
                <span className="inline-flex items-center text-[11px] font-semibold text-blue-400 pt-1">
                  View Topology →
                </span>
              </div>

              <div
                onClick={() => navigate('/vulnerabilities')}
                className="p-4 rounded-xl bg-slate-950/50 border border-white/10 hover:border-indigo-500/40 cursor-pointer transition-all hover:-translate-y-0.5 space-y-2 group"
              >
                <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-400/20 flex items-center justify-center text-indigo-400 group-hover:bg-indigo-500/20">
                  <Bug className="w-4 h-4" />
                </div>
                <h4 className="text-sm font-bold text-white">Vulnerabilities</h4>
                <p className="text-xs text-slate-400 leading-relaxed">
                  CIS Apple Benchmark evaluator, zero-day CVE matches, and exploit intelligence.
                </p>
                <span className="inline-flex items-center text-[11px] font-semibold text-indigo-400 pt-1">
                  View Intelligence →
                </span>
              </div>

            </div>
          </div>

          <div className="pt-4 mt-4 border-t border-white/10 flex items-center justify-between text-xs text-slate-400">
            <span>Security Engine: Python 3.9+ Darwin Runtime</span>
            <span>Target Platform: Apple Silicon (M1/M2/M3/M4) & Intel</span>
          </div>
        </div>

      </div>

      {/* Dedicated Executive Audit Report Popup */}
      <AuditReportModal
        isOpen={isReportOpen}
        onClose={() => setIsReportOpen(false)}
      />

    </div>
  );
}
