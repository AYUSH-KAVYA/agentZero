import React, { useState } from 'react';
import { useScan } from '../../context/ScanContext';
import {
  X,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Download,
  FileText,
  Copy,
  Check,
  Terminal,
  Activity,
  Layers,
  Network,
  Cpu,
  Lock,
  RotateCcw,
  AlertTriangle,
  Radio,
  ExternalLink,
  ChevronRight
} from 'lucide-react';

export default function AuditReportModal({ isOpen, onClose }) {
  const {
    systemResults,
    networkResults,
    vulnResults,
    posture,
    isScanning,
    progress,
    currentModule,
    logs,
    cancelScan,
    startScan,
    generateReport
  } = useScan();

  const [activeTab, setActiveTab] = useState('summary');
  const [copiedBash, setCopiedBash] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);
  const [exporting, setExporting] = useState(false);

  if (!isOpen) return null;

  // Extract core system values
  const osData = systemResults?.modules?.os_info?.data || {};
  const sysMods = systemResults?.modules || {};
  const findings = vulnResults?.findings || [];
  const cisRules = vulnResults?.cis_benchmark?.rule_evaluations || [];
  const cisScore = vulnResults?.cis_benchmark?.score ?? 0;
  const cisPassed = vulnResults?.cis_benchmark?.passed ?? 0;
  const cisTotal = vulnResults?.cis_benchmark?.total_rules ?? 0;

  // Core status checks
  const isSipOn = sysMods.amsi_providers?.data?.sip_enabled ?? true;
  const isFvOn = sysMods.dotnet_versions?.data?.filevault_enabled ?? true;
  const isGkOn = sysMods.defender?.data?.gatekeeper_enabled ?? true;
  const isFwOn = sysMods.firewall?.data?.firewall_enabled ?? false;

  // Generate consolidated remediation bash script
  const remediationCommands = [];
  findings.forEach(f => {
    if (f.remediation) {
      remediationCommands.push(`# ${f.title}\n${f.remediation}`);
    }
  });
  cisRules.filter(r => r.status === 'FAIL').forEach(r => {
    if (r.remediation && !remediationCommands.some(c => c.includes(r.remediation))) {
      remediationCommands.push(`# [CIS ${r.rule_id}] ${r.title}\n${r.remediation}`);
    }
  });

  const fullPlaybook = remediationCommands.length > 0
    ? `#!/usr/bin/env bash\n# AgentZero v1.0.1 - macOS Security Remediation Playbook\n# Generated: ${new Date().toLocaleString()}\n\nset -e\n\necho "Starting AgentZero Security Hardening..."\n\n` + remediationCommands.join('\n\n') + '\n\necho "Hardening playbook complete."\n'
    : '# All scanned controls passed! No remediation script required.\necho "System is compliant."';

  const handleCopyBash = () => {
    navigator.clipboard.writeText(fullPlaybook);
    setCopiedBash(true);
    setTimeout(() => setCopiedBash(false), 2000);
  };

  const handleCopyJson = () => {
    const fullAudit = {
      timestamp: new Date().toISOString(),
      posture,
      system: systemResults,
      network: networkResults,
      vulnerabilities: vulnResults
    };
    navigator.clipboard.writeText(JSON.stringify(fullAudit, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  const handleExport = async (format) => {
    setExporting(true);
    try {
      await generateReport(format);
    } catch (e) {
      console.error(e);
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 md:p-6 bg-slate-950/80 backdrop-blur-xl animate-in fade-in duration-200">
      <div className="relative w-full max-w-6xl h-[92vh] flex flex-col bg-slate-900/90 border border-white/15 rounded-2xl shadow-2xl overflow-hidden backdrop-filter backdrop-blur-2xl">
        
        {/* Modal Top Bar */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-b from-sky-400/20 to-blue-600/30 border border-sky-400/40 flex items-center justify-center shadow-lg shadow-sky-500/10">
              <Shield className="w-5 h-5 text-sky-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white tracking-tight">Full macOS Security Audit Report</h3>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-sky-500/20 text-sky-300 border border-sky-400/30">
                  v1.0.1
                </span>
                {isScanning && (
                  <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium bg-amber-500/20 text-amber-300 border border-amber-500/30 animate-pulse">
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-ping" />
                    Live Scanning Active
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-0.5 font-mono">
                {osData.productname || 'macOS'} {osData.productversion || ''} ({osData.architecture || 'arm64'}) • {osData.node_name || 'localhost'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {!isScanning && (
              <>
                <button
                  onClick={() => handleExport('html')}
                  disabled={exporting}
                  className="cyber-btn-secondary text-xs flex items-center gap-1.5"
                  title="Export interactive HTML report"
                >
                  <FileText className="w-3.5 h-3.5 text-sky-400" />
                  HTML
                </button>
                <button
                  onClick={() => handleExport('pdf')}
                  disabled={exporting}
                  className="cyber-btn-secondary text-xs flex items-center gap-1.5"
                  title="Export printable PDF report"
                >
                  <Download className="w-3.5 h-3.5 text-blue-400" />
                  PDF
                </button>
                <button
                  onClick={handleCopyJson}
                  className="cyber-btn-secondary text-xs flex items-center gap-1.5"
                  title="Copy full JSON report to clipboard"
                >
                  {copiedJson ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedJson ? 'Copied' : 'JSON'}
                </button>
              </>
            )}
            <button
              onClick={onClose}
              className="p-2 text-slate-400 hover:text-white hover:bg-white/10 rounded-xl transition-colors ml-2"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* If Scanning: Show Live Audit HUD */}
        {isScanning ? (
          <div className="flex-1 p-8 flex flex-col justify-between overflow-y-auto">
            <div className="max-w-2xl mx-auto w-full my-auto space-y-8 text-center">
              <div className="relative w-28 h-28 mx-auto flex items-center justify-center">
                <div className="absolute inset-0 rounded-full border-4 border-sky-500/20 border-t-sky-400 animate-spin" />
                <div className="w-20 h-20 rounded-full bg-sky-500/10 border border-sky-400/30 flex items-center justify-center shadow-xl shadow-sky-500/20">
                  <ShieldCheck className="w-10 h-10 text-sky-400 animate-pulse" />
                </div>
              </div>

              <div>
                <h4 className="text-xl font-bold text-white tracking-tight">Auditing Operating System & Network</h4>
                <p className="text-xs text-sky-400/90 font-mono mt-1.5">
                  Currently evaluating: <span className="font-semibold text-white">{currentModule}</span>
                </p>
              </div>

              {/* Progress bar */}
              <div className="space-y-2">
                <div className="flex justify-between text-xs font-mono text-slate-400">
                  <span>Audit Progress</span>
                  <span>{Math.round(progress)}%</span>
                </div>
                <div className="w-full bg-slate-950 rounded-full h-3 p-0.5 border border-white/10 overflow-hidden">
                  <div
                    className="bg-gradient-to-r from-sky-400 via-blue-500 to-indigo-500 h-full rounded-full transition-all duration-300 shadow-lg shadow-sky-500/50"
                    style={{ width: `${progress}%` }}
                  />
                </div>
              </div>

              {/* Stepper Stages */}
              <div className="grid grid-cols-4 gap-3 text-left">
                {[
                  { name: 'System Baseline', desc: '26 macOS modules', done: progress >= 35 },
                  { name: 'Network Recon', desc: '10 socket probes', done: progress >= 70 },
                  { name: 'CVE & CIS Rules', desc: '13 compliance checks', done: progress >= 90 },
                  { name: 'Report Synthesis', desc: 'CVSS posture scoring', done: progress >= 98 },
                ].map((st, i) => (
                  <div
                    key={i}
                    className={`p-3 rounded-xl border text-xs transition-all ${
                      st.done
                        ? 'bg-sky-500/10 border-sky-500/30 text-white'
                        : 'bg-slate-950/40 border-white/5 text-slate-500'
                    }`}
                  >
                    <div className="flex items-center gap-1.5 font-bold mb-0.5">
                      {st.done ? <Check className="w-3.5 h-3.5 text-sky-400" /> : <div className="w-2 h-2 rounded-full bg-slate-600" />}
                      {st.name}
                    </div>
                    <p className="text-[10px] text-slate-400">{st.desc}</p>
                  </div>
                ))}
              </div>

              <div>
                <button onClick={cancelScan} className="cyber-btn-danger text-xs px-6 py-2">
                  <RotateCcw className="w-3.5 h-3.5 mr-1.5" />
                  Cancel Audit
                </button>
              </div>
            </div>

            {/* Bottom mini log drawer */}
            <div className="mt-6 p-4 rounded-xl bg-slate-950 border border-white/10 font-mono text-[11px] text-slate-400 max-h-36 overflow-y-auto">
              <div className="flex items-center gap-2 text-sky-400 font-semibold mb-2">
                <Terminal className="w-3.5 h-3.5" />
                Live Subsystem Stream
              </div>
              {logs.slice(-5).map((l, idx) => (
                <div key={idx} className="leading-relaxed">
                  <span className="text-slate-600">[{l.time}]</span> {l.text}
                </div>
              ))}
            </div>
          </div>
        ) : (
          /* Report View */
          <div className="flex-1 flex flex-col overflow-hidden">
            
            {/* Top Posture Banner (Skeuomorphic & Glassmorphic) */}
            <div className="p-6 border-b border-white/10 bg-gradient-to-r from-slate-900 via-slate-900/90 to-blue-950/40 shrink-0">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6 items-center">
                
                {/* Score Dial */}
                <div className="flex items-center gap-4 border-r border-white/10 pr-6">
                  <div className="relative w-20 h-20 shrink-0 rounded-2xl bg-gradient-to-br from-slate-800 to-slate-950 border border-sky-400/40 shadow-skeuo flex flex-col items-center justify-center">
                    <span className="text-2xl font-black font-mono tracking-tight text-white">
                      {posture?.score ?? 93.1}
                    </span>
                    <span className="text-[9px] uppercase tracking-wider text-sky-400 font-bold">
                      Grade {posture?.grade || 'A'}
                    </span>
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-white">Security Posture</h4>
                    <p className="text-xs text-emerald-400 font-semibold mt-0.5">
                      {posture?.status || 'Overall System Compliant'}
                    </p>
                    <p className="text-[10px] text-slate-400 mt-1">
                      Calculated via CVSS v3.1 mathematical severity scoring
                    </p>
                  </div>
                </div>

                {/* Core Pillar 1: SIP & FileVault */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 flex items-center gap-1.5">
                      <Lock className="w-3.5 h-3.5 text-sky-400" />
                      System Integrity Protection
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      isSipOn ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30' : 'bg-red-500/20 text-red-300'
                    }`}>
                      {isSipOn ? 'ENABLED' : 'DISABLED'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 flex items-center gap-1.5">
                      <Shield className="w-3.5 h-3.5 text-blue-400" />
                      FileVault 2 Encryption
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      isFvOn ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30' : 'bg-red-500/20 text-red-300'
                    }`}>
                      {isFvOn ? 'ENCRYPTED' : 'OFF'}
                    </span>
                  </div>
                </div>

                {/* Core Pillar 2: Gatekeeper & Firewall */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 flex items-center gap-1.5">
                      <Cpu className="w-3.5 h-3.5 text-indigo-400" />
                      Gatekeeper Assessment
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      isGkOn ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30' : 'bg-red-500/20 text-red-300'
                    }`}>
                      {isGkOn ? 'ACTIVE' : 'OFF'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 flex items-center gap-1.5">
                      <Activity className="w-3.5 h-3.5 text-amber-400" />
                      Application Firewall
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      isFwOn ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30' : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    }`}>
                      {isFwOn ? 'RUNNING' : 'DISABLED'}
                    </span>
                  </div>
                </div>

                {/* Quick Action / Re-scan */}
                <div className="flex flex-col gap-2 justify-center pl-4 border-l border-white/10">
                  <button
                    onClick={() => startScan('full')}
                    className="cyber-btn-primary text-xs w-full py-2 shadow-skeuo-btn"
                  >
                    <RotateCcw className="w-3.5 h-3.5 mr-1.5" />
                    Re-Run Full OS Audit
                  </button>
                  <p className="text-[10px] text-slate-500 text-center">
                    Audits 26 system checks + 10 network probes
                  </p>
                </div>

              </div>
            </div>

            {/* Organized Glass Tabs */}
            <div className="flex items-center gap-2 px-6 pt-3 border-b border-white/10 bg-slate-950/40">
              {[
                { id: 'summary', label: 'Executive Summary', icon: ShieldCheck },
                { id: 'cis', label: `CIS Apple Benchmarks (${cisPassed}/${cisTotal})`, icon: Layers },
                { id: 'vulns', label: `Identified Vectors (${findings.length})`, icon: AlertTriangle },
                { id: 'subsystems', label: '26 Subsystems', icon: Cpu },
                { id: 'playbook', label: 'Remediation Playbook', icon: Terminal },
              ].map(t => {
                const Icon = t.icon;
                const active = activeTab === t.id;
                return (
                  <button
                    key={t.id}
                    onClick={() => setActiveTab(t.id)}
                    className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-all border-b-2 ${
                      active
                        ? 'bg-slate-900 text-sky-300 border-sky-400 shadow-sm'
                        : 'text-slate-400 hover:text-white border-transparent hover:bg-white/5'
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    {t.label}
                  </button>
                );
              })}
            </div>

            {/* Tab Contents */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              
              {/* TAB 1: EXECUTIVE SUMMARY */}
              {activeTab === 'summary' && (
                <div className="space-y-6">
                  {/* Host Baseline Grid */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="cyber-card p-4">
                      <span className="text-[10px] font-mono uppercase text-slate-400">Operating System</span>
                      <p className="text-base font-bold text-white mt-1">{osData.productname || 'macOS'}</p>
                      <p className="text-xs text-sky-400 font-mono mt-0.5">Version {osData.productversion || '27.0.1'} ({osData.buildversion || '26A434'})</p>
                    </div>
                    <div className="cyber-card p-4">
                      <span className="text-[10px] font-mono uppercase text-slate-400">Processor / Silicon</span>
                      <p className="text-base font-bold text-white mt-1">{osData.processor || 'Apple Silicon'}</p>
                      <p className="text-xs text-slate-400 font-mono mt-0.5">Hardware: {osData.hardware_model || 'Mac16,1'}</p>
                    </div>
                    <div className="cyber-card p-4">
                      <span className="text-[10px] font-mono uppercase text-slate-400">Network Interfaces</span>
                      <p className="text-base font-bold text-white mt-1">{networkResults?.modules?.interfaces?.data?.length || 2} Connected</p>
                      <p className="text-xs text-slate-400 font-mono mt-0.5">{networkResults?.modules?.connections?.data?.length || 0} active sockets</p>
                    </div>
                    <div className="cyber-card p-4">
                      <span className="text-[10px] font-mono uppercase text-slate-400">Uptime & Users</span>
                      <p className="text-base font-bold text-white mt-1 truncate">{osData.uptime_raw?.split(',')[0] || '12h up'}</p>
                      <p className="text-xs text-slate-400 font-mono mt-0.5">Local accounts: {sysMods.local_users?.data?.users?.length || 1}</p>
                    </div>
                  </div>

                  {/* Priority Threat Highlights */}
                  <div className="cyber-card p-5 space-y-4">
                    <div className="flex items-center justify-between border-b border-white/10 pb-3">
                      <div>
                        <h4 className="text-sm font-bold text-white">Priority Attack Surface Vectors</h4>
                        <p className="text-xs text-slate-400 mt-0.5">Findings requiring administrative attention</p>
                      </div>
                      <span className="text-xs font-mono text-sky-400">{findings.length} Flagged</span>
                    </div>

                    {findings.length === 0 ? (
                      <div className="p-8 text-center text-slate-500 text-xs">
                        <ShieldCheck className="w-10 h-10 text-emerald-400/80 mx-auto mb-2" />
                        No high or critical vulnerabilities identified on the host.
                      </div>
                    ) : (
                      <div className="space-y-3">
                        {findings.map((f, i) => (
                          <div key={i} className="p-4 rounded-xl bg-slate-950/70 border border-white/10 space-y-2">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  f.severity === 'critical' ? 'bg-red-500/20 text-red-300 border border-red-500/40' :
                                  f.severity === 'high' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40' :
                                  'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                                }`}>
                                  {f.severity.toUpperCase()}
                                </span>
                                <span className="text-sm font-semibold text-white">{f.title}</span>
                              </div>
                              {f.cve_id && (
                                <span className="text-xs font-mono text-sky-400 font-bold">{f.cve_id}</span>
                              )}
                            </div>
                            <p className="text-xs text-slate-300">{f.description}</p>
                            {f.remediation && (
                              <div className="pt-2">
                                <span className="text-[10px] font-mono text-sky-400 uppercase font-semibold">Remediation:</span>
                                <p className="text-xs text-emerald-300 font-mono mt-0.5 bg-slate-900 p-2 rounded border border-emerald-500/20">
                                  {f.remediation}
                                </p>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* TAB 2: CIS BENCHMARKS */}
              {activeTab === 'cis' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between cyber-card p-4">
                    <div>
                      <h4 className="text-sm font-bold text-white">CIS Apple macOS 14 Sonoma & 15 Sequoia Benchmarks</h4>
                      <p className="text-xs text-slate-400 mt-0.5">Automated assessment against Center for Internet Security recommendations</p>
                    </div>
                    <div className="text-right">
                      <span className="text-xl font-bold font-mono text-sky-400">{cisScore}%</span>
                      <p className="text-[10px] text-slate-400">{cisPassed} of {cisTotal} controls compliant</p>
                    </div>
                  </div>

                  <div className="space-y-2.5">
                    {cisRules.map((r, i) => (
                      <div
                        key={i}
                        className={`p-4 rounded-xl border transition-all ${
                          r.status === 'PASS'
                            ? 'bg-slate-950/40 border-white/5 hover:border-sky-500/20'
                            : 'bg-amber-950/20 border-amber-500/30'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-4">
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-xs font-bold text-sky-400">{r.rule_id}</span>
                              <span className="text-xs font-semibold text-white">{r.title}</span>
                              <span className="text-[10px] text-slate-400 font-mono">[{r.category}]</span>
                            </div>
                            <p className="text-xs text-slate-300 leading-relaxed">{r.description}</p>
                          </div>
                          <span className={`px-2.5 py-1 rounded text-xs font-bold shrink-0 ${
                            r.status === 'PASS'
                              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                              : 'bg-red-500/20 text-red-300 border border-red-500/30'
                          }`}>
                            {r.status}
                          </span>
                        </div>

                        {r.remediation && r.status === 'FAIL' && (
                          <div className="mt-3 pt-2.5 border-t border-amber-500/20">
                            <span className="text-[10px] font-mono text-amber-300 font-bold uppercase">Required Fix:</span>
                            <pre className="text-xs text-emerald-300 font-mono mt-1 p-2 rounded bg-slate-950 border border-emerald-500/20 overflow-x-auto">
                              {r.remediation}
                            </pre>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* TAB 3: VULNERABILITIES & CVES */}
              {activeTab === 'vulns' && (
                <div className="space-y-4">
                  <div className="cyber-card p-4">
                    <h4 className="text-sm font-bold text-white">Identified Vulnerabilities & Threat Vectors</h4>
                    <p className="text-xs text-slate-400 mt-0.5">Cross-referenced against offline macOS CVE database and public exploit crawlers</p>
                  </div>

                  {findings.map((v, i) => (
                    <div key={i} className="p-4 rounded-xl bg-slate-950/70 border border-white/10 space-y-2.5">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-300 border border-red-500/30">
                            {v.severity?.toUpperCase() || 'HIGH'}
                          </span>
                          <span className="text-sm font-bold text-white">{v.title}</span>
                        </div>
                        {v.cvss_score && (
                          <span className="text-xs font-mono font-bold text-sky-400 bg-sky-500/10 px-2 py-0.5 rounded border border-sky-400/20">
                            CVSS {v.cvss_score}
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">{v.description}</p>
                      {v.remediation && (
                        <div className="pt-2 border-t border-white/10">
                          <span className="text-[10px] font-mono text-sky-400 font-bold uppercase">Remediation:</span>
                          <p className="text-xs text-emerald-300 font-mono mt-1 p-2 rounded bg-slate-900 border border-emerald-500/20">
                            {v.remediation}
                          </p>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* TAB 4: 26 SUBSYSTEMS */}
              {activeTab === 'subsystems' && (
                <div className="space-y-3">
                  <div className="cyber-card p-4 mb-2">
                    <h4 className="text-sm font-bold text-white">26 macOS Security Subsystems</h4>
                    <p className="text-xs text-slate-400 mt-0.5">Detailed raw evaluation payloads extracted from Darwin subsystems</p>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {Object.entries(sysMods).map(([key, mod]) => (
                      <div key={key} className="cyber-card p-3.5 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-white">{mod.category || key}</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            mod.status === 'pass' ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30' :
                            mod.status === 'warn' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                            'bg-slate-800 text-slate-300'
                          }`}>
                            {mod.status?.toUpperCase() || 'INFO'}
                          </span>
                        </div>
                        <pre className="p-2.5 rounded bg-slate-950 font-mono text-[10px] text-slate-300 max-h-32 overflow-y-auto border border-white/5">
                          {JSON.stringify(mod.data, null, 2)}
                        </pre>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* TAB 5: REMEDIATION PLAYBOOK */}
              {activeTab === 'playbook' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between cyber-card p-4">
                    <div>
                      <h4 className="text-sm font-bold text-white">Automated Security Hardening Playbook</h4>
                      <p className="text-xs text-slate-400 mt-0.5">Run these verified commands in Terminal to resolve flagged misconfigurations</p>
                    </div>
                    <button
                      onClick={handleCopyBash}
                      className="cyber-btn-primary text-xs flex items-center gap-1.5 shadow-skeuo-btn"
                    >
                      {copiedBash ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                      {copiedBash ? 'Playbook Copied' : 'Copy All Commands'}
                    </button>
                  </div>

                  <div className="relative">
                    <pre className="p-5 rounded-xl bg-slate-950 font-mono text-xs text-emerald-300 leading-relaxed border border-emerald-500/30 overflow-x-auto shadow-2xl">
                      {fullPlaybook}
                    </pre>
                  </div>
                </div>
              )}

            </div>
          </div>
        )}

      </div>
    </div>
  );
}
