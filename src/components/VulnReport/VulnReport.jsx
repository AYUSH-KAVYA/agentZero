import React, { useState } from 'react';
import { useScan } from '../../context/ScanContext';
import {
  Bug,
  ShieldAlert,
  ExternalLink,
  Download,
  CheckCircle,
  XCircle,
  AlertTriangle,
  FileText,
  Filter,
} from 'lucide-react';

export default function VulnReport() {
  const { vulnResults, isScanning, startScan } = useScan();
  const [activeTab, setActiveTab] = useState('cves');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [exploitFilterOnly, setExploitFilterOnly] = useState(false);
  const [exporting, setExporting] = useState(false);

  const findings = vulnResults?.findings || [];
  const cisEvaluations = vulnResults?.cis_benchmark?.rule_evaluations || [];

  const filteredFindings = findings.filter((f) => {
    if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
    if (exploitFilterOnly && !f.exploit_available) return false;
    return true;
  });

  const handleExport = async (format) => {
    setExporting(true);
    try {
      if (window.agentZero) {
        await window.agentZero.generateReport(format, vulnResults);
      } else {
        // In browser / dev fallback: download JSON report
        const blob = new Blob([JSON.stringify(vulnResults, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `agentzero-report-${Date.now()}.${format === 'pdf' ? 'json' : 'html'}`;
        a.click();
      }
    } catch (e) {
      console.error(e);
    } finally {
      setExporting(false);
    }
  };

  const getSeverityBadge = (sev) => {
    switch (sev) {
      case 'critical':
        return <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/40">CRITICAL</span>;
      case 'high':
        return <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-orange-500/20 text-orange-400 border border-orange-500/40">HIGH</span>;
      case 'medium':
        return <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-yellow-500/20 text-yellow-400 border border-yellow-500/40">MEDIUM</span>;
      default:
        return <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-400 border border-blue-500/40">LOW</span>;
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-cyber-card p-5 rounded-xl border border-cyber-border">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-tight">Vulnerability & Exploit Intelligence</h2>
          <p className="text-xs text-gray-400 mt-1">
            Correlates system state with known Windows CVEs, open-source weaponized exploits, and CIS Benchmarks
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 self-start md:self-auto">
          <button
            onClick={() => handleExport('html')}
            disabled={!vulnResults || exporting}
            className="cyber-btn-secondary text-xs flex items-center gap-1.5 disabled:opacity-50"
          >
            <FileText className="w-3.5 h-3.5 text-blue-400" />
            Export HTML
          </button>
          <button
            onClick={() => handleExport('pdf')}
            disabled={!vulnResults || exporting}
            className="cyber-btn-secondary text-xs flex items-center gap-1.5 disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5 text-emerald-400" />
            Export PDF
          </button>
          <button
            onClick={() => startScan('vulnerabilities')}
            disabled={isScanning}
            className="cyber-btn-primary text-xs flex items-center gap-2 disabled:opacity-50"
          >
            {isScanning ? 'Analyzing CVEs...' : '▶ Run Vuln Analysis'}
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-cyber-border pb-3">
        <button
          onClick={() => setActiveTab('cves')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all ${
            activeTab === 'cves'
              ? 'bg-cyber-accent text-cyber-dark font-bold'
              : 'bg-cyber-card text-gray-400 hover:text-white border border-cyber-border'
          }`}
        >
          <Bug className="w-3.5 h-3.5" />
          CVE Vulnerabilities ({findings.length})
        </button>

        <button
          onClick={() => setActiveTab('cis')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all ${
            activeTab === 'cis'
              ? 'bg-cyber-accent text-cyber-dark font-bold'
              : 'bg-cyber-card text-gray-400 hover:text-white border border-cyber-border'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          CIS Benchmarks ({cisEvaluations.length} Rules)
        </button>
      </div>

      {activeTab === 'cves' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap items-center justify-between gap-3 bg-cyber-card/60 p-3 rounded-lg border border-cyber-border">
            <div className="flex items-center gap-1.5 overflow-x-auto">
              <Filter className="w-3.5 h-3.5 text-gray-400 mr-1" />
              {['all', 'critical', 'high', 'medium', 'low'].map((s) => (
                <button
                  key={s}
                  onClick={() => setSeverityFilter(s)}
                  className={`px-2.5 py-1 rounded text-xs uppercase font-medium transition-colors ${
                    severityFilter === s
                      ? 'bg-cyber-accent text-cyber-dark font-bold'
                      : 'bg-cyber-darker text-gray-400 hover:text-white border border-cyber-border'
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>

            <label className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={exploitFilterOnly}
                onChange={(e) => setExploitFilterOnly(e.target.checked)}
                className="rounded border-cyber-border bg-cyber-dark text-cyber-accent focus:ring-0"
              />
              <span>Weaponized Exploit Available Only</span>
            </label>
          </div>

          {/* CVE Cards */}
          {filteredFindings.length > 0 ? (
            <div className="space-y-3.5">
              {filteredFindings.map((vuln, idx) => (
                <div
                  key={idx}
                  className="cyber-card p-5 border-l-4 border-l-red-500 hover:border-cyber-accent/60 transition-all space-y-3"
                >
                  <div className="flex flex-col md:flex-row md:items-start justify-between gap-2">
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        {getSeverityBadge(vuln.severity)}
                        <span className="font-mono text-xs font-bold text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-500/30">
                          {vuln.cve}
                        </span>
                        {vuln.cvss_score > 0 && (
                          <span className="text-xs font-mono text-gray-400">
                            CVSS {vuln.cvss_score}
                          </span>
                        )}
                        <span className="text-xs text-gray-500">• {vuln.category}</span>
                      </div>
                      <h4 className="text-sm font-bold text-white mt-1.5">{vuln.title}</h4>
                    </div>

                    <div className="flex items-center gap-2 self-start">
                      {vuln.patch_available && (
                        <span
                          className={`text-xs px-2.5 py-1 rounded font-medium border ${
                            vuln.patch_installed
                              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                              : 'bg-red-500/10 text-red-400 border-red-500/30'
                          }`}
                        >
                          {vuln.patch_installed ? '✓ Patched' : `Missing ${vuln.patch_kb}`}
                        </span>
                      )}
                    </div>
                  </div>

                  <p className="text-xs text-gray-300 leading-relaxed">{vuln.description}</p>

                  {/* Exploit Information Section */}
                  {vuln.exploit_available && (
                    <div className="p-3 bg-red-950/20 rounded-lg border border-red-500/30 flex flex-col md:flex-row md:items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                        <span className="text-xs text-red-300 font-semibold">
                          Public Exploit Detected:
                        </span>
                        <span className="text-xs text-gray-300 font-mono">
                          {vuln.exploit_source} ({vuln.exploit_type})
                        </span>
                      </div>
                      {vuln.exploit_url && (
                        <a
                          href={vuln.exploit_url}
                          target="_blank"
                          rel="noreferrer"
                          className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono underline"
                        >
                          View Exploit PoC <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>
                  )}

                  {/* Patch & Remediation Guidance */}
                  <div className="pt-2 border-t border-cyber-border flex flex-col md:flex-row md:items-center justify-between gap-2 text-xs">
                    <div>
                      <span className="text-cyber-accent font-semibold">Remediation: </span>
                      <span className="text-gray-300">{vuln.remediation}</span>
                    </div>

                    {vuln.patch_url && !vuln.patch_installed && (
                      <a
                        href={vuln.patch_url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 shrink-0 font-medium"
                      >
                        Microsoft Catalog <ExternalLink className="w-3 h-3" />
                      </a>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="cyber-card text-center py-16 border-dashed">
              <CheckCircle className="w-12 h-12 text-cyber-accent mx-auto mb-3" />
              <h4 className="text-base font-semibold text-white">No Matching Vulnerabilities</h4>
              <p className="text-xs text-gray-500 mt-1">
                No active CVEs match the current filter or system state.
              </p>
            </div>
          )}
        </div>
      )}

      {activeTab === 'cis' && (
        <div className="cyber-card p-5">
          <div className="flex items-center justify-between mb-4 border-b border-cyber-border pb-3">
            <div>
              <h3 className="text-sm font-semibold text-white">CIS Microsoft Windows Benchmark</h3>
              <p className="text-xs text-gray-400">
                Compliance score:{' '}
                <span className="font-bold text-cyber-accent">
                  {vulnResults?.cis_benchmark?.score ?? 0}%
                </span>{' '}
                ({vulnResults?.cis_benchmark?.passed || 0} passed /{' '}
                {vulnResults?.cis_benchmark?.total_rules || 0} rules)
              </p>
            </div>
          </div>

          <div className="space-y-3">
            {cisEvaluations.map((rule, idx) => (
              <div
                key={idx}
                className="p-3.5 bg-cyber-dark rounded-lg border border-cyber-border flex flex-col md:flex-row md:items-start justify-between gap-3"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-cyan-400">{rule.rule_id}</span>
                    <span className="text-xs text-gray-500">• {rule.category}</span>
                  </div>
                  <h5 className="text-xs font-semibold text-white">{rule.title}</h5>
                  <p className="text-[11px] text-gray-400">{rule.detail}</p>
                  {rule.remediation && rule.status !== 'PASS' && (
                    <p className="text-[11px] font-mono text-emerald-400/90 bg-black/30 p-1.5 rounded mt-1 border border-emerald-500/20">
                      Fix: {rule.remediation}
                    </p>
                  )}
                </div>

                <div className="shrink-0 self-start">
                  {rule.status === 'PASS' ? (
                    <span className="status-pass flex items-center gap-1">
                      <CheckCircle className="w-3 h-3" /> PASS
                    </span>
                  ) : rule.status === 'FAIL' ? (
                    <span className="status-fail flex items-center gap-1">
                      <XCircle className="w-3 h-3" /> FAIL
                    </span>
                  ) : (
                    <span className="status-warn flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" /> WARN
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
