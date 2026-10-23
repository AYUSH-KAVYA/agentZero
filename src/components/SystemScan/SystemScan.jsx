import React, { useState, useMemo } from 'react';
import { useScan } from '../../context/ScanContext';
import { Search, Filter, Copy, Check, ChevronDown, ChevronUp, AlertCircle, ShieldCheck, Info } from 'lucide-react';

export default function SystemScan() {
  const { systemResults, isScanning, progress, currentModule, startScan } = useScan();
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [copiedKey, setCopiedKey] = useState(null);

  const modules = systemResults?.modules || {};

  const filteredModules = useMemo(() => {
    return Object.entries(modules).filter(([key, mod]) => {
      // Status filter
      if (statusFilter !== 'all' && mod.status !== statusFilter) {
        return false;
      }
      // Search query
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesCategory = mod.category?.toLowerCase().includes(query);
        const matchesKey = key.toLowerCase().includes(query);
        const matchesFindings = mod.findings?.some(
          (f) =>
            f.title?.toLowerCase().includes(query) ||
            f.description?.toLowerCase().includes(query) ||
            f.remediation?.toLowerCase().includes(query)
        );
        return matchesCategory || matchesKey || matchesFindings;
      }
      return true;
    });
  }, [modules, statusFilter, searchQuery]);

  const handleCopy = (key, data) => {
    navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'pass':
        return <span className="status-pass">✓ Pass</span>;
      case 'warn':
        return <span className="status-warn">⚠ Warning</span>;
      case 'fail':
        return <span className="status-fail">✗ Fail</span>;
      case 'info':
        return <span className="status-info">ℹ Info</span>;
      case 'error':
        return <span className="status-badge bg-red-900/30 text-red-300 border border-red-500/30">⊘ Platform Error</span>;
      default:
        return <span className="status-info">— Pending</span>;
    }
  };

  const getSeverityBadge = (sev) => {
    switch (sev) {
      case 'critical':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/40">CRITICAL</span>;
      case 'high':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-500/20 text-orange-400 border border-orange-500/40">HIGH</span>;
      case 'medium':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-yellow-500/20 text-yellow-400 border border-yellow-500/40">MEDIUM</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-400 border border-blue-500/40">LOW</span>;
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-cyber-card p-5 rounded-xl border border-cyber-border">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-tight">System Security Audits</h2>
          <p className="text-xs text-gray-400 mt-1">
            26 dedicated OS subsystem categories evaluating AMSI, Defender, UAC, Registry, and Credentials
          </p>
        </div>

        <button
          onClick={() => startScan('system')}
          disabled={isScanning}
          className="cyber-btn-primary text-xs flex items-center gap-2 self-start md:self-auto disabled:opacity-50"
        >
          {isScanning ? 'Auditing Windows...' : '▶ Audit System'}
        </button>
      </div>

      {/* Live Loading Skeleton while Scanning */}
      {isScanning && (
        <div className="cyber-card scan-pulse border-cyber-accent/40 space-y-3">
          <div className="flex justify-between items-center text-xs">
            <span className="text-cyber-accent font-semibold flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyber-accent animate-ping" />
              Auditing: {currentModule}
            </span>
            <span className="font-mono text-gray-400">{Math.round(progress)}%</span>
          </div>
          <div className="w-full bg-cyber-darker rounded-full h-2">
            <div className="bg-cyber-accent h-2 rounded-full transition-all duration-300" style={{ width: `${progress}%` }} />
          </div>
          <div className="grid grid-cols-3 gap-3 pt-2">
            <div className="h-12 bg-white/5 animate-pulse rounded-lg" />
            <div className="h-12 bg-white/5 animate-pulse rounded-lg" />
            <div className="h-12 bg-white/5 animate-pulse rounded-lg" />
          </div>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row gap-3 items-center justify-between">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search checks, findings, policies..."
            className="w-full pl-9 pr-3 py-2 bg-cyber-card border border-cyber-border rounded-lg text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyber-accent"
          />
        </div>

        <div className="flex items-center gap-1.5 w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
          <Filter className="w-3.5 h-3.5 text-gray-400 mr-1 shrink-0" />
          {['all', 'fail', 'warn', 'pass', 'info'].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium uppercase tracking-wider transition-colors shrink-0 ${
                statusFilter === st
                  ? 'bg-cyber-accent text-cyber-dark font-bold'
                  : 'bg-cyber-card text-gray-400 hover:text-white border border-cyber-border'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Zero State */}
      {Object.keys(modules).length === 0 && !isScanning && (
        <div className="cyber-card text-center py-20 border-dashed">
          <AlertCircle className="w-12 h-12 text-gray-600 mx-auto mb-3" />
          <h4 className="text-base font-semibold text-white">No System Audits Performed</h4>
          <p className="text-xs text-gray-500 mt-1 max-w-sm mx-auto">
            Run a system scan or click "Load Sample Profile" in Dashboard to explore findings.
          </p>
        </div>
      )}

      {/* Audit Module Cards List */}
      <div className="space-y-3">
        {filteredModules.map(([key, module]) => (
          <details key={key} className="cyber-card group transition-all duration-200">
            <summary className="flex items-center justify-between cursor-pointer list-none select-none">
              <div className="flex items-center gap-3">
                <span className="text-sm font-semibold text-white tracking-wide">
                  {module.category || key}
                </span>
                <span className="text-[11px] font-mono text-gray-500">[{key}]</span>
              </div>

              <div className="flex items-center gap-3">
                {getStatusBadge(module.status)}
                {module.findings?.length > 0 && (
                  <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-red-500/10 text-red-400 border border-red-500/20">
                    {module.findings.length} Finding{module.findings.length > 1 ? 's' : ''}
                  </span>
                )}
                <ChevronDown className="w-4 h-4 text-gray-400 transition-transform group-open:rotate-180" />
              </div>
            </summary>

            <div className="mt-4 pt-4 border-t border-cyber-border/80 space-y-4">
              {/* Findings List */}
              {module.findings && module.findings.length > 0 ? (
                <div className="space-y-2.5">
                  <h5 className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
                    Security Findings:
                  </h5>
                  {module.findings.map((f, idx) => (
                    <div
                      key={idx}
                      className="p-3.5 bg-cyber-dark/80 rounded-lg border border-red-500/20 space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          {getSeverityBadge(f.severity)}
                          <span className="text-xs font-bold text-white">{f.title}</span>
                        </div>
                      </div>

                      <p className="text-xs text-gray-300 leading-relaxed">{f.description}</p>

                      {f.remediation && (
                        <div className="pt-2 border-t border-cyber-border/60">
                          <span className="text-[11px] font-semibold text-cyber-accent">
                            Remediation Guidance:
                          </span>
                          <p className="text-xs text-emerald-300/90 font-mono mt-0.5 bg-emerald-950/20 p-2 rounded border border-emerald-500/20">
                            {f.remediation}
                          </p>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="flex items-center gap-2 text-xs text-gray-400 italic">
                  <ShieldCheck className="w-4 h-4 text-cyber-accent shrink-0" />
                  <span>No active security misconfigurations flagged for this subsystem.</span>
                </div>
              )}

              {/* Raw JSON Inspector */}
              {module.data && (
                <div className="pt-2">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider">
                      Extracted OS Subsystem Payload
                    </span>
                    <button
                      onClick={() => handleCopy(key, module.data)}
                      className="text-xs text-gray-400 hover:text-white flex items-center gap-1 px-2 py-0.5 rounded bg-white/5 border border-cyber-border"
                    >
                      {copiedKey === key ? (
                        <>
                          <Check className="w-3 h-3 text-cyber-accent" />
                          <span className="text-cyber-accent">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy JSON</span>
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-3 bg-cyber-darker rounded-lg text-[11px] text-gray-300 overflow-x-auto max-h-56 font-mono border border-cyber-border">
                    {JSON.stringify(module.data, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </details>
        ))}
      </div>
    </div>
  );
}
