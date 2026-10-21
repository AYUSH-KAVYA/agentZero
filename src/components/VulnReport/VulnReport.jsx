import React from 'react';
import { useScan } from '../../context/ScanContext';

export default function VulnReport() {
  const { vulnResults, isScanning, startScan } = useScan();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Vulnerability Report</h2>
          <p className="text-sm text-gray-500 mt-1">
            CVE cross-reference, CIS benchmarks, and exploit mapping
          </p>
        </div>
        <div className="flex gap-3">
          <button className="cyber-btn-secondary" disabled={!vulnResults}>
            Export PDF
          </button>
          <button className="cyber-btn-secondary" disabled={!vulnResults}>
            Export HTML
          </button>
          <button
            onClick={() => startScan('vulnerabilities')}
            disabled={isScanning}
            className="cyber-btn-primary disabled:opacity-50"
          >
            {isScanning ? 'Scanning...' : '▶ Run Vuln Scan'}
          </button>
        </div>
      </div>

      {!vulnResults ? (
        <div className="cyber-card text-center py-16">
          <svg className="w-16 h-16 text-gray-600 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <p className="text-gray-500">No vulnerability scan results yet</p>
          <p className="text-gray-600 text-sm mt-1">
            Run a system scan first, then run the vulnerability scan to analyze findings
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Severity Summary */}
          <div className="grid grid-cols-4 gap-4">
            {[
              { label: 'Critical', count: vulnResults.critical || 0, color: 'red-500' },
              { label: 'High', count: vulnResults.high || 0, color: 'orange-500' },
              { label: 'Medium', count: vulnResults.medium || 0, color: 'yellow-500' },
              { label: 'Low', count: vulnResults.low || 0, color: 'blue-500' },
            ].map((s) => (
              <div key={s.label} className="cyber-card text-center">
                <p className={`text-2xl font-bold text-${s.color}`}>{s.count}</p>
                <p className="text-xs text-gray-500 mt-1">{s.label}</p>
              </div>
            ))}
          </div>

          {/* Vulnerability List */}
          <div className="space-y-2">
            {(vulnResults.findings || []).map((vuln, idx) => (
              <div key={idx} className="cyber-card">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={`status-${vuln.severity === 'critical' ? 'fail' : vuln.severity === 'high' ? 'warn' : 'info'}`}>
                        {vuln.severity?.toUpperCase()}
                      </span>
                      <span className="text-sm font-medium text-white">{vuln.title}</span>
                    </div>
                    <p className="text-xs text-gray-500 mt-1">{vuln.description}</p>
                    {vuln.cve && (
                      <p className="text-xs text-blue-400 mt-1 font-mono">{vuln.cve}</p>
                    )}
                  </div>
                  {vuln.patchAvailable && (
                    <span className="text-xs text-green-400 bg-green-500/10 px-2 py-1 rounded">
                      Patch: {vuln.patchKb}
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
