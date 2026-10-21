import React from 'react';
import { useScan } from '../../context/ScanContext';

export default function SystemScan() {
  const { systemResults, isScanning, startScan } = useScan();

  const statusIcon = (status) => {
    switch (status) {
      case 'pass': return <span className="status-pass">✓ Pass</span>;
      case 'warn': return <span className="status-warn">⚠ Warning</span>;
      case 'fail': return <span className="status-fail">✗ Fail</span>;
      case 'info': return <span className="status-info">ℹ Info</span>;
      case 'error': return <span className="status-fail">⊘ Error</span>;
      default: return <span className="status-info">— Pending</span>;
    }
  };

  const modules = systemResults?.modules || {};

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">System Scan</h2>
          <p className="text-sm text-gray-500 mt-1">
            Audits 25+ Windows configuration areas for security misconfigurations
          </p>
        </div>
        <button
          onClick={() => startScan('system')}
          disabled={isScanning}
          className="cyber-btn-primary disabled:opacity-50"
        >
          {isScanning ? 'Scanning...' : '▶ Run System Scan'}
        </button>
      </div>

      {Object.keys(modules).length === 0 ? (
        <div className="cyber-card text-center py-16">
          <svg className="w-16 h-16 text-gray-600 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
          </svg>
          <p className="text-gray-500">No system scan results yet</p>
          <p className="text-gray-600 text-sm mt-1">Run a system scan to audit your Windows configuration</p>
        </div>
      ) : (
        <div className="space-y-3">
          {Object.entries(modules).map(([key, module]) => (
            <details key={key} className="cyber-card group">
              <summary className="flex items-center justify-between cursor-pointer list-none">
                <div className="flex items-center gap-3">
                  <span className="text-sm font-medium text-white">{module.category}</span>
                </div>
                <div className="flex items-center gap-3">
                  {statusIcon(module.status)}
                  {module.findings?.length > 0 && (
                    <span className="text-xs text-gray-500">
                      {module.findings.length} finding(s)
                    </span>
                  )}
                  <svg className="w-4 h-4 text-gray-500 transition-transform group-open:rotate-180" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </summary>
              <div className="mt-4 pt-4 border-t border-cyber-border">
                {module.findings?.length > 0 ? (
                  <ul className="space-y-2">
                    {module.findings.map((finding, idx) => (
                      <li key={idx} className="text-sm text-gray-400 flex items-start gap-2">
                        <span className="text-cyber-warning mt-0.5">•</span>
                        {finding.description || finding}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-gray-500">No issues detected in this category.</p>
                )}
                {module.data && (
                  <details className="mt-3">
                    <summary className="text-xs text-gray-600 cursor-pointer hover:text-gray-400">
                      Raw Data
                    </summary>
                    <pre className="mt-2 p-3 bg-cyber-dark rounded-md text-xs text-gray-400 overflow-auto max-h-60 font-mono">
                      {JSON.stringify(module.data, null, 2)}
                    </pre>
                  </details>
                )}
              </div>
            </details>
          ))}
        </div>
      )}
    </div>
  );
}
