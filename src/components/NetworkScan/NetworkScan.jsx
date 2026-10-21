import React from 'react';
import { useScan } from '../../context/ScanContext';

export default function NetworkScan() {
  const { networkResults, isScanning, startScan } = useScan();

  const modules = networkResults?.modules || {};

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Network Scan</h2>
          <p className="text-sm text-gray-500 mt-1">
            Maps network topology, open ports, connections, and infrastructure devices
          </p>
        </div>
        <button
          onClick={() => startScan('network')}
          disabled={isScanning}
          className="cyber-btn-primary disabled:opacity-50"
        >
          {isScanning ? 'Scanning...' : '▶ Run Network Scan'}
        </button>
      </div>

      {Object.keys(modules).length === 0 ? (
        <div className="cyber-card text-center py-16">
          <svg className="w-16 h-16 text-gray-600 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
          </svg>
          <p className="text-gray-500">No network scan results yet</p>
          <p className="text-gray-600 text-sm mt-1">Run a network scan to map your local environment</p>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Network Diagram placeholder */}
          <div className="cyber-card">
            <h3 className="text-sm font-medium text-white mb-3">Network Topology</h3>
            <div className="bg-cyber-dark rounded-lg p-8 text-center border border-dashed border-cyber-border">
              <p className="text-gray-500 text-sm">Interactive network diagram will render here</p>
            </div>
          </div>

          {/* Module results */}
          {Object.entries(modules).map(([key, module]) => (
            <details key={key} className="cyber-card group">
              <summary className="flex items-center justify-between cursor-pointer list-none">
                <span className="text-sm font-medium text-white">{module.category}</span>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-gray-500">
                    {Array.isArray(module.data) ? `${module.data.length} entries` : ''}
                  </span>
                  <svg className="w-4 h-4 text-gray-500 transition-transform group-open:rotate-180" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </summary>
              <div className="mt-4 pt-4 border-t border-cyber-border">
                <pre className="p-3 bg-cyber-dark rounded-md text-xs text-gray-400 overflow-auto max-h-60 font-mono">
                  {JSON.stringify(module.data, null, 2)}
                </pre>
              </div>
            </details>
          ))}
        </div>
      )}
    </div>
  );
}
