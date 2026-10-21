import React from 'react';
import { useScan } from '../../context/ScanContext';

export default function Dashboard() {
  const {
    isScanning,
    progress,
    currentModule,
    systemResults,
    networkResults,
    vulnResults,
    lastScanTime,
    isAdmin,
    error,
    startScan,
    cancelScan,
    clearError,
  } = useScan();

  const summaryCards = [
    {
      title: 'System Checks',
      count: systemResults ? Object.keys(systemResults.modules || {}).length : '—',
      status: systemResults ? 'Complete' : 'Not scanned',
      color: 'cyber-accent',
    },
    {
      title: 'Network Checks',
      count: networkResults ? Object.keys(networkResults.modules || {}).length : '—',
      status: networkResults ? 'Complete' : 'Not scanned',
      color: 'blue-400',
    },
    {
      title: 'Vulnerabilities',
      count: vulnResults ? (vulnResults.total || 0) : '—',
      status: vulnResults ? `${vulnResults.critical || 0} Critical` : 'Not scanned',
      color: 'red-400',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Dashboard</h2>
          <p className="text-sm text-gray-500 mt-1">
            {lastScanTime
              ? `Last scan: ${new Date(lastScanTime).toLocaleString()}`
              : 'No scans performed yet'}
          </p>
        </div>

        <div className="flex gap-3">
          {isScanning ? (
            <button onClick={cancelScan} className="cyber-btn-danger">
              Cancel Scan
            </button>
          ) : (
            <button onClick={() => startScan('full')} className="cyber-btn-primary">
              ▶ Full Scan
            </button>
          )}
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="flex items-center justify-between bg-red-500/10 border border-red-500/30 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <svg className="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span className="text-red-400 text-sm">{error}</span>
          </div>
          <button onClick={clearError} className="text-red-400 hover:text-red-300 text-sm">
            Dismiss
          </button>
        </div>
      )}

      {/* Admin Warning */}
      {!isAdmin && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <svg className="w-5 h-5 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <span className="text-yellow-400 text-sm">
              Running without administrator privileges. Some scan modules may return limited results.
            </span>
          </div>
        </div>
      )}

      {/* Progress Bar */}
      {isScanning && (
        <div className="cyber-card scan-pulse">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-cyber-accent font-medium">Scanning: {currentModule}</span>
            <span className="text-sm text-gray-400">{Math.round(progress)}%</span>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-2">
            <div
              className="bg-cyber-accent h-2 rounded-full transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-3 gap-4">
        {summaryCards.map((card) => (
          <div key={card.title} className="cyber-card">
            <p className="text-xs text-gray-500 uppercase tracking-wider">{card.title}</p>
            <p className={`text-3xl font-bold text-${card.color} mt-2`}>{card.count}</p>
            <p className="text-xs text-gray-500 mt-1">{card.status}</p>
          </div>
        ))}
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-3 gap-4">
        <button
          onClick={() => startScan('system')}
          disabled={isScanning}
          className="cyber-card hover:border-cyber-accent/50 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed text-left"
        >
          <div className="flex items-center gap-3 mb-2">
            <div className="w-8 h-8 rounded-md bg-green-500/20 flex items-center justify-center">
              <svg className="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
            </div>
            <span className="text-sm font-medium text-white">System Scan</span>
          </div>
          <p className="text-xs text-gray-500">Audit OS config, Defender, firewall, UAC, users, certificates</p>
        </button>

        <button
          onClick={() => startScan('network')}
          disabled={isScanning}
          className="cyber-card hover:border-blue-500/50 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed text-left"
        >
          <div className="flex items-center gap-3 mb-2">
            <div className="w-8 h-8 rounded-md bg-blue-500/20 flex items-center justify-center">
              <svg className="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
              </svg>
            </div>
            <span className="text-sm font-medium text-white">Network Scan</span>
          </div>
          <p className="text-xs text-gray-500">Map ARP table, DNS cache, open ports, RPC endpoints, VLAN devices</p>
        </button>

        <button
          onClick={() => startScan('vulnerabilities')}
          disabled={isScanning}
          className="cyber-card hover:border-red-500/50 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed text-left"
        >
          <div className="flex items-center gap-3 mb-2">
            <div className="w-8 h-8 rounded-md bg-red-500/20 flex items-center justify-center">
              <svg className="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <span className="text-sm font-medium text-white">Vulnerability Scan</span>
          </div>
          <p className="text-xs text-gray-500">Cross-reference CVEs, CIS benchmarks, search for public exploits</p>
        </button>
      </div>
    </div>
  );
}
