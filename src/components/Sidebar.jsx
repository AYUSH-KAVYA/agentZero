import React from 'react';
import { NavLink } from 'react-router-dom';
import { useScan } from '../context/ScanContext';
import { LayoutDashboard, Server, Network, Bug, Shield, CheckCircle2, UserCheck } from 'lucide-react';

const navItems = [
  {
    path: '/',
    label: 'Dashboard',
    icon: LayoutDashboard,
  },
  {
    path: '/system',
    label: 'System Audit',
    icon: Server,
  },
  {
    path: '/network',
    label: 'Network Recon',
    icon: Network,
  },
  {
    path: '/vulnerabilities',
    label: 'Vulnerabilities',
    icon: Bug,
  },
];

export default function Sidebar() {
  const { isScanning, isAdmin } = useScan();

  return (
    <aside className="w-64 bg-slate-950/80 backdrop-blur-2xl border-r border-white/10 flex flex-col justify-between select-none">
      {/* Brand Logo Header */}
      <div>
        <div className="p-6 border-b border-white/10">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-sky-400/20 via-blue-500/20 to-indigo-600/30 border border-sky-400/40 flex items-center justify-center shadow-lg shadow-sky-500/10">
              <Shield className="w-5 h-5 text-sky-400" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <h1 className="text-lg font-bold text-white tracking-tight">AgentZero</h1>
                <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-sky-500/20 text-sky-300 border border-sky-400/30">
                  v1.0.1
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-medium">macOS Security Scanner</p>
            </div>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="p-4 space-y-1.5">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.path === '/'}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition-all duration-150 ${
                    isActive
                      ? 'bg-gradient-to-r from-sky-500/20 to-blue-600/10 text-sky-300 border border-sky-400/30 shadow-sm'
                      : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'
                  }`
                }
              >
                <Icon className="w-4 h-4" />
                {item.label}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* Footer Status Panel */}
      <div className="p-4 border-t border-white/10 space-y-3 bg-slate-950/40">
        {/* Scanning Pulse */}
        {isScanning && (
          <div className="flex items-center gap-2 text-xs text-sky-300 p-2.5 rounded-xl bg-sky-500/10 border border-sky-400/30 scan-pulse">
            <div className="w-2 h-2 rounded-full bg-sky-400 animate-ping" />
            <span className="font-semibold">Audit Engine Running...</span>
          </div>
        )}

        {/* Privilege Indicator */}
        <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-900/60 border border-white/5 text-xs">
          <span className="text-slate-400 flex items-center gap-1.5">
            <UserCheck className="w-3.5 h-3.5 text-sky-400" />
            User Level
          </span>
          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
            isAdmin ? 'bg-sky-500/20 text-sky-300 border border-sky-400/30' : 'bg-slate-800 text-slate-300'
          }`}>
            {isAdmin ? 'ROOT ADMIN' : 'STANDARD'}
          </span>
        </div>

        <p className="text-[10px] text-slate-500 text-center font-mono">
          AgentZero v1.0.1 • Apple macOS
        </p>
      </div>
    </aside>
  );
}
