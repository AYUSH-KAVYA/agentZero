import React from 'react';
import { HashRouter as Router, Routes, Route } from 'react-router-dom';
import { ScanProvider } from './context/ScanContext';
import Dashboard from './components/Dashboard/Dashboard';
import SystemScan from './components/SystemScan/SystemScan';
import NetworkScan from './components/NetworkScan/NetworkScan';
import VulnReport from './components/VulnReport/VulnReport';
import Sidebar from './components/Sidebar';

export default function App() {
  return (
    <ScanProvider>
      <Router>
        <div className="flex h-screen bg-cyber-dark text-slate-100 font-sans antialiased overflow-hidden selection:bg-sky-500/30 selection:text-white">
          <Sidebar />
          <main className="flex-1 overflow-auto p-6 md:p-8">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/system" element={<SystemScan />} />
              <Route path="/network" element={<NetworkScan />} />
              <Route path="/vulnerabilities" element={<VulnReport />} />
              <Route path="*" element={<Dashboard />} />
            </Routes>
          </main>
        </div>
      </Router>
    </ScanProvider>
  );
}
