import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
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
        <div className="flex h-screen bg-cyber-dark">
          <Sidebar />
          <main className="flex-1 overflow-auto p-6">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/system" element={<SystemScan />} />
              <Route path="/network" element={<NetworkScan />} />
              <Route path="/vulnerabilities" element={<VulnReport />} />
            </Routes>
          </main>
        </div>
      </Router>
    </ScanProvider>
  );
}
