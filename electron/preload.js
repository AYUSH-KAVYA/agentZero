const { contextBridge, ipcRenderer } = require('electron');

/**
 * AgentZero IPC Bridge
 * Exposes a secure API from the Electron main process to the React renderer.
 * All communication is done via invoke (request/response) and on (event streams).
 */
contextBridge.exposeInMainWorld('agentZero', {
  // ─── Scan Operations ───────────────────────────────────────────
  startSystemScan: () => ipcRenderer.invoke('scan:system'),
  startNetworkScan: (options) => ipcRenderer.invoke('scan:network', options),
  startVulnScan: () => ipcRenderer.invoke('scan:vulnerabilities'),
  startFullScan: () => ipcRenderer.invoke('scan:full'),
  cancelScan: () => ipcRenderer.invoke('scan:cancel'),

  // ─── Report Operations ─────────────────────────────────────────
  generateReport: (format, data) => ipcRenderer.invoke('report:generate', format, data),
  openReport: (filePath) => ipcRenderer.invoke('report:open', filePath),

  // ─── Results ────────────────────────────────────────────────────
  getLastScanResults: () => ipcRenderer.invoke('results:last'),
  getScanHistory: () => ipcRenderer.invoke('results:history'),
  exportResults: (format) => ipcRenderer.invoke('results:export', format),

  // ─── Progress Events (Renderer listens) ─────────────────────────
  onScanProgress: (callback) => {
    const handler = (_event, data) => callback(data);
    ipcRenderer.on('scan:progress', handler);
    // Return cleanup function
    return () => ipcRenderer.removeListener('scan:progress', handler);
  },
  onScanComplete: (callback) => {
    const handler = (_event, data) => callback(data);
    ipcRenderer.on('scan:complete', handler);
    return () => ipcRenderer.removeListener('scan:complete', handler);
  },
  onScanError: (callback) => {
    const handler = (_event, data) => callback(data);
    ipcRenderer.on('scan:error', handler);
    return () => ipcRenderer.removeListener('scan:error', handler);
  },

  // ─── System Info ────────────────────────────────────────────────
  getPlatformInfo: () => ipcRenderer.invoke('system:info'),
  isAdmin: () => ipcRenderer.invoke('system:isAdmin'),

  // ─── App Controls ──────────────────────────────────────────────
  getAppVersion: () => ipcRenderer.invoke('app:version'),
  openExternal: (url) => ipcRenderer.invoke('app:openExternal', url),
});
