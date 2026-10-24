const { ipcMain, shell, app } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');

let activeProcess = null;
let mainWindowRef = null;

/**
 * Resolves the path to the Python scanner executable.
 * In development: runs python directly.
 * In production: uses the bundled PyInstaller .exe.
 */
function getScannerPath() {
  if (app.isPackaged) {
    if (process.platform === 'win32') {
      return path.join(process.resourcesPath, 'scanner.exe');
    }
    return path.join(process.resourcesPath, 'python', 'main.py');
  }
  // Development mode — run Python directly
  return null; // Will use python interpreter
}

/**
 * Spawns the Python scanner process with the given scan type.
 * Streams progress via stderr and returns results via stdout.
 */
function runScanner(scanType, options = {}) {
  return new Promise((resolve, reject) => {
    const scannerPath = getScannerPath();
    let proc;

    const args = ['--scan-type', scanType, '--output-format', 'json'];

    if (options.ipRange) {
      args.push('--ip-range', options.ipRange);
    }
    if (options.format) {
      args.push('--report-format', options.format);
    }

    if (app.isPackaged && process.platform === 'win32' && scannerPath && scannerPath.endsWith('.exe')) {
      // Production on Windows: use bundled .exe
      proc = spawn(scannerPath, args, { windowsHide: true });
    } else {
      // Packaged on macOS/Linux or Development mode: use python interpreter
      const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
      const pythonScript = scannerPath || path.join(__dirname, '..', 'python', 'main.py');
      proc = spawn(pythonCmd, [pythonScript, ...args], {
        windowsHide: true,
        env: { ...process.env },
      });
    }

    activeProcess = proc;
    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    proc.stderr.on('data', (data) => {
      const rawText = data.toString();
      const lines = rawText.split('\n');

      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line) continue;
        stderr += line + '\n';

        // Forward raw log line to UI terminal
        if (mainWindowRef && !mainWindowRef.isDestroyed()) {
          mainWindowRef.webContents.send('scan:log', {
            text: line,
            time: new Date().toLocaleTimeString(),
          });
        }

        // Try to parse structured progress updates
        try {
          const progress = JSON.parse(line);
          if (progress.progress !== undefined && mainWindowRef && !mainWindowRef.isDestroyed()) {
            mainWindowRef.webContents.send('scan:progress', progress);
          }
        } catch {
          // Plain text log line
        }
      }
    });

    proc.on('close', (code) => {
      activeProcess = null;
      if (code === 0) {
        try {
          const results = JSON.parse(stdout);
          resolve(results);
        } catch (e) {
          reject(new Error(`Failed to parse scanner output: ${e.message}`));
        }
      } else {
        reject(new Error(`Scanner exited with code ${code}: ${stderr}`));
      }
    });

    proc.on('error', (err) => {
      activeProcess = null;
      reject(new Error(`Failed to start scanner: ${err.message}`));
    });
  });
}

/**
 * Registers all IPC handlers for the main process.
 */
function registerIpcHandlers(mainWindow) {
  mainWindowRef = mainWindow;

  // ─── Scan Handlers ──────────────────────────────────────────────
  ipcMain.handle('scan:system', async () => {
    try {
      const results = await runScanner('system');
      mainWindow.webContents.send('scan:complete', { type: 'system', results });
      return { success: true, results };
    } catch (error) {
      mainWindow.webContents.send('scan:error', { type: 'system', error: error.message });
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('scan:network', async (_event, options = {}) => {
    try {
      const results = await runScanner('network', options);
      mainWindow.webContents.send('scan:complete', { type: 'network', results });
      return { success: true, results };
    } catch (error) {
      mainWindow.webContents.send('scan:error', { type: 'network', error: error.message });
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('scan:vulnerabilities', async () => {
    try {
      const results = await runScanner('vulnerabilities');
      mainWindow.webContents.send('scan:complete', { type: 'vulnerabilities', results });
      return { success: true, results };
    } catch (error) {
      mainWindow.webContents.send('scan:error', { type: 'vulnerabilities', error: error.message });
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('scan:full', async () => {
    try {
      const results = await runScanner('full');
      mainWindow.webContents.send('scan:complete', { type: 'full', results });
      return { success: true, results };
    } catch (error) {
      mainWindow.webContents.send('scan:error', { type: 'full', error: error.message });
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('scan:cancel', async () => {
    if (activeProcess) {
      activeProcess.kill('SIGTERM');
      activeProcess = null;
      return { success: true };
    }
    return { success: false, error: 'No active scan' };
  });

  // ─── Report Handlers ───────────────────────────────────────────
  ipcMain.handle('report:generate', async (_event, format, data) => {
    try {
      const results = await runScanner('report', { format, data });
      return { success: true, path: results.reportPath };
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('report:open', async (_event, filePath) => {
    await shell.openPath(filePath);
    return { success: true };
  });

  // ─── Results Handlers ──────────────────────────────────────────
  ipcMain.handle('results:last', async () => {
    // TODO: Implement results storage/retrieval
    return { success: true, results: null };
  });

  ipcMain.handle('results:history', async () => {
    // TODO: Implement scan history
    return { success: true, history: [] };
  });

  ipcMain.handle('results:export', async (_event, format) => {
    // TODO: Implement results export
    return { success: true };
  });

  // ─── System Info Handlers ──────────────────────────────────────
  ipcMain.handle('system:info', async () => {
    return {
      platform: os.platform(),
      release: os.release(),
      arch: os.arch(),
      hostname: os.hostname(),
      cpus: os.cpus().length,
      totalMemory: os.totalmem(),
      freeMemory: os.freemem(),
    };
  });

  ipcMain.handle('system:isAdmin', async () => {
    // On Windows, check if running as administrator
    if (os.platform() === 'win32') {
      try {
        const { execSync } = require('child_process');
        execSync('net session', { stdio: 'ignore' });
        return true;
      } catch {
        return false;
      }
    }
    return process.getuid && process.getuid() === 0;
  });

  // ─── App Handlers ─────────────────────────────────────────────
  ipcMain.handle('app:version', () => app.getVersion());

  ipcMain.handle('app:openExternal', async (_event, url) => {
    await shell.openExternal(url);
    return { success: true };
  });
}

module.exports = { registerIpcHandlers };
