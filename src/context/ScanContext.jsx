import React, { createContext, useContext, useReducer, useCallback, useEffect } from 'react';
import { mockScanData } from '../data/mockScanData';

const ScanContext = createContext(null);

const initialState = {
  // Scan status
  isScanning: false,
  scanType: null, // 'system' | 'network' | 'vulnerabilities' | 'full'
  progress: 0,
  currentModule: '',
  logs: [],

  // Results
  systemResults: null,
  networkResults: null,
  vulnResults: null,
  posture: null,

  // Metadata
  lastScanTime: null,
  scanHistory: [],
  error: null,

  // Admin status
  isAdmin: false,
  platform: null,
  isMockData: false,
};

function scanReducer(state, action) {
  switch (action.type) {
    case 'SCAN_START':
      return {
        ...state,
        isScanning: true,
        scanType: action.payload,
        progress: 0,
        currentModule: 'Initializing execution environment...',
        error: null,
        logs: [
          {
            text: `[${new Date().toLocaleTimeString()}] Initiating ${action.payload} scan...`,
            time: new Date().toLocaleTimeString(),
          },
        ],
      };

    case 'SCAN_PROGRESS':
      return {
        ...state,
        progress: action.payload.progress,
        currentModule: action.payload.module || state.currentModule,
      };

    case 'SCAN_LOG':
      return {
        ...state,
        logs: [...state.logs.slice(-150), action.payload],
      };

    case 'SCAN_COMPLETE': {
      const type = action.payload.type;
      const res = action.payload.results;
      return {
        ...state,
        isScanning: false,
        scanType: null,
        progress: 100,
        currentModule: 'Scan Complete',
        lastScanTime: new Date().toISOString(),
        isMockData: false,
        ...(type === 'system' && { systemResults: res }),
        ...(type === 'network' && { networkResults: res }),
        ...(type === 'vulnerabilities' && {
          vulnResults: res,
          posture: res?.posture || null,
        }),
        ...(type === 'full' && {
          systemResults: res?.system,
          networkResults: res?.network,
          vulnResults: res?.vulnerabilities,
          posture: res?.vulnerabilities?.posture || null,
        }),
        logs: [
          ...state.logs,
          {
            text: `[${new Date().toLocaleTimeString()}] Scan completed successfully.`,
            time: new Date().toLocaleTimeString(),
          },
        ],
      };
    }

    case 'SCAN_ERROR':
      return {
        ...state,
        isScanning: false,
        scanType: null,
        error: action.payload,
        logs: [
          ...state.logs,
          {
            text: `[${new Date().toLocaleTimeString()}] ERROR: ${action.payload}`,
            time: new Date().toLocaleTimeString(),
          },
        ],
      };

    case 'LOAD_MOCK_DATA':
      return {
        ...state,
        isScanning: false,
        scanType: null,
        progress: 100,
        currentModule: 'Demonstration Profile Loaded',
        lastScanTime: mockScanData.timestamp,
        isMockData: true,
        systemResults: mockScanData.system,
        networkResults: mockScanData.network,
        vulnResults: mockScanData.vulnerabilities,
        posture: mockScanData.posture,
        error: null,
        logs: [
          {
            text: `[${new Date().toLocaleTimeString()}] Loaded realistic Windows 11 Enterprise audit dataset for evaluation.`,
            time: new Date().toLocaleTimeString(),
          },
        ],
      };

    case 'SET_ADMIN':
      return { ...state, isAdmin: action.payload };

    case 'SET_PLATFORM':
      return { ...state, platform: action.payload };

    case 'CLEAR_ERROR':
      return { ...state, error: null };

    case 'CLEAR_LOGS':
      return { ...state, logs: [] };

    case 'CLEAR_RESULTS':
      return {
        ...state,
        systemResults: null,
        networkResults: null,
        vulnResults: null,
        posture: null,
        lastScanTime: null,
        isMockData: false,
      };

    default:
      return state;
  }
}

export function ScanProvider({ children }) {
  const [state, dispatch] = useReducer(scanReducer, initialState);

  // Listen for scan events from Electron IPC
  useEffect(() => {
    if (!window.agentZero) return;

    const cleanupProgress = window.agentZero.onScanProgress((data) => {
      dispatch({ type: 'SCAN_PROGRESS', payload: data });
    });

    const cleanupLog = window.agentZero.onScanLog
      ? window.agentZero.onScanLog((data) => {
          dispatch({ type: 'SCAN_LOG', payload: data });
        })
      : () => {};

    const cleanupComplete = window.agentZero.onScanComplete((data) => {
      dispatch({ type: 'SCAN_COMPLETE', payload: data });
    });

    const cleanupError = window.agentZero.onScanError((data) => {
      dispatch({ type: 'SCAN_ERROR', payload: data.error });
    });

    // Fetch system info
    window.agentZero.isAdmin().then((isAdmin) => {
      dispatch({ type: 'SET_ADMIN', payload: isAdmin });
    });

    window.agentZero.getPlatformInfo().then((info) => {
      dispatch({ type: 'SET_PLATFORM', payload: info });
    });

    return () => {
      cleanupProgress();
      cleanupLog();
      cleanupComplete();
      cleanupError();
    };
  }, []);

  const startScan = useCallback(async (type, options = {}) => {
    if (!window.agentZero) {
      dispatch({
        type: 'SCAN_ERROR',
        payload: 'Electron IPC unavailable in standalone browser. Use "Load Audit Sample" to inspect data.',
      });
      return;
    }

    dispatch({ type: 'SCAN_START', payload: type });

    try {
      let result;
      switch (type) {
        case 'system':
          result = await window.agentZero.startSystemScan();
          break;
        case 'network':
          result = await window.agentZero.startNetworkScan(options);
          break;
        case 'vulnerabilities':
          result = await window.agentZero.startVulnScan();
          break;
        case 'full':
          result = await window.agentZero.startFullScan();
          break;
        default:
          throw new Error(`Unknown scan type: ${type}`);
      }

      if (!result.success) {
        dispatch({ type: 'SCAN_ERROR', payload: result.error });
      }
    } catch (error) {
      dispatch({ type: 'SCAN_ERROR', payload: error.message });
    }
  }, []);

  const cancelScan = useCallback(async () => {
    if (window.agentZero) {
      await window.agentZero.cancelScan();
    }
    dispatch({ type: 'SCAN_ERROR', payload: 'Scan cancelled by user.' });
  }, []);

  const loadMockData = useCallback(() => {
    dispatch({ type: 'LOAD_MOCK_DATA' });
  }, []);

  const value = {
    ...state,
    startScan,
    cancelScan,
    loadMockData,
    clearError: () => dispatch({ type: 'CLEAR_ERROR' }),
    clearLogs: () => dispatch({ type: 'CLEAR_LOGS' }),
    clearResults: () => dispatch({ type: 'CLEAR_RESULTS' }),
  };

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

export function useScan() {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error('useScan must be used within a ScanProvider');
  }
  return context;
}
