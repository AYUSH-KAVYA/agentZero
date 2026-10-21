import React, { createContext, useContext, useReducer, useCallback, useEffect } from 'react';

const ScanContext = createContext(null);

const initialState = {
  // Scan status
  isScanning: false,
  scanType: null, // 'system' | 'network' | 'vulnerabilities' | 'full'
  progress: 0,
  currentModule: '',

  // Results
  systemResults: null,
  networkResults: null,
  vulnResults: null,

  // Metadata
  lastScanTime: null,
  scanHistory: [],
  error: null,

  // Admin status
  isAdmin: false,
};

function scanReducer(state, action) {
  switch (action.type) {
    case 'SCAN_START':
      return {
        ...state,
        isScanning: true,
        scanType: action.payload,
        progress: 0,
        currentModule: 'Initializing...',
        error: null,
      };

    case 'SCAN_PROGRESS':
      return {
        ...state,
        progress: action.payload.progress,
        currentModule: action.payload.module || state.currentModule,
      };

    case 'SCAN_COMPLETE':
      return {
        ...state,
        isScanning: false,
        scanType: null,
        progress: 100,
        currentModule: 'Complete',
        lastScanTime: new Date().toISOString(),
        ...(action.payload.type === 'system' && { systemResults: action.payload.results }),
        ...(action.payload.type === 'network' && { networkResults: action.payload.results }),
        ...(action.payload.type === 'vulnerabilities' && { vulnResults: action.payload.results }),
        ...(action.payload.type === 'full' && {
          systemResults: action.payload.results.system,
          networkResults: action.payload.results.network,
          vulnResults: action.payload.results.vulnerabilities,
        }),
      };

    case 'SCAN_ERROR':
      return {
        ...state,
        isScanning: false,
        scanType: null,
        error: action.payload,
      };

    case 'SET_ADMIN':
      return { ...state, isAdmin: action.payload };

    case 'CLEAR_ERROR':
      return { ...state, error: null };

    case 'CLEAR_RESULTS':
      return {
        ...state,
        systemResults: null,
        networkResults: null,
        vulnResults: null,
        lastScanTime: null,
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

    const cleanupComplete = window.agentZero.onScanComplete((data) => {
      dispatch({ type: 'SCAN_COMPLETE', payload: data });
    });

    const cleanupError = window.agentZero.onScanError((data) => {
      dispatch({ type: 'SCAN_ERROR', payload: data.error });
    });

    // Check admin status
    window.agentZero.isAdmin().then((isAdmin) => {
      dispatch({ type: 'SET_ADMIN', payload: isAdmin });
    });

    return () => {
      cleanupProgress();
      cleanupComplete();
      cleanupError();
    };
  }, []);

  const startScan = useCallback(async (type, options = {}) => {
    if (!window.agentZero) {
      dispatch({ type: 'SCAN_ERROR', payload: 'Electron IPC not available' });
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
    dispatch({ type: 'SCAN_ERROR', payload: 'Scan cancelled by user' });
  }, []);

  const value = {
    ...state,
    startScan,
    cancelScan,
    clearError: () => dispatch({ type: 'CLEAR_ERROR' }),
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
