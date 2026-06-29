import { useEffect, useRef, useState } from "react";
import { getApiKey, scanApi, WS_BASE } from "../../services/api";

const MAX_RETRIES = 4;
const STORAGE_PREFIX = "sentinalscan.logs.";

function logKey(log) {
  return `${log.timestamp || ""}|${log.level || ""}|${log.message || ""}|${log.type || ""}`;
}

function storageKey(scanId) {
  return `${STORAGE_PREFIX}${scanId}`;
}

function readStoredLogs(scanId) {
  if (!scanId) return [];
  try {
    const raw = sessionStorage.getItem(storageKey(scanId));
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function writeStoredLogs(scanId, logs) {
  if (!scanId) return;
  try {
    sessionStorage.setItem(storageKey(scanId), JSON.stringify(logs.slice(-1000)));
  } catch {
    // Ignore storage quota/private-mode failures; the in-memory log view still works.
  }
}

export function useLiveLogStream(scanId, isScanning, statusLogs = []) {
  const [logs, setLogs] = useState([]);
  const [connectionStatus, setConnectionStatus] = useState("Closed");
  const retryRef = useRef(0);
  const socketRef = useRef(null);
  const seenRef = useRef(new Set());
  const reconcileRef = useRef(null);
  const retryTimerRef = useRef(null);
  const isScanningRef = useRef(isScanning);
  const scanIdRef = useRef(scanId);

  useEffect(() => {
    isScanningRef.current = isScanning;
  }, [isScanning]);

  useEffect(() => {
    if (!scanId) {
      const resetTimer = window.setTimeout(() => {
        setConnectionStatus("Closed");
        setLogs([]);
        seenRef.current = new Set();
      }, 0);
      return () => window.clearTimeout(resetTimer);
    }

    scanIdRef.current = scanId;
    let cancelled = false;

    const appendLogs = (entries) => {
      if (!Array.isArray(entries) || entries.length === 0) return;
      setLogs((current) => {
        const next = [...current];
        for (const entry of entries) {
          const key = logKey(entry);
          if (!seenRef.current.has(key)) {
            seenRef.current.add(key);
            next.push(entry);
          }
        }
        writeStoredLogs(scanIdRef.current, next);
        return next;
      });
    };

    const fetchRestLogs = async () => {
      try {
        const restLogs = await scanApi.getLogs(scanId);
        appendLogs(restLogs);
        return true;
      } catch {
        return false;
      }
    };

    const startRestReconcile = () => {
      if (reconcileRef.current) return;
      reconcileRef.current = window.setInterval(async () => {
        const ok = await fetchRestLogs();
        if (!ok && socketRef.current?.readyState !== WebSocket.OPEN) {
          setConnectionStatus("Polling fallback");
        }
      }, 1500);
    };

    const connect = () => {
      const apiKey = getApiKey();
      if (!apiKey) {
        setConnectionStatus("Polling fallback");
        startRestReconcile();
        fetchRestLogs();
        return;
      }

      const wsUrl = `${WS_BASE.replace(/\/$/, "")}/ws/logs/${encodeURIComponent(
        scanId
      )}?api_key=${encodeURIComponent(apiKey)}`;

      setConnectionStatus(retryRef.current > 0 ? "Reconnecting" : "Connecting");
      const socket = new WebSocket(wsUrl);
      socketRef.current = socket;

      socket.onopen = () => {
        retryRef.current = 0;
        setConnectionStatus("Connected");
        fetchRestLogs();
      };

      socket.onmessage = (event) => {
        try {
          const entry = JSON.parse(event.data);
          appendLogs([entry]);
          if (entry.type === "scan_complete") {
            fetchRestLogs();
            setConnectionStatus("Closed");
            socket.close();
          }
        } catch {
          appendLogs([
            {
              timestamp: new Date().toISOString(),
              level: "WARNING",
              message: "Received malformed log entry",
            },
          ]);
        }
      };

      socket.onerror = () => {
        socket.close();
      };

      socket.onclose = () => {
        if (cancelled) return;
        if (isScanningRef.current && retryRef.current < MAX_RETRIES) {
          retryRef.current += 1;
          setConnectionStatus("Reconnecting");
          retryTimerRef.current = window.setTimeout(
            connect,
            Math.min(1000 * retryRef.current, 5000)
          );
        } else if (isScanningRef.current) {
          setConnectionStatus("Polling fallback");
        } else {
          setConnectionStatus("Closed");
          fetchRestLogs();
        }
      };
    };

    const bootTimer = window.setTimeout(async () => {
      const storedLogs = readStoredLogs(scanId);
      seenRef.current = new Set(storedLogs.map(logKey));
      setLogs(storedLogs);
      await fetchRestLogs();
      startRestReconcile();
      connect();
    }, 0);

    return () => {
      cancelled = true;
      window.clearTimeout(bootTimer);
      if (retryTimerRef.current) window.clearTimeout(retryTimerRef.current);
      if (reconcileRef.current) {
        window.clearInterval(reconcileRef.current);
        reconcileRef.current = null;
      }
      if (socketRef.current) {
        socketRef.current.close();
        socketRef.current = null;
      }
    };
  }, [scanId]);

  useEffect(() => {
    if (!scanId || !Array.isArray(statusLogs) || statusLogs.length === 0) {
      return undefined;
    }

    const mergeTimer = window.setTimeout(() => {
      setLogs((current) => {
        const next = [...current];
        for (const entry of statusLogs) {
          const key = logKey(entry);
          if (!seenRef.current.has(key)) {
            seenRef.current.add(key);
            next.push(entry);
          }
        }
        writeStoredLogs(scanId, next);
        return next;
      });
    }, 0);

    return () => window.clearTimeout(mergeTimer);
  }, [scanId, statusLogs]);

  const clearLogs = () => {
    seenRef.current = new Set();
    setLogs([]);
    if (scanId) {
      sessionStorage.removeItem(storageKey(scanId));
    }
  };

  return { logs, connectionStatus, clearLogs };
}
