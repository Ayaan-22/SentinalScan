import React, { useEffect, useMemo, useRef, useState } from "react";
import { Check, Copy, Download, Pause, Play, Search, Terminal, Trash2 } from "lucide-react";
import clsx from "clsx";
import { useLiveLogStream } from "./useLiveLogStream";

const LEVELS = ["INFO", "WARNING", "ERROR", "CRITICAL"];

export const LiveLogs = ({ scanId, isScanning, statusLogs = [] }) => {
  const { logs, connectionStatus, clearLogs } = useLiveLogStream(scanId, isScanning, statusLogs);
  const logScrollRef = useRef(null);
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState("");
  const [autoScroll, setAutoScroll] = useState(true);
  const [query, setQuery] = useState("");
  const [levels, setLevels] = useState(new Set(LEVELS));

  const filteredLogs = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return logs.filter((log) => {
      const level = log.level || "INFO";
      if (!levels.has(level)) return false;
      if (!needle) return true;
      return `${log.message || ""} ${log.level || ""}`.toLowerCase().includes(needle);
    });
  }, [logs, levels, query]);

  useEffect(() => {
    if (autoScroll && filteredLogs.length > 0) {
      const container = logScrollRef.current;
      if (container) {
        container.scrollTop = container.scrollHeight;
      }
    }
  }, [autoScroll, filteredLogs]);

  const getLevelColor = (level) => {
    switch (level) {
      case "INFO":
        return "text-blue-300";
      case "WARNING":
        return "text-yellow-300";
      case "ERROR":
        return "text-red-300";
      case "CRITICAL":
        return "text-red-400 font-bold";
      default:
        return "text-slate-300";
    }
  };

  const formatTime = (timestamp) => {
    if (!timestamp) return "";
    return new Date(timestamp).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  };

  const toText = () =>
    filteredLogs
      .map((log) => `[${formatTime(log.timestamp)}] ${log.level || "INFO"}: ${log.message || ""}`)
      .join("\n");

  const handleCopy = async () => {
    setCopyError("");
    try {
      await navigator.clipboard.writeText(toText());
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopyError("Clipboard permission denied");
    }
  };

  const handleDownload = () => {
    const blob = new Blob([toText()], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinalscan-logs-${scanId?.slice(0, 8) || "scan"}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const toggleLevel = (level) => {
    setLevels((current) => {
      const next = new Set(current);
      if (next.has(level)) next.delete(level);
      else next.add(level);
      return next;
    });
  };

  return (
    <div className="flex-1 rounded-xl bg-slate-950/70 border border-slate-800 p-4 font-mono text-xs overflow-hidden flex flex-col h-full min-h-[500px]">
      <div className="flex flex-col gap-3 pb-3 mb-3 border-b border-slate-800">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span className="text-slate-400 uppercase tracking-widest font-semibold text-[10px]">
              Live Log Stream
            </span>
            <span
              className={clsx(
                "rounded-full border px-2 py-0.5 text-[10px] font-semibold",
                connectionStatus === "Connected" && "border-green-500/30 bg-green-500/10 text-green-300",
                connectionStatus === "Reconnecting" && "border-yellow-500/30 bg-yellow-500/10 text-yellow-300",
                connectionStatus === "Polling fallback" && "border-blue-500/30 bg-blue-500/10 text-blue-300",
                !["Connected", "Reconnecting", "Polling fallback"].includes(connectionStatus) &&
                  "border-slate-700 bg-slate-900 text-slate-400"
              )}
            >
              {connectionStatus}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={() => setAutoScroll((v) => !v)} className="log-action">
              {autoScroll ? <Pause className="w-3 h-3" /> : <Play className="w-3 h-3" />}
              {autoScroll ? "Pause" : "Resume"}
            </button>
            <button type="button" onClick={handleCopy} className="log-action">
              {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
              {copied ? "Copied" : "Copy"}
            </button>
            <button type="button" onClick={handleDownload} className="log-action">
              <Download className="w-3 h-3" />
              Download
            </button>
            <button type="button" onClick={clearLogs} className="log-action text-red-300 hover:text-red-200">
              <Trash2 className="w-3 h-3" />
              Clear
            </button>
          </div>
        </div>

        <div className="flex flex-col md:flex-row gap-2">
          <label className="relative flex-1">
            <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
            <span className="sr-only">Search logs</span>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search log messages"
              className="w-full rounded-lg border border-slate-800 bg-slate-900/70 py-2 pl-9 pr-3 text-slate-200 placeholder:text-slate-600 outline-none focus:border-cyan-500/60"
            />
          </label>
          <div className="flex flex-wrap gap-1">
            {LEVELS.map((level) => (
              <button
                key={level}
                type="button"
                onClick={() => toggleLevel(level)}
                className={clsx(
                  "rounded-lg border px-2 py-1.5 text-[10px] font-bold",
                  levels.has(level)
                    ? "border-cyan-500/30 bg-cyan-500/10 text-cyan-300"
                    : "border-slate-800 bg-slate-900 text-slate-500"
                )}
              >
                {level}
              </button>
            ))}
          </div>
        </div>
        {copyError && <p className="text-[10px] text-red-300">{copyError}</p>}
      </div>

      <div ref={logScrollRef} className="flex-1 overflow-y-auto space-y-1 pr-2">
        {filteredLogs.length === 0 ? (
          <div className="h-full flex items-center justify-center text-slate-600 italic">
            {scanId ? "Waiting for log stream..." : "Start or select a scan to view logs"}
          </div>
        ) : (
          filteredLogs.map((log) => (
            <div
              key={`${log.timestamp}-${log.level}-${log.message}`}
              className={clsx("grid grid-cols-[86px_72px_1fr] gap-3 rounded px-2 py-1", getLevelColor(log.level))}
            >
              <span className="opacity-50 text-[10px] pt-0.5">[{formatTime(log.timestamp)}]</span>
              <span className="font-bold">{log.level || "INFO"}</span>
              <span className="break-words whitespace-pre-wrap">{log.message}</span>
            </div>
          ))
        )}
        <div className="h-4" />
      </div>
    </div>
  );
};
