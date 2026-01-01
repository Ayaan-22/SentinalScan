import React, { useEffect, useRef, useState } from "react";
import { Terminal, Copy, Check } from "lucide-react";
import { useScanLogs } from "./logs.hooks";
import clsx from "clsx";

export const LiveLogs = () => {
  const { logs } = useScanLogs();
  const bottomRef = useRef(null);
  const [copied, setCopied] = useState(false);

  // Auto-scroll
  useEffect(() => {
    if (logs.length > 0) {
      bottomRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "nearest",
      });
    }
  }, [logs]);

  const getLevelColor = (level) => {
    switch (level) {
      case "INFO":
        return "text-blue-400";
      case "WARNING":
        return "text-yellow-400";
      case "ERROR":
        return "text-red-400";
      case "CRITICAL":
        return "text-red-600 font-bold";
      default:
        return "text-slate-300";
    }
  };

  const formatTime = (timestamp) => {
    const date = new Date(timestamp * 1000);
    return date.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  };

  const handleCopy = () => {
    const logText = logs
      .map(
        (log) => `[${formatTime(log.timestamp)}] ${log.level}: ${log.message}`
      )
      .join("\n");
    navigator.clipboard.writeText(logText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="flex-1 rounded-xl bg-slate-950/50 border border-slate-800 p-4 font-mono text-xs overflow-hidden flex flex-col h-full min-h-[500px]">
      <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-slate-500" />
          <span className="text-slate-500 uppercase tracking-widest font-semibold text-[10px]">
            System Stream
          </span>
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 px-2 py-1 text-[10px] font-medium text-slate-400 hover:text-cyan-400 bg-slate-900/50 hover:bg-slate-900 border border-slate-800 rounded-md transition-all"
        >
          {copied ? (
            <Check className="w-3 h-3 text-green-400" />
          ) : (
            <Copy className="w-3 h-3" />
          )}
          {copied ? "COPIED" : "COPY LOGS"}
        </button>
      </div>

      <div className="flex-1 overflow-y-auto space-y-1 pr-2 scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent">
        {logs.length === 0 ? (
          <div className="h-full flex items-center justify-center text-slate-600 italic">
            Waiting for log stream...
          </div>
        ) : (
          logs.map((log, i) => (
            <div
              key={i}
              className={`flex gap-3 ${getLevelColor(
                log.level
              )} animate-in fade-in slide-in-from-left-2 duration-300`}
            >
              <span className="opacity-50 min-w-[85px] text-[10px] pt-0.5">
                [{formatTime(log.timestamp)}]
              </span>
              <span
                className={`font-bold min-w-[60px] ${
                  log.level === "CRITICAL" || log.level === "ERROR"
                    ? "animate-pulse"
                    : ""
                }`}
              >
                {log.level}
              </span>
              <span className="break-all whitespace-pre-wrap">
                {log.message}
              </span>
            </div>
          ))
        )}
        <div ref={bottomRef} className="h-4" />
      </div>
    </div>
  );
};
