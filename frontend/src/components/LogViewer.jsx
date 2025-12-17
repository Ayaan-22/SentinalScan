import React, { useEffect, useRef } from "react";
import { Terminal } from "lucide-react";

const LogViewer = ({ logs }) => {
  const endRef = useRef(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  return (
    <div className="glass-card h-[400px] flex flex-col overflow-hidden">
      <div className="p-3 border-b border-slate-700/50 bg-slate-900/50 flex items-center gap-2">
        <Terminal className="w-4 h-4 text-slate-400" />
        <span className="text-sm font-medium text-slate-300">Live Logs</span>
      </div>
      <div className="flex-1 overflow-y-auto p-4 font-mono text-sm scroll-bar">
        {logs.map((log, i) => (
          <div
            key={i}
            className={`mb-1 ${
              log.level === "ERROR" ? "text-red-400" : "text-slate-300"
            }`}
          >
            <span className="text-slate-500">
              [{new Date(log.timestamp * 1000).toLocaleTimeString()}]
            </span>
            <span
              className={`mx-2 font-bold ${
                log.level === "INFO"
                  ? "text-blue-400"
                  : log.level === "WARNING"
                  ? "text-yellow-400"
                  : log.level === "ERROR"
                  ? "text-red-500"
                  : "text-slate-400"
              }`}
            >
              {log.level}
            </span>
            {log.message}
          </div>
        ))}
        <div ref={endRef} />
      </div>
    </div>
  );
};

export default LogViewer;
