import React, { useRef, useEffect } from "react";
import { Terminal, Activity, Clock } from "lucide-react";
import { motion } from "framer-motion";

function LogViewer({ logs }) {
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className="glass-card flex flex-col h-[500px] border-t-4 border-t-cyan-500"
    >
      <div className="p-4 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="p-1.5 bg-slate-800 rounded-lg border border-slate-700">
            <Terminal className="w-4 h-4 text-cyan-400" />
          </div>
          <h3 className="font-mono text-sm font-bold text-slate-200">
            Live Execution Logs
          </h3>
        </div>
        <div className="flex gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full bg-red-500/20 border border-red-500/50" />
          <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/20 border border-yellow-500/50" />
          <div className="w-2.5 h-2.5 rounded-full bg-green-500/20 border border-green-500/50" />
        </div>
      </div>

      <div className="flex-1 overflow-auto p-4 font-mono text-xs space-y-2 bg-slate-950/80 scrollbar-thumb-slate-800 scrollbar-track-transparent">
        {logs.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-600 gap-2 opacity-50">
            <Activity className="w-8 h-8 animate-pulse" />
            <p>Waiting for system initialization...</p>
          </div>
        ) : (
          logs.map((log, index) => {
            const isError = log.level === "ERROR";
            const isInfo = log.level === "INFO";
            const isSucc =
              log.message.includes("successfully") ||
              log.message.includes("Found");

            return (
              <div
                key={index}
                className="flex gap-3 hover:bg-white/5 p-1 rounded transition-colors group"
              >
                <span className="text-slate-600 shrink-0 w-16 select-none opacity-50 group-hover:opacity-100 transition-opacity">
                  {new Date().toLocaleTimeString("en-US", {
                    hour12: false,
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                  })}
                </span>
                <div className="flex-1 break-all">
                  <span
                    className={`font-bold mr-2 ${
                      isError
                        ? "text-red-500"
                        : isSucc
                        ? "text-green-400"
                        : "text-blue-400"
                    }`}
                  >
                    [{log.level}]
                  </span>
                  <span className="text-slate-300">{log.message}</span>
                </div>
              </div>
            );
          })
        )}
        <div ref={bottomRef} />
      </div>
    </motion.div>
  );
}

export default LogViewer;
