import React from "react";
import {
  ExternalLink,
  AlertTriangle,
  CheckCircle,
  Info,
  ShieldAlert,
} from "lucide-react";
import { motion } from "framer-motion";

function ResultsTable({ results }) {
  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "text-red-400 bg-red-500/10 border-red-500/20 shadow-[0_0_10px_rgba(248,113,113,0.2)]";
      case "high":
        return "text-orange-400 bg-orange-500/10 border-orange-500/20";
      case "medium":
        return "text-yellow-400 bg-yellow-500/10 border-yellow-500/20";
      default:
        return "text-blue-400 bg-blue-500/10 border-blue-500/20";
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return <ShieldAlert className="w-3.5 h-3.5" />;
      case "high":
        return <AlertTriangle className="w-3.5 h-3.5" />;
      case "medium":
        return <Info className="w-3.5 h-3.5" />;
      default:
        return <CheckCircle className="w-3.5 h-3.5" />;
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.2 }}
      className="glass-card overflow-hidden flex flex-col h-[500px]"
    >
      <div className="p-6 border-b border-white/5 flex items-center justify-between bg-slate-800/20">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <span className="w-2 h-6 bg-cyan-500 rounded-full" />
          Scan Findings
          <span className="text-sm font-normal text-slate-500 ml-2">
            ({results.length} Detected)
          </span>
        </h2>

        <div className="flex gap-2 text-xs">
          <span className="px-2 py-1 rounded bg-red-500/10 text-red-400 border border-red-500/20">
            Critical:{" "}
            {
              results.filter(
                (r) => r.severity_level.toLowerCase() === "critical"
              ).length
            }
          </span>
          <span className="px-2 py-1 rounded bg-orange-500/10 text-orange-400 border border-orange-500/20">
            High:{" "}
            {
              results.filter((r) => r.severity_level.toLowerCase() === "high")
                .length
            }
          </span>
        </div>
      </div>

      <div className="overflow-auto flex-1 scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent p-4">
        {results.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-slate-500 gap-4">
            <div className="w-16 h-16 rounded-full bg-slate-800/50 flex items-center justify-center border border-slate-700">
              <Info className="w-8 h-8 text-slate-600" />
            </div>
            <p className="text-lg">No findings detected yet...</p>
            <p className="text-sm text-slate-600">
              Start a scan to begin analysis
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {results.map((r, i) => (
              <motion.div
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.05 }}
                key={i}
                className="group bg-slate-900/40 border border-white/5 rounded-xl p-4 hover:bg-slate-800/60 hover:border-cyan-500/30 transition-all duration-300"
              >
                <div className="flex items-start gap-4">
                  <div
                    className={`mt-1 px-2.5 py-1 rounded-lg text-xs font-bold uppercase tracking-wider border flex items-center gap-1.5 ${getSeverityColor(
                      r.severity_level
                    )}`}
                  >
                    {getSeverityIcon(r.severity_level)}
                    {r.severity_level}
                  </div>
                  <div className="flex-1 min-w-0">
                    <h3 className="font-bold text-slate-200 mb-1 group-hover:text-cyan-400 transition-colors">
                      {r.vulnerability_type}
                    </h3>
                    <div className="flex items-center gap-2 mb-2">
                      <a
                        href={r.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 hover:underline truncate max-w-md"
                      >
                        {r.url}
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                    <p className="text-sm text-slate-400 bg-slate-950/50 p-3 rounded-lg border border-white/5 font-mono text-xs">
                      {r.details}
                    </p>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        )}
      </div>
    </motion.div>
  );
}

export default ResultsTable;
