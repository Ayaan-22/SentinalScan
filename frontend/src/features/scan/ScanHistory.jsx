import React from "react";
import { useAllScans } from "./scan.hooks";
import { Clock, CheckCircle2, XCircle, AlertCircle, PlayCircle, Loader2 } from "lucide-react";
import { clsx } from "clsx";

export function ScanHistory({ activeScanId, onSelectScan }) {
  const { data: scans, isLoading } = useAllScans();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-10 text-slate-500">
        <Loader2 className="w-5 h-5 animate-spin mr-2" />
        <span className="text-sm">Loading history...</span>
      </div>
    );
  }

  if (!scans || scans.length === 0) {
    return (
      <div className="text-center py-10 px-4">
        <Clock className="w-8 h-8 text-slate-700 mx-auto mb-3" />
        <p className="text-sm text-slate-500">No scan history found</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <h3 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3 px-1">
        Recent Scans
      </h3>
      <div className="space-y-1 max-h-[400px] overflow-y-auto pr-2 scrollbar-thin scrollbar-thumb-slate-800">
        {scans.map((scan) => (
          <button
            key={scan.scan_id}
            onClick={() => onSelectScan(scan.scan_id)}
            className={clsx(
              "w-full text-left p-3 rounded-xl border transition-all group relative overflow-hidden",
              activeScanId === scan.scan_id
                ? "bg-cyan-500/10 border-cyan-500/30 shadow-[0_0_15px_rgba(6,182,212,0.1)]"
                : "bg-slate-900/30 border-slate-800/50 hover:bg-slate-900/60 hover:border-slate-700"
            )}
          >
            {/* Active Indicator Bar */}
            {activeScanId === scan.scan_id && (
              <div className="absolute left-0 top-0 bottom-0 w-1 bg-cyan-500" />
            )}

            <div className="flex items-start justify-between gap-2 mb-1">
              <span className="text-[11px] font-mono text-slate-300 truncate flex-1">
                {scan.target_url.replace(/^https?:\/\//, "")}
              </span>
              <StatusIcon status={scan.status} />
            </div>

            <div className="flex items-center justify-between text-[10px]">
              <span className="text-slate-500">
                {new Date(scan.start_time).toLocaleDateString(undefined, {
                  month: "short",
                  day: "numeric",
                  hour: "2-digit",
                  minute: "2-digit",
                })}
              </span>
              {scan.vulnerabilities_count > 0 && (
                <span className="text-orange-400 font-bold">
                  {scan.vulnerabilities_count} findings
                </span>
              )}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

function StatusIcon({ status }) {
  switch (status) {
    case "completed":
      return <CheckCircle2 className="w-3.5 h-3.5 text-green-500" />;
    case "failed":
      return <XCircle className="w-3.5 h-3.5 text-red-500" />;
    case "running":
      return <Loader2 className="w-3.5 h-3.5 text-cyan-500 animate-spin" />;
    case "pending":
      return <PlayCircle className="w-3.5 h-3.5 text-slate-400 animate-pulse" />;
    case "stopped":
      return <AlertCircle className="w-3.5 h-3.5 text-yellow-500" />;
    default:
      return null;
  }
}
