import React from "react";
import clsx from "clsx";

const SEVERITY_STYLES = {
  CRITICAL: "bg-red-500/15 text-red-400 border-red-500/30 shadow-[0_0_8px_rgba(239,68,68,0.15)]",
  HIGH: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  MEDIUM: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  LOW: "bg-green-500/15 text-green-400 border-green-500/30",
  INFO: "bg-blue-500/15 text-blue-400 border-blue-500/30",
};

export function SeverityBadge({ severity }) {
  const key = severity?.toUpperCase() || "INFO";
  const styles = SEVERITY_STYLES[key] || "bg-slate-800 text-slate-400 border-slate-700";

  return (
    <span
      className={clsx(
        "px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wide border inline-flex items-center gap-1",
        styles
      )}
    >
      {key === "CRITICAL" && <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />}
      {severity || "UNKNOWN"}
    </span>
  );
}
