import React from "react";
import clsx from "clsx";

export function SeverityBadge({ severity }) {
  const getStyles = (sev) => {
    switch (sev?.toUpperCase()) {
      case "CRITICAL":
      case "HIGH":
        return "bg-red-500/10 text-red-500 border-red-500/20";
      case "MEDIUM":
        return "bg-orange-500/10 text-orange-500 border-orange-500/20";
      case "LOW":
        return "bg-yellow-500/10 text-yellow-500 border-yellow-500/20";
      case "INFO":
        return "bg-blue-500/10 text-blue-500 border-blue-500/20";
      default:
        return "bg-slate-800 text-slate-400 border-slate-700";
    }
  };

  return (
    <span
      className={clsx(
        "px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wide border",
        getStyles(severity)
      )}
    >
      {severity || "UNKNOWN"}
    </span>
  );
}
