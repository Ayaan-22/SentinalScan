import React, { useState } from "react";
import { SeverityBadge } from "./SeverityBadge";
import { ChevronDown, ChevronRight, ExternalLink, Shield, Clock } from "lucide-react";
import clsx from "clsx";
import { AnimatePresence, motion } from "framer-motion";

const MotionDiv = motion.div;

export function FindingsTable({ findings }) {
  const [expandedId, setExpandedId] = useState(null);


  if (!findings || findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center p-12 bg-slate-900/50 rounded-2xl border border-slate-800/50 text-slate-500">
        <div className="w-16 h-16 rounded-full bg-slate-800/50 flex items-center justify-center border border-slate-700 mb-4">
          <Shield className="w-8 h-8 text-slate-600" />
        </div>
        <p className="mb-2 text-lg font-medium text-slate-400">No findings yet</p>
        <p className="text-sm">Start a scan to discover security vulnerabilities</p>
      </div>
    );
  }

  const toggleExpand = (id) => {
    setExpandedId(expandedId === id ? null : id);
  };

  // Sort findings by severity
  const severityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  const sortedFindings = [...findings].sort((a, b) => {
    const aLevel = a.severity_level?.charAt(0).toUpperCase() + a.severity_level?.slice(1).toLowerCase();
    const bLevel = b.severity_level?.charAt(0).toUpperCase() + b.severity_level?.slice(1).toLowerCase();
    return (severityOrder[aLevel] ?? 5) - (severityOrder[bLevel] ?? 5);
  });

  return (
    <div className="overflow-hidden bg-slate-900/50 rounded-2xl border border-slate-800 shadow-sm">
      {/* Table Header */}
      <div className="px-6 py-3 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between">
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
          {findings.length} Findings
        </span>
        <div className="flex gap-2 text-xs">
          <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-medium">
            {findings.filter((f) => f.severity_level?.toLowerCase() === "critical").length} Critical
          </span>
          <span className="px-2 py-0.5 rounded bg-orange-500/10 text-orange-400 border border-orange-500/20 font-medium">
            {findings.filter((f) => f.severity_level?.toLowerCase() === "high").length} High
          </span>
        </div>
      </div>

      <table className="w-full text-left border-collapse">
        <thead className="bg-slate-900/60 text-slate-500 text-xs uppercase tracking-wider font-semibold">
          <tr>
            <th className="px-6 py-3 border-b border-slate-800">Severity</th>
            <th className="px-6 py-3 border-b border-slate-800">Vulnerability</th>
            <th className="px-6 py-3 border-b border-slate-800 hidden md:table-cell">URL</th>
            <th className="px-4 py-3 border-b border-slate-800 hidden sm:table-cell">Confidence</th>
            <th className="px-4 py-3 border-b border-slate-800 text-right w-12"></th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/50">
          {sortedFindings.map((finding, index) => {
            const id = index;
            const isExpanded = expandedId === id;

            return (
              <React.Fragment key={id}>
                <tr
                  onClick={() => toggleExpand(id)}
                  className={clsx(
                    "cursor-pointer transition-colors hover:bg-slate-800/30",
                    isExpanded && "bg-slate-800/20"
                  )}
                >
                  <td className="px-6 py-4 whitespace-nowrap">
                    <SeverityBadge severity={finding.severity_level} />
                  </td>
                  <td className="px-6 py-4">
                    <div className="font-medium text-slate-200 text-sm">
                      {finding.vuln_type}
                    </div>
                    <div className="text-xs text-slate-500 mt-0.5 max-w-md truncate">
                      {finding.description}
                    </div>
                  </td>
                  <td
                    className="px-6 py-4 text-slate-400 text-xs font-mono max-w-[200px] truncate hidden md:table-cell"
                    title={finding.url}
                  >
                    {finding.url}
                  </td>
                  <td className="px-4 py-4 hidden sm:table-cell">
                    <span
                      className={clsx(
                        "text-xs font-semibold px-2 py-0.5 rounded-full border",
                        finding.confidence === "High"
                          ? "bg-green-500/10 text-green-400 border-green-500/20"
                          : finding.confidence === "Medium"
                          ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/20"
                          : "bg-slate-800 text-slate-400 border-slate-700"
                      )}
                    >
                      {finding.confidence || "—"}
                    </span>
                  </td>
                  <td className="px-4 py-4 text-right">
                    <button className="p-1 text-slate-500 hover:text-cyan-400 transition-colors">
                      {isExpanded ? (
                        <ChevronDown className="w-5 h-5" />
                      ) : (
                        <ChevronRight className="w-5 h-5" />
                      )}
                    </button>
                  </td>
                </tr>
                <AnimatePresence>
                  {isExpanded && (
                    <tr>
                      <td colSpan="5" className="p-0 border-0">
                        <MotionDiv
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: "auto", opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          className="bg-slate-950/30 border-b border-slate-800/50 overflow-hidden"
                        >
                          <div className="p-6 grid gap-6 md:grid-cols-2">
                            <div>
                              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                                <Shield className="w-3 h-3" /> Description
                              </h4>
                              <p className="text-sm text-slate-300 leading-relaxed">
                                {finding.description}
                              </p>
                              {finding.url && (
                                <a
                                  href={finding.url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 mt-3 hover:underline"
                                >
                                  <ExternalLink className="w-3 h-3" />
                                  {finding.url}
                                </a>
                              )}
                            </div>

                            <div>
                              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                                Recommendation
                              </h4>
                              <p className="text-sm text-slate-300 leading-relaxed whitespace-pre-line">
                                {finding.remediation || "No specific remediation provided."}
                              </p>
                            </div>

                            <div className="md:col-span-2">
                              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                                Evidence / Payload
                              </h4>
                              <div className="bg-black/40 rounded-lg border border-slate-800 p-3 font-mono text-xs text-cyan-300 overflow-x-auto">
                                {finding.evidence || "No payload available"}
                              </div>
                            </div>

                            {/* Metadata row */}
                            <div className="md:col-span-2 flex items-center gap-4 pt-2 border-t border-slate-800/50 text-xs text-slate-500">
                              <span className="flex items-center gap-1">
                                Score: <strong className="text-slate-300">{finding.severity_score?.toFixed(1) || "—"}</strong>
                              </span>
                              <span className="flex items-center gap-1">
                                Confidence: <strong className="text-slate-300">{finding.confidence || "—"}</strong>
                              </span>
                              {finding.timestamp && (
                                <span className="flex items-center gap-1">
                                  <Clock className="w-3 h-3" />
                                  {new Date(finding.timestamp * 1000).toLocaleString()}
                                </span>
                              )}
                            </div>
                          </div>
                        </MotionDiv>
                      </td>
                    </tr>
                  )}
                </AnimatePresence>
              </React.Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
