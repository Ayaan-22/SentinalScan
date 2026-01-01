import React, { useState } from "react";
import { SeverityBadge } from "./SeverityBadge";
import { ChevronDown, ChevronRight, ExternalLink } from "lucide-react";
import clsx from "clsx";
import { AnimatePresence, motion } from "framer-motion";

export function FindingsTable({ findings }) {
  const [expandedId, setExpandedId] = useState(null);

  if (!findings || findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center p-12 bg-slate-900/50 rounded-2xl border border-slate-800/50 text-slate-500">
        <p className="mb-2 text-lg font-medium">No findings yet</p>
        <p className="text-sm">Start a scan to see security vulnerabilities</p>
      </div>
    );
  }

  const toggleExpand = (id) => {
    setExpandedId(expandedId === id ? null : id);
  };

  return (
    <div className="overflow-hidden bg-slate-900/50 rounded-2xl border border-slate-800 shadow-sm">
      <table className="w-full text-left border-collapse">
        <thead className="bg-slate-900/80 text-slate-400 text-xs uppercase tracking-wider font-semibold">
          <tr>
            <th className="px-6 py-4 border-b border-slate-800">Severity</th>
            <th className="px-6 py-4 border-b border-slate-800">
              Vulnerability
            </th>
            <th className="px-6 py-4 border-b border-slate-800">URL</th>
            <th className="px-4 py-4 border-b border-slate-800 text-right">
              Action
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/50">
          {findings.map((finding, index) => {
            // Create a consistent ID if not present
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
                    <div className="font-medium text-slate-200">
                      {finding.vuln_type}
                    </div>
                    <div className="text-xs text-slate-500 mt-0.5 max-w-md truncate">
                      {finding.description}
                    </div>
                  </td>
                  <td
                    className="px-6 py-4 text-slate-400 text-sm font-mono max-w-xs truncate"
                    title={finding.url}
                  >
                    {finding.url}
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
                      <td colSpan="4" className="p-0 border-0">
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: "auto", opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          className="bg-slate-950/30 border-b border-slate-800/50 overflow-hidden"
                        >
                          <div className="p-6 grid gap-6 md:grid-cols-2">
                            <div>
                              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                                Description
                              </h4>
                              <p className="text-sm text-slate-300 leading-relaxed">
                                {finding.description}
                              </p>
                            </div>

                            <div>
                              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                                Recommendation
                              </h4>
                              <p className="text-sm text-slate-300 leading-relaxed">
                                {finding.remediation ||
                                  "No specific remediation provided."}
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
                          </div>
                        </motion.div>
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
