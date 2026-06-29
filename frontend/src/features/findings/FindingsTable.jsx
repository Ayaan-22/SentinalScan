import React, { useState } from "react";
import { SeverityBadge } from "./SeverityBadge";
import { ChevronDown, ChevronRight, Clock, Copy, ExternalLink, Shield } from "lucide-react";
import clsx from "clsx";
import { AnimatePresence, motion } from "framer-motion";

const MotionDiv = motion.div;

function findingId(finding) {
  return `${finding.url}-${finding.vuln_type}-${finding.description}-${finding.timestamp || ""}`;
}

function specificFindingTitle(finding) {
  const description = finding.description || "";

  const sensitiveFile = description.match(/Sensitive file exposed:\s*([^\s(]+)/i);
  if (sensitiveFile?.[1]) {
    return `${sensitiveFile[1]} exposed`;
  }

  const missingHeader = description.match(/Missing security header:\s*(.+)$/i);
  if (missingHeader?.[1]) {
    return `Missing ${missingHeader[1]}`;
  }

  const misconfiguredHeader = description.match(/Misconfigured security header:\s*(.+)$/i);
  if (misconfiguredHeader?.[1]) {
    return `Misconfigured ${misconfiguredHeader[1]}`;
  }

  const weakHeader = description.match(/Weak\s+(.+?)\s+header/i);
  if (weakHeader?.[1]) {
    return `Weak ${weakHeader[1]}`;
  }

  return description || finding.vuln_type || "Security finding";
}

function evidenceSummary(finding) {
  const evidence = finding.evidence || "";
  if (!evidence) return "";
  return evidence.replace(/^HTTP\s+/i, "HTTP ").replace(/\s+/g, " ").trim();
}

export function FindingsTable({ findings }) {
  const [expandedId, setExpandedId] = useState(null);

  if (!findings || findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center rounded-2xl border border-slate-800/50 bg-slate-900/50 p-12 text-slate-500">
        <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full border border-slate-700 bg-slate-800/50">
          <Shield className="h-8 w-8 text-slate-600" />
        </div>
        <p className="mb-2 text-lg font-medium text-slate-400">No findings yet</p>
        <p className="text-sm">Start a scan to discover security vulnerabilities</p>
      </div>
    );
  }

  const severityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  const sortedFindings = [...findings].sort((a, b) => {
    const aLevel = a.severity_level?.charAt(0).toUpperCase() + a.severity_level?.slice(1).toLowerCase();
    const bLevel = b.severity_level?.charAt(0).toUpperCase() + b.severity_level?.slice(1).toLowerCase();
    return (severityOrder[aLevel] ?? 5) - (severityOrder[bLevel] ?? 5);
  });

  return (
    <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/50 shadow-sm">
      <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/80 px-4 py-3 md:px-6">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          {findings.length} Findings
        </span>
        <div className="flex gap-2 text-xs">
          <span className="rounded border border-red-500/20 bg-red-500/10 px-2 py-0.5 font-medium text-red-400">
            {findings.filter((f) => f.severity_level?.toLowerCase() === "critical").length} Critical
          </span>
          <span className="rounded border border-orange-500/20 bg-orange-500/10 px-2 py-0.5 font-medium text-orange-400">
            {findings.filter((f) => f.severity_level?.toLowerCase() === "high").length} High
          </span>
        </div>
      </div>

      <div className="divide-y divide-slate-800/60">
        {sortedFindings.map((finding) => {
          const id = findingId(finding);
          const isExpanded = expandedId === id;

          return (
            <article key={id} className={clsx("bg-slate-950/10", isExpanded && "bg-slate-950/30")}>
              <button
                type="button"
                onClick={() => setExpandedId(isExpanded ? null : id)}
                className="grid w-full grid-cols-[auto_1fr_auto] gap-4 px-4 py-4 text-left transition hover:bg-slate-800/20 md:grid-cols-[136px_1fr_minmax(180px,280px)_100px_auto] md:px-6"
                aria-expanded={isExpanded}
              >
                <div className="self-start">
                  <SeverityBadge severity={finding.severity_level} />
                </div>

                <div className="min-w-0">
                  <div className="text-sm font-semibold text-slate-100 md:text-base">
                    {specificFindingTitle(finding)}
                  </div>
                  <div className="mt-1 text-xs font-medium text-slate-400">
                    {finding.vuln_type}
                  </div>
                  <div className="mt-1 line-clamp-2 text-xs leading-5 text-slate-500">
                    {finding.description}
                  </div>
                  {evidenceSummary(finding) && (
                    <div className="mt-2 line-clamp-1 rounded-lg border border-cyan-500/15 bg-cyan-500/5 px-2 py-1 font-mono text-[11px] text-cyan-300">
                      {evidenceSummary(finding)}
                    </div>
                  )}
                  <div className="mt-2 block break-all font-mono text-[11px] text-cyan-300 md:hidden">
                    {finding.url}
                  </div>
                </div>

                <div className="hidden min-w-0 break-all font-mono text-xs leading-5 text-slate-400 md:block">
                  {finding.url}
                </div>

                <div className="hidden sm:block">
                  <span
                    className={clsx(
                      "rounded-full border px-2 py-0.5 text-xs font-semibold",
                      finding.confidence === "High"
                        ? "border-green-500/20 bg-green-500/10 text-green-400"
                        : finding.confidence === "Medium"
                          ? "border-yellow-500/20 bg-yellow-500/10 text-yellow-400"
                          : "border-slate-700 bg-slate-800 text-slate-400"
                    )}
                  >
                    {finding.confidence || "Unknown"}
                  </span>
                </div>

                <div className="self-start text-slate-500">
                  {isExpanded ? <ChevronDown className="h-5 w-5" /> : <ChevronRight className="h-5 w-5" />}
                </div>
              </button>

              <AnimatePresence>
                {isExpanded && (
                  <MotionDiv
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    className="overflow-hidden border-t border-slate-800/60 bg-slate-950/35"
                  >
                    <div className="grid gap-6 px-4 py-5 md:grid-cols-2 md:px-6">
                      <section className="min-w-0">
                        <h4 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-400">
                          <Shield className="h-3 w-3" /> Description
                        </h4>
                        <p className="break-words text-sm leading-6 text-slate-300">{finding.description}</p>
                        {finding.url && (
                          <a
                            href={finding.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="mt-3 inline-flex max-w-full items-center gap-1 break-all text-xs text-cyan-400 hover:text-cyan-300 hover:underline"
                          >
                            <ExternalLink className="h-3 w-3 shrink-0" />
                            {finding.url}
                          </a>
                        )}
                      </section>

                      <section className="min-w-0">
                        <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
                          Recommendation
                        </h4>
                        <p className="whitespace-pre-wrap break-words text-sm leading-6 text-slate-300">
                          {finding.remediation || "No specific remediation provided."}
                        </p>
                        {finding.remediation && (
                          <button
                            type="button"
                            onClick={(event) => {
                              event.stopPropagation();
                              navigator.clipboard?.writeText(finding.remediation);
                            }}
                            className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 px-2 py-1 text-xs text-slate-400 hover:text-cyan-300"
                          >
                            <Copy className="h-3 w-3" />
                            Copy remediation
                          </button>
                        )}
                      </section>

                      <section className="min-w-0 md:col-span-2">
                        <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
                          Evidence / Payload
                        </h4>
                        <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-slate-800 bg-black/40 p-3 font-mono text-xs leading-5 text-cyan-300">
                          {finding.evidence || "No payload available"}
                        </pre>
                      </section>

                      <div className="flex flex-wrap items-center gap-4 border-t border-slate-800/50 pt-2 text-xs text-slate-500 md:col-span-2">
                        <span>
                          Score: <strong className="text-slate-300">{finding.severity_score?.toFixed(1) || "-"}</strong>
                        </span>
                        <span>
                          Confidence: <strong className="text-slate-300">{finding.confidence || "-"}</strong>
                        </span>
                        {finding.timestamp && (
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {new Date(finding.timestamp * 1000).toLocaleString()}
                          </span>
                        )}
                      </div>
                    </div>
                  </MotionDiv>
                )}
              </AnimatePresence>
            </article>
          );
        })}
      </div>
    </div>
  );
}
