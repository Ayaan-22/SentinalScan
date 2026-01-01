import React from "react";
import { useScanResults, useScanStatus } from "../scan/scan.hooks";
import { FindingsTable } from "./FindingsTable";
import { Loader2 } from "lucide-react";

export function FindingsDashboard() {
  const { data: results, isLoading } = useScanResults();
  const { data: status } = useScanStatus();

  // If scanning, we might show a "Scanning..." state or partial results if available
  // The API contract says /scan/results is only available after scan.
  const isScanning = status?.is_scanning;

  if (isLoading && !isScanning) {
    return (
      <div className="flex flex-col items-center justify-center p-20 text-slate-500 animate-pulse">
        <Loader2 className="w-8 h-8 mb-4 animate-spin text-cyan-500" />
        <p>Loading security profile...</p>
      </div>
    );
  }

  if (isScanning) {
    return (
      <div className="flex flex-col items-center justify-center p-20 text-slate-500">
        <div className="relative mb-4">
          <div className="w-12 h-12 rounded-full border-2 border-slate-800 border-t-cyan-500 animate-spin" />
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="w-2 h-2 bg-cyan-500 rounded-full animate-pulse" />
          </div>
        </div>
        <p className="text-lg font-medium text-slate-300">Scan In Progress</p>
        <p className="text-sm mt-1">Results will appear here upon completion</p>
      </div>
    );
  }

  // Calculate statistics
  const stats = React.useMemo(() => {
    const initial = {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    if (!results) return initial;

    return results.reduce((acc, curr) => {
      const sev = curr.severity_level?.toLowerCase() || "info";
      if (acc[sev] !== undefined) acc[sev]++;
      acc.total++;
      return acc;
    }, initial);
  }, [results]);

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="bg-slate-950/50 p-4 rounded-xl border border-slate-800 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold text-white mb-1">
            {stats.total}
          </span>
          <span className="text-xs text-slate-500 uppercase tracking-wider font-semibold">
            Total
          </span>
        </div>
        <div className="bg-red-950/20 p-4 rounded-xl border border-red-500/20 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold text-red-500 mb-1">
            {stats.critical}
          </span>
          <span className="text-xs text-red-500/70 uppercase tracking-wider font-semibold">
            Critical
          </span>
        </div>
        <div className="bg-orange-950/20 p-4 rounded-xl border border-orange-500/20 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold text-orange-500 mb-1">
            {stats.high}
          </span>
          <span className="text-xs text-orange-500/70 uppercase tracking-wider font-semibold">
            High
          </span>
        </div>
        <div className="bg-yellow-950/20 p-4 rounded-xl border border-yellow-500/20 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold text-yellow-500 mb-1">
            {stats.medium}
          </span>
          <span className="text-xs text-yellow-500/70 uppercase tracking-wider font-semibold">
            Medium
          </span>
        </div>
        <div className="bg-blue-950/20 p-4 rounded-xl border border-blue-500/20 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold text-blue-500 mb-1">
            {stats.low + stats.info}
          </span>
          <span className="text-xs text-blue-500/70 uppercase tracking-wider font-semibold">
            Low / Info
          </span>
        </div>
      </div>

      <FindingsTable findings={results} />
    </div>
  );
}
