import React from "react";
import { useScanResults, useScanStatus } from "../scan/scan.hooks";
import { FindingsTable } from "./FindingsTable";
import { Loader2, Shield, Download, BarChart3 } from "lucide-react";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
} from "recharts";

const SEVERITY_COLORS = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#22c55e",
  Info: "#3b82f6",
};

function SeverityChart({ stats }) {
  const chartData = [
    { name: "Critical", value: stats.critical, color: SEVERITY_COLORS.Critical },
    { name: "High", value: stats.high, color: SEVERITY_COLORS.High },
    { name: "Medium", value: stats.medium, color: SEVERITY_COLORS.Medium },
    { name: "Low", value: stats.low, color: SEVERITY_COLORS.Low },
    { name: "Info", value: stats.info, color: SEVERITY_COLORS.Info },
  ].filter((d) => d.value > 0);

  if (chartData.length === 0) return null;

  return (
    <div className="bg-slate-900/50 rounded-2xl border border-slate-800 p-4">
      <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
        <BarChart3 className="w-3.5 h-3.5" />
        Severity Distribution
      </h3>
      <ResponsiveContainer width="100%" height={180}>
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            innerRadius={45}
            outerRadius={70}
            paddingAngle={3}
            dataKey="value"
            animationBegin={0}
            animationDuration={600}
          >
            {chartData.map((entry, index) => (
              <Cell
                key={`cell-${index}`}
                fill={entry.color}
                stroke="transparent"
                style={{ filter: `drop-shadow(0 0 4px ${entry.color}40)` }}
              />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: "#0f172a",
              border: "1px solid #1e293b",
              borderRadius: "0.75rem",
              fontSize: "0.75rem",
              color: "#e2e8f0",
            }}
            formatter={(value, name) => [`${value} finding${value !== 1 ? "s" : ""}`, name]}
          />
          <Legend
            verticalAlign="bottom"
            iconType="circle"
            iconSize={8}
            formatter={(value) => (
              <span className="text-xs text-slate-400">{value}</span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

export function FindingsDashboard({ scanId }) {
  const { data: status } = useScanStatus(scanId);
  const isScanning =
    status?.status === "running" || status?.status === "pending";

  const { data: results, isLoading } = useScanResults(scanId, isScanning);

  // Calculate statistics
  const stats = React.useMemo(() => {
    const initial = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    if (!results) return initial;

    return results.reduce((acc, curr) => {
      const sev = curr.severity_level?.toLowerCase() || "info";
      if (acc[sev] !== undefined) acc[sev]++;
      acc.total++;
      return acc;
    }, initial);
  }, [results]);

  const handleExport = () => {
    if (!results || results.length === 0) return;
    const blob = new Blob([JSON.stringify(results, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinalscan-report-${scanId?.slice(0, 8) || "scan"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!scanId) {
    return (
      <div className="flex flex-col items-center justify-center p-20 text-slate-500">
        <div className="w-20 h-20 rounded-full bg-slate-800/50 flex items-center justify-center border border-slate-700 mb-6">
          <Shield className="w-10 h-10 text-slate-600" />
        </div>
        <p className="text-lg font-medium text-slate-400 mb-1">No Active Scan</p>
        <p className="text-sm text-slate-600">Configure and start a scan to see findings</p>
      </div>
    );
  }

  if (isScanning && (!results || results.length === 0)) {
    return (
      <div className="flex flex-col items-center justify-center p-20 text-slate-500">
        <div className="relative mb-6">
          <div className="w-16 h-16 rounded-full border-2 border-slate-800 border-t-cyan-500 animate-spin" />
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="w-3 h-3 bg-cyan-500 rounded-full animate-pulse" />
          </div>
        </div>
        <p className="text-lg font-medium text-slate-300">Scan In Progress</p>
        <p className="text-sm mt-1 text-slate-500">
          Results will appear here as they are discovered
        </p>
        {status?.pages_scanned > 0 && (
          <p className="text-xs mt-3 text-cyan-400 font-mono">
            {status.pages_scanned} pages scanned...
          </p>
        )}
      </div>
    );
  }

  if (isLoading && !results) {
    return (
      <div className="flex flex-col items-center justify-center p-20 text-slate-500 animate-pulse">
        <Loader2 className="w-8 h-8 mb-4 animate-spin text-cyan-500" />
        <p>Loading security profile...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Scanning indicator when results are streaming in */}
      {isScanning && results && results.length > 0 && (
        <div className="flex items-center gap-2 px-4 py-2 bg-cyan-500/5 border border-cyan-500/20 rounded-xl text-xs text-cyan-400 font-medium">
          <div className="w-2 h-2 rounded-full bg-cyan-500 animate-pulse" />
          Scan in progress — findings are updating live
          {status?.pages_scanned > 0 && (
            <span className="ml-auto font-mono text-slate-500">
              {status.pages_scanned} pages scanned
            </span>
          )}
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        {[
          { label: "Total", value: stats.total, bg: "bg-slate-950/50", border: "border-slate-800", text: "text-white" },
          { label: "Critical", value: stats.critical, bg: "bg-red-950/20", border: "border-red-500/20", text: "text-red-500" },
          { label: "High", value: stats.high, bg: "bg-orange-950/20", border: "border-orange-500/20", text: "text-orange-500" },
          { label: "Medium", value: stats.medium, bg: "bg-yellow-950/20", border: "border-yellow-500/20", text: "text-yellow-500" },
          { label: "Low", value: stats.low, bg: "bg-green-950/20", border: "border-green-500/20", text: "text-green-500" },
          { label: "Info", value: stats.info, bg: "bg-blue-950/20", border: "border-blue-500/20", text: "text-blue-500" },
        ].map(({ label, value, bg, border, text }) => (
          <div
            key={label}
            className={`${bg} p-3 rounded-xl border ${border} flex flex-col items-center justify-center`}
          >
            <span className={`text-xl font-bold ${text} mb-0.5 tabular-nums`}>
              {value}
            </span>
            <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">
              {label}
            </span>
          </div>
        ))}
      </div>

      {/* Severity Chart */}
      {stats.total > 0 && <SeverityChart stats={stats} />}

      {/* Actions Bar */}
      {results && results.length > 0 && (
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <BarChart3 className="w-4 h-4" />
            <span>{results.length} vulnerabilities across {new Set(results.map((r) => r.url)).size} pages</span>
          </div>
          <button
            onClick={handleExport}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-cyan-400 bg-slate-900/50 hover:bg-slate-900 border border-slate-800 rounded-lg transition-all"
          >
            <Download className="w-3.5 h-3.5" />
            Export JSON
          </button>
        </div>
      )}

      <FindingsTable findings={results || []} />
    </div>
  );
}
