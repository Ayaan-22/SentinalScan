import React from "react";
import {
  AlertCircle,
  AlertTriangle,
  Info,
  CheckCircle,
  ExternalLink,
} from "lucide-react";

const ResultsTable = ({ results }) => {
  const getSeverityIcon = (severity) => {
    switch (severity.toUpperCase()) {
      case "CRITICAL":
        return <AlertCircle className="w-4 h-4 text-red-500" />;
      case "HIGH":
        return <AlertTriangle className="w-4 h-4 text-orange-500" />;
      case "MEDIUM":
        return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
      case "LOW":
        return <Info className="w-4 h-4 text-green-500" />;
      default:
        return <Info className="w-4 h-4 text-blue-500" />;
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity.toUpperCase()) {
      case "CRITICAL":
        return "bg-red-500/10 text-red-400 border-red-500/20";
      case "HIGH":
        return "bg-orange-500/10 text-orange-400 border-orange-500/20";
      case "MEDIUM":
        return "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
      case "LOW":
        return "bg-green-500/10 text-green-400 border-green-500/20";
      default:
        return "bg-blue-500/10 text-blue-400 border-blue-500/20";
    }
  };

  if (!results.length) return null;

  return (
    <div className="glass-card overflow-hidden mt-6">
      <div className="p-4 border-b border-slate-700/50 bg-slate-900/30">
        <h3 className="font-bold flex items-center gap-2">
          <CheckCircle className="w-5 h-5 text-cyan-500" />
          Findings ({results.length})
        </h3>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900/50 text-slate-400 uppercase text-xs">
            <tr>
              <th className="px-6 py-3 font-medium">Severity</th>
              <th className="px-6 py-3 font-medium">Vulnerability</th>
              <th className="px-6 py-3 font-medium">URL</th>
              <th className="px-6 py-3 font-medium">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700/50">
            {results.map((vuln, i) => (
              <tr key={i} className="hover:bg-slate-800/30 transition-colors">
                <td className="px-6 py-4">
                  <span
                    className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${getSeverityColor(
                      vuln.severity_level
                    )}`}
                  >
                    {getSeverityIcon(vuln.severity_level)}
                    {vuln.severity_level}
                  </span>
                </td>
                <td className="px-6 py-4 font-medium">{vuln.vuln_type}</td>
                <td className="px-6 py-4 max-w-[300px] truncate">
                  <a
                    href={vuln.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-cyan-400 hover:text-cyan-300 hover:underline flex items-center gap-1"
                  >
                    {vuln.url} <ExternalLink className="w-3 h-3" />
                  </a>
                </td>
                <td
                  className="px-6 py-4 text-slate-400 max-w-[400px] truncate"
                  title={vuln.description}
                >
                  {vuln.description}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ResultsTable;
