import React, { useState } from "react";
import {
  Play,
  Square,
  Settings,
  ShieldAlert,
  Globe,
  Radio,
} from "lucide-react";
import { useStartScan, useStopScan, useScanStatus } from "./scan.hooks";
import clsx from "clsx"; // Make sure clsx is installed or use template literals. Check package.json again. clsx was in package.json.

export function ScanForm() {
  const { data: status, isLoading: isStatusLoading } = useScanStatus();
  const startScan = useStartScan();
  const stopScan = useStopScan();

  const isScanning = status?.is_scanning;

  const [url, setUrl] = useState("");
  const [method, setMethod] = useState("full"); // 'full' or 'quick' (just max_pages diff)
  const [options, setOptions] = useState({
    verify_ssl: true,
    obey_robots: true,
    max_pages: 50,
    timeout: 15,
  });

  const [showAdvanced, setShowAdvanced] = useState(false);
  const [advanced, setAdvanced] = useState({
    formatted_headers: "",
    formatted_cookies: "",
    exclude_paths: "",
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!url) return;

    startScan.mutate({
      target_url: url,
      ...options,
      max_pages: method === "quick" ? 10 : options.max_pages,
      headers_str: advanced.formatted_headers,
      cookies_str: advanced.formatted_cookies,
      exclude_paths_str: advanced.exclude_paths,
    });
  };

  const handleStop = () => {
    stopScan.mutate();
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* URL Input */}
      <div>
        <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
          Target URL
        </label>
        <div className="relative group">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <Globe className="h-5 w-5 text-slate-500 group-focus-within:text-cyan-400 transition-colors" />
          </div>
          <input
            type="url"
            required
            placeholder="https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={isScanning}
            className="block w-full pl-10 pr-3 py-3 bg-slate-950/50 border border-slate-700 rounded-xl text-slate-200 placeholder-slate-600 focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 transition-all font-mono"
          />
        </div>
      </div>

      {/* Toggles Grid */}
      <div className="grid grid-cols-2 gap-4">
        <div
          onClick={() =>
            !isScanning &&
            setOptions({ ...options, verify_ssl: !options.verify_ssl })
          }
          className={clsx(
            "flex items-center justify-between p-3 rounded-xl border cursor-pointer transition-all hover:bg-slate-900/80",
            options.verify_ssl
              ? "bg-cyan-500/10 border-cyan-500/50"
              : "bg-slate-950/50 border-slate-800"
          )}
        >
          <span className="text-sm font-medium text-slate-300">Verify SSL</span>
          <div
            className={clsx(
              "w-5 h-5 rounded flex items-center justify-center border transition-all",
              options.verify_ssl
                ? "bg-cyan-500 border-cyan-500"
                : "bg-transparent border-slate-600"
            )}
          >
            {options.verify_ssl && (
              <div className="w-2 h-2 bg-white rounded-sm" />
            )}
          </div>
        </div>

        <div
          onClick={() =>
            !isScanning &&
            setOptions({ ...options, obey_robots: !options.obey_robots })
          }
          className={clsx(
            "flex items-center justify-between p-3 rounded-xl border cursor-pointer transition-all hover:bg-slate-900/80",
            options.obey_robots
              ? "bg-blue-500/10 border-blue-500/50"
              : "bg-slate-950/50 border-slate-800"
          )}
        >
          <span className="text-sm font-medium text-slate-300">
            Obey Robots
          </span>
          <div
            className={clsx(
              "w-5 h-5 rounded flex items-center justify-center border transition-all",
              options.obey_robots
                ? "bg-blue-500 border-blue-500"
                : "bg-transparent border-slate-600"
            )}
          >
            {options.obey_robots && (
              <div className="w-2 h-2 bg-white rounded-sm" />
            )}
          </div>
        </div>
      </div>

      {/* Scan Intensity */}
      <div>
        <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
          Scan Intensity
        </label>
        <div className="grid grid-cols-2 gap-2 bg-slate-950 p-1 rounded-xl border border-slate-800">
          <button
            type="button"
            onClick={() => setMethod("quick")}
            disabled={isScanning}
            className={clsx(
              "flex items-center justify-center gap-2 py-2 rounded-lg text-sm font-medium transition-all",
              method === "quick"
                ? "bg-slate-800 text-white shadow"
                : "text-slate-500 hover:text-slate-300"
            )}
          >
            Quick Scan
          </button>
          <button
            type="button"
            onClick={() => setMethod("full")}
            disabled={isScanning}
            className={clsx(
              "flex items-center justify-center gap-2 py-2 rounded-lg text-sm font-medium transition-all",
              method === "full"
                ? "bg-slate-800 text-white shadow"
                : "text-slate-500 hover:text-slate-300"
            )}
          >
            Deep Scan
          </button>
        </div>
      </div>

      {/* Advanced Options Toggle */}
      <div>
        <button
          type="button"
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="flex items-center gap-2 text-xs font-semibold text-slate-400 uppercase tracking-wider hover:text-cyan-400 transition-colors"
        >
          <Settings className="w-4 h-4" />
          Advanced Configuration
        </button>

        {showAdvanced && (
          <div className="mt-4 space-y-4 p-4 bg-slate-900/50 rounded-xl border border-slate-800 animate-in fade-in slide-in-from-top-2">
            <div>
              <label className="block text-xs text-slate-500 mb-1">
                Custom Headers (Key:Value;Key:Value)
              </label>
              <input
                type="text"
                value={advanced.formatted_headers}
                onChange={(e) =>
                  setAdvanced({
                    ...advanced,
                    formatted_headers: e.target.value,
                  })
                }
                placeholder="Authorization: Bearer token; X-Custom: 123"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 font-mono focus:border-cyan-500 outline-none"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-500 mb-1">
                Cookies (key=value;key=value)
              </label>
              <input
                type="text"
                value={advanced.formatted_cookies}
                onChange={(e) =>
                  setAdvanced({
                    ...advanced,
                    formatted_cookies: e.target.value,
                  })
                }
                placeholder="session_id=xyz; preferences=dark"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 font-mono focus:border-cyan-500 outline-none"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-500 mb-1">
                Exclude Paths (comma separated)
              </label>
              <input
                type="text"
                value={advanced.exclude_paths}
                onChange={(e) =>
                  setAdvanced({ ...advanced, exclude_paths: e.target.value })
                }
                placeholder="/logout, /admin, /api/delete"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 font-mono focus:border-cyan-500 outline-none"
              />
            </div>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="pt-2">
        {!isScanning ? (
          <button
            type="submit"
            disabled={startScan.isPending || !url}
            className="w-full relative group overflow-hidden rounded-xl p-[1px]"
          >
            <div className="absolute inset-0 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-xl" />
            <div className="absolute inset-[1px] bg-slate-900 rounded-[11px] group-hover:bg-slate-800/90 transition-colors" />
            <div className="relative flex items-center justify-center gap-2 py-3 text-cyan-400 font-bold tracking-wide group-hover:text-cyan-300 transition-colors">
              <Play className="w-5 h-5 fill-current" />
              {startScan.isPending ? "STARTING..." : "INITIATE ACTIVE SCAN"}
            </div>
          </button>
        ) : (
          <button
            type="button"
            onClick={handleStop}
            disabled={stopScan.isPending}
            className="w-full flex items-center justify-center gap-2 py-3.5 bg-red-500/10 border border-red-500/20 text-red-500 rounded-xl font-bold hover:bg-red-500/20 transition-colors"
          >
            <Square className="w-5 h-5 fill-current" />
            {stopScan.isPending ? "STOPPING..." : "TERMINATE SCAN"}
          </button>
        )}
      </div>
    </form>
  );
}
