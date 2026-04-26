import React, { useState } from "react";
import {
  Play,
  Square,
  Settings,
  Globe,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { useStartScan } from "./scan.hooks";
import clsx from "clsx";

export function ScanForm({ onScanStarted, onStop, isScanning }) {
  const startScan = useStartScan();

  const [url, setUrl] = useState("");
  const [options, setOptions] = useState({
    verify_ssl: true,
    obey_robots: true,
    max_pages: 50,
    workers: 5,
    timeout: 15,
  });

  const [showAdvanced, setShowAdvanced] = useState(false);
  const [advanced, setAdvanced] = useState({
    formatted_headers: "",
    formatted_cookies: "",
    exclude_paths: "",
    auth_token: "",
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!url) return;

    startScan.mutate(
      {
        target_url: url,
        ...options,
        auth_token: advanced.auth_token || undefined,
        headers_str: advanced.formatted_headers || undefined,
        cookies_str: advanced.formatted_cookies || undefined,
        exclude_paths_str: advanced.exclude_paths || undefined,
      },
      {
        onSuccess: (data) => {
          if (onScanStarted) onScanStarted(data);
        },
        onError: (err) => {
          console.error("Scan start failed", err);
        },
      }
    );
  };

  const updateOption = (key, value) => {
    if (!isScanning) {
      setOptions((prev) => ({ ...prev, [key]: value }));
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      {/* Target URL */}
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
            className="block w-full pl-10 pr-3 py-3 bg-slate-950/50 border border-slate-700 rounded-xl text-slate-200 placeholder-slate-600 focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 transition-all font-mono text-sm"
          />
        </div>
      </div>

      {/* Toggle Grid */}
      <div className="grid grid-cols-2 gap-3">
        <div
          onClick={() => updateOption("verify_ssl", !options.verify_ssl)}
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
            {options.verify_ssl && <div className="w-2 h-2 bg-white rounded-sm" />}
          </div>
        </div>

        <div
          onClick={() => updateOption("obey_robots", !options.obey_robots)}
          className={clsx(
            "flex items-center justify-between p-3 rounded-xl border cursor-pointer transition-all hover:bg-slate-900/80",
            options.obey_robots
              ? "bg-blue-500/10 border-blue-500/50"
              : "bg-slate-950/50 border-slate-800"
          )}
        >
          <span className="text-sm font-medium text-slate-300">Obey Robots</span>
          <div
            className={clsx(
              "w-5 h-5 rounded flex items-center justify-center border transition-all",
              options.obey_robots
                ? "bg-blue-500 border-blue-500"
                : "bg-transparent border-slate-600"
            )}
          >
            {options.obey_robots && <div className="w-2 h-2 bg-white rounded-sm" />}
          </div>
        </div>
      </div>

      {/* Numeric Inputs */}
      <div className="grid grid-cols-3 gap-3">
        <div>
          <label className="block text-xs text-slate-500 mb-1.5 font-medium">
            Max Pages
          </label>
          <input
            type="number"
            min="1"
            max="500"
            value={options.max_pages}
            onChange={(e) => updateOption("max_pages", parseInt(e.target.value) || 50)}
            disabled={isScanning}
            className="w-full bg-slate-950/50 border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-slate-200 font-mono text-center outline-none focus:border-cyan-500/50"
          />
        </div>
        <div>
          <label className="block text-xs text-slate-500 mb-1.5 font-medium">
            Workers
          </label>
          <input
            type="number"
            min="1"
            max="20"
            value={options.workers}
            onChange={(e) => updateOption("workers", parseInt(e.target.value) || 5)}
            disabled={isScanning}
            className="w-full bg-slate-950/50 border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-slate-200 font-mono text-center outline-none focus:border-cyan-500/50"
          />
        </div>
        <div>
          <label className="block text-xs text-slate-500 mb-1.5 font-medium">
            Timeout (s)
          </label>
          <input
            type="number"
            min="1"
            max="60"
            value={options.timeout}
            onChange={(e) => updateOption("timeout", parseInt(e.target.value) || 15)}
            disabled={isScanning}
            className="w-full bg-slate-950/50 border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-slate-200 font-mono text-center outline-none focus:border-cyan-500/50"
          />
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
          {showAdvanced ? (
            <ChevronUp className="w-3 h-3" />
          ) : (
            <ChevronDown className="w-3 h-3" />
          )}
        </button>

        {showAdvanced && (
          <div className="mt-4 space-y-3 p-4 bg-slate-900/50 rounded-xl border border-slate-800">
            <div>
              <label className="block text-xs text-slate-500 mb-1">
                Auth Token
              </label>
              <input
                type="text"
                placeholder="Bearer token (optional)"
                value={advanced.auth_token}
                onChange={(e) =>
                  setAdvanced({ ...advanced, auth_token: e.target.value })
                }
                disabled={isScanning}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 font-mono outline-none focus:border-cyan-500/50"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-500 mb-1">
                Custom Headers
              </label>
              <input
                type="text"
                placeholder="Header:Value; Header2:Value2"
                value={advanced.formatted_headers}
                onChange={(e) =>
                  setAdvanced({ ...advanced, formatted_headers: e.target.value })
                }
                disabled={isScanning}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 font-mono outline-none focus:border-cyan-500/50"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-500 mb-1">
                Cookies
              </label>
              <input
                type="text"
                placeholder="name=value; name2=value2"
                value={advanced.formatted_cookies}
                onChange={(e) =>
                  setAdvanced({ ...advanced, formatted_cookies: e.target.value })
                }
                disabled={isScanning}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 font-mono outline-none focus:border-cyan-500/50"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-500 mb-1">
                Exclude Paths
              </label>
              <input
                type="text"
                placeholder="/admin, /logout, /api"
                value={advanced.exclude_paths}
                onChange={(e) =>
                  setAdvanced({ ...advanced, exclude_paths: e.target.value })
                }
                disabled={isScanning}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 font-mono outline-none focus:border-cyan-500/50"
              />
            </div>
          </div>
        )}
      </div>

      {/* Submit / Stop Button */}
      <div className="pt-2">
        {!isScanning ? (
          <button
            type="submit"
            disabled={startScan.isPending || !url}
            className="w-full relative group overflow-hidden rounded-xl p-[1px] disabled:opacity-50 disabled:cursor-not-allowed"
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
            onClick={onStop}
            className="w-full flex items-center justify-center gap-2 py-3.5 bg-red-500/10 border border-red-500/20 text-red-500 rounded-xl font-bold hover:bg-red-500/20 transition-colors"
          >
            <Square className="w-5 h-5 fill-current" />
            TERMINATE SCAN
          </button>
        )}
      </div>
    </form>
  );
}
