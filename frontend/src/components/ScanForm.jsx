import React, { useState } from "react";
import { Play, Square, Settings } from "lucide-react";

const ScanForm = ({ onStart, onStop, isScanning }) => {
  const [url, setUrl] = useState("");
  const [options, setOptions] = useState({
    max_pages: 50,
    workers: 5,
    timeout: 15,
    verify_ssl: true,
    obey_robots: true,
    auth_token: "",
    cookies_str: "",
    headers_str: "",
    exclude_paths_str: "",
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    if (url) onStart(url, options);
  };

  return (
    <div className="glass-card p-6 mb-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold flex items-center gap-2 text-cyan-400">
          <Settings className="w-5 h-5" />
          Scan Configuration
        </h2>
        <div className="text-xs text-slate-400">v2.0.0</div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="flex gap-4">
          <div className="flex-1">
            <input
              type="url"
              placeholder="https://example.com"
              className="glass-input w-full"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={isScanning}
              required
            />
          </div>

          <button
            type="button"
            className={`glass-btn flex items-center gap-2 ${
              isScanning ? "opacity-50 cursor-not-allowed" : ""
            }`}
            onClick={handleSubmit}
            disabled={isScanning}
          >
            <Play className="w-4 h-4" /> Start Scan
          </button>

          {isScanning && (
            <button
              type="button"
              className="glass-btn bg-red-500/10 text-red-400 border-red-500/30 hover:bg-red-500/20"
              onClick={onStop}
            >
              <Square className="w-4 h-4 fill-current" /> Stop
            </button>
          )}
        </div>

        <div className="grid grid-cols-2 gap-4">
          <label className="flex items-center gap-2 text-sm text-slate-400">
            <input
              type="checkbox"
              checked={options.verify_ssl}
              onChange={(e) =>
                setOptions({ ...options, verify_ssl: e.target.checked })
              }
              className="rounded bg-slate-800 border-slate-600 text-cyan-500 focus:ring-cyan-500/50"
            />
            Verify SSL
          </label>

          <label className="flex items-center gap-2 text-sm text-slate-400">
            <input
              type="checkbox"
              checked={options.obey_robots}
              onChange={(e) =>
                setOptions({ ...options, obey_robots: e.target.checked })
              }
              className="rounded bg-slate-800 border-slate-600 text-cyan-500 focus:ring-cyan-500/50"
            />
            Obey robots.txt
          </label>
        </div>

        <div className="grid grid-cols-3 gap-4">
          <div className="space-y-1">
            <label className="text-xs text-slate-400">Max Pages</label>
            <input
              type="number"
              value={options.max_pages}
              onChange={(e) =>
                setOptions({ ...options, max_pages: parseInt(e.target.value) })
              }
              className="glass-input w-full"
              min="1"
              max="1000"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-slate-400">Workers</label>
            <input
              type="number"
              value={options.workers}
              onChange={(e) =>
                setOptions({ ...options, workers: parseInt(e.target.value) })
              }
              className="glass-input w-full"
              min="1"
              max="20"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-slate-400">Timeout (s)</label>
            <input
              type="number"
              value={options.timeout}
              onChange={(e) =>
                setOptions({ ...options, timeout: parseInt(e.target.value) })
              }
              className="glass-input w-full"
              min="1"
              max="60"
            />
          </div>
        </div>

        <div className="space-y-3 pt-2 border-t border-slate-700/50">
          <h3 className="text-sm font-medium text-slate-300">
            Advanced Authentication
          </h3>

          <input
            type="text"
            placeholder="Bearer Token (optional)"
            className="glass-input w-full text-sm"
            value={options.auth_token}
            onChange={(e) =>
              setOptions({ ...options, auth_token: e.target.value })
            }
          />

          <input
            type="text"
            placeholder="Cookies (name=val; name2=val2)"
            className="glass-input w-full text-sm"
            value={options.cookies_str}
            onChange={(e) =>
              setOptions({ ...options, cookies_str: e.target.value })
            }
          />

          <input
            type="text"
            placeholder="Custom Headers (Header:Value; Header2:Value)"
            className="glass-input w-full text-sm"
            value={options.headers_str}
            onChange={(e) =>
              setOptions({ ...options, headers_str: e.target.value })
            }
          />
          <input
            type="text"
            placeholder="Exclude Paths (/admin, /logout)"
            className="glass-input w-full text-sm"
            value={options.exclude_paths_str}
            onChange={(e) =>
              setOptions({ ...options, exclude_paths_str: e.target.value })
            }
          />
        </div>
      </form>
    </div>
  );
};

export default ScanForm;
