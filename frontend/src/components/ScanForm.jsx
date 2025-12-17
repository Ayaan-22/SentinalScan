import React, { useState } from "react";
import { Play, Square, Settings, ChevronDown, ChevronUp } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

function ScanForm({ onStart, onStop, isScanning }) {
  const [url, setUrl] = useState("https://www.example.com");
  const [method, setMethod] = useState("GET");
  const [verifySsl, setVerifySsl] = useState(true);
  const [obeyRobots, setObeyRobots] = useState(true);
  const [maxPages, setMaxPages] = useState(50);
  const [workers, setWorkers] = useState(5);
  const [timeout, setTimeout] = useState(15);
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Auth / Advanced
  const [authToken, setAuthToken] = useState("");
  const [cookies, setCookies] = useState("");
  const [customHeaders, setCustomHeaders] = useState("");
  const [excludePaths, setExcludePaths] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    if (isScanning) {
      onStop();
    } else {
      const options = {
        scan_method: method,
        max_pages: parseInt(maxPages) || 50,
        threads: parseInt(workers) || 5,
        timeout: parseInt(timeout) || 10,
        verify_ssl: verifySsl,
        obey_robots: obeyRobots,
        auth_token: authToken,
        cookies: parseCookies(cookies),
        custom_headers: parseHeaders(customHeaders),
        exclude_paths: excludePaths
          ? excludePaths.split(",").map((p) => p.trim())
          : [],
      };
      onStart(url, options);
    }
  };

  const parseCookies = (str) => {
    if (!str) return null;
    const result = {};
    str.split(";").forEach((part) => {
      const [k, v] = part.split("=");
      if (k && v) result[k.trim()] = v.trim();
    });
    return result;
  };

  const parseHeaders = (str) => {
    if (!str) return null;
    const result = {};
    str.split(";").forEach((part) => {
      const [k, v] = part.split(":");
      if (k && v) result[k.trim()] = v.trim();
    });
    return result;
  };

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className="glass-card p-6 md:p-8"
    >
      <div className="flex items-center justify-between mb-8">
        <h2 className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent flex items-center gap-2">
          <Settings className="w-5 h-5 text-cyan-500" />
          Scan Configuration
        </h2>
        <span className="text-xs font-mono text-slate-500 border border-slate-800 px-2 py-1 rounded">
          v2.1.0
        </span>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        <div>
          <label className="text-xs text-slate-400 ml-1 mb-2 block uppercase tracking-wider font-semibold">
            Target URL
          </label>
          <div className="flex gap-4">
            <select
              className="glass-input w-24 font-mono text-sm bg-slate-900"
              value={method}
              onChange={(e) => setMethod(e.target.value)}
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
            </select>
            <input
              type="text"
              placeholder="https://example.com"
              className="glass-input flex-1 font-mono text-sm"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
            />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          {/* Toggles */}
          <label className="flex items-center gap-3 p-3 rounded-xl border border-slate-800 bg-slate-900/30 cursor-pointer hover:border-slate-700 transition-colors">
            <input
              type="checkbox"
              checked={verifySsl}
              onChange={(e) => setVerifySsl(e.target.checked)}
              className="accent-cyan-500 w-4 h-4"
            />
            <span className="text-sm font-medium text-slate-300">
              Verify SSL
            </span>
          </label>

          <label className="flex items-center gap-3 p-3 rounded-xl border border-slate-800 bg-slate-900/30 cursor-pointer hover:border-slate-700 transition-colors">
            <input
              type="checkbox"
              checked={obeyRobots}
              onChange={(e) => setObeyRobots(e.target.checked)}
              className="accent-cyan-500 w-4 h-4"
            />
            <span className="text-sm font-medium text-slate-300">
              Obey Robots
            </span>
          </label>
        </div>

        <div className="grid grid-cols-3 gap-4">
          <div>
            <label className="text-xs text-slate-400 ml-1 mb-2 block">
              Max Pages
            </label>
            <input
              type="number"
              value={maxPages}
              onChange={(e) => setMaxPages(e.target.value)}
              className="glass-input w-full text-center font-mono"
            />
          </div>
          <div>
            <label className="text-xs text-slate-400 ml-1 mb-2 block">
              Workers
            </label>
            <input
              type="number"
              value={workers}
              onChange={(e) => setWorkers(e.target.value)}
              className="glass-input w-full text-center font-mono"
            />
          </div>
          <div>
            <label className="text-xs text-slate-400 ml-1 mb-2 block">
              Timeout (s)
            </label>
            <input
              type="number"
              value={timeout}
              onChange={(e) => setTimeout(e.target.value)}
              className="glass-input w-full text-center font-mono"
            />
          </div>
        </div>

        <div>
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="text-xs flex items-center gap-1 text-slate-500 hover:text-cyan-400 transition-colors uppercase tracking-wider font-semibold mx-auto"
          >
            {showAdvanced ? "Hide Advanced Options" : "Show Advanced Options"}
            {showAdvanced ? (
              <ChevronUp className="w-3 h-3" />
            ) : (
              <ChevronDown className="w-3 h-3" />
            )}
          </button>
        </div>

        <AnimatePresence>
          {showAdvanced && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="space-y-4 overflow-hidden"
            >
              <input
                type="text"
                placeholder="Bearer Token (optional)"
                className="glass-input w-full text-sm"
                value={authToken}
                onChange={(e) => setAuthToken(e.target.value)}
              />
              <input
                type="text"
                placeholder="Cookies (name=val; name2=val2)"
                className="glass-input w-full text-sm"
                value={cookies}
                onChange={(e) => setCookies(e.target.value)}
              />
              <input
                type="text"
                placeholder="Custom Headers (Header:Value; Header2:Value)"
                className="glass-input w-full text-sm"
                value={customHeaders}
                onChange={(e) => setCustomHeaders(e.target.value)}
              />
              <input
                type="text"
                placeholder="Exclude Paths (/admin, /logout)"
                className="glass-input w-full text-sm"
                value={excludePaths}
                onChange={(e) => setExcludePaths(e.target.value)}
              />
            </motion.div>
          )}
        </AnimatePresence>

        <button
          type="submit"
          className={`w-full relative group overflow-hidden rounded-xl p-4 font-bold tracking-widest uppercase transition-all duration-300 ${
            isScanning
              ? "bg-red-500/10 text-red-500 border border-red-500/50 hover:bg-red-500/20"
              : "bg-cyan-500 text-slate-950 hover:bg-cyan-400 shadow-[0_0_20px_rgba(6,182,212,0.4)]"
          }`}
        >
          <div className="relative z-10 flex items-center justify-center gap-3">
            {isScanning ? (
              <Square className="w-5 h-5 fill-current" />
            ) : (
              <Play className="w-5 h-5 fill-current" />
            )}
            {isScanning ? "Stop System" : "Initialize Scan"}
          </div>
          {!isScanning && (
            <div className="absolute top-0 -left-[100%] w-full h-full bg-gradient-to-r from-transparent via-white/30 to-transparent skew-x-12 group-hover:animate-shine" />
          )}
        </button>
      </form>
    </motion.div>
  );
}

export default ScanForm;
