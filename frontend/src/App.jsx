import React, { useState, useEffect, useCallback } from "react";
import { Shield, Zap, Search, AlertCircle } from "lucide-react";
import ScanForm from "./components/ScanForm";
import LogViewer from "./components/LogViewer";
import ResultsTable from "./components/ResultsTable";
import StatsCard from "./components/StatsCard";

const API_BASE = "http://localhost:8000";

function App() {
  const [logs, setLogs] = useState([]);
  const [results, setResults] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [stats, setStats] = useState({
    critical: 0,
    high: 0,
    medium: 0,
    total: 0,
  });

  // Connect to WebSocket
  useEffect(() => {
    const ws = new WebSocket(`ws://localhost:8000/ws/logs`);
    ws.onmessage = (event) => {
      const log = JSON.parse(event.data);
      setLogs((prev) => [...prev, log].slice(-100)); // Keep last 100 logs

      // Check for completion message
      if (log.message.includes("Scan finished successfully")) {
        fetchResults();
        setIsScanning(false);
      }
    };
    return () => ws.close();
  }, []);

  const startScan = async (targetUrl, options) => {
    setIsScanning(true);
    setLogs([]);
    setResults([]);
    try {
      await fetch(`${API_BASE}/scan/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: targetUrl, ...options }),
      });
    } catch (err) {
      console.error(err);
      setIsScanning(false);
    }
  };

  const stopScan = async () => {
    try {
      await fetch(`${API_BASE}/scan/stop`, { method: "POST" });
    } catch (err) {
      console.error(err);
    }
  };

  const fetchResults = async () => {
    try {
      const res = await fetch(`${API_BASE}/scan/results`);
      const data = await res.json();
      setResults(data);
      updateStats(data);
    } catch (err) {
      console.error(err);
    }
  };

  const updateStats = (data) => {
    const newStats = { critical: 0, high: 0, medium: 0, total: data.length };
    data.forEach((item) => {
      const sev = item.severity_level.toLowerCase();
      if (newStats[sev] !== undefined) newStats[sev]++;
    });
    setStats(newStats);
  };

  return (
    <div className="min-h-screen p-6">
      <header className="max-w-7xl mx-auto mb-8 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="bg-cyan-500/20 p-2 rounded-xl border border-cyan-500/30">
            <Shield className="w-8 h-8 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              SentinalScan
            </h1>
            <p className="text-xs text-slate-400 font-medium">
              Advanced Web Vulnerability Scanner
            </p>
          </div>
        </div>
        <div className="flex gap-4">
          <div className="glass px-4 py-2 rounded-lg flex items-center gap-2 text-sm text-slate-300">
            <div
              className={`w-2 h-2 rounded-full ${
                isScanning ? "bg-green-500 animate-pulse" : "bg-slate-500"
              }`}
            />
            {isScanning ? "System Active" : "System Idle"}
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Controls & Logs */}
        <div className="lg:col-span-1 space-y-6">
          <ScanForm
            onStart={startScan}
            onStop={stopScan}
            isScanning={isScanning}
          />
          <LogViewer logs={logs} />
        </div>

        {/* Right Column: Dashboard & Results */}
        <div className="lg:col-span-2 space-y-6">
          {/* Stats Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatsCard
              title="Total Findings"
              value={stats.total}
              icon={<Search className="w-6 h-6 text-blue-400" />}
              color="bg-blue-500/10 border border-blue-500/20"
            />
            <StatsCard
              title="Critical"
              value={stats.critical}
              icon={<Zap className="w-6 h-6 text-red-500" />}
              color="bg-red-500/10 border border-red-500/20"
            />
            <StatsCard
              title="High Risk"
              value={stats.high}
              icon={<AlertCircle className="w-6 h-6 text-orange-500" />}
              color="bg-orange-500/10 border border-orange-500/20"
            />
            <StatsCard
              title="Medium"
              value={stats.medium}
              icon={<AlertCircle className="w-6 h-6 text-yellow-500" />}
              color="bg-yellow-500/10 border border-yellow-500/20"
            />
          </div>

          <ResultsTable results={results} />
        </div>
      </main>
    </div>
  );
}

export default App;
