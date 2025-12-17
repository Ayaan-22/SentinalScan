import React, { useState, useEffect } from "react";
import {
  Shield,
  Zap,
  Search,
  AlertCircle,
  Activity,
  Globe,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
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
    <div className="min-h-screen p-4 md:p-8 overflow-x-hidden">
      {/* Background Ambience */}
      <div className="fixed inset-0 z-[-1] overflow-hidden pointer-events-none">
        <div className="absolute top-[-10%] left-[20%] w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl mix-blend-screen animate-pulse" />
        <div className="absolute bottom-[-10%] right-[20%] w-[500px] h-[500px] bg-blue-600/10 rounded-full blur-3xl mix-blend-screen" />
      </div>

      <header className="max-w-7xl mx-auto mb-10">
        <div className="flex flex-col md:flex-row items-center justify-between gap-6">
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            className="flex items-center gap-4"
          >
            <div className="relative group">
              <div className="absolute inset-0 bg-cyan-500/30 blur-xl rounded-full group-hover:bg-cyan-500/50 transition-all duration-500" />
              <div className="relative bg-slate-900 border border-slate-700 p-3 rounded-2xl shadow-2xl">
                <Shield className="w-8 h-8 text-cyan-400" />
              </div>
            </div>
            <div>
              <h1 className="text-3xl font-bold text-white tracking-tight">
                Sentinal<span className="text-cyan-400">Scan</span>
              </h1>
              <div className="flex items-center gap-2 mt-1">
                <div className="h-[2px] w-8 bg-cyan-500/50 rounded-full" />
                <p className="text-xs text-slate-400 font-mono tracking-wider uppercase">
                  Vulnerability Assessment System
                </p>
              </div>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="flex gap-4"
          >
            <div className="glass px-5 py-2.5 rounded-xl flex items-center gap-3 border border-slate-800">
              <div
                className={`w-2.5 h-2.5 rounded-full shadow-[0_0_10px_currentColor] transition-colors duration-500 ${
                  isScanning
                    ? "bg-green-500 text-green-500 animate-pulse"
                    : "bg-slate-600 text-slate-600"
                }`}
              />
              <span className="text-sm font-medium text-slate-300 font-mono">
                {isScanning ? "SYSTEM ACTIVE" : "SYSTEM IDLE"}
              </span>
            </div>
          </motion.div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Dashboard & Controls */}
        <div className="lg:col-span-4 space-y-8 flex flex-col">
          <ScanForm
            onStart={startScan}
            onStop={stopScan}
            isScanning={isScanning}
          />
          <LogViewer logs={logs} />
        </div>

        {/* Right Column: Visualization & Results */}
        <div className="lg:col-span-8 space-y-8">
          {/* Stats Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatsCard
              title="Total Findings"
              value={stats.total}
              icon={<Search className="w-5 h-5" />}
              color="text-blue-400"
              bg="bg-blue-500/10"
              border="border-blue-500/20"
              delay={0.1}
            />
            <StatsCard
              title="Critical"
              value={stats.critical}
              icon={<Zap className="w-5 h-5" />}
              color="text-red-500"
              bg="bg-red-500/10"
              border="border-red-500/20"
              delay={0.2}
            />
            <StatsCard
              title="High Risk"
              value={stats.high}
              icon={<AlertCircle className="w-5 h-5" />}
              color="text-orange-500"
              bg="bg-orange-500/10"
              border="border-orange-500/20"
              delay={0.3}
            />
            <StatsCard
              title="Medium"
              value={stats.medium}
              icon={<AlertCircle className="w-5 h-5" />}
              color="text-yellow-500"
              bg="bg-yellow-500/10"
              border="border-yellow-500/20"
              delay={0.4}
            />
          </div>

          <ResultsTable results={results} />
        </div>
      </main>
    </div>
  );
}

export default App;
