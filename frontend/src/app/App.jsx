import React, { useState, Suspense, lazy } from "react";
import { Shield, Activity } from "lucide-react";
import { ScanForm } from "../features/scan/ScanForm";
import { useScanStatus } from "../features/scan/scan.hooks";
import { LiveLogs } from "../features/scan-logs/LiveLogs";

// Lazy load the dashboard
const FindingsDashboard = lazy(() =>
  import("../features/findings/FindingsDashboard").then((module) => ({
    default: module.FindingsDashboard,
  }))
);

export default function App() {
  const { data: status, isError, isLoading } = useScanStatus();
  const isScanning = status?.is_scanning;
  // If we have status data, we are connected. If error, disconnected.
  const isConnected = !!status && !isError;
  const [activeTab, setActiveTab] = useState("findings");

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500/30">
      {/* Ambient Background */}
      <div className="fixed inset-0 z-0 overflow-hidden pointer-events-none">
        <div className="absolute top-[-10%] left-[20%] w-[500px] h-[500px] bg-cyan-500/5 rounded-full blur-[100px]" />
        <div className="absolute bottom-[-10%] right-[20%] w-[500px] h-[500px] bg-blue-600/5 rounded-full blur-[100px]" />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto p-6 space-y-8">
        {/* Header */}
        <header className="flex flex-col md:flex-row items-center justify-between gap-6 pb-6 border-b border-slate-800/50">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-slate-900 border border-slate-800 rounded-2xl shadow-xl shadow-cyan-900/10">
              <Shield className="w-8 h-8 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight text-white">
                Sentinal<span className="text-cyan-400">Scan</span>
              </h1>
              <p className="text-xs text-slate-400 font-mono tracking-wider uppercase">
                Vulnerability Assessment System
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {/* Status Badge */}
            <div className="flex items-center gap-3 px-4 py-2 bg-slate-900/50 backdrop-blur-sm border border-slate-800 rounded-full">
              <div
                className={`w-2.5 h-2.5 rounded-full shadow-[0_0_10px_currentColor] transition-colors duration-500 ${
                  isScanning
                    ? "bg-green-500 text-green-500 animate-pulse"
                    : isConnected
                    ? "bg-green-500 text-green-500"
                    : "bg-red-500 text-red-500"
                }`}
              />
              <span className="text-sm font-medium font-mono text-slate-300">
                {isScanning
                  ? "SYSTEM RUNNING"
                  : isConnected
                  ? "SYSTEM READY"
                  : "SYSTEM OFFLINE"}
              </span>
            </div>
          </div>
        </header>

        <main className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          {/* Left Panel: Configuration */}
          <div className="lg:col-span-4 space-y-6">
            <div className="p-6 bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded-2xl shadow-sm">
              <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Activity className="w-5 h-5 text-cyan-400" />
                Scan Configuration
              </h2>
              <ScanForm />
            </div>
          </div>

          {/* Right Panel: Findings & Results */}
          <div className="lg:col-span-8">
            <div className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded-2xl shadow-sm min-h-[600px] flex flex-col">
              {/* Tabs Header */}
              <div className="flex items-center border-b border-slate-800">
                <button
                  onClick={() => setActiveTab("findings")}
                  className={`flex-1 flex items-center justify-center gap-2 py-4 text-sm font-medium transition-colors relative ${
                    activeTab === "findings"
                      ? "text-cyan-400"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <Shield className="w-4 h-4" />
                  Security Findings
                  {activeTab === "findings" && (
                    <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-cyan-400" />
                  )}
                </button>
                <button
                  onClick={() => setActiveTab("logs")}
                  className={`flex-1 flex items-center justify-center gap-2 py-4 text-sm font-medium transition-colors relative ${
                    activeTab === "logs"
                      ? "text-cyan-400"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <Activity className="w-4 h-4" />
                  Live Logs
                  {activeTab === "logs" && (
                    <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-cyan-400" />
                  )}
                </button>
              </div>

              {/* Tab Content */}
              <div className="p-6 flex-1 flex flex-col">
                {activeTab === "findings" ? (
                  <Suspense
                    fallback={
                      <div className="text-center text-slate-500 py-20">
                        Loading findings dashboard...
                      </div>
                    }
                  >
                    <FindingsDashboard />
                  </Suspense>
                ) : (
                  <div className="flex-1 flex flex-col min-h-0">
                    <LiveLogs />
                  </div>
                )}
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
