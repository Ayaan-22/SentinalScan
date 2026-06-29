import React, { useState, Suspense, lazy } from "react";
import { Shield, Activity, Heart, CheckCircle2, XCircle, AlertCircle, KeyRound, Target, Gauge, FileWarning } from "lucide-react";
import { clsx } from "clsx";
import { ScanForm } from "../features/scan/ScanForm";
import { useBackendHealth, useScanStatus, useStopScan } from "../features/scan/scan.hooks";
import { LiveLogs } from "../features/scan-logs/LiveLogs";
import { ScanHistory } from "../features/scan/ScanHistory";
import { AnimatePresence, motion as Motion } from "framer-motion";
import { getApiKey, setApiKey } from "../services/api";

const APP_VERSION = "2.2.0";

// Lazy load the dashboard
const FindingsDashboard = lazy(() =>
  import("../features/findings/FindingsDashboard").then((module) => ({
    default: module.FindingsDashboard,
  }))
);

export default function App() {
  const [scanId, setScanId] = useState(null);
  const [apiKeyInput, setApiKeyInput] = useState(() => getApiKey());

  const { data: statusData, isError } = useScanStatus(scanId);
  const { isError: isBackendOffline } = useBackendHealth();
  const isScanning =
    statusData?.status === "running" || statusData?.status === "pending";
  const isConnected = !isBackendOffline && (!!statusData || !scanId) && !isError;
  const displayStatus = isBackendOffline
    ? "backend offline"
    : statusData?.status || "idle";

  const [activeTab, setActiveTab] = useState("findings");
  const [toast, setToast] = useState(null);
  const stopScanMutation = useStopScan();

  const showToast = (message, type = "info") => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  const handleScanStarted = (data) => {
    setScanId(data.scan_id);
    setActiveTab("logs");
    showToast("Vulnerability scan initialized", "success");
  };

  const handleStop = () => {
    if (scanId) {
      stopScanMutation.mutate(scanId);
      showToast("Scan termination requested", "warning");
    }
  };

  const saveApiKey = () => {
    setApiKey(apiKeyInput);
    showToast(apiKeyInput.trim() ? "API key saved for this browser session" : "API key cleared", "info");
  };

  const handleSelectScan = (id) => {
    setScanId(id);
    setActiveTab("findings");
  };

  // Watch for scan completion
  React.useEffect(() => {
    if (statusData?.status === "completed" && scanId) {
      showToast("Scan completed successfully", "success");
    } else if (statusData?.status === "failed" && scanId) {
      showToast("Scan failed", "error");
    }
  }, [statusData?.status, scanId]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500/30 flex flex-col">
      {/* Ambient Background */}
      <div className="fixed inset-0 z-0 overflow-hidden pointer-events-none">
        <div className="absolute top-[-10%] left-[20%] w-[500px] h-[500px] bg-cyan-500/5 rounded-full blur-[120px]" />
        <div className="absolute bottom-[-10%] right-[20%] w-[500px] h-[500px] bg-blue-600/5 rounded-full blur-[120px]" />
        <div className="absolute top-[50%] left-[50%] w-[400px] h-[400px] bg-purple-600/3 rounded-full blur-[100px]" />
      </div>

      <div className="relative z-10 flex-1 max-w-7xl mx-auto w-full p-4 md:p-6 space-y-6 md:space-y-8">
        {/* Header */}
        <header className="flex flex-col md:flex-row items-center justify-between gap-4 pb-4 md:pb-6 border-b border-slate-800/50">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-slate-900 border border-slate-800 rounded-2xl shadow-xl shadow-cyan-900/10">
              <Shield className="w-7 h-7 md:w-8 md:h-8 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-white">
                Sentinal<span className="text-cyan-400">Scan</span>
              </h1>
              <p className="text-[10px] md:text-xs text-slate-400 font-mono tracking-wider uppercase">
                Vulnerability Assessment System
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Status Badge */}
            <div className="flex items-center gap-3 px-4 py-2 bg-slate-900/50 backdrop-blur-sm border border-slate-800 rounded-full">
              <div
                className={`w-2.5 h-2.5 rounded-full shadow-[0_0_10px_currentColor] transition-colors duration-500 ${
                  isBackendOffline
                    ? "bg-red-500 text-red-500"
                    : isScanning
                    ? "bg-green-500 text-green-500 animate-pulse"
                    : isConnected
                    ? "bg-green-500 text-green-500"
                    : "bg-slate-500 text-slate-500"
                }`}
              />
              <span className="text-xs md:text-sm font-medium font-mono text-slate-300">
                {isBackendOffline
                  ? "OFFLINE"
                  : isScanning
                  ? "SCANNING"
                  : isConnected
                  ? "READY"
                  : "IDLE"}
              </span>
            </div>

            {/* Version badge */}
            <span className="hidden sm:inline text-[10px] font-mono text-slate-500 border border-slate-800 px-2 py-1 rounded-lg">
              v{APP_VERSION}
            </span>
          </div>
        </header>

        <section className="grid gap-4 rounded-2xl border border-slate-800/70 bg-slate-900/50 p-4 shadow-2xl shadow-cyan-950/10 backdrop-blur-md md:grid-cols-[1.4fr_1fr]">
          <div>
            <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-1 text-xs font-semibold text-cyan-300">
              <Shield className="h-3.5 w-3.5" />
              Authorized security testing only
            </div>
            <h2 className="text-2xl font-bold tracking-tight text-white md:text-3xl">
              SentinalScan command center
            </h2>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
              Configure bounded scans, watch authenticated live logs, and review findings as they appear.
            </p>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
            <label className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
              <KeyRound className="h-4 w-4 text-cyan-400" />
              Session API Key
            </label>
            <div className="flex gap-2">
              <input
                type="password"
                value={apiKeyInput}
                onChange={(e) => setApiKeyInput(e.target.value)}
                placeholder="Paste SENTINAL_API_KEY"
                className="min-w-0 flex-1 rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500/60"
              />
              <button
                type="button"
                onClick={saveApiKey}
                className="rounded-lg bg-cyan-500 px-3 py-2 text-sm font-bold text-slate-950 transition hover:bg-cyan-400"
              >
                Save
              </button>
            </div>
            <p className="mt-2 text-xs text-slate-500">
              Stored in sessionStorage only. Frontend env keys are public after build.
            </p>
          </div>
        </section>

        <section className="grid grid-cols-2 gap-3 md:grid-cols-4">
          {[
            { label: "Status", value: displayStatus, icon: Activity, tone: isBackendOffline ? "text-red-300" : isScanning ? "text-green-300" : "text-slate-200" },
            { label: "Target", value: statusData?.target_url ? new URL(statusData.target_url).hostname : "none", icon: Target, tone: "text-cyan-300" },
            { label: "Risk Score", value: statusData?.vulnerabilities_count ? Math.min(100, statusData.vulnerabilities_count * 12) : 0, icon: Gauge, tone: "text-orange-300" },
            { label: "Findings", value: statusData?.vulnerabilities_count || 0, icon: FileWarning, tone: "text-red-300" },
          ].map((item) => (
            <div key={item.label} className="rounded-xl border border-slate-800 bg-slate-900/45 p-4">
              <div className="mb-2 flex items-center justify-between text-xs uppercase tracking-wider text-slate-500">
                <span>{item.label}</span>
                <item.icon className="h-4 w-4 text-slate-600" />
              </div>
              <div className={clsx("truncate text-xl font-bold capitalize", item.tone)} title={String(item.value)}>
                {item.value}
              </div>
              {item.label === "Status" && (
                <div className="mt-2 text-xs text-slate-500">
                  {isBackendOffline ? "Backend API is not reachable" : `${statusData?.pages_scanned || 0} pages scanned`}
                </div>
              )}
            </div>
          ))}
        </section>

        <main className="grid grid-cols-1 lg:grid-cols-12 gap-6 md:gap-8">
          {/* Left Panel: Configuration */}
          <div className="lg:col-span-4 space-y-6">
            <div className="p-5 md:p-6 bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded-2xl shadow-sm">
              <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Activity className="w-5 h-5 text-cyan-400" />
                Scan Configuration
              </h2>
              <ScanForm
                onScanStarted={handleScanStarted}
                onStop={handleStop}
                isScanning={isScanning}
              />
            </div>
            
            {/* Scan History Sidebar */}
            <div className="p-5 md:p-6 bg-slate-900/30 backdrop-blur-md border border-slate-800/50 rounded-2xl">
              <ScanHistory 
                activeScanId={scanId} 
                onSelectScan={handleSelectScan} 
              />
            </div>

            {/* Scan Info Card */}
            {scanId && statusData && (
              <div className="p-4 bg-slate-900/30 backdrop-blur-sm border border-slate-800 rounded-2xl text-xs space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-slate-500 uppercase tracking-wider font-semibold text-[10px]">Scan ID</span>
                  <span className="font-mono text-slate-400">{scanId.slice(0, 12)}...</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-500 uppercase tracking-wider font-semibold text-[10px]">Target</span>
                  <span className="font-mono text-cyan-400 truncate max-w-[180px]">{statusData.target_url}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-500 uppercase tracking-wider font-semibold text-[10px]">Status</span>
                  <span className={`font-mono font-bold uppercase ${
                    statusData.status === "completed" ? "text-green-400" :
                    statusData.status === "running" ? "text-cyan-400" :
                    statusData.status === "failed" ? "text-red-400" :
                    "text-slate-400"
                  }`}>
                    {statusData.status}
                  </span>
                </div>
                {statusData.vulnerabilities_count > 0 && (
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500 uppercase tracking-wider font-semibold text-[10px]">Findings</span>
                    <span className="font-mono text-orange-400 font-bold">{statusData.vulnerabilities_count}</span>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Right Panel: Findings & Logs */}
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
                  {statusData?.vulnerabilities_count > 0 && (
                    <span className="ml-1 text-[10px] bg-cyan-500/10 text-cyan-400 px-1.5 py-0.5 rounded-full border border-cyan-500/20 font-bold">
                      {statusData.vulnerabilities_count}
                    </span>
                  )}
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
                  {isScanning && (
                    <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                  )}
                  {activeTab === "logs" && (
                    <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-cyan-400" />
                  )}
                </button>
              </div>

              {/* Tab Content */}
              <div className="p-4 md:p-6 flex-1 flex flex-col">
                {activeTab === "findings" ? (
                  <Suspense
                    fallback={
                      <div className="text-center text-slate-500 py-20">
                        Loading findings dashboard...
                      </div>
                    }
                  >
                    <FindingsDashboard scanId={scanId} />
                  </Suspense>
                ) : (
                  <div className="flex-1 flex flex-col min-h-0">
                    <LiveLogs
                      scanId={scanId}
                      isScanning={isScanning}
                      statusLogs={statusData?.recent_logs || []}
                    />
                  </div>
                )}
              </div>
            </div>
          </div>
        </main>
      </div>

      {/* Footer */}
      <footer className="relative z-10 border-t border-slate-800/50 mt-8">
        <div className="max-w-7xl mx-auto px-6 py-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <Shield className="w-3.5 h-3.5 text-slate-600" />
            <span>SentinalScan v{APP_VERSION} - Automated Vulnerability Assessment</span>
          </div>
          <div className="flex items-center gap-4 text-xs text-slate-600">
            <span className="flex items-center gap-1">
              Made with <Heart className="w-3 h-3 text-red-500/50" /> for security
            </span>
          </div>
        </div>
      </footer>

      {/* Custom Toast System */}
      <AnimatePresence>
        {toast && (
          <Motion.div
            initial={{ opacity: 0, y: 50, scale: 0.9 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, scale: 0.9 }}
            className="fixed bottom-8 right-8 z-[100]"
          >
            <div className={clsx(
              "px-6 py-3 rounded-2xl shadow-2xl border backdrop-blur-xl flex items-center gap-3",
              toast.type === "success" && "bg-green-500/10 border-green-500/50 text-green-400",
              toast.type === "error" && "bg-red-500/10 border-red-500/50 text-red-400",
              toast.type === "warning" && "bg-orange-500/10 border-orange-500/50 text-orange-400",
              toast.type === "info" && "bg-cyan-500/10 border-cyan-500/50 text-cyan-400"
            )}>
              {toast.type === "success" && <CheckCircle2 className="w-5 h-5" />}
              {toast.type === "error" && <XCircle className="w-5 h-5" />}
              {toast.type === "warning" && <AlertCircle className="w-5 h-5" />}
              {toast.type === "info" && <Activity className="w-5 h-5" />}
              <span className="text-sm font-medium">{toast.message}</span>
            </div>
          </Motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
