import { createElement, useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  ArrowUpRight,
  BookOpen,
  Check,
  Copy,
  Crosshair,
  FileText,
  Fingerprint,
  Globe2,
  LayoutDashboard,
  LockKeyhole,
  Menu,
  Plus,
  Radar,
  Search,
  Settings2,
  Shield,
  ShieldCheck,
  Sparkles,
  Square,
  Terminal,
  X,
} from "lucide-react";
import { ScanForm } from "../features/scan/ScanForm";
import { PolicySummary } from "../features/scan/PolicySummary";
import { Select } from "../components/Select";
import {
  useAllScans,
  useBackendHealth,
  useScanResults,
  useScanStatus,
  useStopScan,
} from "../features/scan/scan.hooks";
import { LiveLogs } from "../features/scan-logs/LiveLogs";
import { FindingsDashboard } from "../features/findings/FindingsDashboard";
import { ScanHistory } from "../features/scan/ScanHistory";
import { getApiKey, getFriendlyApiError, setApiKey } from "../services/api";
import { demoScans, getDemoLogs } from "./demo";
import {
  exportReport,
  formatDate,
  hostname,
  SEVERITIES,
  severityCounts,
} from "./utils";

const NAV = [
  ["overview", "Overview", LayoutDashboard],
  ["findings", "Findings", Fingerprint],
  ["scans", "Scan history", Radar],
  ["logs", "Live console", Terminal],
  ["reports", "Reports", FileText],
];

function Modal({ title, subtitle, onClose, children, wide = false }) {
  const ref = useRef(null);
  const closeRef = useRef(onClose);
  useEffect(() => {
    closeRef.current = onClose;
  }, [onClose]);
  useEffect(() => {
    const previous = document.activeElement;
    const dialog = ref.current;
    dialog.focus();
    const onKey = (e) => {
      if (e.key === "Escape") closeRef.current();
      if (e.key !== "Tab") return;
      const nodes = [
        ...dialog.querySelectorAll(
          'button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href], [tabindex="0"]',
        ),
      ].filter((n) => n.getClientRects().length);
      const first = nodes[0];
      const last = nodes.at(-1);
      if (
        e.shiftKey &&
        (document.activeElement === first || document.activeElement === dialog)
      ) {
        e.preventDefault();
        last?.focus();
      } else if (
        !e.shiftKey &&
        (document.activeElement === last || document.activeElement === dialog)
      ) {
        e.preventDefault();
        first?.focus();
      }
    };
    dialog.addEventListener("keydown", onKey);
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      dialog.removeEventListener("keydown", onKey);
      document.body.style.overflow = overflow;
      previous?.focus();
    };
  }, []);
  return (
    <div
      className="modal-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <section
        ref={ref}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby="dialog-title"
        className={`modal ${wide ? "modal-wide" : ""}`}
      >
        <div className="modal-heading">
          <div>
            <span className="eyebrow">SENTINALSCAN / WORKSPACE</span>
            <h2 id="dialog-title">{title}</h2>
            <p>{subtitle}</p>
          </div>
          <button
            className="icon-button"
            onClick={onClose}
            aria-label="Close dialog"
          >
            <X size={20} />
          </button>
        </div>
        {children}
      </section>
    </div>
  );
}

function CommandSnippet({ command }) {
  const [copyState, setCopyState] = useState("idle");

  useEffect(() => {
    if (copyState === "idle") return;
    const timer = setTimeout(() => setCopyState("idle"), 3000);
    return () => clearTimeout(timer);
  }, [copyState]);

  const copyCommand = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopyState("copied");
    } catch {
      setCopyState("error");
    }
  };

  return (
    <>
      <div className="command-snippet">
        <code>{command}</code>
        <button
          type="button"
          className={`icon-button copy-command ${copyState === "copied" ? "copied" : ""}`}
          onClick={copyCommand}
          aria-label={
            copyState === "copied"
              ? "Command copied"
              : "Copy backend startup command"
          }
          title={copyState === "copied" ? "Copied!" : "Copy command"}
        >
          {copyState === "copied" ? <Check size={18} /> : <Copy size={18} />}
        </button>
      </div>
      <span
        role="status"
        className={copyState === "error" ? "command-copy-error" : "sr-only"}
      >
        {copyState === "copied"
          ? "Command copied to clipboard."
          : copyState === "error"
            ? "Clipboard unavailable. Select and copy the command above."
            : ""}
      </span>
    </>
  );
}

function SurfaceMap({ scan, findings, scanning }) {
  const categories = [
    ["Security headers", "Missing Security Headers", 22, 23],
    ["SQL injection", "SQL Injection", 77, 23],
    ["Cross-site scripting", "Cross-Site Scripting (XSS)", 84, 68],
    ["CSRF", "Cross-Site Request Forgery (CSRF)", 50, 86],
    ["Sensitive files", "Sensitive File Exposure", 16, 68],
  ];
  return (
    <div className={`surface-map ${scanning ? "is-scanning" : ""}`}>
      <div className="map-grid" />
      <svg
        className="map-lines"
        viewBox="0 0 600 270"
        preserveAspectRatio="none"
        aria-hidden="true"
      >
        <ellipse cx="300" cy="135" rx="172" ry="90" />
        <ellipse cx="300" cy="135" rx="105" ry="55" />
        {categories.map(([name, , x, y]) => (
          <path key={name} d={`M300 135 L${x * 6} ${y * 2.7}`} />
        ))}
      </svg>
      <div className="map-center">
        <div className="map-core">
          <Shield size={26} />
        </div>
        <strong>{scan ? hostname(scan.target_url) : "Your next target"}</strong>
        <span>
          {scanning
            ? "DISCOVERY IN PROGRESS"
            : scan
              ? `${scan.pages_scanned} PAGES ANALYZED`
              : "AWAITING DISCOVERY"}
        </span>
      </div>
      {categories.map(([name, type, x, y]) => {
        const count = findings.filter((f) => f.vuln_type === type).length;
        return (
          <div
            key={name}
            className={`map-node ${count ? "has-findings" : ""}`}
            style={{ left: `${x}%`, top: `${y}%` }}
          >
            <span className="node-dot" />
            <span>{name}</span>
            <b>
              {scan
                ? `${count} finding${count === 1 ? "" : "s"}`
                : "Ready to inspect"}
            </b>
          </div>
        );
      })}
      <div className="map-caption">
        <span className={`status-dot ${scanning ? "pulse" : ""}`} />
        {scan
          ? "Finding relationships by detector"
          : "5 detection modules · Same-origin scope"}
      </div>
    </div>
  );
}

function SeverityPanel({ findings, onFilter }) {
  const counts = severityCounts(findings);
  let cumulative = 0;
  const segments = SEVERITIES.map(({ name, color }) => {
    const start = cumulative;
    cumulative += findings.length ? (counts[name] / findings.length) * 100 : 0;
    return `${color} ${start}% ${cumulative}%`;
  });
  return (
    <section className="panel severity-panel">
      <div className="panel-heading">
        <h3>Severity distribution</h3>
        <span className="tiny-label">CURRENT SCAN</span>
      </div>
      <div className="severity-content">
        <div
          className="severity-ring"
          style={{
            background: findings.length
              ? `conic-gradient(${segments.join(",")})`
              : "#30332d",
          }}
          role="img"
          aria-label={SEVERITIES.map(
            (s) => `${s.name}: ${counts[s.name]}`,
          ).join(", ")}
        >
          <div>
            <strong>{findings.length}</strong>
            <span>Total findings</span>
          </div>
        </div>
        <div className="severity-legend">
          {SEVERITIES.map(({ name, color }) => (
            <button key={name} onClick={() => onFilter(name)}>
              <span className="legend-dot" style={{ background: color }} />
              {name}
              <b>{counts[name].toString().padStart(2, "0")}</b>
              <ArrowUpRight size={12} />
            </button>
          ))}
        </div>
      </div>
      <div className="panel-footnote">
        <ShieldCheck size={13} /> Prioritize critical and high severity
        findings.
      </div>
    </section>
  );
}

function ScanActivity({ scans }) {
  const recent = scans.slice(0, 12).reverse();
  const max = Math.max(1, ...recent.map((s) => s.vulnerabilities_count));
  return (
    <section className="panel activity-panel">
      <div className="panel-heading">
        <div>
          <h3>Assessment activity</h3>
          <p>Findings across recent scans</p>
        </div>
        <span className="mini-tag">{recent.length} SESSIONS</span>
      </div>
      <div className="activity-chart">
        {recent.length ? (
          recent.map((s, i) => (
            <div className="activity-column" key={s.scan_id}>
              <div
                title={`${hostname(s.target_url)}: ${s.vulnerabilities_count} findings`}
                style={{
                  height: `${Math.max(4, (s.vulnerabilities_count / max) * 100)}%`,
                }}
              >
                <span>{s.vulnerabilities_count}</span>
              </div>
              <small>{String(i + 1).padStart(2, "0")}</small>
            </div>
          ))
        ) : (
          <div className="chart-empty">
            <Activity size={26} />
            <span>Your scan activity will appear here</span>
          </div>
        )}
      </div>
      <div className="activity-axis">
        <span>OLDER SCANS</span>
        <span>
          MOST RECENT <ArrowRight size={11} />
        </span>
      </div>
    </section>
  );
}

export default function App() {
  const [view, setView] = useState("overview");
  const [selectedId, setSelectedId] = useState(null);
  const [demo, setDemo] = useState(false);
  const [modal, setModal] = useState(null);
  const [sidebar, setSidebar] = useState(false);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [apiKeyInput, setApiKeyInput] = useState(getApiKey);
  const [toast, setToast] = useState("");
  const queryClient = useQueryClient();
  const health = useBackendHealth();
  const history = useAllScans();
  const scans = demo ? demoScans : history.data || [];
  const scanId = selectedId || scans[0]?.scan_id;
  const status = useScanStatus(demo ? null : scanId);
  const scan = demo
    ? scans.find((s) => s.scan_id === scanId)
    : status.data || scans.find((s) => s.scan_id === scanId);
  const scanning = scan?.status === "running" || scan?.status === "pending";
  const results = useScanResults(demo ? null : scanId, scanning);
  const findings = demo
    ? scan?.results || []
    : results.data || scan?.results || [];
  const stop = useStopScan();
  const counts = severityCounts(findings);
  const totalPages = scans.reduce((n, s) => n + s.pages_scanned, 0);
  const highest = findings.length
    ? Math.max(...findings.map((f) => Number(f.severity_score) || 0))
    : null;
  const connected = health.isSuccess;
  const scanStatus = scan?.status;
  useEffect(() => {
    if (
      !demo &&
      scanId &&
      ["completed", "failed", "stopped"].includes(scanStatus)
    ) {
      queryClient.invalidateQueries({ queryKey: ["scanResults", scanId] });
    }
  }, [demo, scanId, scanStatus, queryClient]);
  useEffect(() => {
    if (!sidebar) return;
    const close = (event) => {
      if (event.key === "Escape") setSidebar(false);
    };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [sidebar]);
  const notify = (message) => setToast(message);
  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(""), 4500);
    return () => clearTimeout(t);
  }, [toast]);
  useEffect(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        document.getElementById("workspace-search")?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  const navigate = (next) => {
    setView(next);
    setSidebar(false);
    setSearch("");
    setSeverity("all");
  };
  const selectScan = (id) => {
    setSelectedId(id);
    navigate("overview");
  };
  const handleExport = (format) => {
    exportReport(format, scan, findings, demo);
    notify(`${demo ? "Demo " : ""}${format.toUpperCase()} report downloaded`);
  };
  const saveKey = () => {
    setApiKey(apiKeyInput);
    queryClient.resetQueries();
    notify(
      apiKeyInput.trim()
        ? "Session API key saved. Reconnecting…"
        : "Session API key cleared",
    );
  };
  const stopScan = () =>
    stop.mutate(scanId, {
      onSuccess: () => notify("Scan stop requested"),
      onError: (e) => notify(getFriendlyApiError(e)),
    });
  const onFilter = (name) => {
    setSeverity(name);
    setView("findings");
  };
  const toggleDemo = () => {
    setDemo(!demo);
    setSelectedId(null);
    setSearch("");
    setSeverity("all");
  };
  const findingsProps = {
    findings,
    loading: !demo && !!scanId && results.isPending,
    error: !demo && results.isError ? getFriendlyApiError(results.error) : "",
    search,
    setSearch,
    severity,
    setSeverity,
    onExport: handleExport,
  };
  return (
    <div className="workspace">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      {sidebar && (
        <button
          className="sidebar-scrim"
          aria-label="Close navigation"
          onClick={() => setSidebar(false)}
        />
      )}
      <aside
        id="workspace-navigation"
        className={`sidebar ${sidebar ? "sidebar-open" : ""}`}
      >
        <a
          href="#"
          className="brand"
          onClick={(e) => {
            e.preventDefault();
            navigate("overview");
          }}
        >
          <div className="brand-mark">
            <Shield size={24} />
            <span />
          </div>
          <div>
            sentinal<span>scan</span>
            <small>SECURITY INTELLIGENCE</small>
          </div>
        </a>
        <div className="workspace-switch">
          <div className="workspace-avatar">S</div>
          <div>
            <strong>Security workspace</strong>
            <span>Local environment</span>
          </div>
          <LockKeyhole size={13} />
        </div>
        <span className="nav-label">WORKSPACE</span>
        <nav aria-label="Main navigation">
          {NAV.map(([id, label, icon]) => (
            <button
              key={id}
              onClick={() => navigate(id)}
              className={`nav-item ${view === id ? "active" : ""}`}
              aria-current={view === id ? "page" : undefined}
            >
              {createElement(icon, { size: 18 })}
              <span>{label}</span>
              {id === "findings" && <b>{findings.length}</b>}
              {id === "logs" && scanning && <i className="status-dot pulse" />}
            </button>
          ))}
        </nav>
        <span className="nav-label tools-label">TOOLS & CONFIGURATION</span>
        <button
          className="nav-item"
          onClick={() => {
            setModal("settings");
            setSidebar(false);
          }}
        >
          <Settings2 size={18} />
          <span>Connection settings</span>
        </button>
        <button
          className="nav-item"
          onClick={() => {
            setModal("guide");
            setSidebar(false);
          }}
        >
          <BookOpen size={18} />
          <span>Field guide</span>
          <ArrowUpRight size={13} />
        </button>
        <div className="sidebar-bottom">
          <div className="engine-card">
            <div>
              <span className={`status-dot ${connected ? "" : "offline"}`} />
              <strong>
                {health.isPending
                  ? "Connecting to engine"
                  : connected
                    ? "Scan engine online"
                    : "Scan engine offline"}
              </strong>
            </div>
            <p>
              {connected
                ? "Backend is reachable. Connect your API key to access scans."
                : "Connect your local backend to start assessing targets."}
            </p>
            <button onClick={() => setModal("settings")}>
              Manage connection <ArrowUpRight size={13} />
            </button>
          </div>
          <div className="operator">
            <div className="operator-avatar">
              <Fingerprint size={18} />
            </div>
            <div>
              <strong>Security operator</strong>
              <span>Local session · v2.2.0</span>
            </div>
            <button
              onClick={() => setModal("settings")}
              className="icon-button"
              aria-label="Open session settings"
            >
              <Settings2 size={16} />
            </button>
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            <button
              className="icon-button mobile-menu"
              aria-expanded={sidebar}
              aria-controls="workspace-navigation"
              onClick={() => setSidebar(true)}
              aria-label="Open navigation"
            >
              <Menu size={20} />
            </button>
            <Shield size={15} />
            <span>Workspace</span>
            <span className="breadcrumb-slash">/</span>
            <strong>{NAV.find((n) => n[0] === view)?.[1]}</strong>
          </div>
          <div className="topbar-right">
            <label className="global-search">
              <Search size={15} />
              <input
                id="workspace-search"
                aria-label="Search findings or scans"
                placeholder="Search the workspace…"
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  if (!["findings", "scans"].includes(view))
                    setView("findings");
                }}
              />
              <kbd>⌃ K</kbd>
            </label>
            <span className="topbar-divider" />
            <button
              className="session-button"
              aria-label="Session key settings"
              onClick={() => setModal("settings")}
            >
              <LockKeyhole size={15} />
              <span>Session key</span>
              <i className={`status-dot ${getApiKey() ? "" : "offline"}`} />
            </button>
          </div>
        </header>
        <main id="main-content" className="main-content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">
                <span className="lime-tick" /> YOUR PERIMETER. YOUR PERSPECTIVE.
              </div>
              <h1>
                {view === "overview" ? (
                  <>
                    Security <span>overview</span>
                    <span className="heading-dot">.</span>
                  </>
                ) : (
                  NAV.find((n) => n[0] === view)?.[1]
                )}
              </h1>
              <p>
                {
                  {
                    overview:
                      "A sharper view of your attack surface. Every signal, in one place.",
                    findings:
                      "Inspect the evidence. Understand the impact. Know what to fix.",
                    scans: "Every assessment, every target, every outcome.",
                    logs: "Follow discovery and detection as they happen.",
                    reports:
                      "Turn security signals into actionable intelligence.",
                  }[view]
                }
              </p>
            </div>
            <div className="heading-actions">
              <button
                className={`button secondary demo-toggle ${demo ? "demo-on" : ""}`}
                onClick={toggleDemo}
              >
                <Sparkles size={15} />
                {demo ? "Exit demo" : "Explore demo"}
              </button>
              <button
                className="button primary"
                onClick={() => setModal("scan")}
              >
                <Plus size={17} /> New scan
              </button>
            </div>
          </div>
          {demo ? (
            <div className="notice demo-notice">
              <Sparkles size={15} />
              <strong>DEMO WORKSPACE</strong>
              <span>
                Illustrative sample data. No targets are being scanned.
              </span>
              <button onClick={toggleDemo}>
                Return to live <ArrowRight size={14} />
              </button>
            </div>
          ) : !connected && !health.isPending ? (
            <div className="notice">
              <span className="status-dot offline" />
              <span>
                <strong>Your workspace is ready.</strong> Connect the scan
                engine to see live assessments, or explore the demo.
              </span>
              <button onClick={() => setModal("settings")}>
                Connect engine <ArrowRight size={14} />
              </button>
            </div>
          ) : history.isError ? (
            <div className="notice error-notice">
              <LockKeyhole size={15} />
              <span>{getFriendlyApiError(history.error)}</span>
              <button onClick={() => setModal("settings")}>
                Update key <ArrowRight size={14} />
              </button>
            </div>
          ) : null}
          {view === "overview" && (
            <>
              <section className="metrics-grid" aria-label="Assessment metrics">
                <Metric
                  label="TOTAL ASSESSMENTS"
                  value={scans.length.toString().padStart(2, "0")}
                  icon={Radar}
                  note={`${scans.filter((s) => s.status === "completed").length} completed`}
                  detail="All sessions"
                />
                <Metric
                  label="CURRENT FINDINGS"
                  value={findings.length.toString().padStart(2, "0")}
                  icon={Fingerprint}
                  note={`${counts.Critical + counts.High} need priority review`}
                  detail="Selected scan"
                  tone="coral"
                />
                <Metric
                  label="PAGES ANALYZED"
                  value={totalPages.toLocaleString()}
                  icon={Globe2}
                  note={`${new Set(scans.map((s) => hostname(s.target_url))).size} unique target hosts`}
                  detail="All sessions"
                />
                <Metric
                  label="HIGHEST SEVERITY"
                  value={highest === null ? "—" : highest.toFixed(1)}
                  suffix={highest === null ? "" : "/ 10"}
                  icon={Crosshair}
                  note={
                    highest === null
                      ? "Awaiting assessment"
                      : "Maximum reported finding score"
                  }
                  detail="Selected scan"
                  tone="lime"
                />
              </section>
              <div className="overview-grid">
                <section className="panel surface-panel">
                  <div className="panel-heading">
                    <div>
                      <h3>
                        <span className="status-dot" /> Attack surface
                      </h3>
                      <p>Your target, connected to the findings that matter.</p>
                    </div>
                    <span className="mini-tag">
                      <Radar size={12} />
                      {scanning ? "SCANNING" : "DETECTION MAP"}
                    </span>
                  </div>
                  <SurfaceMap
                    scan={scan}
                    findings={findings}
                    scanning={scanning}
                  />
                </section>
                <SeverityPanel findings={findings} onFilter={onFilter} />
              </div>
              <div className="section-header">
                <div>
                  <span className="eyebrow">THE CURRENT PICTURE</span>
                  <h2>
                    Assessment intelligence
                    <span className="heading-dot">.</span>
                  </h2>
                </div>
                <button
                  className="text-button"
                  onClick={() => navigate("scans")}
                >
                  All assessments <ArrowUpRight size={15} />
                </button>
              </div>
              <div className="intelligence-grid">
                <section className="panel current-scan">
                  <div className="panel-heading">
                    <h3>Selected assessment</h3>
                    <span className={`status-badge ${scan?.status || "idle"}`}>
                      <span />
                      {scan?.status || "No scan selected"}
                    </span>
                  </div>
                  <div className="target-summary">
                    <div className="target-icon">
                      <Globe2 size={24} />
                    </div>
                    <div>
                      <span className="tiny-label">TARGET ENDPOINT</span>
                      <h3>
                        {scan
                          ? hostname(scan.target_url)
                          : "Start with a target"}
                      </h3>
                      <p>
                        {scan?.target_url ||
                          "Launch a scan to map your web application."}
                      </p>
                    </div>
                  </div>
                  <PolicySummary scan={scan} />
                  <dl className="scan-details">
                    <div>
                      <dt>Scan identifier</dt>
                      <dd className="mono">{scan?.scan_id || "—"}</dd>
                    </div>
                    <div>
                      <dt>Started</dt>
                      <dd>{formatDate(scan?.start_time)}</dd>
                    </div>
                    <div>
                      <dt>Finished</dt>
                      <dd>
                        {scan?.end_time
                          ? formatDate(scan.end_time)
                          : scanning
                            ? "In progress"
                            : "—"}
                      </dd>
                    </div>
                    <div>
                      <dt>Pages / affected URLs</dt>
                      <dd>
                        {scan?.pages_scanned || 0} <span>/</span>{" "}
                        {new Set(findings.map((f) => f.url)).size}
                      </dd>
                    </div>
                  </dl>
                  <div className="current-scan-footer">
                    <span>
                      <span
                        className={`status-dot ${scanning ? "pulse" : ""}`}
                      />
                      {scanning
                        ? "Findings update every 3 seconds"
                        : scan
                          ? "Assessment snapshot"
                          : "Ready when you are"}
                    </span>
                    {scanning && !demo ? (
                      <button
                        className="text-button danger"
                        disabled={stop.isPending}
                        onClick={stopScan}
                      >
                        <Square size={12} /> Stop scan
                      </button>
                    ) : (
                      <button
                        className="text-button"
                        onClick={() =>
                          scan ? navigate("findings") : setModal("scan")
                        }
                      >
                        {scan ? "Inspect findings" : "Configure scan"}
                        <ArrowRight size={14} />
                      </button>
                    )}
                  </div>
                </section>
                <ScanActivity scans={scans} />
              </div>
              <FindingsDashboard
                {...findingsProps}
                compact
                onViewAll={() => navigate("findings")}
              />
              <section className="bottom-banner">
                <div className="banner-symbol">
                  <ShieldCheck size={32} />
                </div>
                <div>
                  <span className="eyebrow">BUILT FOR THE DETAILS</span>
                  <h3>Find the signal. Close the gaps.</h3>
                  <p>
                    Five detection modules. Full evidence. A clearer path to
                    remediation.
                  </p>
                </div>
                <button
                  className="button secondary"
                  onClick={() => setModal("guide")}
                >
                  Explore capabilities <ArrowUpRight size={15} />
                </button>
              </section>
            </>
          )}
          {view === "findings" && (
            <>
              <ScanSelector
                scans={scans}
                scanId={scanId}
                onChange={setSelectedId}
              />
              <FindingsDashboard {...findingsProps} />
            </>
          )}
          {view === "scans" && (
            <ScanHistory
              scans={scans}
              loading={!demo && history.isPending}
              error={
                !demo && history.isError
                  ? getFriendlyApiError(history.error)
                  : ""
              }
              activeScanId={scanId}
              onSelectScan={selectScan}
              search={search}
              onNewScan={() => setModal("scan")}
            />
          )}
          {view === "logs" && (
            <>
              <ScanSelector
                scans={scans}
                scanId={scanId}
                onChange={setSelectedId}
              />
              <div className="panel console-panel">
                {demo ? (
                  <DemoConsole logs={getDemoLogs(scan)} />
                ) : (
                  <LiveLogs
                    key={scanId || "empty"}
                    scanId={scanId}
                    isScanning={scanning}
                    statusLogs={status.data?.recent_logs}
                  />
                )}
              </div>
            </>
          )}
          {view === "reports" && (
            <>
              <ScanSelector
                scans={scans}
                scanId={scanId}
                onChange={setSelectedId}
              />
              <section className="report-intro">
                <div className="report-art">
                  <FileText size={52} />
                  <span className="report-art-line" />
                  <span className="report-art-line short" />
                  <span className="report-art-stamp">
                    <ShieldCheck size={20} />
                  </span>
                </div>
                <div>
                  <span className="eyebrow">ASSESSMENT / EXPORT</span>
                  <h2>Your findings, ready to share.</h2>
                  <p>
                    Export the selected assessment with severity, confidence,
                    full evidence, affected URLs, and remediation. Reports
                    reflect the current snapshot
                    {scanning ? "; this scan is still in progress" : ""}.
                  </p>
                  <div className="report-stats">
                    <span>
                      <b>{findings.length}</b> findings
                    </span>
                    <span>
                      <b>{new Set(findings.map((f) => f.url)).size}</b> affected
                      URLs
                    </span>
                    <span>
                      <b>{scan?.status || "No assessment"}</b>
                    </span>
                  </div>
                </div>
              </section>
              <div className="report-grid">
                {[
                  [
                    "json",
                    "Structured report",
                    "Complete scan metadata and findings for integrations and further analysis.",
                    "{ }",
                  ],
                  [
                    "csv",
                    "Analyst spreadsheet",
                    "Every finding field in a flat, spreadsheet-ready format for triage and tracking.",
                    "CSV",
                  ],
                ].map(([format, title, description, symbol]) => (
                  <section className="panel report-card" key={format}>
                    <div className="report-format">{symbol}</div>
                    <h3>{title}</h3>
                    <p>{description}</p>
                    <button
                      disabled={!scan}
                      className="button secondary"
                      onClick={() => handleExport(format)}
                    >
                      <ArrowDownToLine size={15} /> Download{" "}
                      {format.toUpperCase()}
                      <ArrowUpRight size={14} />
                    </button>
                  </section>
                ))}
              </div>
            </>
          )}
          {view === "overview" && scans.length > 0 && (
            <div className="assessment-switcher">
              <ScanSelector
                scans={scans}
                scanId={scanId}
                onChange={setSelectedId}
              />
            </div>
          )}
          <footer className="workspace-footer">
            <span>
              <Shield size={12} /> SENTINALSCAN <span className="muted">/</span>{" "}
              SECURITY INTELLIGENCE
            </span>
            <span>
              {demo ? "SAMPLE DATA" : "AUTHORIZED ASSESSMENTS ONLY"}
              <i /> v2.2.0
            </span>
          </footer>
        </main>
      </div>
      {modal === "scan" && (
        <Modal
          title="Launch an assessment"
          subtitle="Define the scope. Set the boundaries. Discover what matters."
          onClose={() => setModal(null)}
          wide
        >
          <ScanForm
            isScanning={!demo && scanning}
            onStop={stopScan}
            stopPending={stop.isPending}
            onScanStarted={(data) => {
              setDemo(false);
              setSelectedId(data.scan_id);
              setView("logs");
              setModal(null);
              notify("Assessment started. Following live discovery.");
            }}
          />
        </Modal>
      )}
      {modal === "settings" && (
        <Modal
          title="Connect your engine"
          subtitle="Your browser session connects directly to the local scan backend."
          onClose={() => setModal(null)}
        >
          <div className="connection-summary">
            <Activity size={22} />
            <div>
              <strong>
                {connected
                  ? "Backend reachable"
                  : health.isPending
                    ? "Checking backend…"
                    : "Backend unavailable"}
              </strong>
              <p>
                {import.meta.env.VITE_API_URL || "http://localhost:8000/api/v1"}
              </p>
            </div>
            <button
              className="icon-button"
              onClick={() => health.refetch()}
              aria-label="Refresh backend connection"
            >
              <Radar size={19} />
            </button>
          </div>
          <label className="field-label" htmlFor="api-key">
            Session API key
          </label>
          <div className="key-input">
            <LockKeyhole size={16} />
            <input
              id="api-key"
              type="password"
              autoComplete="off"
              value={apiKeyInput}
              onChange={(e) => setApiKeyInput(e.target.value)}
              placeholder="Paste SENTINAL_API_KEY"
            />
          </div>
          <p className="field-help">
            Use the API key configured on your backend. Saved only for this
            browser session.
          </p>
          <button className="button primary full-width" onClick={saveKey}>
            <Check size={16} />
            Save session key
          </button>
          <div className="settings-note">
            <Terminal size={18} />
            <div>
              <strong>Start the local backend</strong>
              <CommandSnippet command="uvicorn app.main:app --reload" />
              <p>
                Run from the backend directory with your environment configured.
                See the project README for setup.
              </p>
            </div>
          </div>
        </Modal>
      )}
      {modal === "guide" && (
        <Modal
          title="Know your capabilities"
          subtitle="Focused detection. Bounded scope. Evidence you can investigate."
          onClose={() => setModal(null)}
          wide
        >
          <div className="capabilities">
            {[
              [
                "01",
                "Reflected XSS",
                "Tests reflected input for cross-site scripting indicators.",
              ],
              [
                "02",
                "SQL injection",
                "Checks for database error and response-based injection indicators.",
              ],
              [
                "03",
                "CSRF protection",
                "Inspects forms for missing anti-forgery protection.",
              ],
              [
                "04",
                "Security headers",
                "Identifies missing browser security response headers.",
              ],
              [
                "05",
                "Sensitive files",
                "Checks common paths for exposed configuration and sensitive files.",
              ],
            ].map(([n, title, description]) => (
              <div key={n}>
                <span>{n}</span>
                <div>
                  <h3>{title}</h3>
                  <p>{description}</p>
                </div>
                <ShieldCheck size={18} />
              </div>
            ))}
          </div>
          <div className="guide-note">
            <LockKeyhole size={20} />
            <p>
              Scans stay within the target origin, honor configured limits, and
              respect your exclusions. Review findings as indicators requiring
              verification. Scan only systems you own or have explicit
              permission to test.
            </p>
          </div>
          <button className="button primary" onClick={() => setModal("scan")}>
            Configure an assessment <ArrowRight size={15} />
          </button>
        </Modal>
      )}
      {toast && (
        <div className="toast" role="status">
          <Check size={17} />
          {toast}
          <button
            aria-label="Dismiss notification"
            onClick={() => setToast("")}
          >
            <X size={15} />
          </button>
        </div>
      )}
    </div>
  );
}

function Metric({ label, value, icon, note, detail, tone = "", suffix = "" }) {
  return (
    <article className={`metric-card ${tone}`}>
      <div className="metric-label">
        {label}
        {createElement(icon, { size: 17 })}
      </div>
      <div className="metric-value">
        {value}
        <span>{suffix}</span>
        <div className="metric-decoration" aria-hidden="true">
          <i />
          <i />
          <i />
          <i />
          <i />
        </div>
      </div>
      <div className="metric-note">
        <span>{note}</span>
        <small>{detail}</small>
      </div>
    </article>
  );
}
function ScanSelector({ scans, scanId, onChange }) {
  return (
    <div className="scan-selector">
      <span className="tiny-label">
        <Crosshair size={13} /> SELECTED ASSESSMENT
      </span>
      <Select
        label="Selected assessment"
        className="assessment-select"
        value={scanId || ""}
        onChange={onChange}
        placeholder="No assessments available"
        menuWidth={460}
        options={scans.map((scan) => ({
          value: scan.scan_id,
          label: hostname(scan.target_url),
          description: `${formatDate(scan.start_time)} · ${scan.status} · ${scan.scan_id}`,
        }))}
      />
    </div>
  );
}
function DemoConsole({ logs }) {
  return (
    <div className="demo-console">
      <div className="panel-heading">
        <h3>
          <Terminal size={16} /> Assessment console
        </h3>
        <span className="mini-tag">DEMO · RECORDED SAMPLE</span>
      </div>
      {logs.map((log, i) => (
        <div className="demo-log" key={i}>
          <span>14:32:{String(i * 4).padStart(2, "0")}</span>
          <b className={log.level === "WARNING" ? "warning-text" : "lime-text"}>
            {log.level}
          </b>
          <p>{log.message}</p>
        </div>
      ))}
      <div className="console-end">
        <span /> END OF SAMPLE OUTPUT
      </div>
    </div>
  );
}
