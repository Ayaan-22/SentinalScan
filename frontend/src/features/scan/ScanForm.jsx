import { useState } from "react";
import {
  ArrowRight,
  ChevronDown,
  Eye,
  EyeOff,
  Globe2,
  LockKeyhole,
  Settings2,
  ShieldCheck,
  Square,
} from "lucide-react";
import { useStartScan } from "./scan.hooks";
import { getFriendlyApiError, hasApiKey } from "../../services/api";

export function ScanForm({ onScanStarted, onStop, isScanning, stopPending }) {
  const start = useStartScan();
  const [url, setUrl] = useState("");
  const [advanced, setAdvanced] = useState(false);
  const [showToken, setShowToken] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState("");
  const [options, setOptions] = useState({
    mode: "passive",
    captured_content: "",
    captured_headers: "",
    allowed_endpoints_str: "GET /",
    policy_expires_at: "",
    max_pages: 50,
    workers: 5,
    timeout: 15,
    verify_ssl: true,
    obey_robots: true,
    allow_private_targets: false,
    auth_token: "",
    headers_str: "",
    cookies_str: "",
    exclude_paths_str: "",
  });
  const update = (key, value) => {
    setOptions((prev) => ({ ...prev, [key]: value }));
    setAuthorized(false);
  };
  const valid = (() => {
    try {
      const u = new URL(url.trim());
      return (
        ["http:", "https:"].includes(u.protocol) &&
        !!u.hostname &&
        !u.username &&
        !u.password
      );
    } catch {
      return false;
    }
  })();
  const submit = (e) => {
    e.preventDefault();
    setError("");
    if (!valid || !authorized) return;
    if (!hasApiKey()) {
      setError(
        "Add your session API key in Connection settings before launching a scan.",
      );
      return;
    }
    start.mutate(
      { target_url: url.trim(), ...options, authorization_confirmed: authorized },
      {
        onSuccess: onScanStarted,
        onError: (e) => setError(getFriendlyApiError(e)),
      },
    );
  };
  const disabled = isScanning || start.isPending;
  return (
    <form onSubmit={submit} className="scan-form">
      {isScanning && (
        <div className="notice">
          <span className="status-dot pulse" />
          <span>
            The selected assessment is still running. Stop it or wait for
            completion before configuring another.
          </span>
        </div>
      )}
      <fieldset disabled={disabled}>
        <div className="form-section-label">
          <span>01</span> TARGET & SCOPE
        </div>
        <label className="field-label" htmlFor="target-url">
          Target URL
        </label>
        <div className={`target-input ${url && !valid ? "invalid" : ""}`}>
          <Globe2 size={20} />
          <input
            id="target-url"
            type="url"
            required
            autoComplete="url"
            placeholder="https://your-application.com"
            value={url}
            onChange={(e) => { setUrl(e.target.value); setAuthorized(false); }}
          />
          <span>HTTP / HTTPS</span>
        </div>
        <p className={`field-help ${url && !valid ? "error-text" : ""}`}>
          {url && !valid
            ? "Enter a full HTTP or HTTPS URL without embedded credentials."
            : options.mode === "passive" ? "Captured pages must stay within this target's origin. No target requests are made." : "Discovery stays within this target's origin and the exact endpoint grants."}
        </p>
        <div className="form-section-label">
          <span>02</span> SCAN PARAMETERS
        </div>
        <fieldset className="policy-controls">
          <legend>Execution policy</legend>
          {[
            ["passive", "Passive — captured traffic only (default)"],
            ["safe-active", "Safe-active — approved GET / HEAD endpoints"],
            ["custom-active", "Custom-active — approved endpoint / method pairs"],
          ].map(([mode, label]) => (
            <label className="field-label" key={mode}>
              <input type="radio" name="scan-mode" value={mode} checked={options.mode === mode}
                onChange={() => update("mode", mode)} /> {label}
            </label>
          ))}
          {options.mode === "passive" ? <>
            <p className="field-help">No crawling, form submissions, XSS, SQLi or sensitive-file probes. Analyze HTML captured within the selected target origin. Missing response headers are skipped.</p>
            <label className="field-label" htmlFor="captured-content">Captured HTML</label>
            <textarea id="captured-content" required rows={5} value={options.captured_content}
              onChange={(e) => update("captured_content", e.target.value)} placeholder="Paste an existing HTML response" />
            <label className="field-label" htmlFor="captured-headers">Captured response headers (optional JSON object)</label>
            <textarea id="captured-headers" rows={2} value={options.captured_headers}
              onChange={(e) => update("captured_headers", e.target.value)} placeholder={'{"Content-Type":"text/html"}'} />
          </> : <>
            <p className="field-help">Selected mode: {options.mode}. Requests may change application state, including GET. The server records this authorization before scanning and checks it on every request.</p>
            <p className="field-help">Scope: {valid ? new URL(url.trim()).origin : "Enter a target origin"}. Only exact paths and methods below are allowed. Include GET for the target and GET /robots.txt if crawl directives are needed.</p>
            <label className="field-label" htmlFor="allowed-endpoints">Allowed endpoints and methods (one per line)</label>
            <textarea id="allowed-endpoints" required rows={4} value={options.allowed_endpoints_str}
              onChange={(e) => update("allowed_endpoints_str", e.target.value)} placeholder={"GET /\nGET /search\nPOST /search"} />
            <label className="field-label" htmlFor="policy-expiry">Authorization expires (local time, at most 7 days)</label>
            <input id="policy-expiry" type="datetime-local" required value={options.policy_expires_at}
              onChange={(e) => update("policy_expires_at", e.target.value)} />
            <p className="field-help">Logout, checkout, purchase, payments, deletion, recovery, password, account, user, settings, email and transfer workflows are blocked. Add further excluded path prefixes in Advanced configuration.</p>
            <p className="field-help">Additional excluded prefixes: {options.exclude_paths_str || "None added"}.</p>
          </>}
        </fieldset>
        <div className="numeric-fields">
          {[
            ["max_pages", "Page limit", 1, 500, "pages"],
            ["workers", "Concurrent workers", 1, 20, "workers"],
            ["timeout", "Request timeout", 1, 60, "seconds"],
          ].map(([key, label, min, max, unit]) => (
            <label key={key}>
              <span className="field-label">{label}</span>
              <div className="number-field">
                <input
                  type="number"
                  required
                  min={min}
                  max={max}
                  step={1}
                  value={options[key]}
                  onChange={(e) =>
                    update(
                      key,
                      e.target.value === "" ? "" : Number(e.target.value),
                    )
                  }
                />
                <span>{unit}</span>
              </div>
              <small>
                {min}–{max} {unit}
              </small>
            </label>
          ))}
        </div>
        <div className="scan-toggles">
          {[
            [
              "verify_ssl",
              "Verify TLS certificates",
              "Validate the target's certificate chain.",
            ],
            [
              "obey_robots",
              "Respect robots.txt",
              "Honor the target's crawl directives.",
            ],
          ].map(([key, label, help]) => (
            <label className="toggle-card" key={key}>
              <div>
                <strong>{label}</strong>
                <span>{help}</span>
              </div>
              <input
                type="checkbox"
                checked={options[key]}
                onChange={(e) => update(key, e.target.checked)}
              />
              <span className="toggle-track" />
            </label>
          ))}
        </div>
        <button
          type="button"
          className={`advanced-toggle ${advanced ? "open" : ""}`}
          aria-expanded={advanced}
          aria-controls="advanced-config"
          onClick={() => setAdvanced(!advanced)}
        >
          <Settings2 size={16} />
          <span>
            Advanced configuration
            <small>
              Authentication, headers, exclusions & internal targets
            </small>
          </span>
          <ChevronDown size={17} />
        </button>
        {advanced && (
          <div id="advanced-config" className="advanced-config">
            <label className="toggle-card internal-toggle">
              <div>
                <strong>Allow private/internal target</strong>
                <span>
                  Enable for authorized RFC1918 systems. Loopback, link-local,
                  and metadata addresses remain blocked.
                </span>
              </div>
              <input
                type="checkbox"
                checked={options.allow_private_targets}
                onChange={(e) =>
                  update("allow_private_targets", e.target.checked)
                }
              />
              <span className="toggle-track" />
            </label>
            <label className="field-label" htmlFor="auth-token">
              Target bearer token
            </label>
            <div className="key-input">
              <LockKeyhole size={16} />
              <input
                id="auth-token"
                type={showToken ? "text" : "password"}
                autoComplete="off"
                value={options.auth_token}
                onChange={(e) => update("auth_token", e.target.value)}
                placeholder="Optional target authentication token"
              />
              <button
                type="button"
                aria-label={
                  showToken ? "Hide target token" : "Show target token"
                }
                onClick={() => setShowToken(!showToken)}
              >
                {showToken ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
            <div className="advanced-textareas">
              {[
                [
                  "headers_str",
                  "Custom headers",
                  "X-Header: value\nX-Other-Header: value",
                ],
                ["cookies_str", "Cookies", "session=value; preference=value"],
                [
                  "exclude_paths_str",
                  "Excluded paths",
                  "/logout\n/admin\n/destructive-actions",
                ],
              ].map(([key, label, placeholder]) => (
                <label key={key}>
                  <span className="field-label">{label}</span>
                  <textarea
                    rows={key === "exclude_paths_str" ? 3 : 2}
                    value={options[key]}
                    onChange={(e) => update(key, e.target.value)}
                    placeholder={placeholder}
                  />
                </label>
              ))}
            </div>
          </div>
        )}
        <label className="authorization">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            required
          />
          <ShieldCheck size={19} />
          <span>
            <strong>{options.mode === "passive" ? "I am authorized to analyze this captured traffic." : `I explicitly authorize this ${options.mode} scope, methods and expiry.`}</strong>
            <small>
              I own this system or have explicit permission, and have chosen
              appropriate scan limits.
            </small>
          </span>
        </label>
      </fieldset>
      {error && (
        <div className="form-error" role="alert">
          {error}
        </div>
      )}
      <div className="scan-submit">
        <span>
          <ShieldCheck size={14} /> Selected policy: {options.mode}
        </span>
        {isScanning ? (
          <button
            className="button danger-button"
            type="button"
            disabled={stopPending}
            onClick={onStop}
          >
            <Square size={15} />
            {stopPending ? "Stopping…" : "Stop current scan"}
          </button>
        ) : (
          <button
            type="submit"
            className="button primary"
            disabled={!valid || !authorized || start.isPending}
          >
            {start.isPending ? "Initializing…" : "Launch assessment"}
            <ArrowRight size={16} />
          </button>
        )}
      </div>
    </form>
  );
}
