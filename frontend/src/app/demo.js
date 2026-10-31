// Opt-in illustrative samples. These never reach the scan API.
const samples = [
  [
    "SQL Injection",
    "Critical",
    9.1,
    "/catalog?category=books",
    "Database error returned for a quote-delimited category parameter.",
    "Response indicator: SQL syntax error near the supplied category value. This sample is illustrative.",
    "Use parameterized queries for all database access. Validate category identifiers against an allowlist.",
  ],
  [
    "Cross-Site Scripting (XSS)",
    "High",
    7.5,
    "/search?q=sample",
    "User-controlled search input was reflected in an HTML response without appropriate encoding.",
    "The test marker appeared unescaped in the search result markup.",
    "Apply context-aware output encoding and enforce a Content Security Policy.",
  ],
  [
    "Sensitive File Exposure",
    "High",
    7.5,
    "/.env",
    "A configuration file path returned content matching environment variable patterns.",
    "HTTP 200 · Content contains configuration-style key/value pairs. Values omitted in this sample.",
    "Block access to dotfiles and remove configuration files from the public web root. Rotate exposed credentials.",
  ],
  [
    "Cross-Site Request Forgery (CSRF)",
    "Medium",
    5.4,
    "/account/preferences",
    "A state-changing form was detected without an identifiable anti-CSRF token.",
    "POST form /account/preferences · no recognized hidden anti-forgery field.",
    "Add server-validated CSRF tokens to state-changing forms and configure SameSite cookies.",
  ],
  [
    "Missing Security Headers",
    "Medium",
    5.3,
    "/",
    "Content-Security-Policy response header is missing.",
    "Response headers did not include Content-Security-Policy.",
    "Deploy a restrictive Content Security Policy tailored to the application's resource requirements.",
  ],
  [
    "Missing Security Headers",
    "Low",
    3.1,
    "/login",
    "X-Content-Type-Options response header is missing.",
    "Response headers did not include X-Content-Type-Options.",
    "Set X-Content-Type-Options: nosniff on all responses.",
  ],
  [
    "Missing Security Headers",
    "Low",
    2.6,
    "/help",
    "Referrer-Policy response header is missing.",
    "Response headers did not include Referrer-Policy.",
    "Set Referrer-Policy: strict-origin-when-cross-origin or a stricter policy.",
  ],
  [
    "Missing Security Headers",
    "Info",
    0,
    "/status",
    "The response exposes a server software identifier.",
    "Server: example-server (illustrative sample)",
    "Review server version disclosures and remove unnecessary identifying headers.",
  ],
];
const baseTime = new Date("2026-10-31T09:32:00Z").getTime();
const findings = samples.map(
  (
    [
      vuln_type,
      severity_level,
      severity_score,
      path,
      description,
      evidence,
      remediation,
    ],
    i,
  ) => ({
    vuln_type,
    severity_level,
    severity_score,
    url: `https://demo.sentinalscan.example${path}`,
    description,
    evidence,
    remediation,
    confidence: i === 3 ? "Medium" : "High",
    timestamp: baseTime / 1000 + i * 7,
  }),
);
export const demoScans = [
  {
    scan_id: "demo-a7f3c9e1",
    target_url: "https://demo.sentinalscan.example",
    status: "completed",
    start_time: "2026-10-31T09:32:00Z",
    end_time: "2026-10-31T09:34:42Z",
    pages_scanned: 48,
    vulnerabilities_count: 8,
    results: findings,
  },
  ...[5, 7, 3, 6, 2, 4, 1].map((n, i) => ({
    scan_id: `demo-session-${i + 2}`,
    target_url: `https://${i % 2 ? "api" : "staging"}.sentinalscan.example`,
    status: i === 4 ? "stopped" : "completed",
    start_time: new Date(baseTime - (i + 1) * 86400000).toISOString(),
    end_time: new Date(baseTime - (i + 1) * 86400000 + 120000).toISOString(),
    pages_scanned: 24 + i * 3,
    vulnerabilities_count: n,
    results: findings.slice(0, n).map((finding) => ({
      ...finding,
      url: finding.url.replace(
        "demo.sentinalscan.example",
        `${i % 2 ? "api" : "staging"}.sentinalscan.example`,
      ),
      timestamp: finding.timestamp - (i + 1) * 86400,
    })),
  })),
];
const demoLogs = [
  { level: "INFO", message: "Assessment initialized · demo-a7f3c9e1" },
  {
    level: "INFO",
    message: "Scope locked to https://demo.sentinalscan.example",
  },
  {
    level: "INFO",
    message: "Crawler started · 5 workers · 50-page limit · robots respected",
  },
  {
    level: "INFO",
    message:
      "Security headers, XSS, SQLi, CSRF, and sensitive-file modules loaded",
  },
  {
    level: "INFO",
    message: "Discovered /catalog, /search, /account/preferences, /login",
  },
  {
    level: "WARNING",
    message:
      "SQL injection indicator found · /catalog?category=books · Critical",
  },
  {
    level: "WARNING",
    message: "Reflected XSS indicator found · /search?q=sample · High",
  },
  {
    level: "WARNING",
    message: "Potential configuration exposure · /.env · High",
  },
  {
    level: "INFO",
    message:
      "Assessment completed · 48 pages · 8 findings · review evidence before remediation",
  },
];
export function getDemoLogs(scan) {
  if (!scan) return [];
  return [
    ...demoLogs
      .slice(0, 4)
      .map((log) => ({
        ...log,
        message: log.message
          .replace("demo-a7f3c9e1", scan.scan_id)
          .replace("https://demo.sentinalscan.example", scan.target_url),
      })),
    ...scan.results.map((finding) => ({
      level: ["Critical", "High"].includes(finding.severity_level)
        ? "WARNING"
        : "INFO",
      message: `${finding.vuln_type} indicator · ${new URL(finding.url).pathname} · ${finding.severity_level}`,
    })),
    {
      level: "INFO",
      message: `Assessment ${scan.status} · ${scan.pages_scanned} pages · ${scan.vulnerabilities_count} findings · verify evidence before remediation`,
    },
  ];
}
