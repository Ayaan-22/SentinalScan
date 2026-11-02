export const SEVERITIES = [
  { name: "Critical", color: "#fa796f" },
  { name: "High", color: "#f4aa68" },
  { name: "Medium", color: "#e0c76e" },
  { name: "Low", color: "#bddb7b" },
  { name: "Info", color: "#8fa9bf" },
];
export function severityCounts(findings) {
  return findings.reduce(
    (counts, f) => {
      if (f.severity_level in counts) counts[f.severity_level]++;
      return counts;
    },
    Object.fromEntries(SEVERITIES.map((s) => [s.name, 0])),
  );
}
export function hostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url || "—";
  }
}
export function formatDate(date) {
  if (!date) return "—";
  const d = new Date(date);
  return Number.isNaN(d.getTime())
    ? "—"
    : d.toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
}
export function safeHttpUrl(value) {
  try {
    const u = new URL(value);
    return ["http:", "https:"].includes(u.protocol) ? u.href : undefined;
  } catch {
    return undefined;
  }
}
export function serializeReport(format, scan, findings, demo) {
  const columns = [
    "severity_level",
    "severity_score",
    "vuln_type",
    "url",
    "confidence",
    "description",
    "evidence",
    "remediation",
    "timestamp",
  ];
  const escape = (value) => {
    let text = String(value ?? "");
    if (/^[\s]*[=+@-]/.test(text)) text = `'${text}`;
    return `"${text.replaceAll('"', '""')}"`;
  };
  return format === "csv"
    ? [columns, ...findings.map((f) => columns.map((c) => f[c]))]
        .map((row) => row.map(escape).join(","))
        .join("\r\n")
    : JSON.stringify(
        {
          source: demo ? "illustrative-demo" : "scan-engine",
          exported_at: new Date().toISOString(),
          scan: scan
            ? {
                scan_id: scan.scan_id,
                target_url: scan.target_url,
                status: scan.status,
                start_time: scan.start_time,
                end_time: scan.end_time,
                pages_scanned: scan.pages_scanned,
                mode: scan.mode,
                policy: scan.policy,
                policy_description: scan.policy_description,
              }
            : null,
          findings,
        },
        null,
        2,
      );
}
export function exportReport(format, scan, findings, demo) {
  const content = serializeReport(format, scan, findings, demo);
  const url = URL.createObjectURL(
    new Blob([format === "csv" ? "\uFEFF" + content : content], {
      type: format === "csv" ? "text/csv;charset=utf-8" : "application/json",
    }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = `sentinalscan-${demo ? "demo-" : ""}${scan?.scan_id?.slice(0, 12) || "report"}.${format}`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
