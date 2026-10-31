import { useState } from "react";
import {
  ArrowDownToLine,
  ArrowRight,
  Fingerprint,
  Search,
  SlidersHorizontal,
  X,
} from "lucide-react";
import { FindingsTable } from "./FindingsTable";
import { Select } from "../../components/Select";
import { SEVERITIES, severityCounts } from "../../app/utils";

export function FindingsDashboard({
  findings = [],
  loading,
  error,
  search,
  setSearch,
  severity,
  setSeverity,
  compact = false,
  onViewAll,
  onExport,
}) {
  const [sort, setSort] = useState("severity");
  const [type, setType] = useState("all");
  const [page, setPage] = useState(1);
  const counts = severityCounts(findings);
  const needle = search.trim().toLowerCase();
  const rank = Object.fromEntries(SEVERITIES.map((s, i) => [s.name, i]));
  const types = [...new Set(findings.map((f) => f.vuln_type))];
  const activeType = type === "all" || types.includes(type) ? type : "all";
  const filtered = findings
    .filter(
      (f) =>
        (severity === "all" || f.severity_level === severity) &&
        (activeType === "all" || f.vuln_type === activeType) &&
        (!needle ||
          [
            f.url,
            f.vuln_type,
            f.description,
            f.evidence,
            f.remediation,
            f.confidence,
          ].some((v) =>
            String(v || "")
              .toLowerCase()
              .includes(needle),
          )),
    )
    .sort((a, b) =>
      sort === "score"
        ? b.severity_score - a.severity_score
        : sort === "recent"
          ? (b.timestamp || 0) - (a.timestamp || 0)
          : sort === "url"
            ? a.url.localeCompare(b.url)
            : (rank[a.severity_level] ?? 5) - (rank[b.severity_level] ?? 5),
    );
  const perPage = 10;
  const pages = Math.max(1, Math.ceil(filtered.length / perPage));
  const currentPage = Math.min(page, pages);
  const shown = compact
    ? filtered.slice(0, 4)
    : filtered.slice((currentPage - 1) * perPage, currentPage * perPage);
  const clear = () => {
    setSeverity("all");
    setSearch("");
    setType("all");
    setPage(1);
  };
  return (
    <section className="findings-section">
      <div className="section-header">
        <div>
          <span className="eyebrow">INVESTIGATE & REMEDIATE</span>
          <h2>
            {compact ? "Priority findings" : "Findings explorer"}
            <span className="count-pill">{findings.length}</span>
          </h2>
        </div>
        <div className="inline-actions">
          {compact ? (
            <button className="text-button" onClick={onViewAll}>
              View all findings <ArrowRight size={15} />
            </button>
          ) : (
            <>
              <button
                className="button secondary small"
                disabled={!findings.length}
                onClick={() => onExport("json")}
              >
                <ArrowDownToLine size={14} /> JSON
              </button>
              <button
                className="button secondary small"
                disabled={!findings.length}
                onClick={() => onExport("csv")}
              >
                <ArrowDownToLine size={14} /> CSV
              </button>
            </>
          )}
        </div>
      </div>
      <div className="panel findings-panel">
        {!compact && (
          <>
            <div
              className="filter-tabs"
              aria-label="Filter findings by severity"
            >
              {[
                { name: "all", label: "All findings", count: findings.length },
                ...SEVERITIES.map((s) => ({
                  name: s.name,
                  label: s.name,
                  count: counts[s.name],
                })),
              ].map((s) => (
                <button
                  key={s.name}
                  className={severity === s.name ? "selected" : ""}
                  onClick={() => {
                    setSeverity(s.name);
                    setPage(1);
                  }}
                  aria-pressed={severity === s.name}
                >
                  {s.name !== "all" && (
                    <i className={`severity-dot ${s.name.toLowerCase()}`} />
                  )}{" "}
                  {s.label}
                  <span>{s.count}</span>
                </button>
              ))}
            </div>
            <div className="findings-toolbar">
              <label className="table-search">
                <Search size={16} />
                <input
                  aria-label="Search finding details"
                  value={search}
                  placeholder="Search findings, URLs, evidence…"
                  onChange={(e) => {
                    setSearch(e.target.value);
                    setPage(1);
                  }}
                />
              </label>
              <div className="table-controls">
                <SlidersHorizontal size={15} />
                <Select
                  label="Filter by detection module"
                  value={activeType}
                  onChange={(value) => {
                    setType(value);
                    setPage(1);
                  }}
                  options={[
                    { value: "all", label: "All modules" },
                    ...types.map((type) => ({ value: type, label: type })),
                  ]}
                />
                <Select
                  label="Sort findings"
                  value={sort}
                  onChange={setSort}
                  options={[
                    { value: "severity", label: "Severity first" },
                    { value: "score", label: "Highest score" },
                    { value: "recent", label: "Most recent" },
                    { value: "url", label: "Endpoint A–Z" },
                  ]}
                />
              </div>
            </div>
          </>
        )}
        {error && (
          <div className="table-error" role="alert">
            Could not refresh findings: {error}
          </div>
        )}
        {loading && !findings.length ? (
          <div className="empty-state">
            <div className="empty-symbol scanning">
              <Fingerprint size={28} />
            </div>
            <h3>Gathering intelligence</h3>
            <p>Findings appear as the engine reports them.</p>
          </div>
        ) : !shown.length ? (
          <div className="empty-state">
            <div className="empty-symbol">
              <Fingerprint size={28} />
            </div>
            <h3>
              {findings.length
                ? "No matching signals"
                : "No findings to review yet"}
            </h3>
            <p>
              {findings.length
                ? "Adjust the filters or search across another field."
                : "Run or select an assessment to inspect severity, evidence, and remediation."}
            </p>
            {(severity !== "all" || search || type !== "all") && (
              <button className="button secondary small" onClick={clear}>
                <X size={13} /> Clear filters
              </button>
            )}
          </div>
        ) : (
          <FindingsTable
            key={`${severity}-${type}-${search}-${currentPage}`}
            findings={shown}
          />
        )}
        <div className="table-footer">
          <span>
            <span className="status-dot" />
            {compact
              ? `${shown.length} priority findings`
              : `${filtered.length} of ${findings.length} findings`}{" "}
            <span className="footer-separator">/</span>{" "}
            {new Set(filtered.map((f) => f.url)).size} affected URLs
          </span>
          {compact ? (
            <span>
              Click a finding to inspect evidence <ArrowUpRightIcon />
            </span>
          ) : (
            <div className="pagination">
              <button
                disabled={currentPage === 1}
                onClick={() => setPage(currentPage - 1)}
                aria-label="Previous findings page"
              >
                ←
              </button>
              <span>
                {currentPage} / {pages}
              </span>
              <button
                disabled={currentPage === pages}
                onClick={() => setPage(currentPage + 1)}
                aria-label="Next findings page"
              >
                →
              </button>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
function ArrowUpRightIcon() {
  return <ArrowRight size={12} style={{ transform: "rotate(-45deg)" }} />;
}
