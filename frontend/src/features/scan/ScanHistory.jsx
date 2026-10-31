import { useState } from "react";
import { ArrowUpRight, Globe2, Plus, Radar } from "lucide-react";
import { formatDate, hostname } from "../../app/utils";
import { Select } from "../../components/Select";

export function ScanHistory({
  scans = [],
  loading,
  error,
  activeScanId,
  onSelectScan,
  search = "",
  onNewScan,
}) {
  const [filter, setFilter] = useState("all");
  const [sort, setSort] = useState("recent");
  const filtered = scans
    .filter(
      (s) =>
        (filter === "all" || s.status === filter) &&
        `${s.target_url} ${s.scan_id} ${s.status}`
          .toLowerCase()
          .includes(search.toLowerCase()),
    )
    .sort((a, b) =>
      sort === "findings"
        ? b.vulnerabilities_count - a.vulnerabilities_count
        : new Date(b.start_time) - new Date(a.start_time),
    );
  return (
    <section className="panel history-panel">
      <div className="panel-heading">
        <div>
          <h3>
            Assessment archive{" "}
            <span className="count-pill">{scans.length}</span>
          </h3>
          <p>Select a session to open its full assessment.</p>
        </div>
        <div className="table-controls">
          <Select
            label="Filter scan status"
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: "All statuses" },
              ...["completed", "running", "pending", "failed", "stopped"].map(
                (status) => ({
                  value: status,
                  label: status[0].toUpperCase() + status.slice(1),
                }),
              ),
            ]}
          />
          <Select
            label="Sort scan history"
            value={sort}
            onChange={setSort}
            options={[
              { value: "recent", label: "Most recent" },
              { value: "findings", label: "Most findings" },
            ]}
          />
        </div>
      </div>
      {error && (
        <div className="table-error" role="alert">
          Could not load assessment history: {error}
        </div>
      )}
      {loading ? (
        <div className="empty-state">
          <Radar className="scanning" size={30} />
          <h3>Loading assessments…</h3>
        </div>
      ) : !filtered.length ? (
        <div className="empty-state">
          <div className="empty-symbol">
            <Radar size={28} />
          </div>
          <h3>
            {scans.length
              ? "No matching assessments"
              : "Your first assessment starts here"}
          </h3>
          <p>
            {scans.length
              ? "Try another search or status filter."
              : "Configure a target to build a detailed history of your security assessments."}
          </p>
          <button className="button primary" onClick={onNewScan}>
            <Plus size={15} /> New scan
          </button>
        </div>
      ) : (
        <div className="history-table">
          <div className="history-row table-heading">
            <span>TARGET / SESSION</span>
            <span>STATUS</span>
            <span>PAGES</span>
            <span>FINDINGS</span>
            <span>STARTED</span>
            <span />
          </div>
          {filtered.map((s) => (
            <button
              key={s.scan_id}
              onClick={() => onSelectScan(s.scan_id)}
              className={`history-row ${activeScanId === s.scan_id ? "selected-scan" : ""}`}
            >
              <span className="history-target">
                <span className="history-target-icon">
                  <Globe2 size={18} />
                </span>
                <span>
                  <strong>{hostname(s.target_url)}</strong>
                  <small>{s.scan_id}</small>
                </span>
              </span>
              <span className={`status-badge ${s.status}`}>
                <span />
                {s.status}
              </span>
              <span className="mono history-pages">{s.pages_scanned}</span>
              <span
                className={`mono ${s.vulnerabilities_count ? "warning-text" : ""}`}
              >
                {s.vulnerabilities_count}
              </span>
              <span className="history-date">{formatDate(s.start_time)}</span>
              <ArrowUpRight size={16} />
            </button>
          ))}
        </div>
      )}
      <div className="table-footer">
        <span>{filtered.length} assessments shown</span>
        <span>
          <Radar size={12} /> History reflects the current engine session
        </span>
      </div>
    </section>
  );
}
