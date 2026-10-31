import { useState } from "react";
import {
  ArrowUpRight,
  Check,
  ChevronDown,
  ChevronRight,
  Clock3,
  Copy,
  FileCode2,
  ShieldCheck,
} from "lucide-react";
import { safeHttpUrl } from "../../app/utils";

export function FindingsTable({ findings }) {
  const [expanded, setExpanded] = useState(new Set());
  const [copyStatus, setCopyStatus] = useState("");
  const toggle = (index) =>
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  const copy = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopyStatus("Remediation copied");
    } catch {
      setCopyStatus("Clipboard unavailable. Select and copy the text below.");
    }
  };
  return (
    <div className="findings-table">
      <div className="finding-grid table-heading">
        <span>SEVERITY / SCORE</span>
        <span>FINDING</span>
        <span>AFFECTED ENDPOINT</span>
        <span>CONFIDENCE</span>
        <span />
      </div>
      {findings.map((f, i) => {
        const open = expanded.has(i);
        const id = `finding-details-${i}`;
        const score = Number(f.severity_score);
        let endpoint = f.url;
        try {
          const url = new URL(f.url);
          endpoint = url.pathname + url.search;
        } catch {
          /* Show the supplied endpoint as text. */
        }
        return (
          <article
            key={`${f.url}-${f.vuln_type}-${f.description}-${i}`}
            className={`finding-item ${open ? "expanded" : ""}`}
          >
            <button
              className="finding-grid finding-row"
              aria-expanded={open}
              aria-controls={id}
              onClick={() => toggle(i)}
            >
              <span className="finding-severity">
                <span
                  className={`severity-badge ${f.severity_level?.toLowerCase()}`}
                >
                  <i />
                  {f.severity_level || "Unknown"}
                </span>
                <b>{Number.isFinite(score) ? score.toFixed(1) : "—"}</b>
              </span>
              <span className="finding-title">
                <strong>{f.vuln_type}</strong>
                <small>{f.description}</small>
              </span>
              <span className="finding-endpoint" title={f.url}>
                <FileCode2 size={13} />
                <span>{endpoint}</span>
              </span>
              <span className="confidence">
                <i
                  className={f.confidence === "High" ? "high-confidence" : ""}
                />
                {f.confidence || "Unknown"}
              </span>
              {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
            </button>
            {open && (
              <div id={id} className="finding-details">
                <div className="finding-detail-header">
                  <span className="eyebrow">FINDING DETAILS</span>
                  <span>
                    {f.timestamp
                      ? new Date(f.timestamp * 1000).toLocaleString()
                      : "Detection timestamp unavailable"}
                    <Clock3 size={12} />
                  </span>
                </div>
                <div className="finding-detail-grid">
                  <section>
                    <h4>Description</h4>
                    <p>{f.description || "No description provided."}</p>
                    <h4 className="detail-subheading">Affected URL</h4>
                    {safeHttpUrl(f.url) ? (
                      <a
                        href={safeHttpUrl(f.url)}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        {f.url}
                        <ArrowUpRight size={13} />
                      </a>
                    ) : (
                      <p className="mono">{f.url}</p>
                    )}
                  </section>
                  <section>
                    <h4>
                      <ShieldCheck size={13} /> Recommended remediation
                    </h4>
                    <p>
                      {f.remediation ||
                        "No specific remediation was provided. Review the evidence and verify the finding."}
                    </p>
                    {f.remediation && (
                      <button
                        className="text-button"
                        onClick={() => copy(f.remediation)}
                      >
                        <Copy size={12} /> Copy remediation
                      </button>
                    )}
                    <span className="copy-status" role="status">
                      {copyStatus && (
                        <>
                          <Check size={12} />
                          {copyStatus}
                        </>
                      )}
                    </span>
                  </section>
                  <section className="evidence-section">
                    <h4>
                      <FileCode2 size={13} /> Evidence / payload{" "}
                      <span>EVIDENCE SNAPSHOT</span>
                    </h4>
                    <pre>
                      {f.evidence ||
                        "No evidence was provided for this finding."}
                    </pre>
                  </section>
                </div>
              </div>
            )}
          </article>
        );
      })}
    </div>
  );
}
