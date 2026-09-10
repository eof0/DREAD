import { useEffect, useMemo, useState } from "react";
import { getJSON } from "./api";
import type { HistoryRun, JobSummary, NormalizedFinding, SuiteReport } from "./types";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export function useReports(reloadKey: number) {
  const [report, setReport] = useState<SuiteReport | null>(null);
  const [runs, setRuns] = useState<HistoryRun[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const list = await getJSON<HistoryRun[]>("/api/runs");
        setRuns(list);
        if (list.length) setReport(await getJSON<SuiteReport>("/api/runs/latest"));
        else setReport(null);
      } catch (reason) {
        setError(String(reason instanceof Error ? reason.message : reason));
      }
    })();
  }, [reloadKey]);

  const select = async (id: string) => setReport(await getJSON<SuiteReport>(`/api/runs/${id}`));
  return { report, runs, error, select };
}

function RiskRail({ report }: { report: SuiteReport }) {
  const stats = report.statistics || {};
  const score = stats.risk?.normalized_score ?? 0;
  const level = stats.risk?.level || "unrated";
  const total = report.rollups?.total_findings ?? stats.total_findings ?? report.findings?.length ?? 0;
  return (
    <section className="risk-rail" aria-label="Risk summary">
      <div className="risk-score">
        <span className="eyebrow">Exposure index</span>
        <strong>{Math.round(score)}</strong>
        <span className={`risk-level level-${level.toLowerCase()}`}>{level}</span>
      </div>
      <div className="rail-stat">
        <span>Grouped findings</span>
        <strong>{total}</strong>
      </div>
      <div className="rail-stat">
        <span>Endpoints in scope</span>
        <strong>{report.findings?.reduce((sum, finding) => sum + (finding.endpoint_count || 1), 0) || 0}</strong>
      </div>
      <p className="rail-note">Counts represent distinct issues, not every page where they appeared.</p>
    </section>
  );
}

function SeveritySummary({ report }: { report: SuiteReport }) {
  const values = report.rollups?.findings_by_severity || {};
  const total = SEVERITIES.reduce((sum, severity) => sum + (values[severity] || 0), 0) || 1;
  return (
    <section className="severity-section">
      <div className="section-heading">
        <span className="eyebrow">Signal / severity</span>
        <h2>Where the exposure concentrates</h2>
      </div>
      <div className="severity-bars">
        {SEVERITIES.map((severity) => {
          const count = values[severity] || 0;
          return (
            <div className={`severity-row severity-${severity}`} key={severity}>
              <span>{severity}</span>
              <div className="severity-track"><i style={{ width: `${(count / total) * 100}%` }} /></div>
              <strong>{count}</strong>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function FindingItem({ finding }: { finding: NormalizedFinding }) {
  const [open, setOpen] = useState(false);
  const severity = (finding.severity || "info").toLowerCase();
  const endpoints = finding.affected_endpoints || (finding.url ? [finding.url] : []);
  return (
    <article className={`finding-item finding-${severity}`}>
      <button className="finding-toggle" onClick={() => setOpen(!open)} aria-expanded={open}>
        <span className="severity-mark" aria-hidden="true" />
        <span className="finding-copy">
          <span className="finding-meta">{severity} / {finding.plugin_name || "scanner"}</span>
          <strong>{finding.title || "Untitled finding"}</strong>
          <span>{finding.description || "No description provided."}</span>
        </span>
        <span className="endpoint-count">{finding.endpoint_count || endpoints.length || 1}<small> endpoints</small></span>
        <span className="chevron" aria-hidden="true">{open ? "−" : "+"}</span>
      </button>
      {open && (
        <div className="finding-detail">
          <div>
            <span className="eyebrow">Remediation</span>
            <p>{finding.remediation || "Review and remediate the affected behavior."}</p>
          </div>
          <div>
            <span className="eyebrow">Affected endpoints</span>
            <ul>{endpoints.map((endpoint) => <li key={endpoint}><code>{endpoint}</code></li>)}</ul>
          </div>
        </div>
      )}
    </article>
  );
}

function FindingsRegister({ findings }: { findings: NormalizedFinding[] }) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const filtered = useMemo(() => findings.filter((finding) => {
    const text = `${finding.title || ""} ${finding.description || ""} ${finding.plugin_name || ""} ${(finding.affected_endpoints || []).join(" ")}`.toLowerCase();
    return (!query || text.includes(query.toLowerCase())) && (severity === "all" || finding.severity?.toLowerCase() === severity);
  }), [findings, query, severity]);

  return (
    <section className="register">
      <div className="register-header">
        <div className="section-heading"><span className="eyebrow">Findings / grouped</span><h2>Exposure register</h2></div>
        <span className="result-count">{filtered.length} of {findings.length}</span>
      </div>
      <div className="filters">
        <input aria-label="Search findings" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search findings or endpoints" />
        <select aria-label="Filter by severity" value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="all">All severities</option>
          {SEVERITIES.map((item) => <option key={item} value={item}>{item}</option>)}
        </select>
      </div>
      <div className="finding-list">
        {filtered.length ? filtered.map((finding, index) => <FindingItem key={finding.id || `${finding.title}-${index}`} finding={finding} />) : <p className="empty-state">No findings match this filter.</p>}
      </div>
    </section>
  );
}

function RunPicker({ runs, activeId, onPick }: { runs: HistoryRun[]; activeId?: string; onPick: (id: string) => void }) {
  if (runs.length < 2) return null;
  return (
    <div className="run-picker">
      <span className="eyebrow">Past runs</span>
      <div className="run-chips">
        {runs.slice(0, 8).map((run) => (
          <button key={run.id} className={run.run_id === activeId ? "chip active" : "chip"} onClick={() => onPick(run.id)}>
            {run.generated_at?.slice(0, 10) || run.id?.slice(0, 8)}
          </button>
        ))}
      </div>
    </div>
  );
}

export function ReportView({ reloadKey }: { reloadKey: number }) {
  const { report, runs, error, select } = useReports(reloadKey);
  if (error) return <p className="empty-state">{error}</p>;
  if (!report) {
    return (
      <div className="placeholder">
        <span className="eyebrow">No completed runs</span>
        <h2>Run a scan to populate the register.</h2>
        <p>Reports from Probe and Scope land here once an assessment finishes.</p>
      </div>
    );
  }
  return (
    <div className="report-view">
      <RunPicker runs={runs} activeId={report.run_id} onPick={select} />
      <RiskRail report={report} />
      <SeveritySummary report={report} />
      <FindingsRegister findings={report.findings || []} />
    </div>
  );
}

export function reportJobDone(job: JobSummary): boolean {
  return job.status === "completed" && !!job.has_report;
}
