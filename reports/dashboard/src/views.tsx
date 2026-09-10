import { useEffect, useState } from "react";
import { getJSON, postJSON } from "./api";
import { JobConsole, useJob } from "./runner";
import type { CannonTool, JobSummary } from "./types";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
    </label>
  );
}

export function ScanView({ onReportsChanged }: { onReportsChanged: () => void }) {
  const [target, setTarget] = useState("");
  const [subs, setSubs] = useState(10);
  const { job, events, error, running, start } = useJob((done: JobSummary) => {
    if (done.status === "completed") onReportsChanged();
  });
  return (
    <div className="view">
      <div className="view-lede">
        <h2>Full assessment</h2>
        <p>Discovery through Scope, then Probe vulnerability scanning. Findings land in the register.</p>
      </div>
      <div className="control-row">
        <Field label="Target"><input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="example.com" disabled={running} /></Field>
        <Field label="Max subdomains"><input type="number" min={0} max={100} value={subs} onChange={(e) => setSubs(Number(e.target.value))} disabled={running} /></Field>
        <button className="run" disabled={!target.trim() || running} onClick={() => start("/api/scans", { target, max_subdomains: subs })}>Start scan</button>
      </div>
      {error && <p className="form-error">{error}</p>}
      <JobConsole job={job} events={events} />
    </div>
  );
}

export function DiscoverView() {
  const [target, setTarget] = useState("");
  const { job, events, error, running, start } = useJob();
  return (
    <div className="view">
      <div className="view-lede">
        <h2>Attack surface discovery</h2>
        <p>Scope maps DNS, certificate transparency, cloud hints, and IP intelligence for a target.</p>
      </div>
      <div className="control-row">
        <Field label="Target"><input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="example.com" disabled={running} /></Field>
        <button className="run" disabled={!target.trim() || running} onClick={() => start("/api/scope/discover", { target })}>Discover</button>
      </div>
      {error && <p className="form-error">{error}</p>}
      <JobConsole job={job} events={events} />
    </div>
  );
}

export function CannonView() {
  const [tools, setTools] = useState<CannonTool[]>([]);
  const [tool, setTool] = useState("");
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("all");
  const [authorized, setAuthorized] = useState(false);
  const { job, events, error, running, start } = useJob();

  const loadTools = () =>
    getJSON<CannonTool[]>("/api/cannon/tools").then((list) => {
      setTools(list);
      const first = list.find((item) => item.available);
      if (first) setTool(first.name);
    }).catch(() => setTools([]));

  useEffect(() => {
    loadTools();
  }, []);

  return (
    <div className="view">
      <div className="view-lede">
        <h2>Authorized stress testing</h2>
        <p>Cannon drives active tools installed on this system against a target. Only run it where you have permission.</p>
      </div>

      <div className="tools-head">
        <span className="eyebrow">Installed tooling</span>
        <button className="link" onClick={loadTools}>Re-check</button>
      </div>
      <div className="tool-grid">
        {tools.map((item) => (
          <div key={item.name} className={item.available ? "tool ok" : "tool off"}>
            <strong>{item.name}</strong>
            <span>{item.category}</span>
            <small>{item.available ? "installed" : "missing"}</small>
            {!item.available && item.install && (
              item.install.command
                ? <code className="install-cmd">{item.install.command}</code>
                : <em className="install-note">{item.install.manager ? `not in ${item.install.manager}, install manually` : "install manually"}</em>
            )}
          </div>
        ))}
      </div>

      <label className="authorize">
        <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
        I am authorized to test this target.
      </label>

      <div className="control-row">
        <Field label="Target"><input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="example.com" disabled={running} /></Field>
        <Field label="Tool">
          <select value={tool} onChange={(e) => setTool(e.target.value)} disabled={running}>
            {tools.filter((item) => item.available).map((item) => <option key={item.name} value={item.name}>{item.name}</option>)}
          </select>
        </Field>
        <button className="run" disabled={!authorized || !tool || !target.trim() || running} onClick={() => start("/api/cannon/run", { tool, target, authorized })}>Run tool</button>
      </div>

      <div className="control-row">
        <Field label="Kaboom mode">
          <select value={mode} onChange={(e) => setMode(e.target.value)} disabled={running}>
            <option value="all">all</option>
            <option value="load">load</option>
            <option value="staged">staged</option>
          </select>
        </Field>
        <button className="run danger" disabled={!authorized || !target.trim() || running} onClick={() => start("/api/cannon/kaboom", { target, mode, authorized })}>Fire kaboom</button>
      </div>

      {error && <p className="form-error">{error}</p>}
      <JobConsole job={job} events={events} />
    </div>
  );
}

export function DreadAIView() {
  const [prompt, setPrompt] = useState("");
  const [answer, setAnswer] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const ask = async () => {
    setBusy(true);
    setError("");
    setAnswer("");
    try {
      const data = await postJSON<{ result: string }>("/api/dreadai/chat", { prompt });
      setAnswer(data.result);
    } catch (reason) {
      setError(String(reason instanceof Error ? reason.message : reason));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="view">
      <div className="view-lede">
        <h2>DreadAI</h2>
        <p>Direct the agent to run a full assessment on an authorized target: vulnerability scanning and penetration testing, CVE intelligence correlation, finding verification, and reporting. It drives the suite tooling directly.</p>
      </div>
      <textarea className="prompt" value={prompt} onChange={(e) => setPrompt(e.target.value)} placeholder="Scan example.com and summarize the highest-severity findings." disabled={busy} />
      <div className="control-row">
        <button className="run" disabled={!prompt.trim() || busy} onClick={ask}>{busy ? "Thinking" : "Ask DreadAI"}</button>
      </div>
      {error && <p className="form-error">{error}</p>}
      {answer && <div className="answer">{answer}</div>}
    </div>
  );
}

export function DatabaseView() {
  const { job, events, error, running, start } = useJob();
  return (
    <div className="view">
      <div className="view-lede">
        <h2>Intelligence databases</h2>
        <p>Refresh the local ASN and CVE stores that Probe and CVE correlation read from.</p>
      </div>
      <div className="control-row">
        <button className="run" disabled={running} onClick={() => start("/api/db/update", {})}>Update ASN database</button>
        <button className="run" disabled={running} onClick={() => start("/api/db/update-cve", {})}>Update CVE database</button>
      </div>
      {error && <p className="form-error">{error}</p>}
      <JobConsole job={job} events={events} />
    </div>
  );
}
