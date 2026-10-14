import { useEffect, useRef, useState } from "react";
import { getJSON, HttpError, postJSON } from "./api";
import type { JobEvent, JobSummary } from "./types";

const DONE = ["completed", "partial", "failed", "cancelled", "timed_out", "interrupted"];
type EventPage = { events: JobEvent[]; cursor: number };

export function useJob(kind: string, onDone?: (job: JobSummary) => void) {
  const [job, setJob] = useState<JobSummary | null>(null);
  const [events, setEvents] = useState<JobEvent[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const doneCallback = useRef(onDone);
  doneCallback.current = onDone;

  useEffect(() => {
    let disposed = false;
    getJSON<JobSummary[]>("/api/jobs").then((jobs) => {
      if (disposed) return;
      const matching = jobs.filter((item) => item.kind?.startsWith(kind));
      setJob(matching.find((item) => !DONE.includes(item.status)) || matching[0] || null);
    }).catch((reason) => {
      if (!disposed) setError(reason.message);
    }).finally(() => {
      if (!disposed) setLoading(false);
    });
    return () => { disposed = true; };
  }, [kind]);

  const jobId = job?.id;
  useEffect(() => {
    if (!jobId) return;
    let disposed = false;
    let timer: number;
    let cursor = 0;
    setEvents([]);
    const poll = async () => {
      try {
        const next = await getJSON<JobSummary>(`/api/jobs/${jobId}`);
        let page: EventPage;
        do {
          page = await getJSON<EventPage>(`/api/jobs/${jobId}/events?cursor=${cursor}`);
          if (disposed) return;
          cursor = page.cursor;
          setEvents((previous) => [...previous, ...page.events].slice(-2000));
        } while (page.events.length === 200);
        if (disposed) return;
        setError("");
        setJob(next);
        if (DONE.includes(next.status)) {
          doneCallback.current?.(next);
          return;
        }
      } catch (reason) {
        if (disposed) return;
        setError(reason instanceof Error ? reason.message : String(reason));
        if (reason instanceof HttpError && reason.status === 404) {
          setJob((previous) => previous && { ...previous, status: "interrupted" });
          return;
        }
      }
      if (!disposed) timer = window.setTimeout(poll, 1200);
    };
    void poll();
    return () => { disposed = true; window.clearTimeout(timer); };
  }, [jobId]);

  const start = async (url: string, body: unknown) => {
    setLoading(true);
    setError("");
    try {
      setJob(await postJSON<JobSummary>(url, body));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setLoading(false);
    }
  };

  const cancel = async () => {
    if (!job) return;
    try {
      setJob(await postJSON<JobSummary>(`/api/jobs/${job.id}/cancel`, {}));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    }
  };

  const running = loading || (!!job && !DONE.includes(job.status));
  return { job, events, error, running, start, cancel };
}

export function JobConsole({ job, events, onCancel }: {
  job: JobSummary | null; events: JobEvent[]; onCancel: () => void;
}) {
  const logs = events.filter((event) => event.type === "log");
  const ref = useRef<HTMLPreElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [events]);
  if (!job) return null;

  return (
    <div className="console" role="log" aria-live="polite">
      <div className="console-head">
        <span className="eyebrow">{job.target || "Output"}</span>
        <span className={`status-pill status-${job.status}`}>{job.status}</span>
        {!DONE.includes(job.status) && <button className="link" onClick={onCancel} disabled={job.status === "cancelling"}>Cancel</button>}
      </div>
      {job.error && <p className="form-error">{job.error}</p>}
      <pre ref={ref}>{logs.length ? logs.map((event) => event.message).join("\n") : DONE.includes(job.status) ? "No output recorded" : "Waiting for output"}</pre>
    </div>
  );
}
