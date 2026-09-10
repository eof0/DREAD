import { useEffect, useRef, useState } from "react";
import { getJSON, postJSON } from "./api";
import type { JobEvent, JobSummary } from "./types";

const DONE = ["completed", "failed"];

export function useJob(onDone?: (job: JobSummary) => void) {
  const [job, setJob] = useState<JobSummary | null>(null);
  const [events, setEvents] = useState<JobEvent[]>([]);
  const [error, setError] = useState("");
  const timer = useRef<number>();

  useEffect(() => {
    if (!job || DONE.includes(job.status)) return;
    timer.current = window.setInterval(async () => {
      try {
        const next = await getJSON<JobSummary>(`/api/jobs/${job.id}`);
        setEvents(await getJSON<JobEvent[]>(`/api/jobs/${job.id}/events`));
        setJob(next);
        if (DONE.includes(next.status)) onDone?.(next);
      } catch {
        // transient poll error, keep waiting
      }
    }, 1200);
    return () => window.clearInterval(timer.current);
  }, [job, onDone]);

  const start = async (url: string, body: unknown) => {
    setError("");
    setEvents([]);
    try {
      setJob(await postJSON<JobSummary>(url, body));
    } catch (reason) {
      setError(String(reason instanceof Error ? reason.message : reason));
    }
  };

  const running = !!job && !DONE.includes(job.status);
  return { job, events, error, running, start };
}

export function JobConsole({ job, events }: { job: JobSummary | null; events: JobEvent[] }) {
  const logs = events.filter((event) => event.type === "log");
  const ref = useRef<HTMLPreElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [events]);
  if (!job) return null;

  return (
    <div className="console" role="log" aria-live="polite">
      <div className="console-head">
        <span className="eyebrow">Live output</span>
        <span className={`status-pill status-${job.status}`}>{job.status}</span>
      </div>
      <pre ref={ref}>{logs.length ? logs.map((event) => event.message).join("\n") : "Waiting for output"}</pre>
    </div>
  );
}
