export const standalone = document.querySelector('meta[name="dread-mode"]')?.getAttribute("content") === "standalone";

export class HttpError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

export async function getJSON<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { detail?: string };
    throw new HttpError(res.status, body.detail || res.statusText);
  }
  return res.json() as Promise<T>;
}

export async function postJSON<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = (await res.json().catch(() => ({}))) as { detail?: string };
  if (!res.ok) throw new HttpError(res.status, data.detail || res.statusText);
  return data as T;
}
