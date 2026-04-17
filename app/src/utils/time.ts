/**
 * Centralized timestamp formatter.
 *
 * The backend wire format is epoch seconds (i64). This module is the single
 * place frontend code should go to convert those to something a human can
 * read. Each rendering context picks the mode that fits — full ISO for
 * logs, time-only for hunt pagination, dash-separated for node details.
 *
 * Treat `ts === 0` (and falsy) as "no timestamp" and return a dash so
 * tables don't render as "1970-01-01T00:00:00Z".
 */

export type TimeMode = "iso" | "iso_space" | "time" | "epoch" | "relative";

const FALLBACK = "—";

export function formatTimestamp(ts: number, mode: TimeMode = "iso"): string {
  if (!ts) return FALLBACK;
  const d = new Date(ts * 1000);
  if (Number.isNaN(d.getTime())) return FALLBACK;

  switch (mode) {
    case "iso":
      return d.toISOString();
    case "iso_space":
      // `YYYY-MM-DD HH:MM:SS` — readable in tight columns where the `T`
      // costs a character and nothing needs the strict ISO form.
      return d.toISOString().replace("T", " ").slice(0, 19);
    case "time":
      return d.toLocaleTimeString("en-US", { hour12: false });
    case "epoch":
      return String(ts);
    case "relative":
      return formatRelative(ts);
  }
}

function formatRelative(ts: number): string {
  const nowSec = Math.floor(Date.now() / 1000);
  const delta = nowSec - ts;
  const abs = Math.abs(delta);
  const suffix = delta >= 0 ? "ago" : "from now";
  if (abs < 60) return `${abs}s ${suffix}`;
  if (abs < 3600) return `${Math.floor(abs / 60)}m ${suffix}`;
  if (abs < 86_400) return `${Math.floor(abs / 3600)}h ${suffix}`;
  return `${Math.floor(abs / 86_400)}d ${suffix}`;
}
