// ── Entity extractor used by the overlap nudge in ContextEnricher ─────────
//
// Scans the first N rows of a tool result for IP / User / Domain / Hostname
// values. Used only to feed the `/graph/overlap` request — the resulting
// list is the set of entities we ask the backend whether it knows about.
//
// Trade-offs:
//   - Regex-based, not parser-based. False positives (e.g. version strings
//     that look like IPs) are acceptable because the backend will simply
//     report them as missing.
//   - Hostname detection is gated on the column name (Computer / Hostname /
//     DeviceName) so generic FQDNs in arbitrary text don't get misclassified.
//   - Hard cap of 500 entities (mirrors the backend's OVERLAP_MAX_ENTITIES).
//   - First-N rows cap (default 100) keeps p99 bounded on huge KQL results.

const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const FQDN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b/gi;
const HOST_FIELD_NAMES = new Set(["Computer", "Hostname", "DeviceName"]);

export type EntityKind = "IP" | "User" | "Domain" | "Hostname";

export interface ExtractedEntity {
  type: EntityKind;
  value: string;
}

export interface ExtractOpts {
  /** Cap on rows scanned (default 100). */
  maxRows?: number;
  /** Cap on returned entities (default 500). */
  maxEntities?: number;
}

export function extractEntities(
  rows: Array<Record<string, unknown>>,
  opts: ExtractOpts = {},
): ExtractedEntity[] {
  const maxRows = opts.maxRows ?? 100;
  const maxEntities = opts.maxEntities ?? 500;
  const out = new Map<string, ExtractedEntity>();

  for (const row of rows.slice(0, maxRows)) {
    if (!row || typeof row !== "object") continue;
    for (const [field, raw] of Object.entries(row)) {
      if (raw == null) continue;
      const s = String(raw);

      // Emails first so @-containing tokens are classified as User
      // before the generic FQDN matcher sees them.
      for (const m of s.matchAll(EMAIL_RE)) {
        push(out, "User", m[0], maxEntities);
        if (out.size >= maxEntities) return [...out.values()];
      }

      for (const m of s.matchAll(IP_RE)) {
        push(out, "IP", m[0], maxEntities);
        if (out.size >= maxEntities) return [...out.values()];
      }

      const isHostField = HOST_FIELD_NAMES.has(field);
      const seenInThisField = new Set<string>();
      for (const m of s.matchAll(FQDN_RE)) {
        if (m[0].includes("@")) continue; // already classified as User
        if (seenInThisField.has(m[0])) continue;
        seenInThisField.add(m[0]);
        push(out, isHostField ? "Hostname" : "Domain", m[0], maxEntities);
        if (out.size >= maxEntities) return [...out.values()];
      }
    }
  }
  return [...out.values()];
}

function push(
  out: Map<string, ExtractedEntity>,
  type: EntityKind,
  value: string,
  max: number,
): void {
  const key = `${type}:${value}`;
  if (out.has(key) || out.size >= max) return;
  out.set(key, { type, value });
}
