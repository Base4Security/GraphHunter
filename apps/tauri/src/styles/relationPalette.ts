// Single source of truth for relation-type → display color.
//
// Grouped semantically so analysts can read incident topology at a
// glance instead of squinting at a uniform-grey edge soup:
//   Network  (cyan / sky)  — Connect, DNS
//   Identity (amber)       — Auth (Kerberos, NTLM, LDAP)
//   Process  (green)       — Execute, Spawn
//   File     (yellow → red)— Read, Write, Modify, Delete
//   Other    (violet)      — any rel_type we haven't classified
//
// The intra-group variation (e.g. Connect=cyan vs DNS=sky) keeps
// adjacent relations distinguishable without breaking the group
// reading. Destructive operations (Delete) stand out in red as a
// deliberate alarm signal.
//
// Used by GraphCanvas edge styling and by EdgeDetailPanel for the
// header dot. To recolour a rel_type globally, edit this file
// once — there is no other place these values are inlined.

export interface RelationStyle {
  /** CSS color string for the edge line + arrow + UI badge dot. */
  color: string;
  /** Semantic grouping. UI surfaces may group by this for legends. */
  group: "network" | "identity" | "process" | "file" | "other";
}

export const REL_PALETTE: Record<string, RelationStyle> = {
  // Network
  Connect: { color: "#06b6d4", group: "network" }, // cyan-500
  DNS:     { color: "#0ea5e9", group: "network" }, // sky-500

  // Identity / authentication
  Auth:    { color: "#f59e0b", group: "identity" }, // amber-500

  // Process
  Execute: { color: "#10b981", group: "process" }, // emerald-500
  Spawn:   { color: "#22c55e", group: "process" }, // green-500

  // File operations — read is cool yellow, modifications warmer, delete red.
  Read:    { color: "#eab308", group: "file" },    // yellow-500
  Write:   { color: "#f97316", group: "file" },    // orange-500
  Modify:  { color: "#fb923c", group: "file" },    // orange-400
  Delete:  { color: "#dc2626", group: "file" },    // red-600 (destructive)
};

/** Color used for any rel_type not in `REL_PALETTE`. Matches
 *  the `Other(_)` variant of `RelationType` in the Rust DSL. */
export const REL_OTHER_COLOR = "#a855f7"; // violet-500

/** Color used for hunt-result-highlighted edges. Kept consistent
 *  with the existing `.highlighted` selector in GraphCanvas
 *  (was `#ff4444` before; same red, named here so PR-D's command
 *  palette can offer "highlight by rel_type" without duplicating
 *  the literal). */
export const REL_HIGHLIGHT_COLOR = "#ff4444";

/** Resolve a rel_type string to its display color. Pure function
 *  so cytoscape's function-style style mapping can call it on
 *  every redraw without churning. */
export function relColor(relType: string): string {
  return REL_PALETTE[relType]?.color ?? REL_OTHER_COLOR;
}

/** Resolve a rel_type string to its semantic group. Used by
 *  legend rendering and by the EdgeDetailPanel group badge. */
export function relGroup(relType: string): RelationStyle["group"] {
  return REL_PALETTE[relType]?.group ?? "other";
}
