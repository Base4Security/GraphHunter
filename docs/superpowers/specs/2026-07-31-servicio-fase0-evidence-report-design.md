# Design — Servicio Fase 0: autonomous hunt + evidence-linked HTML report

**Date:** 2026-07-31
**Status:** Approved design (§8 decisions resolved 2026-07-31), pending implementation plan
**Related:** Hunt Journal L1 (`2026-07-17-hunt-journal-provenance-design.md`, branch `spec/hunt-journal`) — the capture substrate this design builds on; `gh_hunt` one-shot (branch `spec/gh-hunt-graph-first`) — the autonomous hunt executor; `informes-a/` 5-phase report format — the deliverable this replaces/automates; Sentinel sidecar differential polling — ingestion for later phases.

**The service, in one sentence.** GraphHunter runs a hunt cycle end-to-end (hypotheses → hunts → findings) driven by an LLM over MCP, the Hunt Journal mandatorily captures everything, and a **report generator** turns the sealed journal into an HTML report where **every claim cites captured evidence** — so the human verifies by spot-checking claim cards, not by redoing the hunt.

This is Fase 0 of a 4-phase service roadmap (§7). It is deliberately the phase that requires **no new infrastructure**: no headless binary, no scheduler, no web UI. Trigger is a human starting a Claude session (MCP). What Fase 0 adds is the piece that makes all later phases trustworthy: the **claim–evidence contract**.

---

## 1. Problem

The weekly hunting cycle (Niubiz) already runs through GraphHunter tools, and the journal (L1) now captures every action. But the deliverable — the `informes-a/` HTML reports — is still hand-narrated by the LLM/analyst, with no structural link between what the report *says* and what the journal *recorded*. Consequences:

- **Trust gap.** A number in the report ("47 flows to rare SaaS domains") is LLM-written prose. It may be right, may be hallucinated, may be stale. The client (and Lucas, and Diego) can only verify by re-running the hunt by hand — exactly the cost the service is supposed to eliminate.
- **No fact/interpretation boundary.** The report mixes deterministic facts (counts, entities, edges — things GraphHunter computed) with LLM interpretation (severity, hypothesis narrative) with no visual or structural distinction.
- **The journal is write-only value.** L1 captures provenance, but nothing downstream *consumes* it yet. The audit trail exists; the audit *experience* doesn't.

**Goal:** a report generator where (a) every quantitative claim is **injected from journal data, never written by the LLM**; (b) every finding **cites journal event sequence numbers** and the citation is **validated at write time**; (c) anything the LLM asserts without evidence is **visibly flagged as unverified interpretation** in the HTML. Hallucination is not eliminated — it is made visible and confined to the narrative layer.

## 2. Scope

**In (Fase 0):**
1. `finding` records with mandatory evidence citations (§4) — new journal endpoint + MCP tool.
2. Citation validator (§5) — enforced server-side at finding-write time.
3. Report generator (§6) — sealed journal → single-file HTML in the `informes-a/` visual style, claim cards linked to evidence.
4. Narrative layer with claim placeholders (§6b) — the LLM writes prose around `{{f:N}}` / `{{ev:N}}` tokens; the generator resolves them from journal data.
5. Token-cost appendix — surface the journal's Part B per-hunt token metric in the report (the "cheaper than raw" number, already measured).

**Out (later phases, §7):** headless binary, scheduler/cron, Agent SDK orchestrator (Fase 0 uses an interactive Claude session over MCP as the orchestrator), case memory across runs, web UI, multi-tenant anything.

## 3. Architecture — the Fase 0 pipeline

```
analyst opens Claude session (MCP)
  └─ journal_start {label: "Hunting-2026-08-04-S01"}
  └─ LLM: hypotheses → seeds → builds → traversals → queries
        (every action captured as HuntEvents — L1, already built)
  └─ LLM: journal_finding {claim, evidence:[seq...], ...}   ← NEW (§4)
        (server validates citations — §5)
  └─ LLM: journal_narrative {section, md_with_placeholders}  ← NEW (§6b)
  └─ journal_close
  └─ report_generate {hunt_id} → informes-a/<cycle-id>.html  ← NEW (§6)
```

The orchestrator is a plain Claude session; nothing in the server distinguishes "autonomous" from "human-driven" — which is exactly why Fases 1–3 reuse this pipeline unchanged, swapping only the trigger.

## 4. The claim–evidence contract

A new journal record type, stored alongside events in the hunt's journal (same append-only store, `findings.jsonl`):

```
Finding {
  id: u32,                    // per-hunt monotonic
  ts: i64,
  claim: String,              // one-sentence assertion, NO NUMBERS (see below)
  evidence: Vec<u64>,         // HuntEvent seq numbers — MUST be non-empty
  metrics: Vec<MetricRef>,    // numbers the claim relies on, each bound to an event
  severity: String,           // info|low|medium|high|critical
  confidence: String,         // confirmed|probable|hypothesis
  status: String,             // set by validator: verified|partial|unverified
}

MetricRef {
  label: String,              // e.g. "flows_to_rare_saas"
  event_seq: u64,             // the event that produced the number
  field: String,              // which result field: "row_count" | "new_entities" | ...
}
```

**The no-numbers rule.** `claim` text must not carry quantities; quantities live in `metrics`, each bound to a captured event field. The report renders "«{claim}» — **{metrics resolved from journal}**". An LLM cannot hallucinate a count it is structurally prevented from writing. (Validator enforcement: §5.)

`POST /journal/finding` + MCP tool `journal_finding`. Findings with `evidence: []` are rejected — an uncited finding is not a finding, it is narrative, and belongs in §6b where it gets flagged as such.

## 5. Citation validator (server-side, at write time)

On `POST /journal/finding`, before persisting:

1. **Existence:** every `evidence[i]` and `metrics[i].event_seq` must be a captured seq in the current hunt. Unknown seq → 422, the tool returns the valid seq range so the LLM can self-correct.
2. **Field resolution:** every `metrics[i].field` must resolve to a present value on that event's `result`. Missing → 422.
3. **Relevance floor (cheap heuristic, not semantic):** cited events must be of evidential kinds (`query|traverse|seed|build`) — citing a `note` or `export` as evidence → 422.
4. **No-numbers enforcement:** `claim` containing a digit sequence → 422, with an error message directing the quantity into `metrics` (identifiers like CVE ids can be referenced via the cited event's params, or phrased without the digits). Blunt by design, same tradeoff as §6b: a rephrased claim is cheap; an unflagged hallucinated count is the failure mode this exists to kill.
5. **Status stamping:** all checks pass and every metric resolves → `verified`. Evidence exists but some metric field was absent at write time → `partial`. (`unverified` is reserved for narrative-layer assertions, §6b — it cannot occur on a persisted Finding.)

The validator is deliberately **structural, not semantic** — it cannot know whether event 41 truly supports the claim. What it guarantees: every claim is *checkable in one click*, and every number is *provably from the engine*. Semantic spot-checking is the human's residual job, and it is now O(clicks), not O(redo-the-hunt).

## 6. Report generator

`POST /journal/:id/report` (+ MCP tool `report_generate`). Requires a **sealed** journal (closed hunt); generating from an open hunt → 409.

**Output:** one self-contained HTML file (inline CSS, no external assets — same constraint as current `informes-a/` deliverables, which are shared with the client as files). Written to a configurable output dir; default `informes-a/`.

**Structure** (mirrors the 5-phase format):
1. Executive summary — narrative (§6b) with resolved placeholders.
2. Findings — one **claim card** per Finding:
   - claim text + resolved metrics (from journal, rendered distinctly — e.g. mono-space, sourced badge);
   - severity/confidence chips; status badge **VERIFICADO / PARCIAL**;
   - collapsible evidence list: per cited event → `kind`, endpoint, redacted params (the KQL string, the anchor entity), `row_count`, timestamp, duration. This *is* the re-check: the analyst reads the exact query and its result size without touching Sentinel.
3. Hunt topology — accumulated per-hunt topology counts from `meta.json` (entities/edges touched, builds, traversals).
4. Narrative sections — §6b, with unverified-assertion flagging.
5. Appendix: journal manifest — hunt id, event count, time range, **token-cost metric** (Part B), and the full event index (seq, ts, kind, endpoint) so the report is also the provenance appendix the L1 spec promised.

**Renderer lives server-side in Rust** (`platform/api`), templated with the same approach as existing export endpoints — *not* an LLM step. The generator is deterministic: same sealed journal → same report bytes (modulo generation timestamp). This matters: the report can be regenerated later from the archived journal and diffed.

### 6b. Narrative layer

`POST /journal/narrative {section, markdown}` (+ MCP tool). The LLM writes prose per section with placeholders:

- `{{f:3}}` → renders Finding 3's claim card inline (or a link to it).
- `{{ev:41.row_count}}` → renders that event's captured value.
- Any **digit sequence in raw narrative text** that is not inside a placeholder gets wrapped by the generator in an `unverified` span — rendered with a dashed underline + "sin verificar" tooltip. Blunt (years and CVE ids will get flagged too — accepted; a flagged-but-true year is noise, an unflagged hallucinated count is the failure mode we are eliminating), and it makes writing evidence-free numbers *costly* for the orchestrator prompt, pushing metric flow through the validated path.

## 7. Roadmap context (non-goals here, so the cut lines are explicit)

- **Fase 1 — headless + scheduler:** extract the HTTP server start from `apps/tauri/src-tauri/src/lib.rs` into a standalone binary (`apps/cli` as base); cron/Task Scheduler runs ingest (Sentinel sidecar) + an Agent SDK orchestrator on an interval; reports land in a directory. The orchestrator prompt is the *same* one refined during Fase 0 sessions.
- **Fase 2 — case memory:** orchestrator reads prior sealed journals + findings as context ("last run saw X; did it evolve?"). The journal store is already the substrate; this is a read path + prompt discipline.
- **Fase 3 — web UI:** submit context, browse reports, drill into claim cards. Renders the same HTML/data Fase 0 produces.

## 8. RESOLVED DECISIONS (Lucas, 2026-07-31) — the claim-card acceptance bar

1. **Evidence card = `query + row_count + timestamp` — no result samples in Fase 0.** Samples would re-open a redaction/PII surface in a client-facing file; the journal retains detail server-side (`journal expand` covers row-level drill-down during the hunt), and Fase 3's UI can show samples behind auth.
2. **`confidence: hypothesis` findings ARE allowed as Findings**, rendered in a visually separate **"Hipótesis abiertas"** subsection of the Findings section — the weekly cycle's value partly *is* the open hypotheses. Same citation rules apply (a hypothesis still cites the events that motivated it).

## 9. Acceptance criteria

1. A real weekly cycle (next Niubiz run) executed end-to-end through the pipeline: journal_start → hunt → ≥5 findings → narrative → close → report_generate.
2. 100% of findings in the generated HTML carry resolvable evidence links; 0 quantitative values in finding cards originate from LLM text.
3. Deliberate-failure tests: finding with unknown seq → 422; metric on absent field → `partial`; digits in raw narrative → flagged span in HTML.
4. Determinism: regenerating the report from the same sealed journal produces identical HTML (excluding generation timestamp).
5. Report includes the per-hunt token metric, and the number is compared against the raw-KQL baseline in the report appendix.
6. Redaction: generated HTML contains no `*secret*`/`*token*`/`*password*` field values (reuse L1 redactor tests against report output).
