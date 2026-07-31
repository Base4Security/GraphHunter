# Servicio Fase 0 — findings with evidence + deterministic HTML report — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** `docs/superpowers/specs/2026-07-31-servicio-fase0-evidence-report-design.md` (approved, §8 resolved).

**Goal:** Add the claim–evidence contract on top of the Hunt Journal: `Finding` records whose citations are validated server-side at write time (no-numbers rule included), a narrative layer with placeholders, and a deterministic Rust report generator that turns a **sealed** journal into a self-contained HTML report (informes-a/ style) where every quantitative value is injected from captured journal data — never from LLM text.

**Architecture:** All server work extends the existing journal module (`apps/tauri/src-tauri/src/journal/`): new `finding.rs` (schema + validator, pure), `narrative.rs` (tiny store), `report.rs` (pure renderer). Store growth in `store.rs` (per-hunt `findings.jsonl` + `narratives.jsonl`, read-back API). New HTTP endpoints in `http/journal.rs`: `POST /journal/finding`, `POST /journal/narrative`, `POST /journal/:id/report`. MCP: one new tool `finding` (ops add/list), one new tool `report` (op generate — token-lean: returns path + counts, never the HTML body). E2E script following `scripts/e2e-journal.mjs`.

**Tech Stack:** Rust (`apps/tauri/src-tauri`, axum, serde) + TypeScript (`platform/mcp`, zod). Tests: `cd apps/tauri/src-tauri && cargo test --lib` + `cd platform/mcp && npm run build && npm run test:contract`.

## Global Constraints

- **Validation is server-side and structural** — existence of cited seqs, field resolution, kind allowlist, digits-in-claim rejection. NO semantic/LLM validation anywhere in this plan.
- **The LLM never writes numbers into rendered fact positions.** Metrics resolve from `HuntEvent.result` fields; raw digit runs in narrative markdown render inside an `unverified` span.
- **Report generation requires a sealed hunt** (`closed_at` set) → 409 otherwise. Findings/narrative attach only to the **current open** hunt (same current-hunt model as capture).
- **Determinism:** `report.rs::render` is a pure function; same inputs → identical bytes. The only variable element (generation timestamp) is passed in as a parameter, not read from the clock inside `render`.
- **Redaction reuse:** finding/narrative/report write paths run through the existing `redact_secrets` before persistence; report output is asserted secret-free in tests.
- **Token-lean MCP:** `report generate` returns `{path, bytes, findings, flagged_digit_runs}` — never the HTML. `finding add` returns `{id, status}` — never echoes the full finding.
- **Additive** — no changes to existing endpoint contracts, capture middleware, or the `journal` MCP tool's existing ops.
- Commits: **no Claude / Co-Authored-By trailers.** Conventional-commit prefixes.
- Branch: `spec/servicio-fase0` cut from `spec/hunt-journal` (depends on L1). Working tree has unrelated modified/untracked files — every task stages ONLY the files it changes.

---

### Task 0: Baseline + discovery

**Files:** none (read-only).

- [ ] **Step 1:** `cd apps/tauri/src-tauri && cargo test --lib` — record baseline green count. If red, STOP.
- [ ] **Step 2:** Record exact shapes the later tasks consume:
  - `journal/store.rs`: `HuntMeta` fields (need: does it carry `closed_at`? cumulative topology counts? label/cycle id); signatures of `read(&self, id)`, `close_hunt`, `current_hunt_id`, and how `append` locks `Inner` — findings/narrative appends must reuse the same lock discipline.
  - `journal/event.rs`: exact `EventResult` field names (`row_count`, `new_entities`, `new_relations`, …) — these are the legal `MetricRef.field` values.
  - `http/journal.rs`: handler + extractor pattern (how existing handlers get `HttpState`/`AppState`, error-to-status mapping for 4xx).
  - `journal/summarize.rs`: whether a per-event stored summary exists that the evidence card can render (top-rows summary) — evidence cards show `params` (redacted) + result metadata ONLY, but confirm what's available.
  - Where `dirs::data_dir` subpaths are built (reports dir will be `<data-dir>/graphhunter/reports/`).
- [ ] **Step 3:** `cd platform/mcp && npm run build && npm run test:contract` — baseline green. Record how `defineTool` + registry registration work (copy pattern from `tools/journal/index.ts`, `registry.ts`).
- [ ] **Step 4:** Open one recent `informes-a/Hunting-Phase*.html` and record its inline-CSS conventions (fonts, section headers, chip/badge styles) — the report template must read as the same deliverable family.

---

### Task 1: `Finding` schema + citation validator (pure)

**Files:**
- Create: `apps/tauri/src-tauri/src/journal/finding.rs`
- Modify: `apps/tauri/src-tauri/src/journal/mod.rs` (add `pub mod finding;`)

**Interfaces (produces):**
```rust
pub struct MetricRef { pub label: String, pub event_seq: u64, pub field: String }
pub struct Finding {
    pub id: u32, pub ts: i64,
    pub claim: String,
    pub evidence: Vec<u64>,
    pub metrics: Vec<MetricRef>,
    pub severity: String,     // info|low|medium|high|critical
    pub confidence: String,   // confirmed|probable|hypothesis
    pub status: String,       // stamped by validator: verified|partial
}
pub enum FindingError { EmptyEvidence, UnknownSeq(u64), NonEvidentialKind(u64, String),
                        UnresolvableField(u64, String), DigitsInClaim, BadEnum(&'static str) }
/// Structural validation against the hunt's captured events.
/// Ok(status) stamps verified (all metrics resolve) or partial.
pub fn validate(events: &[HuntEvent], f: &FindingDraft) -> Result<String, FindingError>
```
Evidential kinds allowlist: `seed|build|query|traverse|pivot`. Digit rule: `claim` matching regex `\d` → `DigitsInClaim`. Metric field resolution: `field` must name a `Some(_)` field on that event's `result` (`row_count`, `new_entities`, `new_relations`, `body_bytes`, `est_tokens` — exact legal set from Task 0 Step 2). `FindingError` carries enough for a 422 body that tells the LLM the valid seq range / legal fields (self-correction).

- [ ] **Step 1 (RED):** `#[cfg(test)]` in `finding.rs`: build 3 synthetic `HuntEvent`s (kinds `query` w/ `row_count: Some(47)`, `note`, `traverse` w/ `new_entities: None`); assert: valid finding citing the query → `Ok("verified")`; metric on the traverse's absent `new_entities` → `Ok("partial")` when evidence otherwise fine; `evidence: []` → `EmptyEvidence`; cite seq 99 → `UnknownSeq`; cite the `note` → `NonEvidentialKind`; claim `"47 flows to rare SaaS"` → `DigitsInClaim`; `severity: "urgent"` → `BadEnum`. Run: FAIL (module missing).
- [ ] **Step 2:** Implement. Run target tests GREEN.
- [ ] **Step 3:** Full `cargo test --lib` green. Commit `feat(journal): Finding schema + structural citation validator`.

---

### Task 2: Store — findings + narratives persistence

**Files:**
- Create: `apps/tauri/src-tauri/src/journal/narrative.rs` (`Narrative { section: String, markdown: String, ts: i64 }`)
- Modify: `apps/tauri/src-tauri/src/journal/store.rs`

**Interfaces (produces, on `JournalStore`):**
```rust
pub fn append_finding(&self, draft: FindingDraft) -> Result<Finding, FindingError>  // validates against CURRENT hunt's events, assigns id, persists
pub fn upsert_narrative(&self, section: String, markdown: String)                    // current hunt; last-write-wins per section
pub fn read_findings(&self, id: &str) -> Vec<Finding>
pub fn read_narratives(&self, id: &str) -> Vec<Narrative>                            // section-deduped, stable section order
pub fn is_sealed(&self, id: &str) -> Option<bool>
```
On disk: `<hunt-dir>/findings.jsonl`, `<hunt-dir>/narratives.jsonl` — append-only like `events.jsonl`; narrative dedup happens at read time (replay, keep last per section). `append_finding` runs `redact_secrets` over the draft params-free fields is N/A (claim/metrics are strings) — but run claim/markdown through the redactor anyway (cheap, uniform guarantee). Same `Inner` mutex as `append`.

- [ ] **Step 1 (RED):** store tests (tempdir, same pattern as existing store tests): start hunt → append 2 synthetic events → `append_finding` valid draft → assigned `id: 1`, persisted (`read_findings` after re-open returns it); invalid draft (unknown seq) → `Err`, nothing persisted; `upsert_narrative("resumen", ...)` twice → `read_narratives` returns 1 entry, latest markdown; `is_sealed` false → `close_hunt` → true.
- [ ] **Step 2:** Implement. GREEN. Full suite green. Commit `feat(journal): persist findings + narratives per hunt`.

---

### Task 3: HTTP endpoints — `/journal/finding`, `/journal/narrative`

**Files:**
- Modify: `apps/tauri/src-tauri/src/http/journal.rs` (add `handler_finding`, `handler_narrative`)
- Modify: `apps/tauri/src-tauri/src/http/mod.rs` (routes; ensure both paths remain inside the `journal_capture_skips` prefix — they are `/journal/*`, so already excluded — confirm)

**Interfaces:** `POST /journal/finding {claim, evidence, metrics, severity, confidence}` → 200 `{id, status}` | 422 `{error, valid_seq_range?, legal_fields?}`. `POST /journal/narrative {section, markdown}` → 200 `{section}`. Both operate on the current hunt; if the current hunt was just sealed (no open hunt), lazily opening a new empty hunt would make every citation fail — instead return 409 `{error: "no open hunt"}` when the store has no open current hunt.

- [ ] **Step 1 (RED):** axum-level tests following the existing handler test pattern from Task 0: valid finding round-trip 200 with stamped status; unknown seq → 422 with `valid_seq_range`; digits in claim → 422; narrative upsert → 200; finding after close (no open hunt) → 409.
- [ ] **Step 2:** Implement. GREEN. Full suite. Commit `feat(api): journal finding + narrative endpoints`.

---

### Task 4: Report renderer (pure) — `journal/report.rs`

**Files:**
- Create: `apps/tauri/src-tauri/src/journal/report.rs`
- Modify: `apps/tauri/src-tauri/src/journal/mod.rs`

**Interfaces (produces):**
```rust
pub struct ReportInput<'a> { pub meta: &'a HuntMeta, pub events: &'a [HuntEvent],
    pub findings: &'a [Finding], pub narratives: &'a [Narrative],
    pub stats: &'a serde_json::Value, pub generated_at: i64 }
pub fn render(input: &ReportInput) -> String   // full self-contained HTML document
```
Layout per spec §6 (informes-a visual family, inline CSS only, zero external assets):
1. Executive summary = narrative section `resumen` with placeholders resolved.
2. **Findings**: confirmed/probable findings as claim cards; `hypothesis` ones under an **"Hipótesis abiertas"** subheading (spec §8.2). Card = claim text + resolved metrics (`<code class="metric">` + "· journal #seq" source tag) + severity/confidence chips + `VERIFICADO`/`PARCIAL` badge + `<details>` evidence list (per cited event: kind, endpoint, redacted params pretty-printed, row_count, ts ISO, duration).
3. Hunt topology (from meta cumulative counts).
4. Remaining narrative sections in insertion order.
5. Appendix: manifest (hunt id, label, event count, time range), token metric from `stats` (`cumulative_est_tokens`, `by_kind`), full event index table (seq, ts, kind, endpoint, status).

Placeholder grammar (resolve before digit-flagging): `{{f:N}}` → anchor link to finding card N (unknown N → literal text + `unverified` span); `{{ev:SEQ.FIELD}}` → the captured value (unresolvable → `unverified` span). Then any remaining digit run `\d+` in narrative-originated text wraps in `<span class="unverified" title="sin verificar">…</span>`. Markdown: minimal deterministic subset (paragraphs, `**bold**`, `- ` lists, `## ` headings) rendered by hand — no new dependency unless one already exists in the crate (check Task 0; if `pulldown-cmark` is already a dep, use it).

- [ ] **Step 1 (RED):** tests with a synthetic sealed hunt (3 events, 2 findings incl. one `hypothesis`, 2 narratives):
  - `render` twice with same input → byte-identical.
  - Output contains: claim card with `47` present ONLY inside the metric element sourced from the event (claim text itself has no digits by construction); `VERIFICADO` badge; `Hipótesis abiertas` subheading containing the hypothesis card.
  - Narrative `"vimos {{ev:1.row_count}} flujos y quizas 12 mas"` → renders `47` un-flagged (resolved) and `12` inside `class="unverified"`.
  - `{{f:99}}` → `unverified` span.
  - No external refs: output contains no `http://`, `https://` in `src=`/`href=` (anchors `#...` allowed), no `<script src`.
  - Redaction: input params containing `azure_client_secret` → output contains `[REDACTED]`, not the secret.
- [ ] **Step 2:** Implement. GREEN. Full suite. Commit `feat(journal): deterministic evidence-linked HTML report renderer`.

---

### Task 5: `POST /journal/:id/report` endpoint

**Files:**
- Modify: `apps/tauri/src-tauri/src/http/journal.rs`, `apps/tauri/src-tauri/src/http/mod.rs` (route)
- Modify: `apps/tauri/src-tauri/src/journal/store.rs` (if a `read_stats`-style accessor is missing for reuse)

**Interfaces:** `POST /journal/:id/report {output_dir?}` → 200 `{path, bytes, findings, flagged_digit_runs}` | 404 unknown hunt | **409 hunt not sealed**. Writes `<output_dir||data_dir/graphhunter/reports>/<hunt-id>.html`. `generated_at` = now at the endpoint layer (renderer stays pure). `flagged_digit_runs` = count of `unverified` spans emitted (renderer returns it — adjust `render` to `-> (String, RenderStats)` in this task if not already shaped that way).

- [ ] **Step 1 (RED):** handler tests: open hunt → 409; sealed hunt → 200, file exists at returned path, `bytes` matches file len; regenerate → identical file content (strip the single `generated_at` line before compare, or inject fixed timestamp via test seam).
- [ ] **Step 2:** Implement. GREEN. Full suite. Commit `feat(api): report generation endpoint (sealed hunts only)`.

---

### Task 6: MCP tools — `finding`, `report`

**Files:**
- Create: `platform/mcp/src/tools/journal/finding.ts` — tool `finding`, `op: add|list` (`add` → `POST /journal/finding`; `list {id}` → served from `GET /journal/:id` companion data or a small `GET /journal/:id/findings` if Task 3 added one — match what the server exposes). Description must teach the contract: *claims carry no digits; put quantities in metrics bound to event seqs; 422s tell you how to fix.*
- Create: `platform/mcp/src/tools/journal/report.ts` — tool `report`, `op: generate {id}` → returns the endpoint's token-lean summary verbatim. Description: *requires a closed hunt (use journal op=start rotation or /journal/close first).*
- Modify: `platform/mcp/src/registry.ts` (register both)
- Modify: `platform/mcp/tests/contract/schema.test.ts` (schemas present, zod parses, categories correct)

- [ ] **Step 1 (RED):** contract tests for both tools. `npm run build && npm run test:contract` → new tests fail.
- [ ] **Step 2:** Implement tools. GREEN. Commit `feat(mcp): finding + report tools`.

---

### Task 7: E2E — `scripts/e2e-report.mjs` + acceptance sweep

**Files:**
- Create: `scripts/e2e-report.mjs` (pattern: `scripts/e2e-journal.mjs` — drives the live local API)

Flow: `POST /journal/start {label:"e2e-report"}` → 2 real captured actions (cheapest available endpoints that produce `query`/`build` events — reuse whatever e2e-journal exercises) → `finding` valid → assert `{id:1, status}` → finding with unknown seq → assert 422 → finding with digits in claim → assert 422 → narrative with `{{ev:..}}` + raw digit → `/journal/close` → report → 200 → read the HTML file → assert: evidence link resolvable (cited seq appears in appendix index), `unverified` span present, no secret strings, no external asset refs → second generate → byte-identical (modulo timestamp seam).

- [ ] **Step 1:** Write + run against a locally running app. All assertions pass.
- [ ] **Step 2:** Verify spec §9 acceptance criteria 2–4 and 6 are each covered by a test somewhere in Tasks 1–7; list the mapping in the task report. (Criteria 1 and 5 — the real Niubiz cycle — are the post-merge validation run, not CI.)
- [ ] **Step 3:** Docs touch-up: add the two tools to `docs/reference/mcp.rst`, one paragraph in `docs/reference/architecture.rst` (journal → findings → report pipeline). Commit `docs: fase-0 findings/report surface`.

---

## Post-plan (not tasks): run the next Niubiz weekly cycle end-to-end through the pipeline (spec §9.1, §9.5) and compare its report against the hand-written `informes-a/` predecessors before proposing Fase 1.
