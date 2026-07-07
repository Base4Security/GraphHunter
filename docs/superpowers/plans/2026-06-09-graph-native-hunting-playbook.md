# Graph-Native Hunting Playbook — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite the weekly hunting playbook (Phase 1–4 prompt templates the operator pastes into Claude Desktop) so the default flow is graph-native — `sentinel_seed → node_enrich/node_expand → graph analytics` — with `sentinel_query` (KQL) as a justified escape hatch, and output formats that demand graph evidence instead of raw KQL.

**Architecture:** Versioned docs under `docs/hunting-playbook/`. A shared "Tooling Doctrine" block (graph-first principle + tool cheat-sheet) is inlined into each phase prompt so each file works standalone when pasted. Phase 1 stays KQL-capable (pre-graph recon) but adds a Seeding Strategy that bridges to the graph; Phases 2–4 are graph-first.

**Tech Stack:** Markdown prose (LLM prompt templates). No code. "Tests" are verification checks: greps for forbidden/required phrases and a tool-name existence check against the live MCP catalog.

**Spec:** `docs/superpowers/specs/2026-06-08-graph-native-hunting-playbook-design.md`

**Scope note:** This plan covers the **5 prompt docs only**. The HTML report templates (spec §4.6) are deferred to a separate follow-up plan, blocked on the operator uploading the 5 source HTML files. Do NOT create `templates/` HTML here.

**Authoritative tool catalog (43 tools — every tool the playbook references MUST be in this list):**
```
catalog_get enrich export graph_channel_behavior graph_datasets graph_entity_types
graph_heavy_edges graph_path_nodes graph_relation_schema graph_subnet_analysis
graph_summary graph_temporal_heatmap hunt_diff hunt_parse hunt_results hunt_run
ingest_canonical_map ingest_dead_letters ingest_fetch_shared_mappings
ingest_invariants_hypothetical ingest_invariants_live ingest_negotiate
ingest_parser_generate ingest_pcap_preview ingest_publish_mapping
ingest_regression_test ingest_schema_drift node_enrich node_events node_expand
node_get node_score_explanation node_search node_subgraph notes publish review
scores_recompute sentinel_query sentinel_seed sentinel_status session_check tags
```

**Cross-cutting verification helper (used by several tasks):**
```bash
# Every backticked tool token in a playbook doc must exist in the catalog.
CATALOG="catalog_get enrich export graph_channel_behavior graph_datasets graph_entity_types graph_heavy_edges graph_path_nodes graph_relation_schema graph_subnet_analysis graph_summary graph_temporal_heatmap hunt_diff hunt_parse hunt_results hunt_run ingest_canonical_map ingest_dead_letters ingest_fetch_shared_mappings ingest_invariants_hypothetical ingest_invariants_live ingest_negotiate ingest_parser_generate ingest_pcap_preview ingest_publish_mapping ingest_regression_test ingest_schema_drift node_enrich node_events node_expand node_get node_score_explanation node_search node_subgraph notes publish review scores_recompute sentinel_query sentinel_seed sentinel_status session_check tags"
# extract `tool_name`-looking tokens (snake_case in backticks) from a file and report any not in CATALOG:
grep -oE '`[a-z]+_[a-z_]+`' "$FILE" | tr -d '`' | sort -u | while read t; do echo "$CATALOG" | grep -qw "$t" || echo "UNKNOWN TOOL: $t"; done
```
(A token flagged UNKNOWN that is NOT a tool — e.g. `time_window`, `entity_type` — is fine; only real tool references must resolve. Use judgment.)

**Reminder:** commit trailer `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

---

## Task 1: README + shared Tooling Doctrine

**Files:**
- Create: `docs/hunting-playbook/README.md`
- Create: `docs/hunting-playbook/00-tooling-doctrine.md`

- [ ] **Step 1: Write `00-tooling-doctrine.md`**

This is the shared block that gets inlined verbatim at the top of Phases 2–4. Write it EXACTLY as below (this is the behavioral lever — do not paraphrase):

```markdown
## Tooling Doctrine (graph-first)

**Principle:** GraphHunter's value is the correlated, persistent graph — cross-source
entity unification, multi-hop traversal, temporal/behavioral analytics, anomaly scoring.
The graph is the artifact of the hunt, not the query. Build the graph, then reason over it.

**Default execution flow for every hypothesis:**
1. `sentinel_seed` — cold-start the graph from the scenario's IoC(s).
2. `node_enrich` / `node_expand` — pull the relevant slice(s) and build the neighborhood.
3. Graph analytics — run the test on the graph (see cheat-sheet).
4. Only if the graph cannot express the test: `sentinel_query` (raw KQL) — and you MUST
   justify in the report why no graph tool sufficed.

**`sentinel_query` is an escape hatch, not the main path.** Reaching for it first means you
are using GraphHunter as a KQL console and getting none of its value.

**Ingest vs inspect:** the graph-building tools (`sentinel_seed`, `node_enrich`,
`node_expand` live) always ingest. `sentinel_query` defaults to inspect (no graph change);
pass `ingest=true` to load results. When you re-pull a layer, pass a stable `dataset` name
so it REPLACES instead of duplicating.

**Tool cheat-sheet (intent → tool):**
| I need to… | Tool |
|---|---|
| Start a hunt from an IoC (IP/User/Host/Process/File) | `sentinel_seed` |
| Pull a specific slice of one node's events | `node_enrich` |
| Expand a node's neighborhood / hydrate it | `node_expand` (`live=true` to hydrate) |
| Get a k-hop subgraph around a node (blast radius / attack path) | `node_subgraph` |
| Detect beaconing / periodicity | `graph_channel_behavior` |
| Find heavy channels / exfil volume | `graph_heavy_edges` |
| Understand why a node is anomalous | `node_score_explanation` |
| Analyze a subnet / neighbors by range | `graph_subnet_analysis` |
| Hunt a structural pattern | `hunt_run` |
| List a node's raw events | `node_events` |
| Check the SIEM connection state | `sentinel_status` |
| De-conflict against existing SOC detections | `catalog_get` |
| Tag / annotate findings | `tags`, `notes` |
| Raw KQL the graph can't express (LAST RESORT, justify) | `sentinel_query` |
```

- [ ] **Step 2: Write `README.md`**

Content requirements (write the prose; cover each):
- One-paragraph purpose: this is the graph-native weekly hunting playbook; the prompts are pasted into Claude Desktop with the GraphHunter MCP connected.
- The phase map: Phase 1 (telemetry audit + seeding strategy) → Phase 2 (hypothesis execution, graph-first) → Phase 3 (validation + blast radius) → Phase 4 (synthesis + reporting). One line each.
- A "How to use" note: each `0N-*.md` is a self-contained prompt; paste it into the session at the corresponding step; the Tooling Doctrine is inlined in Phases 2–4 (also kept standalone in `00-tooling-doctrine.md` for reference).
- A "Why graph-native" line: link the value statement to `docs/superpowers/specs/2026-06-08-graph-native-hunting-playbook-design.md`.
- Do NOT mention HTML templates (deferred).

- [ ] **Step 3: Verify tool references resolve**

Run the cross-cutting verification helper with `FILE=docs/hunting-playbook/00-tooling-doctrine.md`.
Expected: no real tool flagged UNKNOWN (non-tool tokens like `live` are fine — there are none expected here).

- [ ] **Step 4: Commit**

```bash
git add docs/hunting-playbook/README.md docs/hunting-playbook/00-tooling-doctrine.md
git commit -m "docs(playbook): README + graph-first tooling doctrine

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Phase 1 — Telemetry Audit & Seeding Strategy

**Files:**
- Create: `docs/hunting-playbook/01-phase1-telemetry-audit.md`

- [ ] **Step 1: Write the Phase 1 prompt**

Base it on the operator's existing Phase 1 prompt (persona: Senior Lead Threat Hunter doing environment recon) but graph-aware. Required sections (write full prose for each):

- **[PERSONA]** — Senior Lead Threat Hunter; environment-recon mindset.
- **[CONTEXT]** — weekly hunting cycle, Phase 1; GraphHunter MCP connected to Sentinel. State that Phase 1 is pre-graph recon (KQL is appropriate here to audit what telemetry exists) but MUST end by defining how the graph will be built in Phase 2.
- **[TASK]**:
  1. Telemetry audit — enumerate active tables, volumes, stack layers (KQL OK).
  2. Visibility matrix — coverage gaps / blind spots.
  3. De-confliction — use `catalog_get` to avoid overlapping existing SOC detections.
  4. Scenario construction — propose N scenarios over uncovered telemetry.
  5. **Seeding Strategy (NEW, the bridge)** — for EACH proposed scenario, specify: the seed IoCs/entities with their `entity_type` (IP/User/Host/Process/File), the graph-build plan (which tools in which order, e.g. "`sentinel_seed` the IP → `node_expand` 2 hops → `graph_channel_behavior` on its channels"), and the lookback window.
- **[CONSTRAINTS]** — map gaps/scenarios to MITRE where applicable; KQL allowed for the audit, but the deliverable must include the Seeding Strategy.
- **[OUTPUT FORMAT]** — a `Hunting-Phase1-<timestamp>` markdown report with: Telemetry Audit, Visibility Matrix, De-confliction summary, Proposed Scenarios, and the **Seeding Strategy** table per scenario (columns: Scenario | Seed IoC(s) + entity_type | Graph-build plan (tools) | Lookback).

Inline the `00-tooling-doctrine.md` block near the top (copy it verbatim) so this prompt is self-contained, EXCEPT note in Phase 1 that KQL is acceptable for the audit step (Phase 1 is the one place raw KQL is a first-class tool).

- [ ] **Step 2: Verify**

- Run the tool-reference helper with `FILE=docs/hunting-playbook/01-phase1-telemetry-audit.md` → no real tool UNKNOWN.
- Confirm the doctrine block is present: `grep -q "Tooling Doctrine" docs/hunting-playbook/01-phase1-telemetry-audit.md` → exit 0.
- Confirm the Seeding Strategy is required in the output: `grep -qi "Seeding Strategy" docs/hunting-playbook/01-phase1-telemetry-audit.md` → exit 0.

- [ ] **Step 3: Commit**

```bash
git add docs/hunting-playbook/01-phase1-telemetry-audit.md
git commit -m "docs(playbook): Phase 1 — telemetry audit + seeding strategy

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Phase 2 — Hypothesis Formulation & Graph Execution (keystone)

**Files:**
- Create: `docs/hunting-playbook/02-phase2-hypothesis-execution.md`

- [ ] **Step 1: Write the Phase 2 prompt**

This is the highest-leverage rewrite. Persona/rigor unchanged from the operator's Phase 2 (Senior Lead Threat Hunter; testable hypotheses; long-tail/outlier focus; MITRE sub-technique). What changes is the EXECUTION METHOD and the OUTPUT FORMAT.

Required sections:
- Inline the `00-tooling-doctrine.md` block verbatim at the top.
- **[PERSONA]** — as above.
- **[CONTEXT]** — execution phase; consume the Seeding Strategy from Phase 1.
- **[TASK]**:
  1. **Hypothesis Formulation** — 3 granular, testable hypotheses per scenario, each stating expected technical behavior + the graph signal that would confirm it.
  2. **Graph Execution (per hypothesis, in this order):**
     a. `sentinel_seed` the scenario's IoC → graph populated.
     b. `node_enrich` / `node_expand` → build the neighborhood (use a stable `dataset` name so re-pulls refresh, not duplicate).
     c. Test the hypothesis with graph analytics: `graph_channel_behavior` (beaconing), `graph_heavy_edges` (volume/exfil), `node_score_explanation` (anomaly), `node_subgraph` (paths/blast radius), `graph_subnet_analysis`, `hunt_run` (pattern).
     d. Only if no graph tool expresses the test: `sentinel_query` — and record the justification.
  3. **Result Triaging** — separate false positives (known service accounts, scheduled tasks) from true anomalies; document negative findings as control-effectiveness evidence.
  4. **Tactical Pivoting** — expand suspicious entities via `node_expand` / `node_enrich`.
- **[CONSTRAINTS]** — every finding mapped to MITRE sub-technique.
- **[OUTPUT FORMAT]** — write this EXACTLY (it is the inversion that reprograms the LLM away from KQL):

```markdown
Create a `Hunting-Phase2-<timestamp>` markdown report. For EACH hypothesis include:

- **Tactical Hypothesis:** the what and why, + MITRE sub-technique.
- **Graph Evidence:** what the graph showed — entities/relations added (from the seed/enrich
  outcome), the seeded subgraph or neighborhood, paths found, anomaly scores, and the output
  of `graph_channel_behavior` / `graph_heavy_edges` where applicable. THIS is the primary
  evidence — not a KQL query.
- **Pivot History:** secondary `node_expand` / `node_enrich` steps used to validate a lead.
- **Escape-Hatch Log (only if used):** the raw `sentinel_query` KQL you ran AND a one-line
  justification of why no graph tool could express the test.
- **Current Risk Status:** Clean / Suspicious / Needs Escalation, + a Reliability metric
  (how certain the activity is malicious).
```

CRITICAL: the phrase "(Not DSL patterns)" from the operator's old Phase 2 must NOT appear. The default evidence is graph evidence; KQL appears only in the Escape-Hatch Log.

- [ ] **Step 2: Verify (the keystone checks)**

```bash
FILE=docs/hunting-playbook/02-phase2-hypothesis-execution.md
grep -qi "not dsl" "$FILE" && echo "FAIL: forbidden phrase present" || echo "OK: no 'Not DSL'"
grep -q "Graph Evidence" "$FILE" && echo "OK: graph evidence required" || echo "FAIL"
grep -q "Escape-Hatch Log" "$FILE" && echo "OK: escape hatch documented" || echo "FAIL"
grep -q "sentinel_seed" "$FILE" && echo "OK: seed is step 1" || echo "FAIL"
```
Expected: OK on all four. Then run the tool-reference helper on the file → no real tool UNKNOWN.

Also confirm the first execution step is a graph tool, not `sentinel_query`: read the [TASK] Graph Execution block and verify step (a) is `sentinel_seed`.

- [ ] **Step 3: Commit**

```bash
git add docs/hunting-playbook/02-phase2-hypothesis-execution.md
git commit -m "docs(playbook): Phase 2 — graph-first execution + graph-evidence output

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Phase 3 — Validation & Blast Radius (graph-native)

**Files:**
- Create: `docs/hunting-playbook/03-phase3-validation-blast-radius.md`

- [ ] **Step 1: Write the Phase 3 prompt**

Persona unchanged (adversarial QA / red-team-your-own-findings; demand corroboration before promoting to True Positive). Method becomes graph-native.

Required sections:
- Inline the `00-tooling-doctrine.md` block verbatim at the top.
- **[PERSONA]** — Senior Lead Threat Hunter + QA; skeptical; false-positive eradication; blast-radius scoping.
- **[CONTEXT]** — consume Phase 2's Suspicious / Needs-Escalation findings.
- **[TASK]**:
  1. **Contextual Cross-Examination** — for each suspicious entity, pull historical baselines via `node_enrich` (wider lookback) and context via `node_expand`; check prior findings with `tags` / `notes` / `catalog_get` (ignore finding types already in reported-findings).
  2. **Enrichment & Correlation** — cross-reference suspicious entities; determine isolated vs systemic using the graph.
  3. **Blast Radius Construction** — for any surviving anomaly, build the ±N-hop neighborhood with `node_expand` / `node_subgraph` and stitch the attack chain (this REPLACES the old "±60-minute KQL window" approach — say so explicitly).
  4. **Verdict Adjudication** — rule each finding: True Positive (Active Threat) | Environmental Anomaly (Misconfig/Benign) | False Positive (Expected).
- **[CONSTRAINTS]** — verdicts based only on telemetry/graph evidence + logical deduction; maintain MITRE mapping; link validated techniques to potential lateral movement / persistence.
- **[OUTPUT FORMAT]** — a `Hunting-Phase3-Validation-<timestamp>` markdown report with: a **Validation Matrix** (Phase 2 Finding | Initial Risk | Post-Validation Risk | Final Verdict | Justification); a **Blast Radius Assessment** expressed as a graph neighborhood/timeline (the subgraph + chronology, derived via `node_expand`/`node_subgraph`); **Enrichment Data** (new IOCs/behavioral anomalies); and a **Handoff Summary** (validated threats, gaps, verified controls for Phase 4).

- [ ] **Step 2: Verify**

```bash
FILE=docs/hunting-playbook/03-phase3-validation-blast-radius.md
grep -q "Tooling Doctrine" "$FILE" && echo OK || echo FAIL
grep -qE "node_expand|node_subgraph" "$FILE" && echo "OK: blast radius is graph traversal" || echo FAIL
grep -qi "Validation Matrix" "$FILE" && echo OK || echo FAIL
```
Expected: OK on all. Run the tool-reference helper → no real tool UNKNOWN.

- [ ] **Step 3: Commit**

```bash
git add docs/hunting-playbook/03-phase3-validation-blast-radius.md
git commit -m "docs(playbook): Phase 3 — validation + blast radius as graph traversal

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Phase 4 — Synthesis, Reporting & Remediation

**Files:**
- Create: `docs/hunting-playbook/04-phase4-synthesis-reporting.md`

- [ ] **Step 1: Write the Phase 4 prompt**

Persona/structure unchanged (Security Advisor; risk communication; synthesis-oriented). Two graph-aware nuances.

Required sections:
- Inline the `00-tooling-doctrine.md` block verbatim at the top.
- **[PERSONA]** — Senior Lead Threat Hunter + Security Advisor.
- **[CONTEXT]** — synthesize the Phase 2/3 results into a final client report.
- **[TASK]**:
  1. **Executive Synthesis** — hunting-cycle summary; hypotheses tested; environment Health Score.
  2. **Finding Categorization** — Critical/High Findings; Security Gaps (visibility/logging); Validated Controls (negative findings).
  3. **MITRE ATT&CK Heatmap** — aggregate techniques covered.
  4. **Remediation & Hardening Plan** — per finding: short-term fix + long-term strategic recommendation.
  5. **Continuous Improvement** — propose 2 next-cycle scenarios / high-visibility zones.
- **[CONSTRAINTS]** — authoritative yet constructive; non-hyperbolic; recommendations specific to the Microsoft Sentinel/Azure ecosystem.
- **[OUTPUT FORMAT]** — a `Hunting-Phase4-<timestamp>` markdown report with: Executive Summary; Detailed Technical Findings; the **"Sentinel Hardening" List** (KQL snippets/logic to convert hunts into permanent Scheduled Analytics Rules — KQL IS the deliverable here, this is correct and stays); a **Visibility & Coverage Audit**; and a **Next Cycle Preview**.
- ADD a short note in the report structure: include the **graph evidence** that backed the key findings (the attack-path subgraph, beacon scores, heavy channels) — the differentiator the graph surfaced.

CRITICAL nuance: Phase 4's Hardening List producing KQL is CORRECT (those are detection rules the SOC runs in Sentinel — the deliverable, not the hunting method). Do not "graph-ify" the Hardening List. The graph-evidence note is additive, not a replacement.

- [ ] **Step 2: Verify**

```bash
FILE=docs/hunting-playbook/04-phase4-synthesis-reporting.md
grep -q "Tooling Doctrine" "$FILE" && echo OK || echo FAIL
grep -qi "Hardening" "$FILE" && echo "OK: hardening list (KQL deliverable) kept" || echo FAIL
grep -qiE "graph evidence|subgraph|beacon" "$FILE" && echo "OK: graph evidence in report" || echo FAIL
```
Expected: OK on all. Run the tool-reference helper → no real tool UNKNOWN.

- [ ] **Step 3: Commit**

```bash
git add docs/hunting-playbook/04-phase4-synthesis-reporting.md
git commit -m "docs(playbook): Phase 4 — synthesis + reporting (hardening KQL stays)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final verification (after all tasks)

```bash
ls docs/hunting-playbook/                       # README + 00..04 (5 prompt docs)
# Keystone: the forbidden phrase appears nowhere in the playbook
grep -rli "not dsl" docs/hunting-playbook/ && echo "FAIL: forbidden phrase" || echo "OK: clean"
# Every phase prompt inlines the doctrine
for f in 01 02 03 04; do grep -q "Tooling Doctrine" docs/hunting-playbook/0${f}-*.md && echo "$f OK" || echo "$f FAIL"; done
# Dry-run check (manual): re-read Phase 2 and confirm that, for the Niubiz Scenario A
# (seed IP 181.196.73.138 → node_expand → graph_channel_behavior/graph_heavy_edges),
# the prompt would drive a graph-first flow, NOT the KQL-by-hand flow the old playbook produced.
```
Expected: clean on the forbidden phrase; doctrine present in all four phase prompts.

**Deferred (separate plan):** HTML report templates (spec §4.6) — write that plan once the operator uploads the 5 source HTML files (`01-WeeklyHunting-Step1..4.html`, `informe-threat-hunting.html`).

---

## Self-Review notes

- **Spec coverage:** §4.1 doctrine + cheat-sheet → Task 1; §4.2 Phase 1 + Seeding Strategy → Task 2; §4.3 Phase 2 graph-first + inverted output → Task 3 (keystone, with verbatim output format + the "(Not DSL patterns)" ban); §4.4 Phase 3 blast-radius-as-traversal → Task 4; §4.5 Phase 4 + Hardening-List-stays-KQL → Task 5; §4.6 HTML → explicitly deferred. §6 acceptance criteria → encoded as the per-task grep checks + final verification (forbidden-phrase grep, doctrine-present, tool-existence, dry-run).
- **Placeholder scan:** the verbatim blocks (doctrine, cheat-sheet, Phase 2 output format) are provided in full; the remaining prose is specified section-by-section with concrete content + exact tool references — appropriate granularity for prose deliverables (the spec holds the complete design; reproducing all four prompts verbatim in the plan would duplicate the deliverable).
- **Tool consistency:** every tool named in the doctrine/cheat-sheet and phase tasks is in the authoritative catalog (verified against the live MCP list). `graph_path_nodes` was intentionally dropped from the cheat-sheet (it lists pinned path nodes, not auto attack-paths); blast-radius/attack-path uses `node_expand`/`node_subgraph`.
- **Decomposition:** prompt docs (this plan) vs HTML templates (deferred plan) — independent subsystems per the Scope Check.
