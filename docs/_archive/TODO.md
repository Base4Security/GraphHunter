# TODO

## Event View freezes with high-degree nodes (frontend wire-up)

**Core: done. Frontend: wire-up pending.**

The core engine already has the primitives the feedback asked for:

- `expand_node_grouped` + `GroupedNeighborhood` (in `graph_hunter_core::analytics`) collapse edges of the same type between a pair into a single entry with `count`, `first_ts`, `last_ts`. The MCP tool `expand_node_grouped` and the HTTP `/neighborhood/grouped` endpoint already expose it. See `AUTO_GROUPED_THRESHOLD` in `analytics.rs` for the auto-switch threshold (500 edges).
- `top_anomalies` + `AnomalyScorer::score_path` produce the composite anomaly score the feedback described (centrality + frequency + temporal deviation). Trait-based composition via `ScoreComponent` shipped in P2-A.

What still needs frontend work:

- `EventsViewPanel.tsx` / `NodeDetailPanel.tsx` should call `expand_node_grouped` when the selected node's edge count crosses `AUTO_GROUPED_THRESHOLD`, instead of the raw `expand_node` that causes the freeze.
- Edge pagination inside the view (load first N, lazy-load on scroll).
- Anomaly-based highlighting: gradient / badge on nodes whose `top_anomalies` rank is in the top-decile. The data is already in the `HuntResultsTable` payload — just not rendered.

## Deferred (evaluated, waiting for trigger)

### P2-F — StringInterner generational or partitioning

Trait seam + metrics shipped (`StringInternerBackend`, `InternerMetrics`). The **implementation** of a second backend is deferred until one of these triggers fires:

- `InternerMetrics.unique_strings > 10_000_000` on a live session (≈ hundreds of MB of string content alone, before hashmap overhead).
- Streaming session running 24×7 for more than 72h without a `cmd_compact` cycle.
- MSSP / multi-tenant deployment where one process serves more than one customer (strings from tenant A leak into tenant B's lookup space).

When any of these hits, add `GenerationalInterner` or `PartitionedInterner` as a second `StringInternerBackend` impl and route via a new `InternerKind` enum. The 121+ call sites don't need to change — they hold concrete `StringInterner` today but can migrate to the enum in a follow-up.

### P3 — MVCC edge-level + time-travel

Not started. Plan-sized at 1.5 weeks of full-time work; requires `CompactRelation` layout change, ingest pipeline propagation of `ingested_at`, query API extension with `snapshot` parameter, `diff_hunts` redesign (`diff_by_snapshot` vs `diff_by_event_time`), SessionFile v2 migration, spill v2 migrator. Worth doing when audit / replay / rolling-baseline features move out of "nice to have" into a deal-critical gap.

### P2-E — IngestAdapter trait + Consent/Assign/Create/Forward pipeline

Partial: `LogSource` trait already exists in `sources/mod.rs` with `poll_since` + `query_scoped`. Missing: the higher-level `IngestAdapter` (`stream_events` + `normalize`) and the orchestrator pipeline. Outcome = "adding a new source (Okta, Crowdstrike) stops being a core edit and becomes a trait impl in a child crate". No hard blocker; triggers when a new source request comes in that doesn't fit the current per-source files.
