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
| Find nodes by property/value when you have no direct IoC to seed | `node_search` |
| Orient — current graph summary (counts, top entities) | `graph_summary` |
| Inspect available entity types / edge (relation) types | `graph_entity_types`, `graph_relation_schema` |
| Pull a specific slice of one node's events | `node_enrich` |
| Expand a node's neighborhood / hydrate it | `node_expand` (`live=true` to hydrate) |
| Get a k-hop subgraph around a node (blast radius / attack path) | `node_subgraph` |
| Detect beaconing / periodicity | `graph_channel_behavior` |
| See temporal concentration / off-hours / bursts across the graph | `graph_temporal_heatmap` |
| Find heavy channels / exfil volume | `graph_heavy_edges` |
| Understand why a node is anomalous | `node_score_explanation` |
| Analyze a subnet / neighbors by range | `graph_subnet_analysis` |
| Hunt a structural pattern | `hunt_run` |
| Retrieve the results of a hunt run | `hunt_results` |
| Re-score after a large manual expansion | `scores_recompute` |
| List a node's raw events | `node_events` |
| Check the SIEM connection state | `sentinel_status` |
| De-conflict against existing SOC detections | `catalog_get` |
| Tag / annotate findings | `tags`, `notes` |
| Raw KQL the graph can't express (LAST RESORT, justify) | `sentinel_query` |
