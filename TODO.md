# TODO

## Event View freezes with high-degree nodes (mega graph)

When selecting a node with many edges in the Event View, the UI freezes.

### Lossless graph compression
- Implement edge grouping: collapse N edges of the same type between the same pair (src, dst) into a single edge with metadata `count`, `first_ts`, `last_ts`
- Edge pagination in the view: load only the first N visible edges, lazy-load the rest on demand
- Adaptive level of detail: if a node has >500 edges, show a summary grouped by type/destination instead of all individual edges

### Intelligent suspicious detection system
- Not only highlight nodes that satisfy the hypothesis, but also detect and highlight anomalous behavior within the results:
  - Nodes with unusual temporal patterns (bursts, off-hours activity)
  - Entities that appear in multiple distinct attack chains
  - Relationships with atypical metadata compared to the graph baseline
  - Composite score combining: centrality + frequency of appearance in results + temporal deviation
- Visualization: color gradient or visual indicator that distinguishes "satisfies hypothesis" vs "satisfies hypothesis AND is suspicious"
