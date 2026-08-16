# Reproducible benchmark harness

The performance numbers in the paper come from one command, run the same
way on any machine, so the table is reproducible rather than pasted from a
one-off run. This is WS1.5 of the top-tier plan.

## Run it

```sh
cargo build --release -p graph_hunter_cli
./target/release/graph_hunter_cli bench --runs 30 --seed 42 --format csv --out perf.csv
```

Flags (all optional):

| Flag | Default | Meaning |
|---|---|---|
| `--runs N` | 30 | Repeats per config. ≥30 gives stable p50/p95. |
| `--seed S` | 42 | PRNG seed. Same seed → same graphs. |
| `--format csv\|json` | csv | Output shape. |
| `--out FILE` | stdout | Where to write. |

**Build in `--release`.** Debug DFS is several times slower and not
representative; the harness prints a warning on stderr if it detects a
debug build.

## What it measures — and what it does not

**Measures:** search latency (p50, p95, mean, min, max in µs) versus graph
size, over a fixed set of synthetic Erdős–Rényi and Barabási–Albert graphs
(100–5 000 nodes), plus a structural memory estimate. Single-threaded and
deterministic in graph shape for a given seed.

**Does not measure:** efficacy — step recall, path precision, hits@k.
Those require ground-truth attack labels from the DARPA TC datasets and
belong to WS2. The harness omits them rather than print a number it cannot
back with ground truth.

**`paths_found` is normally 0**, and that is expected. Types are assigned
uniformly at random, so a specific typed 3-step chain almost never closes.
What is timed is the search *work* — start selection, NLF / k-hop /
semi-join pruning, temporal expansion — which the DFS performs in full
whether or not it emits a path. That is also the common case in real
hunting: most hypotheses run and find nothing, and their latency is what
the analyst waits on. Planting attack subgraphs to exercise the emitter is
WS2 work (it needs a ground-truth model).

`memory_bytes_approx` is a structural estimate (`approx_memory`), not
measured RSS. It is labelled as such in every row so no reader mistakes it
for a heap measurement.

## Reproducibility contract

Same seed + same machine → identical graphs (entity/relation counts,
`paths_found`) and comparable latencies. The graph-shape determinism is
pinned by a test (`benchmark::perf_harness_tests`); latencies are
wall-clock and will vary run to run, which is why the table reports a
distribution, not a single number.

## Not yet in the harness (tracked)

- Efficacy metrics (recall/precision/hits@k) — WS2, needs DARPA labels.
- Bootstrap 95% CIs on the mean — p50/p95 are reported instead for now.
- Query-engine baselines (Neo4j / Memgraph / Kùzu) — WS2.5.
- The ordered-CSR successor search and LFTJ paths already exist in the
  engine; this harness exercises the default DFS. Wiring the harness to
  A/B those operators is a follow-up.
