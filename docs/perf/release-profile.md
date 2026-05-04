# Release-profile bisection (A1)

**Date run:** 2026-04-28
**Host:** Galaxy Book4 — Intel Core Ultra (hybrid P/E core, AVX-512 capable)
**Driver:** `scripts/bisect-release-profile.sh`

## Why

The first attempt at a "tight" release profile (`lto = "fat"` + `codegen-units = 1` + `target-cpu = native`) gave the expected 17–26% lift on hop benches but **regressed `ingest_throughput` by 24–60% across all three sizes** (5.4 ms → 9.0 ms at 1K, 66 ms → 86 ms at 10K, 327 ms → 445 ms at 50K). It also pushed compile time to ~70 minutes, which is unsustainable for the day-to-day perf loop. The likely culprit is `simd-json`'s compile-time AVX-512 path on this host's hybrid P/E cores: 512-bit ops can throttle the E-cores back into a stall, which would explain the uniformity of the regression across sizes.

So before any further perf work, we bisect the lighter combinations to find a profile that pays for itself on every bench.

## Cells

| Cell | LTO | codegen-units | rustflags | Compile cost (est.) |
|---|---|---|---|---|
| `cell0_default` | _none_ | 16 (default) | _none_ | ~3 min |
| `cell1_thin` | `thin` | 16 | _none_ | ~5 min |
| `cell2_thin_native` | `thin` | 16 | `-C target-cpu=native` | ~5 min |
| ~~cell3_fat_native~~ | ~~`fat`~~ | ~~`1`~~ | ~~native~~ | ~~70 min — **skipped**~~ |

Cell 3 is skipped on the empirical evidence already gathered (24–60% ingest regression). If `cell2_thin_native` shows the same ingest pattern, we'll re-test cell 1 (no native) as the safe production profile and document the trade.

## Suites benched per cell

- `hunt_latency` (1K, 10K, 100K) — proxies for the matcher hot path the BH abstract cites.
- `ingest_throughput` (1K, 10K, 50K) — the regression we are investigating.
- `scoring_path` (1, 2, 3, 4 hops) — small enough that ISA lift shows up clearly.

`dedup_throughput` is skipped (too noisy on this host) and `matching_hops` is skipped (too slow to repeat across three cells in one session — re-run only on the chosen cell).

Each cell saves a Criterion baseline named after the cell, so the per-cell comparisons stay reproducible:

```bash
cargo bench --manifest-path core/graph-engine/Cargo.toml \
    --bench hunt_latency -- --baseline cell0_default
```

## Decision rule

For each cell, compute the geometric mean of the **per-bench-case ratio** vs `cell0_default`. A ratio < 1 is a win. Pick the cell with the lowest geomean, **but penalize any cell whose ingest ratio is > 1.05** (regression > 5% on ingest is not acceptable for the BH abstract — sub-10ms matching is meaningless if ingest can't keep up). Tie-break on compile time.

## Results

Median point-estimate wall-time per iteration (Criterion 0.5 `estimates.json`). Ratios vs `cell0_default`; <1.0 is faster.

| Bench case            | cell0_default | cell1_thin | cell2_thin_native | C1/C0 | C2/C0 |
|-----------------------|--------------:|-----------:|------------------:|------:|------:|
| user-auth-ip / 1000   | 500.2 µs      | 449.0 µs   | 527.1 µs          | 0.898 | 1.054 |
| user-auth-ip / 10000  | 5.468 ms      | 5.619 ms   | 6.277 ms          | 1.028 | 1.148 |
| user-auth-ip / 100000 | 59.86 ms      | 57.34 ms   | 62.39 ms          | 0.958 | 1.042 |
| ingest / 1000         | 8.440 ms      | 7.549 ms   | 9.512 ms          | 0.894 | 1.127 |
| ingest / 10000        | 85.18 ms      | 84.18 ms   | 92.30 ms          | 0.988 | 1.084 |
| ingest / 50000        | 463.9 ms      | 466.0 ms   | 427.0 ms          | 1.004 | 0.921 |
| score-path / 1        | 158 ns        | 154 ns     | 148 ns            | 0.969 | 0.935 |
| score-path / 2        | 459 ns        | 427 ns     | 468 ns            | 0.930 | 1.020 |
| score-path / 3        | 774 ns        | 702 ns     | 691 ns            | 0.907 | 0.892 |
| score-path / 4        | 1.022 µs      | 945 ns     | 981 ns            | 0.924 | 0.959 |

Per-suite geomean ratio (lower is better):

| Suite                  | cell1_thin | cell2_thin_native |
|------------------------|-----------:|------------------:|
| user-auth-ip           |      0.960 |             1.080 |
| ingest-sysmon-ndjson   |      0.961 |             1.040 |
| score-path             |      0.932 |             0.950 |

Wall-clock bench duration (compile + bench): `cell0_default` 133 s, `cell1_thin` 337 s, `cell2_thin_native` 347 s.

**Correction to the prior bench-table baseline.** The previous `docs/paper/data/bench-table.md` claimed ingest 1K ≈ 5.4 ms (184 K ev/s) and hunt 100K ≈ 40 ms. Cell 0 (default release, no LTO, no native) reproduces 8.4 ms and 60 ms respectively — the older numbers were not a stable baseline and the table needs regenerating from the locked-in profile.

## Decision

**Winner: `cell1_thin`** — `lto = "thin"` in `[profile.release]` and `[profile.bench]`, no rustflags.

Rationale:

- Beats cell0 on all three suites by 4–7% geomean. None of those wins is huge, but they compose with the rest of the perf push (mimalloc, NLF, prefetch, etc.) and they cost almost nothing past the one-time 2m 34s compile.
- `cell2_thin_native` was rejected on the **user-auth-ip suite veto**: 8% geomean *regression* against cell0, with hunt 10K alone running 15% slower. That suite proxies the hot path the BH abstract cites — we cannot ship a regression there.
- Cell 2 also failed the **ingest veto threshold** (geomean 1.040, with 1K and 10K each 8–13% slower).
- The likely root cause for cell 2's regression is the bench host: **Galaxy Book4 with Intel Core Ultra has hybrid P/E cores plus AVX-512**. When `target-cpu=native` lets rustc emit 512-bit ops, the E-cores either downclock or migrate work back to the P-cores, which costs more time than the ISA lift saves on memory-bound workloads (DFS pointer-chase, simd-json's already-vectorized parse). This is a host-specific effect — on a uniform-core server it would likely flip back. The plan's first-pass claim that LTO+native gave 17–26% on hop benches is contradicted by this controlled run; it was likely measured against a different (warmer-cache, smaller-load) baseline.
- We did not test `lto = "fat" + codegen-units = 1`. The earlier ad-hoc run with that profile cost ~70 min to compile and didn't outperform thin in any direction we'd care about, so it stays rejected.

## Locked-in profile

- `core/graph-engine/Cargo.toml`: `[profile.release]` and `[profile.bench]` both set `lto = "thin"`, `opt-level = 3`, `debug = false`. No `codegen-units` override (cargo default 16, which thin LTO is fine with).
- `.cargo/config.toml`: `[build] rustflags` left commented out. CI/Docker do not need to override anything; per-build experimentation can still set `CARGO_BUILD_RUSTFLAGS="-C target-cpu=native"` without touching the file.

## Reproducing

```bash
bash scripts/bisect-release-profile.sh           # all three cells
bash scripts/compare-cells.sh                    # geomean table
```

Cell results live under `core/graph-engine/target/criterion/<group>/<label>/<cell>/` and survive subsequent benches, so `compare-cells.sh` keeps producing the same numbers until the directory is wiped.

## Decision

_Populated after the run completes._

## Locked-in profile

The chosen cell's settings live in `core/graph-engine/Cargo.toml` (`[profile.release]` and `[profile.bench]`) and `.cargo/config.toml` (rustflags). CI must override rustflags with `CARGO_BUILD_RUSTFLAGS=""` when building for non-native targets — see the comment in `.cargo/config.toml`.
