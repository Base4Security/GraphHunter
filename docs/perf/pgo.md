# Profile-Guided Optimization (B7)

## What PGO is

Profile-Guided Optimization is a two-pass compile workflow. The first
pass produces an **instrumented** binary that records per-edge counters
into raw profile shards while it runs a representative workload. Those
shards are merged with `llvm-profdata` into a single profile, and the
second pass re-compiles using that profile to drive inlining, basic-block
layout, register allocation, and branch prediction. The result is a
binary that's usually 5–15% faster on the workload it was trained on,
on top of whatever release optimizations were already in effect.

We drive this through Kobzol's [`cargo-pgo`](https://github.com/Kobzol/cargo-pgo),
which wraps the `RUSTFLAGS=-Cprofile-generate=...` /
`-Cprofile-use=...` dance, the `llvm-profdata merge` step, and the
target-directory bookkeeping into two cargo subcommands.

## How to run it

```bash
bash scripts/build-pgo.sh
```

The script:

1. Verifies `cargo-pgo` is installed and `llvm-profdata` is reachable
   (rustup component `llvm-tools-preview`).
2. Runs `cargo pgo build --manifest-path core/graph-engine/Cargo.toml`
   to produce the instrumented binary.
3. Runs `scripts/demo.sh all` as the training corpus. That executes the
   three illustrative paper scenarios (Sentinel auth, Sysmon spawn,
   generic-CSV exfil), which together hit the matcher, parser, and
   scoring hot paths. If `demo.sh` fails the script falls back to the
   bench harness (`hunt_latency` + `ingest_throughput` with a short
   `measurement-time`) so the profile is still populated.
4. Runs `cargo pgo optimize build --manifest-path core/graph-engine/Cargo.toml`.
5. Prints the path to the optimized artifacts and the size delta vs
   the regular release directory.

Prerequisites:

```bash
cargo install cargo-pgo
rustup component add llvm-tools-preview
```

## Why the demo scenarios are the trainer

PGO's quality is bounded by how representative the training corpus is.
A profile collected from `cargo test` would mostly capture error paths,
fixture setup, and assertion overhead — none of which matter at runtime.
The demo scenarios are the closest thing in-tree to "what the operator
actually does": parse a real log batch, build a temporal graph, run the
matcher, score paths. Re-using `scripts/demo.sh` also means the trainer
evolves whenever we extend the demo set instead of drifting silently.

If you have a recorded production workload, point `cargo pgo run`
at it instead. Anything that exercises the matcher and ingest hot
paths for at least a few thousand events is fine.

## Expected lift

The plan budgets **5–15%** on top of release+LTO for PGO. Validate per
host with:

```bash
# Before:
cargo bench --manifest-path core/graph-engine/Cargo.toml \
    --bench hunt_latency -- --save-baseline pre

# Run the PGO build:
bash scripts/build-pgo.sh

# After (the optimized binary is at target/<triple>/release/):
cargo pgo optimize bench -- --bench hunt_latency \
    -- --baseline pre
```

## Verdict: not used in production today

PGO ran end-to-end successfully on this host (galaxy-book4) with the
rustup `llvm-tools-preview` PATH fix, but its observed lift was
**unstable** across runs. Two training profiles were tried:

| training              | 1K     | 10K    | 100K   |
|-----------------------|--------|--------|--------|
| 2 s measurement-time  | -32.4% | -25.6% | -18.7% |
| 8 s measurement-time  | -30.7% | -13.0% | -11.1% |
| (vs pre-2c2 baseline) |        |        |        |

The "longer training" attempt regressed 10K and 100K versus the
shorter training, which is the opposite of what PGO theory
predicts. The most likely cause: bench noise on this host (the
100K case has been observed at 13–17 ms across consecutive runs of
the *same* binary, ~25% variance) overwhelms PGO's typical 5–15%
lift signal, so we can't tell whether PGO is helping or just
noise-fitting.

**Action:** the non-PGO snapshot + lock-free FrozenNeighborList
pipeline reliably delivers `-21..-33%` vs pre-2c2; PGO's marginal
lift on top is below the noise floor. Skipping PGO in production
until either (a) the host gets a quieter bench environment with
locked CPU frequency, or (b) PGO is re-attempted with multi-run
averaged baselines.

## Observed lift (galaxy-book4, 2026-05-04)

Training corpus: hunt_latency + ingest_throughput benches, 2-second
measurement-time per case. Optimize-build emitted "PGO profile data
was not found for 5044 functions" because the training only sampled
the matcher and ingest hot paths (most of the codebase isn't on those
paths and stays at default release optimization).

`hunt_latency` vs `pre-2c2` baseline (snapshot included):

| size  | non-PGO | PGO     | PGO delta vs non-PGO |
|-------|---------|---------|----------------------|
| 1K    | -25.8%  | -32.4%  | **−7 pp better**     |
| 10K   | -29.2%  | -25.6%  | +4 pp                |
| 100K  | -29.2%  | -18.7%  | +10 pp regression    |

The 100K case regressed under PGO because the training run's
`--measurement-time 2` undersamples the 100K workload's actual code
paths — the profile was dominated by the smaller-case hot paths,
and PGO laid out the binary to favor those. **Action item:** when
running PGO for production, train with longer measurement-time (8s+)
and explicitly include the 100K bench so the profile is balanced.

The 1K case shows where PGO is uncontested (5-7 pp improvement on top
of the snapshot win). For `BlackHat 2026 sub-10 ms @ 100K`, PGO is
not the win — the snapshot + parking_lot path is closer.

## Composition with the locked release profile

The release profile is locked to `lto = "thin"` per the per-host
bisection in [`release-profile.md`](release-profile.md). PGO **composes
on top of that**; it does not replace it. cargo-pgo drives PGO through
`RUSTFLAGS` (`-Cprofile-generate` / `-Cprofile-use`), so no
`Cargo.toml` edits are required and the locked thin-LTO settings stay
in effect for both passes.

If you want the PGO-optimized artifact to also enable `target-cpu=native`,
do **not** assume the bisection's "rejected" verdict carries over. The
bisection was run on a Galaxy Book4 with hybrid P/E cores and AVX-512;
on a uniform-core server the verdict could flip. Re-run
`scripts/bisect-release-profile.sh` on the new host before reintroducing
`-C target-cpu=native`. **PGO's dynamic profile feedback is not a
substitute for that bisection** — PGO improves layout for the binary's
own observed hot paths, but it cannot tell you that the AVX-512 code
your compiler emitted is throttling the E-cores. That's an ISA/uarch
question, and only the per-host bisection answers it.

## Notes for CI

Adding a PGO job to CI is opt-in and out of scope for B7. When we do
add it: cache the merged `.profdata` blob between runs (the training
phase is the slow part), and gate the bench-delta report on a known
host — running PGO inside an unpredictably-sized CI runner produces
noisy "lift" numbers that are not comparable run-to-run.
