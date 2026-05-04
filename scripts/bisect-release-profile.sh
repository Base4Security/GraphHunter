#!/usr/bin/env bash
# A1 — release-profile bisection.
#
# Drives a 3-cell experiment over `[profile.bench]` knobs without
# editing Cargo.toml between cells: each cell exports the relevant
# `CARGO_PROFILE_BENCH_*` (and rustflags) env vars and runs the three
# representative bench suites (hunt_latency, ingest_throughput,
# scoring_path). Criterion stores per-cell results under
# `target/criterion/.../<baseline_id>/` via `--save-baseline`, so we
# can diff cells after the run without re-benching.
#
# We deliberately skip the `lto="fat" + codegen-units=1 + native` cell
# already in the tree: empirical run on 2026-04-28 showed 24–60%
# ingest regression and a 70-min compile time. Documented in
# docs/perf/release-profile.md.
#
# Usage:
#   bash scripts/bisect-release-profile.sh         # run all 3 cells
#   bash scripts/bisect-release-profile.sh cell0   # run a single cell
#
# Output: per-cell criterion baselines named `cell0_default`,
#         `cell1_thin`, `cell2_thin_native`. Compare with:
#   cargo bench --manifest-path core/graph-engine/Cargo.toml \
#       --bench hunt_latency -- --baseline cell0_default

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

MANIFEST="core/graph-engine/Cargo.toml"
BENCHES=("hunt_latency" "ingest_throughput" "scoring_path")
WARM=1
MEASURE=3

run_cell() {
    local name="$1"
    shift
    echo "=================================================="
    echo " Cell: $name"
    echo " Env:  $*"
    echo "=================================================="
    local start
    start=$(date +%s)
    for bench in "${BENCHES[@]}"; do
        echo "--- $bench ($name) ---"
        env "$@" cargo bench --manifest-path "$MANIFEST" --bench "$bench" -- \
            --save-baseline "$name" --warm-up-time "$WARM" --measurement-time "$MEASURE"
    done
    local end=$(date +%s)
    echo "Cell $name finished in $((end - start))s"
}

cell="${1:-all}"

case "$cell" in
    cell0|all)
        # Cell 0: stock release profile. No LTO, codegen-units=16
        # (cargo default), no rustflags.
        run_cell "cell0_default" \
            CARGO_BUILD_RUSTFLAGS=""
        ;;
esac

case "$cell" in
    cell1|all)
        # Cell 1: thin LTO only. Cheap to compile, captures most of
        # the cross-crate inlining benefit.
        run_cell "cell1_thin" \
            CARGO_PROFILE_BENCH_LTO=thin \
            CARGO_BUILD_RUSTFLAGS=""
        ;;
esac

case "$cell" in
    cell2|all)
        # Cell 2: thin LTO + target-cpu=native. The candidate winner.
        # AVX2/AVX-512 ISA lift, but watch ingest (simd-json's AVX-512
        # path can throttle hybrid P/E core CPUs).
        run_cell "cell2_thin_native" \
            CARGO_PROFILE_BENCH_LTO=thin \
            CARGO_BUILD_RUSTFLAGS="-C target-cpu=native"
        ;;
esac

echo "=================================================="
echo " Bisection done. Compare baselines with:"
echo "   cargo bench --manifest-path $MANIFEST --bench <suite> -- --baseline cell0_default"
echo " Then update docs/perf/release-profile.md with the geomean winner."
echo "=================================================="
