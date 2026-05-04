#!/usr/bin/env bash
# B7 — Profile-Guided Optimization build driver.
#
# Wraps Kobzol's `cargo-pgo` (https://github.com/Kobzol/cargo-pgo) into a
# one-shot driver that produces a PGO-optimized binary from
# core/graph-engine. PGO composes on top of the locked-in `lto = "thin"`
# release profile (see docs/perf/release-profile.md); it does not
# replace it.
#
# The training corpus is the demo scenario test set from scripts/demo.sh
# (the three illustrative paper scenarios). PGO requires a representative
# workload for the profile to be useful — `cargo test` is the wrong
# choice because it exercises non-hot paths. See docs/perf/pgo.md for
# the rationale.
#
# Usage:
#   bash scripts/build-pgo.sh
#
# Exit codes:
#   0 — optimized binary produced
#   1 — missing tooling (cargo-pgo or llvm-profdata) or build failure

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

MANIFEST="core/graph-engine/Cargo.toml"
RELEASE_DIR="core/graph-engine/target/release"
PGO_DIR="core/graph-engine/target/x86_64-pc-windows-msvc/release"

echo "=== B7 PGO build pipeline ==="
echo "Repo: $REPO_ROOT"
echo "Manifest: $MANIFEST"
echo ""

# 1. Verify cargo-pgo. We use `command -v` for portability — `which` is
#    not POSIX and behaves differently on Git Bash vs Linux.
if ! command -v cargo-pgo >/dev/null 2>&1; then
    echo "error: cargo-pgo is not installed." >&2
    echo "" >&2
    echo "Install with:" >&2
    echo "    cargo install cargo-pgo" >&2
    echo "" >&2
    echo "See https://github.com/Kobzol/cargo-pgo for prerequisites." >&2
    exit 1
fi

# 2. PGO requires llvm-profdata to merge raw profile shards.
#    cargo-pgo uses the first `llvm-profdata` it finds on PATH; if a
#    system LLVM install (e.g. /usr/bin, C:/Program Files/LLVM/bin)
#    shadows the rustup one, the profile format may be incompatible
#    with rustc's instrumented output. Force the rustup tool to win
#    by prepending its directory to PATH unconditionally.
rustlib_bin="$(rustc --print sysroot 2>/dev/null)/lib/rustlib/$(rustc -vV 2>/dev/null | awk '/host:/ {print $2}')/bin"
if [[ -x "$rustlib_bin/llvm-profdata" || -x "$rustlib_bin/llvm-profdata.exe" ]]; then
    export PATH="$rustlib_bin:$PATH"
    echo "info: prepended rustup llvm tools to PATH ($rustlib_bin)"
elif command -v llvm-profdata >/dev/null 2>&1; then
    echo "warn: using system llvm-profdata; if cargo-pgo reports format" >&2
    echo "      version mismatches, install the rustup component:" >&2
    echo "          rustup component add llvm-tools-preview" >&2
else
    echo "error: llvm-profdata is not on PATH." >&2
    echo "" >&2
    echo "Install the rustup component:" >&2
    echo "    rustup component add llvm-tools-preview" >&2
    echo "" >&2
    echo "Then re-run this script." >&2
    exit 1
fi

# Capture pre-PGO release size for the delta report at the end.
pre_size=""
if [[ -d "$RELEASE_DIR" ]]; then
    pre_size=$(du -sb "$RELEASE_DIR" 2>/dev/null | awk '{print $1}' || echo "")
fi

echo ""
echo "=== Phase 1: instrumented build (cargo pgo build) ==="
# cargo-pgo runs `cargo metadata` from the current directory and does
# not respect --manifest-path for that step (only for the cargo build
# it wraps). Cd into the crate so metadata resolution works on this
# multi-crate non-workspace tree.
(cd core/graph-engine && cargo pgo build)

echo ""
echo "=== Phase 2: training run via instrumented benches ==="
# cargo-pgo's `bench` subcommand wraps `cargo bench` so the
# benchmark harness is built and executed with the PGO-instrumented
# profile. Profile data lands in
# core/graph-engine/target/pgo-profiles/. We use hunt_latency and
# ingest_throughput because they exercise the matcher hot-path
# and the parser/ingest hot-path respectively — the two regions
# PGO benefits from re-laying out.
(
  cd core/graph-engine && \
  cargo pgo bench -- \
    --bench hunt_latency \
    --bench ingest_throughput \
    -- --warm-up-time 1 --measurement-time 2
) || {
  echo "warn: pgo bench training failed" >&2
  exit 1
}

echo ""
echo "=== Phase 3: optimize build (cargo pgo optimize build) ==="
(cd core/graph-engine && cargo pgo optimize build)

echo ""
echo "=== Done ==="

# cargo-pgo writes the optimized artifacts under the host triple
# directory (target/<triple>/release/). Surface whichever variant
# exists so the operator can locate the binary on Linux or Windows.
echo "Optimized artifacts:"
shopt -s nullglob
found=0
for d in core/graph-engine/target/*/release core/graph-engine/target/release; do
    if [[ -d "$d" ]]; then
        echo "  $d"
        found=1
    fi
done
if (( found == 0 )); then
    echo "  (no release output found — check cargo pgo logs above)"
fi

# Size delta vs pre-PGO release, when both are available. Using `du -sb`
# (apparent size in bytes) keeps the comparison unit-stable across the
# host filesystem.
if [[ -n "$pre_size" && -d "$RELEASE_DIR" ]]; then
    post_size=$(du -sb "$RELEASE_DIR" 2>/dev/null | awk '{print $1}' || echo "")
    if [[ -n "$post_size" && "$pre_size" != "0" ]]; then
        delta=$(awk -v a="$pre_size" -v b="$post_size" \
            'BEGIN { printf "%+.1f", (b - a) * 100.0 / a }')
        echo ""
        echo "Release dir size: $pre_size B -> $post_size B (${delta}%)"
    fi
fi

echo ""
echo "Validate the lift by re-running cargo bench against a 'pre' baseline."
echo "See docs/perf/pgo.md for the full recipe."
