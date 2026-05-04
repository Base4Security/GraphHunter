#!/usr/bin/env bash
# F8 — generate docs/paper/data/bench-table.md from criterion's JSON
# output.
#
# Criterion writes its per-benchmark stats to
# target/criterion/<group>/<label>/new/estimates.json. This script
# walks those files for the 5 canonical benchmark binaries
# (hunt_latency, dedup_throughput, ingest_throughput, matching_hops,
# scoring_path), extracts the point estimate + 95% CI for the median,
# and emits a Markdown table. Paper §results cites this file directly.
#
# Usage:
#   scripts/bench-report.sh            # read target/criterion
#   scripts/bench-report.sh path/to    # read a non-default dir
#
# Preconditions: run `cargo bench` for the five suites first. Missing
# suites are reported as "— (not run)" rather than failing, so a
# partial run still produces a useful diff.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CRITERION_DIR="${1:-core/graph-engine/target/criterion}"
OUT_DIR="docs/paper/data"
OUT_FILE="$OUT_DIR/bench-table.md"

cd "$REPO_ROOT"
mkdir -p "$OUT_DIR"

# Format nanoseconds as a human-readable duration. Keeps three
# significant digits so reviewers comparing tables across releases
# can see sub-percent drifts.
fmt_time() {
    local ns="$1"
    awk -v n="$ns" 'BEGIN {
        if (n >= 1e9)      printf "%.3f s",  n/1e9
        else if (n >= 1e6) printf "%.3f ms", n/1e6
        else if (n >= 1e3) printf "%.3f µs", n/1e3
        else               printf "%.0f ns", n
    }'
}

# Walk criterion's tree and emit `group | label | median_ns | lo_ns | hi_ns`
# lines, which we then post-process into a Markdown table.
emit_rows() {
    if [[ ! -d "$CRITERION_DIR" ]]; then
        return 0
    fi
    # Criterion layout: $CRITERION_DIR/<group>/<label>/new/estimates.json
    find "$CRITERION_DIR" -type f -path '*/new/estimates.json' | while IFS= read -r est; do
        # Derive group + label from the path; skip the `report/` aggregates.
        local parent label group
        parent="$(dirname "$(dirname "$est")")"
        label="$(basename "$parent")"
        group="$(basename "$(dirname "$parent")")"
        if [[ "$group" == "report" || "$label" == "report" ]]; then
            continue
        fi
        # estimates.json nests median.{confidence_interval, point_estimate,
        # standard_error} — we want median's CI lo/hi and point_estimate.
        # jq isn't guaranteed on the dev box so use awk: split at `"median":{`,
        # take the tail, then extract the three fields in order.
        local point lo hi
        local tail
        tail=$(awk -v RS='"median":' 'NR==2 {print; exit}' "$est")
        lo=$(echo "$tail" | grep -oE '"lower_bound":[0-9.eE+-]+' \
                | head -1 | grep -oE '[0-9.eE+-]+$' || echo "")
        hi=$(echo "$tail" | grep -oE '"upper_bound":[0-9.eE+-]+' \
                | head -1 | grep -oE '[0-9.eE+-]+$' || echo "")
        point=$(echo "$tail" | grep -oE '"point_estimate":[0-9.eE+-]+' \
                | head -1 | grep -oE '[0-9.eE+-]+$' || echo "")
        if [[ -z "$point" ]]; then
            continue
        fi
        echo "$group|$label|$point|${lo:-$point}|${hi:-$point}"
    done | sort
}

{
    echo "# Benchmark results"
    echo ""
    echo "Source: \`target/criterion\` (criterion 0.5 estimates.json)."
    echo "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ') by \`scripts/bench-report.sh\`."
    echo ""
    echo "Values are **median** wall-time per iteration with the 95% CI."
    echo "Run \`cargo bench --manifest-path core/graph-engine/Cargo.toml\` first."
    echo ""
    echo "| Benchmark | Case | Median | 95% CI |"
    echo "|-----------|------|-------:|:-------|"
    while IFS='|' read -r group label point lo hi; do
        [[ -z "$group" ]] && continue
        med=$(fmt_time "$point")
        lo_f=$(fmt_time "$lo")
        hi_f=$(fmt_time "$hi")
        echo "| $group | $label | $med | [$lo_f, $hi_f] |"
    done < <(emit_rows)
    echo ""
    echo "## Suites expected"
    echo ""
    echo "- \`hunt_latency\` — matcher wall-time for 1-hop spray across |V| ∈ {1K, 10K, 100K}."
    echo "- \`dedup_throughput\` — \`score_and_paginate_paths\` on redundant path sets."
    echo "- \`ingest_throughput\` — \`SysmonJsonParser.parse()\` on 1K / 10K / 50K NDJSON events."
    echo "- \`matching_hops\` — \`search_temporal_pattern\` for 2/3/4-hop patterns."
    echo "- \`scoring_path\` — \`AnomalyScorer.score_path\` over paths of length 1..4."
    echo ""
    echo "> Missing rows indicate that bench was not run on this host;"
    echo "> re-run \`cargo bench\` to populate."
} > "$OUT_FILE"

echo "Wrote $OUT_FILE"
