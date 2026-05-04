#!/usr/bin/env bash
# A1 helper — compare baselines saved by bisect-release-profile.sh.
#
# Reads `target/criterion/<group>/<label>/<baseline>/estimates.json` for
# each cell and prints a per-bench-case ratio table plus a per-cell
# geomean across the three suites (hunt_latency, ingest_throughput,
# scoring_path). The cell with the lowest geomean wins, subject to the
# ingest-regression veto documented in docs/perf/release-profile.md.
#
# Usage: bash scripts/compare-cells.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

CRIT="core/graph-engine/target/criterion"
BASELINES=("cell0_default" "cell1_thin" "cell2_thin_native")
SUITES=("user-auth-ip" "ingest-sysmon-ndjson" "score-path")

# Extract median point estimate from an estimates.json file.
# Same awk/grep approach scripts/bench-report.sh uses, since jq is not
# guaranteed on this dev box.
median_ns() {
    local file="$1"
    [[ -f "$file" ]] || { echo ""; return; }
    awk -v RS='"median":' 'NR==2 {print; exit}' "$file" \
        | grep -oE '"point_estimate":[0-9.eE+-]+' \
        | head -1 \
        | grep -oE '[0-9.eE+-]+$'
}

# Collect every (group,label) pair that has a cell0 baseline.
mapfile -t PAIRS < <(
    if [[ ! -d "$CRIT" ]]; then exit 0; fi
    find "$CRIT" -type d -name "cell0_default" 2>/dev/null \
        | while read -r dir; do
            label="$(basename "$(dirname "$dir")")"
            group="$(basename "$(dirname "$(dirname "$dir")")")"
            echo "$group|$label"
        done | sort -u
)

if [[ "${#PAIRS[@]}" -eq 0 ]]; then
    echo "No cell0_default baselines found under $CRIT — run cell0 first."
    exit 1
fi

printf "%-22s %-18s" "group" "label"
for b in "${BASELINES[@]}"; do printf " %14s" "$b"; done
printf " %14s %14s\n" "ratio_c1" "ratio_c2"

declare -A SUM_LOG_C1 COUNT_C1 SUM_LOG_C2 COUNT_C2

for pair in "${PAIRS[@]}"; do
    group="${pair%%|*}"
    label="${pair##*|}"
    c0=$(median_ns "$CRIT/$group/$label/cell0_default/estimates.json")
    c1=$(median_ns "$CRIT/$group/$label/cell1_thin/estimates.json")
    c2=$(median_ns "$CRIT/$group/$label/cell2_thin_native/estimates.json")

    r1=""; r2=""
    if [[ -n "$c0" && -n "$c1" ]]; then
        r1=$(awk -v a="$c1" -v b="$c0" 'BEGIN { printf "%.3f", a/b }')
    fi
    if [[ -n "$c0" && -n "$c2" ]]; then
        r2=$(awk -v a="$c2" -v b="$c0" 'BEGIN { printf "%.3f", a/b }')
    fi

    printf "%-22s %-18s" "$group" "$label"
    for v in "$c0" "$c1" "$c2"; do
        if [[ -z "$v" ]]; then printf " %14s" "—"
        else printf " %14s" "$(awk -v n="$v" 'BEGIN {
            if (n>=1e9) printf "%.3fs", n/1e9
            else if (n>=1e6) printf "%.3fms", n/1e6
            else if (n>=1e3) printf "%.3fus", n/1e3
            else printf "%.0fns", n
        }')"
        fi
    done
    printf " %14s %14s\n" "${r1:-—}" "${r2:-—}"

    # Bucket suite for geomean. Use the suite stem matched against the
    # group name.
    bucket=""
    for s in "${SUITES[@]}"; do
        if [[ "$group" == *"$s"* ]] || [[ "$group" == "$s" ]]; then
            bucket="$s"
            break
        fi
    done
    [[ -z "$bucket" ]] && bucket="other"

    if [[ -n "$r1" ]]; then
        SUM_LOG_C1[$bucket]=$(awk -v s="${SUM_LOG_C1[$bucket]:-0}" -v r="$r1" 'BEGIN { printf "%.6f", s + log(r) }')
        COUNT_C1[$bucket]=$(( ${COUNT_C1[$bucket]:-0} + 1 ))
    fi
    if [[ -n "$r2" ]]; then
        SUM_LOG_C2[$bucket]=$(awk -v s="${SUM_LOG_C2[$bucket]:-0}" -v r="$r2" 'BEGIN { printf "%.6f", s + log(r) }')
        COUNT_C2[$bucket]=$(( ${COUNT_C2[$bucket]:-0} + 1 ))
    fi
done

echo
echo "Per-suite geomean ratio (cell vs cell0_default; <1.0 = faster):"
all_buckets=$(echo "${!COUNT_C1[@]} ${!COUNT_C2[@]}" | tr ' ' '\n' | sort -u)
for bucket in $all_buckets; do
    g1=$(awk -v s="${SUM_LOG_C1[$bucket]:-0}" -v n="${COUNT_C1[$bucket]:-0}" 'BEGIN { if (n>0) printf "%.3f", exp(s/n); else printf "—" }')
    g2=$(awk -v s="${SUM_LOG_C2[$bucket]:-0}" -v n="${COUNT_C2[$bucket]:-0}" 'BEGIN { if (n>0) printf "%.3f", exp(s/n); else printf "—" }')
    printf "  %-25s cell1=%s  cell2=%s\n" "$bucket" "$g1" "$g2"
done
echo
echo "Pick the cell with the lowest overall geomean,"
echo "but veto any cell whose ingest geomean > 1.05 (>5% regression)."
