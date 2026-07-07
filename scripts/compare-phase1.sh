#!/usr/bin/env bash
# Phase-1 coordinator helper — compares the `phase1` Criterion baseline
# (mimalloc + SmallVec + hugepages stub + PGO scripts on top of locked
# thin-LTO) against the A1 `cell1_thin` baseline.
#
# Usage: bash scripts/compare-phase1.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

CRIT="core/graph-engine/target/criterion"
SUITES=("user-auth-ip" "ingest-sysmon-ndjson" "score-path")

median_ns() {
    local file="$1"
    [[ -f "$file" ]] || { echo ""; return; }
    awk -v RS='"median":' 'NR==2 {print; exit}' "$file" \
        | grep -oE '"point_estimate":[0-9.eE+-]+' \
        | head -1 \
        | grep -oE '[0-9.eE+-]+$'
}

mapfile -t PAIRS < <(
    if [[ ! -d "$CRIT" ]]; then exit 0; fi
    find "$CRIT" -type d -name "phase1" 2>/dev/null \
        | while read -r dir; do
            label="$(basename "$(dirname "$dir")")"
            group="$(basename "$(dirname "$(dirname "$dir")")")"
            echo "$group|$label"
        done | sort -u
)

if [[ "${#PAIRS[@]}" -eq 0 ]]; then
    echo "No phase1 baselines found under $CRIT — run the coordinator bench first."
    exit 1
fi

printf "%-22s %-12s %14s %14s %10s\n" "group" "label" "cell1_thin" "phase1" "ratio"
declare -A SUM_LOG COUNT

for pair in "${PAIRS[@]}"; do
    group="${pair%%|*}"
    label="${pair##*|}"
    base=$(median_ns "$CRIT/$group/$label/cell1_thin/estimates.json")
    p1=$(median_ns "$CRIT/$group/$label/phase1/estimates.json")

    r=""
    if [[ -n "$base" && -n "$p1" ]]; then
        r=$(awk -v a="$p1" -v b="$base" 'BEGIN { printf "%.3f", a/b }')
    fi

    printf "%-22s %-12s" "$group" "$label"
    for v in "$base" "$p1"; do
        if [[ -z "$v" ]]; then printf " %14s" "—"
        else printf " %14s" "$(awk -v n="$v" 'BEGIN {
            if (n>=1e9) printf "%.3fs", n/1e9
            else if (n>=1e6) printf "%.3fms", n/1e6
            else if (n>=1e3) printf "%.3fus", n/1e3
            else printf "%.0fns", n
        }')"
        fi
    done
    printf " %10s\n" "${r:-—}"

    bucket=""
    for s in "${SUITES[@]}"; do
        if [[ "$group" == *"$s"* ]] || [[ "$group" == "$s" ]]; then bucket="$s"; break; fi
    done
    [[ -z "$bucket" ]] && bucket="other"

    if [[ -n "$r" ]]; then
        SUM_LOG[$bucket]=$(awk -v s="${SUM_LOG[$bucket]:-0}" -v r="$r" 'BEGIN { printf "%.6f", s + log(r) }')
        COUNT[$bucket]=$(( ${COUNT[$bucket]:-0} + 1 ))
    fi
done

echo
echo "Per-suite geomean ratio (phase1 vs cell1_thin; <1.0 = faster):"
for bucket in "${!COUNT[@]}"; do
    g=$(awk -v s="${SUM_LOG[$bucket]:-0}" -v n="${COUNT[$bucket]:-0}" 'BEGIN { if (n>0) printf "%.3f", exp(s/n); else printf "—" }')
    printf "  %-25s phase1/cell1_thin = %s\n" "$bucket" "$g"
done
