#!/usr/bin/env bash
# F7 — human-facing demo runner.
#
# Wraps the snapshot tests in `platform/api/tests/demo_scenarios.rs` so
# reviewers can reproduce the paper's three illustrative scenarios from
# a single shell invocation. The tests themselves own the tolerances
# (±10 % on path count, ±0.05 on score when scoring is re-enabled); this
# script just surfaces them individually with readable output.
#
# Usage:
#   scripts/demo.sh lateral-movement
#   scripts/demo.sh office-spawn
#   scripts/demo.sh exfil-dns
#   scripts/demo.sh all
#
# Exit code matches the underlying `cargo test` run — non-zero when any
# scenario's assertions fail.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

run_one() {
    local label="$1"
    local test_fn="$2"
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo " demo.sh — $label"
    echo "════════════════════════════════════════════════════════════════"
    cargo test \
        --manifest-path platform/api/Cargo.toml \
        --test demo_scenarios \
        "$test_fn" \
        -- --nocapture
}

case "${1:-all}" in
    lateral-movement)
        run_one "Sentinel SigninLogs → User -[Auth]-> Host" \
            demo_lateral_movement_sentinel
        ;;
    office-spawn)
        run_one "Sysmon → Process -[Spawn]-> Process -[DNS]-> Domain" \
            demo_office_spawn_sysmon
        ;;
    exfil-dns)
        run_one "Generic CSV → Host -[Connect]-> IP" \
            demo_exfil_dns_generic_csv
        ;;
    all)
        cargo test \
            --manifest-path platform/api/Cargo.toml \
            --test demo_scenarios \
            -- --nocapture
        ;;
    -h|--help|help)
        sed -n '1,20p' "$0"
        ;;
    *)
        echo "Unknown scenario: $1" >&2
        echo "Valid: lateral-movement | office-spawn | exfil-dns | all" >&2
        exit 2
        ;;
esac
