#!/usr/bin/env bash
# Perf bisection harness for the graph-context enricher (Task 18).
#
# Runs the bisection test once with GH_MCP_ENRICH=off (baseline) and once
# with GH_MCP_ENRICH=on (treatment). Each run records p50/p95 latency
# per tool call and total tokens. The merge gate (enforced by the test):
#   - enrich p95 overhead per tool call < 300 ms
#   - total token delta < 15 %
#
# Methodology comes from feedback_bench_methodology: bisect via env vars,
# never by editing code paths.

set -euo pipefail

cd "$(dirname "$0")/../platform/mcp"

echo "=== baseline (GH_MCP_ENRICH=off) ==="
PERF_BISECT=1 GH_MCP_ENRICH=off npm run test:contract -- --test-name-pattern bisection

echo "=== treatment (GH_MCP_ENRICH=on) ==="
PERF_BISECT=1 GH_MCP_ENRICH=on  npm run test:contract -- --test-name-pattern bisection
