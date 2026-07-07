# GraphHunter — local safety net
#
# Why: GitHub Actions was removed (billing). This Makefile is the local
# replacement so a `make pre-merge` before pushing catches the regressions
# CI used to catch.
#
# Usage:
#   make pre-merge   # Full safety net before pushing. Run before `git push`.
#   make check       # Fast: cargo check --tests on hot crates only.
#   make test        # cargo test on hot crates.
#   make clippy      # cargo clippy on hot crates (warnings as errors).
#   make fmt-check   # Verify rustfmt would not change anything.
#   make layering    # Run the layering guard (core/* → platform/* whitelist).
#   make smoke-bench # Tiny bench run to detect catastrophic ingest regressions.
#   make help        # List targets.
#
# Notes:
# - There is no cargo workspace; each crate is invoked via --manifest-path.
# - HOT_CRATES = the crates that gate correctness (engine, API, binaries).
#   Other crates (gnn, parsers, siem, ...) are checked by `make check-all`.
# - Targets are ordered cheapest → most expensive so `make pre-merge`
#   fails fast on the easy stuff.

SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c

HOT_CRATES := \
	core/graph-engine \
	platform/api \
	apps/cli \
	apps/tauri/src-tauri

ALL_CRATES := \
	core/graph-engine \
	core/gnn \
	core/matcher-ffi \
	platform/api \
	platform/canonical \
	platform/constrained-decode \
	platform/dsl \
	platform/local-llm \
	platform/parsers \
	platform/siem \
	platform/sources \
	platform/vrl \
	apps/cli \
	apps/tauri/src-tauri

CARGO ?= cargo

.PHONY: help pre-merge check check-all test clippy fmt-check layering smoke-bench

help:
	@echo "GraphHunter Makefile targets:"
	@echo "  pre-merge   - Full safety net (layering + check + test) before pushing."
	@echo "  check       - cargo check --tests on hot crates."
	@echo "  check-all   - cargo check --tests on every crate."
	@echo "  test        - cargo test on hot crates (skips long-running benchmark_*)."
	@echo "  test-bench  - Run the in-tree paper-table benchmark_* tests on demand."
	@echo "  clippy      - cargo clippy -D warnings on hot crates."
	@echo "  fmt-check   - Verify rustfmt would not change anything (hot crates)."
	@echo "  layering    - Run scripts/check-layering.sh."
	@echo "  smoke-bench - Tiny ingest bench (1K only) to catch catastrophic regressions."

# `pre-merge` intentionally excludes fmt-check and clippy: the codebase has
# pre-existing fmt drift and clippy warnings that we are not addressing in
# this safety-net PR. Run `make fmt-check` and `make clippy` opt-in when
# touching code you want to keep clean.
pre-merge: layering check test
	@echo ""
	@echo "pre-merge OK - safe to push."

check:
	@for c in $(HOT_CRATES); do \
		echo ">>> cargo check --tests --manifest-path $$c/Cargo.toml"; \
		$(CARGO) check --tests --manifest-path $$c/Cargo.toml; \
	done

check-all:
	@for c in $(ALL_CRATES); do \
		echo ">>> cargo check --tests --manifest-path $$c/Cargo.toml"; \
		$(CARGO) check --tests --manifest-path $$c/Cargo.toml; \
	done

# `--skip benchmark_` excludes the in-tree paper-table tests
# (`benchmark_full_report`, `benchmark_scale_test_er`, etc.) — those are
# long-running #[test]-tagged benches that produce paper data, not
# correctness gates. Run them on demand with `make test-bench`.
test:
	@for c in $(HOT_CRATES); do \
		echo ">>> cargo test --manifest-path $$c/Cargo.toml -- --skip benchmark_"; \
		$(CARGO) test --manifest-path $$c/Cargo.toml -- --skip benchmark_; \
	done

test-bench:
	@echo ">>> cargo test --manifest-path core/graph-engine/Cargo.toml --release benchmark_ -- --nocapture --test-threads=1"
	@$(CARGO) test --manifest-path core/graph-engine/Cargo.toml --release benchmark_ -- --nocapture --test-threads=1

clippy:
	@for c in $(HOT_CRATES); do \
		echo ">>> cargo clippy --tests --manifest-path $$c/Cargo.toml -- -D warnings"; \
		$(CARGO) clippy --tests --manifest-path $$c/Cargo.toml -- -D warnings; \
	done

fmt-check:
	@for c in $(HOT_CRATES); do \
		echo ">>> cargo fmt --manifest-path $$c/Cargo.toml -- --check"; \
		$(CARGO) fmt --manifest-path $$c/Cargo.toml -- --check; \
	done

layering:
	@bash scripts/check-layering.sh

smoke-bench:
	@echo ">>> ingest_throughput smoke (1K only, --warm-up-time 1 --measurement-time 2)"
	@$(CARGO) bench --manifest-path core/graph-engine/Cargo.toml \
		--bench ingest_throughput \
		-- "ingest-sysmon-ndjson/1000$$" --warm-up-time 1 --measurement-time 2
