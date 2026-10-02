# demo_data

Test fixtures and demo datasets. **This directory is only partly
committed**, which is why several tests report `SKIPPED` on a fresh
clone rather than failing.

## What is committed

Small fixtures live here and are versioned. Note that `.gitignore` scopes
the LaTeX `*.log` rule so that `.log` fixtures in this directory are
committable — before that, `git add demo_data/whatever.log` silently did
nothing and the file only ever existed on one machine.

| File | Used by |
|---|---|
| `ambiguous_fields_forti.log` | `platform/api/tests/agentic_ambiguous_fields.rs` |
| `ambiguous_iis_for_llm.log` | LLM field-mapping fixtures |

## What is not committed, and why

Two groups.

**Multi-GB corpora**, deliberately excluded in `.gitignore` — they would
dominate the repository and every clone of it:

| File | Approx. size | Used by |
|---|---:|---|
| `mordor_combined_attacks.json` | ~132 MB | `benchmark_empirical_data_for_paper` (optional branch) |
| `mega_attack_dataset.json` | large | performance work |
| `mega_dataset_1gb.json` | ~1 GB | performance work |

Every test that reads these already checks for their presence and skips
when absent.

**Small fixtures that were never committed.** These are not ignored —
they simply are not in the repository, and nobody noticed because the
tests that need them had been failing (or, worse, failing to *compile*)
for long enough to read as background noise:

| File | Used by |
|---|---|
| `apt_attack_simulation.json` | `demo_data_all_presets_produce_results`, `benchmark_empirical_data_for_paper`, `benchmark_naive_vs_pruned` |
| `sentinel_attack_simulation.json` | `sentinel_demo_data_ingestion_and_hunt`, `benchmark_empirical_data_for_paper` |
| `generic_csv_logs.csv` | `csv_demo_data_loads_successfully` |
| `ambiguous_fields_csv.csv` | `platform/api/tests/agentic_ambiguous_fields.rs` |

These are small enough to belong in the repository. If you have a copy,
committing it turns the corresponding `SKIPPED` back into real coverage.

## How absence is handled

A missing fixture makes a test print

```
SKIPPED: demo_data/<name> is absent — this test did not run.
```

and return. This is a deliberate compromise, and it has a cost worth
stating plainly: **a skipped test is not a passing test.** The suite goes
green while some of it did not run.

The alternative was worse in both directions. Failing kept five tests
permanently red for a missing *input* rather than a broken *behaviour*,
and a suite with permanent red is a suite nobody reads. And
`platform/api/tests/agentic_ambiguous_fields.rs` used `include_str!`,
so an absent fixture was a *compile error* that took every other test in
that file down with it — the worst possible way to learn a test input is
missing.

The notices go to stderr and name the file, so the gap stays visible
instead of turning into a silent green.
