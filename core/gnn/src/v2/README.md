# GNN v2 — experimental

**Status:** experimental. Not shipped in production builds.

## What this is

The v2 GNN adds cloud-identity and SaaS-workload context on top of the
stable v1 model. It shares the `k_max=32` subgraph radius but uses a
widened per-node feature vector (`d_node`) to encode attributes the v1
feature extractor doesn't see today.

## Why it's gated

Per ADR-003, v2 is compiled only when `--features gnn-v2-experimental`
is explicitly passed. Without the flag:

- The `v2` Rust module is `#[cfg]`-out — callers can't link against it.
- `load_and_validate_metadata` rejects any sidecar with
  `trained_on = "synthetic"` via `ModelLoadError::UntrainedOnSynthetic`.

With the flag:

- Synthetic-corpus models load, but an accuracy floor of 0.80 still
  applies regardless of the flag.
- `get_health()` (F4.7) reports `{"v2": {"loaded": true, "experimental": true}}`
  so operators can see that scores are coming from an experimental path.

## Current corpus status

`scripts/train_gnn_v2.py` produces models tagged `trained_on = "synthetic"`.
Until a real AAD corpus export replaces the synthetic one, v2 scores
are **not** valid for detection decisions.

Work pending before v2 is production-grade:

1. Real AAD/M365 audit log export into the training corpus.
2. Re-train with the mixed corpus; validation accuracy must clear 0.80
   on a held-out production sample.
3. Update `train_gnn_v2.py` to emit `trained_on: "mixed"` (or
   `"production"`) in the sidecar after that run.
4. Drop the `gnn-v2-experimental` gate from CI release workflows only
   after this is done.

## Loading a model programmatically

```rust
#[cfg(feature = "gnn-v2-experimental")]
use graph_hunter_gnn::v2::load_v2_metadata;

let meta = load_v2_metadata("models/gnn_v2.onnx")?;
println!("loaded v2 model trained on {:?}", meta.trained_on);
```

Errors from the gate surface via `ModelLoadError` — see the rustdoc for
`graph_hunter_gnn::common::model_gate`.

## Related

- ADR-003: `docs/architecture/phase1/ADR/003-gnn-v2-experimental.md`
- Training script: `scripts/train_gnn_v2.py`
- Shared gate: `core/gnn/src/common/model_gate.rs`
