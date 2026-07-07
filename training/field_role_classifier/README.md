# Field-Role Classifier — Training Pipeline

M6.d scaffold. Documents the offline weak-supervision pipeline that
trains a small transformer to vote on `(FieldRole, EntityType)` for
unknown field names. Today the runtime path uses
`graph_hunter_core::mapping_library::MappingLibraryClassifier` (a pure
look-up over approved library entries) — the trained checkpoint
becomes a *second* classifier that wins ties on names absent from the
library, exposed through the same `FieldRoleClassifier` trait so the
runtime swap is additive.

## Why this exists

The heuristic in `graph_hunter_core::field_preview::suggest_entity_type_with_source`
covers names with obvious English keywords (`username`, `src_ip`,
`process_name`, etc.) and value-regex hits (IPv4, MD5, …). It misses:

- Localized headers (`usuario`, `procesamiento`, `direccion_origen`).
- Vendor-specific field names that aren't in the catalog
  (`ev_actor`, `evt.principal`, `subject_user_sid`).
- Names whose meaning only becomes clear in context with their
  sample values (a column called `id` carrying email strings).

The trained classifier sees `(field_name, sample_values)` and emits a
`(role, entity_type, confidence)` vote. The preview pipeline only
adopts it when confidence ≥ `CLASSIFIER_MIN_CONFIDENCE` (0.6) and the
heuristic returned no canonical match.

## Pipeline stages

| Step | Script             | Purpose                                                                                              |
|-----:|--------------------|------------------------------------------------------------------------------------------------------|
| 1    | `extract.py`       | Read `<data>/mapping_library/mappings.jsonl` → `(field_name, sample_values, role, entity_type)` rows |
| 2    | `weak_label.py`    | Augment with weak labels from the existing heuristic + canonical catalog                             |
| 3    | `train.py`         | Fine-tune a small transformer (default: `distilbert-base-multilingual-cased`)                        |
| 4    | `eval.py`          | Held-out F1 vs the heuristic baseline (target ≥ +10 pp F1)                                           |
| 5    | `export_onnx.py`   | Export to ONNX so the runtime can load it without PyO3                                               |

## Quickstart

```bash
cd training/field_role_classifier
python -m venv .venv && source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt

python extract.py --library "$LOCALAPPDATA/GraphHunter/mapping_library/mappings.jsonl" \
                  --out data/raw.jsonl
python weak_label.py --in data/raw.jsonl --out data/labelled.jsonl
python train.py     --in data/labelled.jsonl --out checkpoints/v1
python eval.py      --checkpoint checkpoints/v1 --report eval.txt
python export_onnx.py --checkpoint checkpoints/v1 --out checkpoints/v1/model.onnx
```

The `extract.py` script and friends are scaffolded as TODO files in
this directory; they're stubs because the data input — a
`mappings.jsonl` populated by analyst-approved drafts — only exists
once a real reviewer workflow has been running for a while. Until then
the runtime path uses the look-up classifier and this directory just
documents the offline contract.

## Acceptance bar

Per the M6 plan: the trained classifier must beat the heuristic
baseline on a held-out set of ≥ 500 fields by **≥ 10 pp F1**. Eval
report lands at `eval.txt` and is committed as the canonical record
when a checkpoint is promoted.
