# ADR-003 — GNN v2 Experimental: feature flag + gate al carga de modelo

- **Fecha**: 2026-04-23
- **Estado**: propuesto
- **Decisión**: aislar GNN v2 detrás de `feature = "gnn-v2-experimental"`, separar "corpus export + training + inference" en tres componentes con contratos claros, y gate al carga del modelo que rechaza archivos no validados.

## Contexto

- `scripts/train_gnn_v2.py:29-31` declara: *"skeleton... has NOT been trained on real AAD data yet"*.
- El modelo resultante `gnn_v2.onnx` es referenciado en producción vía string literal en `graph_hunter_api/src/operations/anomaly.rs:120`.
- Si un binario se shippea con el modelo skeleton cargado, el scorer devuelve probabilidades **arbitrarias** sin fallar visiblemente.
- `graph_hunter_core/src/sources/aad_training_export.rs` (trackeado) exporta el corpus de entrenamiento.
- `graph_hunter_core/src/gnn_bridge.rs` tiene `K_MAX=32, D_NODE=16` (v1). El v2 agrega dimensiones adicionales para cloud-identity context.
- El plan del usuario requiere "marcar experimental lo que es experimental" y "GNN v2 detrás de feature flag".

## Decisión

### D1 — Tres componentes separados con contratos

```
core/gnn/
├─ v1/                          ← estable
│   ├─ bridge.rs               (K_MAX=32, D_NODE=16, 5-class)
│   └─ scorer.rs               (ONNX inference)
├─ v2/                          ← feature = "gnn-v2-experimental"
│   ├─ bridge.rs               (K_MAX=32, D_NODE_V2=>16, 6-class)
│   ├─ scorer.rs
│   └─ README.md               (status: experimental, limitations)
└─ common/                      ← tensor shape, ONNX session, gate
    ├─ model_gate.rs
    └─ tensor_types.rs
```

- `common/model_gate.rs` enforza validación al carga:

```rust
pub struct ModelMetadata {
    pub version: ModelVersion,
    pub trained_on: TrainingCorpus,       // "synthetic" | "production" | "mixed"
    pub validation_accuracy: f32,         // mínimo aceptable: 0.80
    pub class_labels: Vec<String>,
    pub input_shape: TensorShape,
    pub sha256: [u8; 32],
}

pub enum ModelLoadError {
    MissingMetadata,
    UntrainedOnSynthetic,                  // D2
    ValidationAccuracyBelowThreshold { got: f32, min: f32 },
    ShapeMismatch,
    SignatureMismatch,
}

pub fn load_gnn_model(path: &Path) -> Result<GnnSession, ModelLoadError>;
```

### D2 — Gate al carga: rechazar modelos `synthetic`

Un archivo `.onnx` acompaña un `.metadata.json`:

```json
{
  "version": "v2",
  "trained_on": "synthetic",
  "validation_accuracy": 0.42,
  "class_labels": ["benign", "exfiltration", "c2_beacon", "lateral_movement", "privilege_escalation", "credential_attack"],
  "input_shape": { "k_max": 32, "d_node": 16 },
  "sha256": "..."
}
```

- Si `trained_on == "synthetic"` y el feature flag `gnn-v2-experimental` **no** está activo → `ModelLoadError::UntrainedOnSynthetic`.
- Si el flag **sí** está activo, se loggea un warning al startup pero se permite cargar (para desarrollo).
- Si `validation_accuracy < 0.80` → siempre falla la carga, flag o no.

### D3 — Feature flag propagation

```toml
# core/gnn/Cargo.toml
[features]
default = []
ml-scoring = ["dep:ort", "dep:ndarray"]
gnn-v2-experimental = ["ml-scoring"]

# core/graph-engine/Cargo.toml
ml-scoring = ["gnn/ml-scoring"]
gnn-v2-experimental = ["gnn/gnn-v2-experimental"]

# platform/api/Cargo.toml
ml-scoring = ["graph-engine/ml-scoring"]
gnn-v2-experimental = ["graph-engine/gnn-v2-experimental"]
```

- Builds de producción **no** activan `gnn-v2-experimental`. Publicación (BlackHat, release) con v1 únicamente hasta que v2 supere gate.
- Builds de dev/research activan el flag explícitamente.

### D4 — Documentación de estado

- `core/gnn/v2/README.md` declara explícitamente: estado experimental, limitaciones, corpus actual, work pendiente (entrenar con data real AAD).
- `docs/GNN_STRATEGY.md` se actualiza en Fase 5 para alinear con esta ADR.
- Rustdoc:

```rust
#[cfg(feature = "gnn-v2-experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "gnn-v2-experimental")))]
/// **EXPERIMENTAL** — trained on synthetic data, not production-validated.
/// Activating this loads the v2 model with 6-class inference. Do not
/// rely on scores for detection decisions until validation corpus runs
/// accuracy >= 0.80 (see ADR-003 and `core/gnn/v2/README.md`).
pub mod v2 { ... }
```

### D5 — Métricas observables

Agregar al `GraphHunterApi::get_health()`:

```json
{
  "gnn": {
    "v1": { "loaded": true, "version": "1.2.0", "accuracy": 0.87 },
    "v2": { "loaded": false, "reason": "gnn-v2-experimental feature disabled" }
  }
}
```

- MCP `check_connection` y Tauri status panel reflejan el estado del modelo.
- Clientes saben si los scores provienen de v1 o v2.

## Consecuencias positivas

- Imposibilita (por compile-time flag + runtime gate) shipear un binario con modelo skeleton silenciosamente activo.
- Corpus export, training script, y runtime inference quedan desacoplados: cada uno se puede iterar independientemente.
- El día que haya un v3, el patrón es replicable: nuevo módulo, nuevo flag, gate genérico reusable.
- Transparencia hacia el usuario: versión activa visible en el status.

## Consecuencias negativas / costos

- Duplicación aparente de código v1 vs v2 (cada uno con su bridge + scorer). Real; justificado por "tipos fuertes que codifiquen invariantes" del plan del usuario. `common/` comparte lo genérico.
- Un build extra en CI (`--features gnn-v2-experimental`) para asegurar que v2 compila.
- El gate requiere emitir `.metadata.json` junto al `.onnx` al exportar desde training; `train_gnn_v2.py` se adapta.

## Alternativas consideradas

- **Gate solo en runtime, sin feature flag**: rechazado; permite que código v2 entre a builds de producción y corrompa tests.
- **Eliminar v2 hasta que esté entrenado**: rechazado; el training script y el corpus export son progreso real, vale la pena mantener el trabajo visible pero aislado.
- **Un solo módulo `gnn` con `version: u32`**: rechazado; no comunica "experimental" lo suficientemente fuerte, y typestate por versión es más complejo.

## Referencias

- PAIN_POINTS §4 (GNN v2 skeleton)
- CURRENT_STATE §1 (scripts/train_gnn_v2.py status)
- TARGET_ARCHITECTURE §4 (feature flags)
