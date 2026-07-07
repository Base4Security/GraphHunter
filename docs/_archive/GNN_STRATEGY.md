# GNN Strategy: Datasets, Models & Size Estimates

> Graph Hunter — Feeding the GNN with real-world data

## 1. Current State

| Component | Status | Details |
|-----------|--------|---------|
| `gnn_bridge.rs` | Done | k-hop BFS, 32 nodes max, 16-dim features → **1536-float input tensor** |
| `npu_scorer.rs` | Done | ONNX Runtime (`ort` 2.0.0-rc.11), DirectML + CPU, 5-class output |
| `provenance_gcn.onnx` | Placeholder | **15 KB** — toy model, not trained on real data |
| Tauri + React UI | Done | Load model, configure k-hops, compute scores, W5 weight slider |

**Input shape:** `[1, 1536]` → `[K_MAX × D_NODE] + [K_MAX × K_MAX]` = `[512] + [1024]`
**Output shape:** `[1, 5]` → `[Benign, Exfiltration, C2Beacon, LateralMovement, PrivilegeEscalation]`

---

## 2. Target Datasets

### Tier 1 — Provenance Graphs (direct fit)

Estos datasets ya modelan entidades y relaciones de sistema, alineados con nuestro modelo `Entity`/`Relation`.

| Dataset | Source | Size (raw) | Format | Entities | Attack Types | Link |
|---------|--------|-----------|--------|----------|-------------|------|
| **DARPA TC E3 (CADETS)** | DARPA | ~20 GB | JSON CDM | Process, File, Socket, Pipe | APT: backdoors, data theft, lateral movement | [GitHub](https://github.com/darpa-i2o/Transparent-Computing) |
| **DARPA TC E5** | DARPA | ~50 GB | JSON CDM | Process, File, NetFlow, Memory | APT multi-stage, Firefox exploits, phishing | [GitHub](https://github.com/darpa-i2o/Transparent-Computing) |
| **DARPA OpTC** | DARPA/IARPA | ~1 TB | JSON | 1000 hosts, all OS events | Red team APT over 2 weeks | [IEEE DataPort](https://ieee-dataport.org/open-access/operationally-transparent-cyber-optc) |
| **StreamSpot** | SBU | ~500 MB | Edge streams | Typed system entities | 5 attack scenarios (drive-by, phishing, etc.) | [GitHub](https://github.com/sbustreamspot) |

**Recomendado para empezar: DARPA TC E3 (CADETS)**
- Tamaño manejable (~20 GB raw, ~2 GB procesado en grafos)
- Ya tiene ground truth (timestamps de ataques del red team)
- El proyecto MAGIC ya lo tiene preprocesado para GNN

### Tier 2 — Network Flow (requieren conversión a grafo)

| Dataset | Size | Records | Classes | Conversión necesaria |
|---------|------|---------|---------|---------------------|
| **UNSW-NB15** | ~2 GB | 2.5M | 10 ataques | IP→IP flow graphs, port mapping to services |
| **CIC-IDS-2017** | ~8 GB | Millones | 24 ataques | Session-based temporal graphs |

Útiles como **dataset complementario** para entrenar la detección de patrones de red (C2 beacon, exfiltración), pero requieren pipeline de conversión IP-flow → knowledge-graph.

### Tier 3 — Proyectos con código + datos preprocesados

| Proyecto | Dataset base | Formato GNN-ready | Lo que aporta |
|----------|--------------|--------------------|---------------|
| **[MAGIC](https://github.com/FDUDSDE/MAGIC)** | DARPA TC E3/E5 | PyG `Data` objects | Grafos ya particionados, labels por nodo, código de entrenamiento |
| **[threaTrace](https://github.com/threaTrace-detector/threaTrace)** | DARPA TC E3 | NetworkX → DGL | Detección node-level, código GCN completo |
| **[PPT-GNN](https://arxiv.org/abs/2406.13365)** | CICIDS/UNSW | Spatio-temporal snapshots | Pre-training self-supervised (sin labels) |

---

## 3. Model Architecture Options

### Option A: GCN Ligero (recomendado para v1)

```
Input [1, 1536]
  → Linear(1536, 256) + ReLU
  → Linear(256, 128) + ReLU
  → Linear(128, 64) + ReLU
  → Linear(64, 5) + Softmax
Output [1, 5]
```

Un MLP que recibe los features ya agregados por nuestro `gnn_bridge.rs`.
El message-passing (agregación de vecinos) lo hace Rust nativamente en la extracción BFS.

### Option B: GCN con Message-Passing en ONNX

```
Input: node_features [32, 16], adjacency [32, 32]
  → GCN Layer 1: A·X·W₁ [32, 64] + ReLU
  → GCN Layer 2: A·H₁·W₂ [32, 32] + ReLU
  → Global Mean Pool → [1, 32]
  → Linear(32, 5) + Softmax
Output [1, 5]
```

Requiere exportar MatMul + scatter como ops estándar de ONNX (viable, pero más frágil).

### Option C: GAT (Graph Attention Network)

```
Input: node_features [32, 16], adjacency [32, 32]
  → GAT Layer (4 heads): attention-weighted aggregation [32, 64]
  → GAT Layer (4 heads): [32, 32]
  → Global Attention Pool → [1, 32]
  → Linear(32, 5) + Softmax
Output [1, 5]
```

Mayor capacidad expresiva pero difícil de exportar a ONNX puro (attention masking dinámico).

### Option D: Transformer-style (futuro)

Para un modelo pre-entrenado à la PPT-GNN. Parámetros en el rango de millones.
Se justifica solo con datasets masivos (OpTC).

---

## 4. Size Estimates

### 4.1 Model Weight (ONNX file)

| Architecture | Parameters | Size (FP32) | Size (FP16) | Size (INT8) |
|-------------|-----------|-------------|-------------|-------------|
| **Option A: MLP** | ~435K | **1.7 MB** | 870 KB | 435 KB |
| **Option B: GCN 2-layer** | ~75K | **300 KB** | 150 KB | 75 KB |
| **Option C: GAT 2-layer** | ~150K | **600 KB** | 300 KB | 150 KB |
| Option B ampliado (4 capas) | ~500K | 2.0 MB | 1.0 MB | 500 KB |
| Option D: Transformer | ~5-50M | 20-200 MB | 10-100 MB | 5-50 MB |

**Desglose Option A (MLP):**

```
Linear(1536, 256):  1536 × 256 + 256 bias = 393,472 params
Linear(256, 128):    256 × 128 + 128 bias =  32,896 params
Linear(128, 64):     128 ×  64 +  64 bias =   8,256 params
Linear(64, 5):        64 ×   5 +   5 bias =     325 params
─────────────────────────────────────────────────────────────
Total:                                       434,949 params
× 4 bytes (FP32):                           1,739,796 bytes ≈ 1.7 MB
+ ONNX overhead (~5%):                              ≈ 1.8 MB
```

**Desglose Option B (GCN 2-layer):**

```
W₁ [16, 64]:          16 × 64 + 64 =   1,088 params
W₂ [64, 32]:          64 × 32 + 32 =   2,080 params
Pooling → FC [32, 5]: 32 ×  5 +  5 =     165 params
───────────────────────────────────────────────────────
Total:                                   3,333 params
+ adjacency MatMul overhead in graph:      ~70K (sparse ops metadata)
Effective ONNX size:                       ≈ 300 KB
```

### 4.2 Runtime Memory (Inference)

| Scenario | Peak RAM | Notes |
|----------|----------|-------|
| Model load | Model size × 2 | ONNX Runtime buffers + session |
| Single inference | +24 KB | 1536 floats in + 5 floats out + intermediates |
| Batch 1000 entities | +24 MB | Secuencial, no batched GPU |
| Batch 10K entities | +240 MB | Consider chunking |

### 4.3 Dataset Storage (post-processing)

| Dataset | Raw | Processed (graph labels) | Training-ready |
|---------|-----|--------------------------|----------------|
| DARPA TC E3 (CADETS) | 20 GB | ~2 GB | ~500 MB (PyG/DGL objects) |
| StreamSpot | 500 MB | ~100 MB | ~50 MB |
| UNSW-NB15 | 2 GB | ~800 MB | ~200 MB |
| DARPA OpTC | 1 TB | ~100 GB | ~20 GB |

**Para el repo** solo shiparíamos el ONNX entrenado, no los datasets:

| Lo que va en el repo | Tamaño estimado |
|---------------------|----------------|
| `models/provenance_gcn.onnx` (Option A) | **~1.8 MB** |
| `models/provenance_gcn.onnx` (Option B) | **~300 KB** |
| `models/provenance_gcn_fp16.onnx` (A quantized) | **~900 KB** |
| Training scripts (Python, fuera del build) | ~50 KB |

### 4.4 Binary Impact (compilado)

| Component | Size added to binary |
|-----------|---------------------|
| `ort` crate (ONNX Runtime DLL) | **~25 MB** (onnxruntime.dll) |
| `ort` crate (static, CPU only) | **~15 MB** |
| DirectML EP (directml.dll) | **~8 MB** adicional |
| `ndarray` crate | ~200 KB |
| `gnn_bridge.rs` + `npu_scorer.rs` | ~50 KB |

**Total footprint con feature `ml-scoring`:** ~40 MB en disco (runtime + model)
**Sin feature `ml-scoring`:** 0 bytes adicionales (stub)

---

## 5. Instructivo: Descarga, Entrenamiento y Despliegue

### 5.0 Requisitos previos

```bash
# Python 3.10+
python --version

# Crear entorno virtual
cd training/
python -m venv .venv

# Activar (Windows)
.venv\Scripts\activate

# Activar (Linux/Mac)
source .venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt
```

Espacio en disco necesario:

| Componente | Espacio |
|------------|---------|
| Dependencias Python (torch, etc.) | ~3 GB |
| DARPA TC E3 CADETS (raw) | ~20 GB |
| Datos procesados | ~500 MB |
| Modelo final ONNX | ~1.8 MB |

### 5.1 Scripts del pipeline

```
training/
├── requirements.txt            # torch, onnx, onnxruntime, networkx, sklearn
├── 01_parse_darpa_cdm.py       # DARPA JSON CDM → nodes.json + edges.json
├── 02_extract_subgraphs.py     # Grafo → tensores [N, 1536] (mirrors gnn_bridge.rs)
├── 03_train_model.py           # MLP training + ONNX export
├── 04_validate_onnx.py         # Verifica compatibilidad con npu_scorer.rs
├── .gitignore                  # Excluye datasets descargados
└── data/
    └── .gitkeep                # Datasets van aquí (gitignored)
```

### 5.2 Paso 1 — Descargar datasets

#### 5.2.1 DARPA TC E3 CADETS (recomendado)

El dataset está hospedado en Google Drive por DARPA. Son archivos JSON con trazas de
auditoría de sistema (procesos, archivos, red) con ataques APT inyectados por un red team.

**Descargar archivos:**

1. Ir a: https://drive.google.com/drive/folders/1okt4AYElyBohW4XiOBqmsvjwXsnUjLVf
2. Navegar a la carpeta `data/cadets/`
3. Descargar estos archivos:
   - `ta1-cadets-e3-official.json.tar.gz`
   - `ta1-cadets-e3-official-2.json.tar.gz`
4. Extraer en `training/data/cadets/`:

```bash
mkdir -p data/cadets
cd data/cadets

# Extraer (cada .tar.gz contiene múltiples .json)
tar -xzf ta1-cadets-e3-official.json.tar.gz
tar -xzf ta1-cadets-e3-official-2.json.tar.gz

cd ../..
```

**Descargar ground truth (labels de qué nodos son maliciosos):**

```bash
# Clonar threaTrace para obtener los labels
git clone --depth 1 https://github.com/threaTrace-detector/threaTrace.git /tmp/threaTrace

# Copiar labels
cp /tmp/threaTrace/groundtruth/cadets.txt data/cadets/cadets.txt
```

**Estructura esperada:**

```
training/data/cadets/
├── cadets.txt                          <- ground truth labels
├── ta1-cadets-e3-official.json         <- log de auditoría 1
├── ta1-cadets-e3-official-2.json       <- log de auditoría 2
└── ...                                 <- otros .json extraídos
```

> **IMPORTANTE:** No borrar archivos JSON que no se usan directamente para training
> (ej. `ta1-theia-e3-official-6r.4-7.json`). Contienen definiciones de entidades
> necesarias para resolver UUIDs de eventos, incluyendo entidades maliciosas.

#### 5.2.2 DARPA TC E3 THEIA (opcional, más datos)

Mismo proceso pero con archivos THEIA:

1. Desde el mismo Google Drive, carpeta `data/theia/`
2. Descargar `ta1-theia-e3-official-6r.json.tar.gz`
3. Extraer en `data/theia/`
4. Ground truth: `cp /tmp/threaTrace/groundtruth/theia.txt data/theia/theia.txt`

#### 5.2.3 StreamSpot (alternativa ligera, ~500 MB)

Dataset más pequeño con 600 grafos pre-construidos (500 benignos + 100 ataques).

```bash
mkdir -p data/streamspot && cd data/streamspot
git clone --depth 1 https://github.com/sbustreamspot/sbustreamspot-data.git .
tar -xzf all.tar.gz
cd ../..
```

Formato TSV: `source-id  source-type  dest-id  dest-type  edge-type  graph-id`

| Graph IDs | Escenario |
|-----------|-----------|
| 0-99 | YouTube (benigno) |
| 100-199 | Gmail (benigno) |
| 200-299 | VGame (benigno) |
| 300-399 | **Drive-by-download (ataque)** |
| 400-499 | Download (benigno) |
| 500-599 | CNN (benigno) |

#### 5.2.4 DARPA OpTC (avanzado, ~1 TB)

Solo si tienes espacio y tiempo. 1000 hosts Windows 10, 2 semanas de telemetría.

1. Requiere cuenta IEEE gratuita: https://ieee-dataport.org/open-access/operationally-transparent-cyber-optc
2. O desde Google Drive: https://drive.google.com/drive/u/0/folders/1n3kkS3KR31KUegn42yk3-e6JkZvf0Caa
3. Ground truth: https://github.com/FiveDirections/OpTC-data

| Carpeta | Contenido |
|---------|-----------|
| `ecar/` | Telemetría de endpoints (500 hosts Win10) |
| `ecar-bro/` | Flows de red con IDs de flujo |
| `bro/` | Sensor de red por fecha |

### 5.3 Paso 2 — Parsear datos crudos a grafos

Convierte los JSON CDM de DARPA en un grafo de procedencia con nodos (entidades)
y edges (eventos), mapeando a los tipos de Graph Hunter.

```bash
cd training/

# Parsear CADETS
python 01_parse_darpa_cdm.py --dataset cadets

# (Opcional) Parsear THEIA
python 01_parse_darpa_cdm.py --dataset theia
```

**Qué hace:**

- Lee cada archivo JSON línea por línea (soporta `.json` y `.json.gz`)
- Mapea entidades CDM → EntityType de Graph Hunter:
  - `com.bbn.tc.schema.avro.cdm18.Subject` → `Process`
  - `com.bbn.tc.schema.avro.cdm18.FileObject` → `File`
  - `com.bbn.tc.schema.avro.cdm18.NetFlowObject` → `IP`
  - `com.bbn.tc.schema.avro.cdm18.Principal` → `User`
  - etc.
- Mapea eventos CDM → RelationType de Graph Hunter:
  - `EVENT_READ/OPEN/MMAP` → `Read`
  - `EVENT_WRITE/CLOSE/RENAME` → `Write`
  - `EVENT_EXECUTE/FORK/CLONE` → `Execute`
  - `EVENT_CONNECT/ACCEPT/SEND*` → `Connect`
  - `EVENT_LOGIN/CHANGE_PRINCIPAL` → `Auth`
- Guarda `data/<dataset>/parsed/nodes.json` y `edges.json`

**Output esperado:**

```
Found 2 files for 'cadets'
  Parsing: ta1-cadets-e3-official.json
  Parsing: ta1-cadets-e3-official-2.json
  Wrote 125,432 nodes -> data/cadets/parsed/nodes.json
  Wrote 2,341,567 edges -> data/cadets/parsed/edges.json

  Node types:
    Process: 45,231
    File: 52,100
    IP: 15,420
    User: 3,210
  Edge types:
    Read: 890,123
    Write: 567,890
    Execute: 234,567
    Connect: 432,100
    Auth: 12,340
```

**Tiempo estimado:** ~5-15 minutos.

### 5.4 Paso 3 — Extraer subgrafos y featurizar

Extrae vecindarios k-hop alrededor de cada entidad y los convierte en tensores de
1536 floats, **idénticos** a los que genera `gnn_bridge.rs` en Rust.

```bash
# Extraer subgrafos (k=2 hops, default)
python 02_extract_subgraphs.py --dataset cadets --k-hops 2

# O limitar cantidad para prueba rápida
python 02_extract_subgraphs.py --dataset cadets --k-hops 2 --max-samples 5000
```

**Qué hace:**

1. Construye un grafo NetworkX desde los nodos/edges parseados
2. Para cada entidad maliciosa + muestra de benignas:
   - BFS de k-hops, máximo 32 nodos (`K_MAX`)
   - 16 features por nodo (`D_NODE`): one-hot tipo, grado normalizado, is_center
   - Matriz de adyacencia 32x32 (binaria, dirigida)
   - Flatten a vector de 1536 floats
3. Asigna clase de amenaza con heurísticas sobre ground truth:
   - Proceso malicioso + conexiones de red → `C2Beacon`
   - Proceso malicioso + spawn de procesos → `LateralMovement`
   - Usuario malicioso + auth events → `PrivilegeEscalation`
   - Otro malicioso → `Exfiltration`
   - No malicioso → `Benign`
4. Balancea clases: 5x benignos por cada malicioso (o min 1000)
5. Guarda como `.npz` comprimido

**Output esperado:**

```
Loading graph...
  Graph: 125,432 nodes, 2,341,567 edges
  Loaded 1,234 malicious entity UUIDs from data/cadets/cadets.txt
  Extracting features for 7,404 centers (1,234 malicious, 6,170 benign)

  Saved 7,404 samples -> data/cadets/features/subgraphs_k2.npz
  Feature shape: (7404, 1536)

  Class distribution:
    Benign: 6,170 (83.3%)
    Exfiltration: 456 (6.2%)
    C2Beacon: 312 (4.2%)
    LateralMovement: 289 (3.9%)
    PrivilegeEscalation: 177 (2.4%)
```

**Tiempo estimado:** ~10-30 minutos.

### 5.5 Paso 4 — Entrenar el modelo

Entrena un MLP que clasifica subgrafos en 5 clases de amenaza y lo exporta como ONNX.

```bash
# Entrenar con defaults (50 epochs, lr=0.001)
python 03_train_model.py --dataset cadets --k-hops 2

# Más epochs y menor learning rate para mejor accuracy
python 03_train_model.py --dataset cadets --k-hops 2 --epochs 100 --lr 0.0005

# Especificar output path
python 03_train_model.py --dataset cadets --output ../models/provenance_gcn.onnx
```

**Arquitectura del modelo (Option A del cap. 3):**

```
Input [1, 1536]
  → Linear(1536, 256) + ReLU + Dropout(0.3)     ← 393,472 params
  → Linear(256, 128)  + ReLU + Dropout(0.2)      ←  32,896 params
  → Linear(128, 64)   + ReLU                     ←   8,256 params
  → Linear(64, 5)                                ←     325 params
Output [1, 5]                                   Total: 434,949 params
```

Incluye:
- **Class weighting** automático (inverse frequency) para manejar desbalance
- **Early stopping** con patience=10 sobre validation loss
- **Learning rate scheduler** (ReduceLROnPlateau, factor=0.5)
- **Train/Val/Test split** estratificado (68% / 12% / 20%)

**Output esperado:**

```
  Device: cuda (o cpu)
  Loaded 7,404 samples, 1536 features, 5 classes
  Train: 5,034  Val: 889  Test: 1,481
  Model parameters: 434,949

 Epoch  Train Loss  Train Acc   Val Loss   Val Acc
────────────────────────────────────────────────────
     1      1.2345     0.6123     1.1234    0.6543
     5      0.5678     0.8234     0.6789    0.7890
    10      0.2345     0.9123     0.3456    0.8765
    ...
    50      0.0567     0.9834     0.1234    0.9456

  Test Loss: 0.1345
  Test Accuracy: 0.9423

  Classification Report:
                      precision  recall  f1-score  support
             Benign       0.97    0.98      0.97     1234
       Exfiltration       0.89    0.85      0.87       91
           C2Beacon       0.87    0.82      0.84       63
    LateralMovement       0.85    0.80      0.82       58
  PrivEscalation         0.82    0.78      0.80       35

  ONNX exported -> ../models/provenance_gcn.onnx
  ONNX verification OK: output shape = (1, 5)
  Model size: 1.7 MB
```

**Tiempo estimado:** ~2-10 minutos (GPU) o ~15-30 minutos (CPU).

### 5.6 Paso 5 — Validar el modelo ONNX

Verifica que el ONNX funciona correctamente y es compatible con `npu_scorer.rs`.

```bash
python 04_validate_onnx.py

# O con path específico
python 04_validate_onnx.py --model ../models/provenance_gcn.onnx
```

Ejecuta 4 checks:

1. **Estructura ONNX** — Verifica input `[batch, 1536]` y output `[batch, 5]`
2. **File size** — Alerta si es demasiado pequeño (no entrenado) o grande (>200 MB)
3. **Inferencia con test inputs** — 5 escenarios sintéticos:
   - All zeros (subgrafo vacío)
   - Proceso aislado
   - Flujo benigno: User → Process → File
   - Patrón sospechoso: Process → 5 IPs (C2 beacon pattern)
   - Ruido aleatorio
4. **Batch inference** — Verifica que batch dinámico funciona

**Output esperado:**

```
  [1/4] Checking ONNX model structure...
    Inputs:  1 — input: ['batch_size', 1536]
    Outputs: 1 — output: ['batch_size', 5]
    Dimensions OK

  [2/4] Checking file size...
    Size: 1.7 MB — OK

  [3/4] Running inference tests...
    all_zeros                      -> Benign               score=0.123
    single_process                 -> Benign               score=0.234
    benign_user_proc_file          -> Benign               score=0.087
    suspicious_c2_pattern          -> C2Beacon             score=0.876
    random_noise                   -> Exfiltration         score=0.543

  [4/4] Testing batch inference...
    Batch shape (16 samples): (16, 5) OK

  All checks passed.
  Model is ready for Graph Hunter (npu_scorer.rs)
```

### 5.7 Paso 6 — Usar en Graph Hunter

#### Desde la UI

1. Abrir Graph Hunter: `npm run tauri dev` desde `app/`
2. Panel izquierdo → sección **"GNN Threat Model"**
3. Click **"Load Model (.onnx)"** → seleccionar `models/provenance_gcn.onnx`
4. Ajustar **K-hops** (recomendado: 2)
5. Click **"Compute Scores"**
6. Ajustar peso **W5 (GNN Threat)** en el slider para ponderar vs las otras 4 heurísticas

#### Compilar con ml-scoring

```bash
cd app/src-tauri

# CPU only
cargo build --release --features "graph_hunter_core/ml-scoring"

# Con DirectML (Windows GPU/NPU)
cargo build --release --features "graph_hunter_core/ml-scoring,graph_hunter_core/directml"
```

#### Solo core (tests)

```bash
cd graph_hunter_core/
cargo test --features ml-scoring -- --skip benchmark
```

### 5.8 Troubleshooting

| Error | Solución |
|-------|----------|
| `No JSON files found` | Extraer los `.tar.gz` primero. Verificar `.json` dentro de `data/cadets/` |
| `No ground truth file` | `git clone --depth 1 https://github.com/threaTrace-detector/threaTrace.git /tmp/threaTrace && cp /tmp/threaTrace/groundtruth/cadets.txt data/cadets/` |
| `CUDA out of memory` | Reducir batch: `--batch-size 16` |
| Baja accuracy | Verificar descarga completa, subir epochs (`--epochs 100`), bajar lr (`--lr 0.0005`) |
| ONNX validation fail | Verificar `opset_version=17`, instalar `pip install onnxruntime` |
| `Model file not found` en Graph Hunter | Verificar path absoluto al `.onnx` desde la UI |
| `ML scoring not available` | Compilar con `--features ml-scoring` |

### 5.9 Resumen visual del pipeline

```
┌──────────────────────────────────────────────────────────────────┐
│  DARPA TC E3 Google Drive                                        │
│  (20 GB JSON CDM)                                                │
└─────────────────────┬────────────────────────────────────────────┘
                      │ descargar + extraer .tar.gz
                      ▼
┌──────────────────────────────────────────────────────────────────┐
│  01_parse_darpa_cdm.py                                           │
│  JSON CDM → nodes.json + edges.json                              │
│  (~5-15 min)                                                     │
└─────────────────────┬────────────────────────────────────────────┘
                      ▼
┌──────────────────────────────────────────────────────────────────┐
│  02_extract_subgraphs.py                                         │
│  Grafo → subgrafos k-hop → tensores [N, 1536] + labels          │
│  (~10-30 min)                                                    │
└─────────────────────┬────────────────────────────────────────────┘
                      ▼
┌──────────────────────────────────────────────────────────────────┐
│  03_train_model.py                                               │
│  MLP training → ONNX export (~1.8 MB)                            │
│  (~5-30 min)                                                     │
└─────────────────────┬────────────────────────────────────────────┘
                      ▼
┌──────────────────────────────────────────────────────────────────┐
│  04_validate_onnx.py                                             │
│  Verificar estructura + inferencia + compatibilidad              │
│  (~30 seg)                                                       │
└─────────────────────┬────────────────────────────────────────────┘
                      ▼
┌──────────────────────────────────────────────────────────────────┐
│  Graph Hunter                                                    │
│  Load model → Compute GNN Scores → W5 weight                    │
│  models/provenance_gcn.onnx                                      │
└──────────────────────────────────────────────────────────────────┘
```

**Tiempo total estimado (sin descarga):** ~30-60 minutos
**Resultado:** ONNX de ~1.8 MB con 5 clases de amenaza APT entrenadas con datos reales.

**Quick start (4 comandos):**

```bash
cd training && pip install -r requirements.txt
python 01_parse_darpa_cdm.py --dataset cadets
python 02_extract_subgraphs.py --dataset cadets --k-hops 2
python 03_train_model.py --dataset cadets
python 04_validate_onnx.py
```

---

## 6. Roadmap

### Phase 1 — MLP on DARPA TC E3 (2-3 semanas)

1. Descargar DARPA TC E3 CADETS subset (~20 GB)
2. Ejecutar pipeline completo (secciones 5.2-5.6)
3. Validar con Graph Hunter: cargar modelo → ingestar datos de demo → verificar scores

**Resultado:** ONNX de ~1.8 MB entrenado con datos reales de APT.

### Phase 2 — GCN nativo + más datos (4-6 semanas)

1. Implementar message-passing en `gnn_bridge.rs` (Rust nativo, no ONNX)
2. Exportar solo las capas lineales como ONNX (Option B)
3. Agregar StreamSpot como segundo dataset de validación
4. Implementar fine-tuning workflow: exportar subgrafos de Graph Hunter → reentrenar

**Resultado:** Modelo más expresivo (~300 KB), message-passing eficiente en Rust.

### Phase 3 — Self-supervised pre-training (futuro)

1. Adoptar approach PPT-GNN: pre-training sin labels sobre tráfico benigno
2. Fine-tune con datos etiquetados (DARPA TC E3/E5)
3. Considerar UNSW-NB15 para augmentar detección de red
4. Evaluar si justifica modelo Transformer (~20-200 MB)

---

## 7. Decision Matrix

| Criterio | Option A (MLP) | Option B (GCN) | Option C (GAT) |
|----------|---------------|----------------|-----------------|
| Size ONNX | 1.8 MB | 300 KB | 600 KB |
| Accuracy esperada | Buena | Mejor | Mejor+ |
| Exportación ONNX | Trivial | Viable | Difícil |
| Implementación | Ya compatible | Rust message-passing | Rust attention ops |
| Tiempo a producción | 2 semanas | 5 semanas | 8+ semanas |
| Datasets mínimos | TC E3 | TC E3 | TC E3 + E5 |

**Recomendación: Option A primero, luego migrar a Option B.**

Option A ya es compatible al 100% con nuestro pipeline (`gnn_bridge.rs` → flatten → ONNX → `npu_scorer.rs`). Se puede entrenar y shipar rápido. Luego, una vez validado con datos reales, evolucionamos a Option B con message-passing en Rust que es más eficiente y expresivo.
