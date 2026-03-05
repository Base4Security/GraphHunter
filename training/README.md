# Training Pipeline — Graph Hunter GNN

Instructivo completo para descargar datasets, entrenar el modelo GNN y desplegarlo en Graph Hunter.

## Requisitos previos

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

---

## Paso 1 — Descargar datasets

### 1A. DARPA TC E3 CADETS (recomendado)

El dataset está hospedado en Google Drive por DARPA. Son archivos JSON con trazas de auditoría de sistema (procesos, archivos, red) con ataques APT inyectados por un red team.

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
training/
└── data/
    └── cadets/
        ├── cadets.txt                          <- ground truth labels
        ├── ta1-cadets-e3-official.json         <- log de auditoría 1
        ├── ta1-cadets-e3-official-2.json       <- log de auditoría 2
        └── ...                                 <- otros .json extraídos
```

### 1B. DARPA TC E3 THEIA (opcional, más datos)

Mismo proceso pero con archivos THEIA:

1. Desde el mismo Google Drive, carpeta `data/theia/`
2. Descargar `ta1-theia-e3-official-6r.json.tar.gz`
3. Extraer en `data/theia/`
4. Ground truth: `cp /tmp/threaTrace/groundtruth/theia.txt data/theia/theia.txt`

### 1C. StreamSpot (alternativa ligera, ~500 MB)

Dataset más pequeño con 600 grafos pre-construidos (500 benignos + 100 ataques).

```bash
mkdir -p data/streamspot
cd data/streamspot

# Descargar
git clone --depth 1 https://github.com/sbustreamspot/sbustreamspot-data.git .

# Extraer
tar -xzf all.tar.gz

cd ../..
```

### 1D. DARPA OpTC (avanzado, ~1 TB)

Solo si tienes espacio y tiempo. 1000 hosts Windows 10, 2 semanas de telemetría.

1. Requiere cuenta IEEE gratuita: https://ieee-dataport.org/open-access/operationally-transparent-cyber-optc
2. O directamente desde Google Drive: https://drive.google.com/drive/u/0/folders/1n3kkS3KR31KUegn42yk3-e6JkZvf0Caa
3. Ground truth: https://github.com/FiveDirections/OpTC-data

---

## Paso 2 — Parsear datos crudos a grafos

Convierte los JSON CDM de DARPA en un grafo de procedencia con nodos (entidades) y edges (eventos).

```bash
cd training/

# Parsear CADETS
python 01_parse_darpa_cdm.py --dataset cadets

# (Opcional) Parsear THEIA
python 01_parse_darpa_cdm.py --dataset theia
```

**Qué hace:**
- Lee cada archivo JSON línea por línea
- Mapea entidades CDM a tipos de Graph Hunter (Process, File, IP, User, etc.)
- Mapea eventos CDM a relaciones (Read, Write, Execute, Connect, Auth)
- Guarda `data/cadets/parsed/nodes.json` y `data/cadets/parsed/edges.json`

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
    ...
  Edge types:
    Read: 890,123
    Write: 567,890
    Execute: 234,567
    Connect: 432,100
    Auth: 12,340
```

**Tiempo estimado:** ~5-15 minutos dependiendo del tamaño del JSON.

---

## Paso 3 — Extraer subgrafos y featurizar

Extrae vecindarios k-hop alrededor de cada entidad y los convierte en tensores de 1536 floats, idénticos a los que genera `gnn_bridge.rs` en Rust.

```bash
# Extraer subgrafos (k=2 hops, default)
python 02_extract_subgraphs.py --dataset cadets --k-hops 2

# O limitar cantidad para prueba rápida
python 02_extract_subgraphs.py --dataset cadets --k-hops 2 --max-samples 5000
```

**Qué hace:**
- Construye un grafo NetworkX desde los nodos/edges parseados
- Para cada entidad maliciosa + muestra de benignas:
  - BFS de k-hops, máximo 32 nodos (K_MAX)
  - 16 features por nodo (D_NODE): one-hot tipo, grado, is_center
  - Matriz de adyacencia 32×32
  - Flatten todo a vector de 1536 floats
- Asigna clase de amenaza basada en ground truth + heurísticas
- Guarda como `.npz` comprimido

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

---

## Paso 4 — Entrenar el modelo

Entrena un MLP (Multi-Layer Perceptron) que clasifica subgrafos en 5 clases de amenaza y lo exporta como ONNX.

```bash
# Entrenar con defaults (50 epochs, lr=0.001)
python 03_train_model.py --dataset cadets --k-hops 2

# Más epochs y menor learning rate para mejor accuracy
python 03_train_model.py --dataset cadets --k-hops 2 --epochs 100 --lr 0.0005

# Especificar output path
python 03_train_model.py --dataset cadets --output ../models/provenance_gcn.onnx
```

**Arquitectura del modelo:**
```
Input [1, 1536]
  → Linear(1536, 256) + ReLU + Dropout(0.3)     ← 393,472 params
  → Linear(256, 128)  + ReLU + Dropout(0.2)      ←  32,896 params
  → Linear(128, 64)   + ReLU                     ←   8,256 params
  → Linear(64, 5)                                ←     325 params
Output [1, 5]                                   Total: 434,949 params
```

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

---

## Paso 5 — Validar el modelo ONNX

Verifica que el ONNX funciona correctamente y es compatible con `npu_scorer.rs`.

```bash
python 04_validate_onnx.py

# O con path específico
python 04_validate_onnx.py --model ../models/provenance_gcn.onnx
```

**Output esperado:**
```
  Model: ../models/provenance_gcn.onnx

  [1/4] Checking ONNX model structure...
    Inputs:  1
      input: ['batch_size', 1536]
    Outputs: 1
      output: ['batch_size', 5]
    Dimensions OK

  [2/4] Checking file size...
    Size: 1.7 MB
    Size OK

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

---

## Paso 6 — Usar en Graph Hunter

### Opción A: Desde la UI

1. Abrir Graph Hunter (`npm run tauri dev` desde `app/`)
2. Panel izquierdo → sección "GNN Threat Model"
3. Click "Load Model (.onnx)" → seleccionar `models/provenance_gcn.onnx`
4. Ajustar K-hops (recomendado: 2)
5. Click "Compute Scores"
6. Ajustar peso W5 (GNN Threat) en el slider

### Opción B: Compilar con ml-scoring

```bash
# Desde app/src-tauri/
cd app/src-tauri

# Compilar con soporte ONNX (CPU)
cargo build --release --features "graph_hunter_core/ml-scoring"

# Con DirectML (Windows GPU/NPU)
cargo build --release --features "graph_hunter_core/ml-scoring,graph_hunter_core/directml"
```

### Opción C: Solo el core (tests)

```bash
cd graph_hunter_core/

# Compilar con ml-scoring
cargo test --features ml-scoring -- --skip benchmark
```

---

## Troubleshooting

### "No JSON files found"
Los archivos .tar.gz deben extraerse primero. Verificar que existan `.json` dentro de `data/cadets/`.

### "No ground truth file"
Descargar labels de threaTrace:
```bash
git clone --depth 1 https://github.com/threaTrace-detector/threaTrace.git /tmp/threaTrace
cp /tmp/threaTrace/groundtruth/cadets.txt data/cadets/cadets.txt
```

### "CUDA out of memory"
Reducir batch size: `--batch-size 32` o `--batch-size 16`

### "Model too small / bad accuracy"
- Verificar que los datos se descargaron completos (no solo headers)
- Aumentar epochs: `--epochs 100`
- Reducir learning rate: `--lr 0.0005`
- Verificar distribución de clases (debe haber muestras de cada clase)

### ONNX validation fails
- Asegurar `opset_version=17` en el export
- Verificar que onnxruntime está instalado: `pip install onnxruntime`
- Si hay errores de shape, el modelo no coincide con GNN_INPUT_DIM=1536

---

## Resumen del pipeline

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
**Resultado:** ONNX de ~1.8 MB con 5 clases de amenaza APT entrenadas con datos reales de red team DARPA.
