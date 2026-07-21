# Bloque 1: ADR + Auditoría de Suficiencia — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Producir el ADR del modelo SOT (`docs/adr/ADR-SOT-source-independent-ingestion.md` en GraphHunter) y la auditoría de suficiencia de ingesta de GraphHunter en el repo sot (`validation/graphhunter/` + runner + resultados congelados), escritos contra la **realidad corregida** del assessment, no contra el borrador del spec.

**Architecture:** Dos repos. En GraphHunter: un ADR (solo docs). En sot: el patrón sotOs replicado — modelo declarado en JSON (`ingest_surface.json` + `catalog_snapshot.json`), analizador propio (`gh_audit.py`, ~150 líneas; el `sot_audit` existente está atado al SysIR de sotOs y no se reutiliza), runner determinista con `--check` (`audit_graphhunter.py`, espejo de `audit_sotos.py`), y dos documentos (correspondencia + hallazgos) cuyos números se leen del JSON congelado.

**Tech Stack:** Python 3 stdlib (sin PyYAML: los `cat-*.yaml` son planos `key: value` y se parsean a mano), `unittest` (convención del repo sot: `make test` = `python -m unittest discover -s tests`), Markdown.

## Global Constraints

- **Dos repos, ramas fijas:** repo sot (`C:\Users\lsotomayor\sot`) commitea en `sot-sys/bootstrap`; repo GraphHunter (`C:\Users\lsotomayor\GraphHunter`) commitea en `spec/hunt-journal` y SOLO el archivo del ADR. GraphHunter tiene WIP ajeno sin commitear: jamás `git add -A` / `git stash` / `git checkout --`.
- **Fuente de verdad fáctica:** `GraphHunter/docs/architecture/sot-integration-assessment.md` (commit `b9335cf`). Toda afirmación sobre GraphHunter cita su sección S* (o `path:line` re-verificado). El borrador §4 del spec quedó corregido por S15 — no heredar sus filas sin el veredicto de S15.
- **Disciplina de claims (spec §5-bis(4)):** cada afirmación de garantía lleva etiqueta `proved / implemented / tested / proposed / inference`. La auditoría es evidencia `experiment` — "offline audit over a declared model", nunca certificación del sistema real ni replicación externa.
- **Determinismo congelado:** `audit_results.json` byte-idéntico entre corridas (`sort_keys=True`, sin timestamps ni orden de dict dependiente de sistema); el runner ofrece `--check` (patrón `audit_sotos.py`).
- **Suficiencia solo relativa a B declarada:** nunca "suficiente para consultas futuras no especificadas".
- **Idiomas:** entregables del repo sot en inglés (convención de `validation/`); el ADR de GraphHunter en español con términos de código en inglés (convención del assessment).
- **Taxonomía de testigos (spec §5-bis(1), SOT-VM §5):** `behavior` (la observación base ya no determina el behavior) vs `future_behavior` (la insuficiencia aparece solo bajo contextos declarados).
- **MANIFEST:** tras añadir archivos al repo sot, regenerar con `python scripts/write_manifest.py` y commitear el MANIFEST.sha256 junto con la tarea que lo alteró.
- Tests del repo sot: `make test` debe quedar verde al final de cada tarea con código.

---

### Task 1: ADR-SOT-source-independent-ingestion (repo GraphHunter)

**Files:**
- Create: `C:\Users\lsotomayor\GraphHunter\docs\adr\ADR-SOT-source-independent-ingestion.md`

**Interfaces:**
- Consumes: assessment S1–S16 (mismo repo), spec `docs/superpowers/specs/2026-07-21-sot-integration-design.md` §3 (modelo X/S/B/C/R) y §5-bis.
- Produces: la enumeración canónica de **B** (30 hipótesis + operaciones Domain API + 2 transversales) y de **C** (contextos) que las Tareas 4–6 usan con estos ids exactos: transversales `loss_reconstruction` y `exhaustiveness_marking`; contextos `crash_reingest`, `malformed_row`, `unmapped_field`, `memory_critical`, `circuit_breaker`, `late_arrival`, `mapping_edit`.

- [ ] **Step 1: Escribir el ADR**

Estructura obligatoria (secciones, cada una con su contenido contra la realidad corregida):

```markdown
# ADR: Ingesta independiente de la fuente, gobernada por SOT

- Estado: aceptado (diseño) — implementación por fases (spec Bloque 2)
- Base fáctica: docs/architecture/sot-integration-assessment.md @ b9335cf
- Modelo teórico: SOT monografía v2.1; patrones SOT-VM v1.1 (spec §5-bis)

## Contexto  [qué se decidió y por qué; 2 párrafos: inversión MCP/KQL +
  los 5+2 puntos de pérdida, citando S13; corregir explícitamente las
  premisas muertas del spec: dedup implícito NO existe (S3), pipeline
  streaming dormido (S5), sidecar sin fuente (S2/S6)]

## Estado concreto X  [lista del spec §3 anotada con qué existe hoy:
  eventos crudos NO persistidos (no hay journal, S5); checkpoints
  test-only (S5); etc. Cada ítem con (S*)]

## Observador base S  [la representación actual: grafo GHS1, interning,
  aristas append-only con multiplicidad real (S3), ingested_at_delta=0
  (S6), ProvenanceCtx export-time (S4)]

## Comportamientos B (familia declarada, cerrada)
  1. Las 30 hipótesis del catálogo cat-001..030 (+shape_rules) — citar ruta.
  2. Operaciones Domain API (S9): run_hunt, k-hop, vecindarios,
     procedencia, ranking, resultados MCP/frontend.
  3. Transversales: `loss_reconstruction` (¿puedo reconstruir cuánto se
     perdió en cada punto?), `exhaustiveness_marking` (¿puedo marcar una
     respuesta como posiblemente incompleta?).
  Nota de monotonía (SOT-VM Thm 7.2, spec §5-bis(3)): ampliar B solo
  refina — etiqueta `proved` en SOT-VM, `proposed` como aplicación aquí.

## Contextos C  [lista del spec §3 con ids canónicos: crash_reingest,
  malformed_row, unmapped_field, memory_critical, circuit_breaker,
  late_arrival, mapping_edit, más los del spec (reinicio, backfill,
  cambio de versión, reconciliación). Cada uno con el hallazgo del
  assessment que lo hace real hoy (S3/S4/S5/S6)]

## Clase de realización R  [journal append-only (NUEVO, S15 fila 2),
  índice dedup por huella canónica (NUEVO — hoy no hay dedup, S3),
  identidades canónicas (EXISTE: interner, S3), multigrafo temporal
  (EXISTE, S3), procedencia congelada en ingesta (NUEVO — hoy retroactiva,
  S4), checkpoints por fuente (EXISTE dormido, S5), ventanas (NUEVO)]

## Invariante principal  [equivalencia con rebuild tras cada lote
  confirmado, sobre B declarada, no byte a byte; framing de validación
  por traducción + ecuación de descenso (spec §5-bis(2)); etiqueta:
  `proposed` — no existe hoy ni contrato ni test (S15 fila 5)]

## Consecuencias  [qué compra: caso 26 testeable, casos 10-12/25
  implementables; qué cuesta: journal y GraphDelta son construcción
  nueva; qué NO se decide aquí: Differential Dataflow (spec decisión 4)]
```

Reglas: cada afirmación fáctica cita (S*); cada garantía lleva etiqueta de estatus; ninguna promesa sobre comportamiento futuro sin etiqueta `proposed`.

- [ ] **Step 2: Verificar**

Checklist: (a) las 7 secciones del modelo presentes (X/S/B/C/R/invariante/consecuencias); (b) `grep -n "S1[0-6]\|S[2-9]"` muestra ≥15 citas a secciones del assessment; (c) los ids canónicos de transversales y contextos aparecen textualmente (los consumen las tareas 4–5); (d) cero afirmaciones de garantía sin etiqueta; (e) las tres premisas muertas del spec aparecen corregidas explícitamente.

- [ ] **Step 3: Commit (repo GraphHunter)**

```powershell
Set-Location C:\Users\lsotomayor\GraphHunter
git add docs/adr/ADR-SOT-source-independent-ingestion.md
git commit -m "docs(adr): SOT source-independent ingestion - X/S/B/C/R model against assessed reality"
```

---

### Task 2: Documento de correspondencia (repo sot)

**Files:**
- Create: `C:\Users\lsotomayor\sot\validation\graphhunter\graphhunter_integration.md`

**Interfaces:**
- Consumes: patrón de `validation/sotos_integration.md` (leerlo primero como plantilla de tono/estructura); ADR de la Tarea 1; assessment S1/S13/S15/S16.
- Produces: la tabla de correspondencia GraphHunter↔SOT que el documento de hallazgos (Tarea 6) referencia como "the correspondence document".

- [ ] **Step 1: Leer la plantilla y escribir el documento**

Leer `C:\Users\lsotomayor\sot\validation\sotos_integration.md` completo. Escribir `graphhunter_integration.md` (inglés) con:

1. **Header**: "Third entry in SOT's External Systems Validation series"; evidence label `reference` (correspondencia documental, no experiment — el experiment es la auditoría de la Tarea 6).
2. **What this is**: GraphHunter (repo `~/GraphHunter`) como observador en el sentido SOT: telemetría heterogénea → multigrafo temporal tipado (el observador desplegado S) → hipótesis tipadas con monotonía causal (la familia B), con los puntos de pérdida del pipeline como el problema de suficiencia relativa.
3. **Correspondence table**: columna SOT (X, S, B, C, R, invariante) ↔ columna GraphHunter (con cita al ADR y a la sección S* del assessment). Usar la realidad corregida: p. ej. R incluye "canonical identities: EXISTS (interner)" pero "dedup index: does NOT exist today (assessment S3)".
4. **Bridges and limits** (patrón sotOs "Bridge-1/2/3"): Bridge A — las hipótesis del catálogo son machine-readable (primera entrada de la serie sin autoría manual de la familia B); Bridge B — el invariante incremental=rebuild corresponde a la formulación de un paso de la monografía, etiqueta `proposed` (nada implementado); Bridge C (abierto) — el scoring de anomalía/GNN queda FUERA de B en esta fase (análogo honesto del Bridge-3 de sotOs: modelarlo necesita maquinaria que esta auditoría no fabrica).
5. **Not claimed**: no replicación externa, no certificación del sistema corriendo, suficiencia solo relativa a B declarada.

- [ ] **Step 2: Verificar**

Checklist: (a) tabla cubre las 6 filas del modelo; (b) ≥8 citas (S*/ADR); (c) sección "Not claimed" presente; (d) Bridge C declara explícitamente el scoring fuera de B; (e) sin lenguaje de garantía sin etiqueta.

- [ ] **Step 3: Commit (repo sot)**

```bash
cd /c/Users/lsotomayor/sot
git add validation/graphhunter/graphhunter_integration.md
git commit -m "GraphHunter correspondence: third External Systems Validation entry"
```

---

### Task 3: Parser del catálogo + snapshot (repo sot, TDD)

**Files:**
- Create: `C:\Users\lsotomayor\sot\scripts\sot_sys\gh_catalog.py`
- Test: `C:\Users\lsotomayor\sot\tests\test_gh_audit.py` (se crea aquí; la Tarea 4 le añade clases)

**Interfaces:**
- Produces: `parse_dsl(pattern: str) -> list[dict]` (cada step `{"src": str, "rel": str, "dst": str}`); `parse_cat_file(text: str) -> dict` (claves `id,name,mitre_id,description,dsl_pattern,k_simplicity`); `build_snapshot(catalog_dir: Path, commit: str) -> dict` con schema `{"source": {"repo","path","commit","files"}, "hypotheses": [{id,name,mitre_id,k_simplicity,dsl_pattern,steps,entity_types,relation_types}]}` — `entity_types`/`relation_types` ordenadas y únicas; hipótesis ordenadas por `id`.

- [ ] **Step 1: Escribir los tests que fallan**

Formato real de un `cat-*.yaml` de GraphHunter (plano, sin anidamiento — verificado en `core/graph-engine/src/catalog/builtin/cat-001.yaml`):

```yaml
id: cat-001
name: "Valid Accounts — Lateral Auth"
mitre_id: T1078
description: Compromised credentials used to authenticate across hosts, then execute processes.
dsl_pattern: "User -[Auth]-> Host -[Execute]-> Process"
k_simplicity: 1
```

```python
# tests/test_gh_audit.py
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "sot_sys"))

import gh_catalog

CAT_001 = '''id: cat-001
name: "Valid Accounts — Lateral Auth"
mitre_id: T1078
description: Compromised credentials used to authenticate.
dsl_pattern: "User -[Auth]-> Host -[Execute]-> Process"
k_simplicity: 1
'''


class TestParseDsl(unittest.TestCase):
    def test_two_step_chain(self):
        steps = gh_catalog.parse_dsl("User -[Auth]-> Host -[Execute]-> Process")
        self.assertEqual(steps, [
            {"src": "User", "rel": "Auth", "dst": "Host"},
            {"src": "Host", "rel": "Execute", "dst": "Process"},
        ])

    def test_single_step(self):
        steps = gh_catalog.parse_dsl("IP -[Connect]-> Host")
        self.assertEqual(steps, [{"src": "IP", "rel": "Connect", "dst": "Host"}])

    def test_wildcards(self):
        steps = gh_catalog.parse_dsl("* -[DNS]-> Domain")
        self.assertEqual(steps, [{"src": "*", "rel": "DNS", "dst": "Domain"}])

    def test_malformed_raises(self):
        with self.assertRaises(ValueError):
            gh_catalog.parse_dsl("User -> Host")


class TestParseCatFile(unittest.TestCase):
    def test_flat_fields(self):
        h = gh_catalog.parse_cat_file(CAT_001)
        self.assertEqual(h["id"], "cat-001")
        self.assertEqual(h["name"], "Valid Accounts — Lateral Auth")  # comillas fuera
        self.assertEqual(h["k_simplicity"], 1)
        self.assertEqual(h["dsl_pattern"], "User -[Auth]-> Host -[Execute]-> Process")


class TestBuildSnapshot(unittest.TestCase):
    def test_snapshot_shape_and_order(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "cat-002.yaml").write_text(
                CAT_001.replace("cat-001", "cat-002"), encoding="utf-8")
            (Path(d) / "cat-001.yaml").write_text(CAT_001, encoding="utf-8")
            (Path(d) / "shape_rules.yaml").write_text("rules: []\n", encoding="utf-8")
            snap = gh_catalog.build_snapshot(Path(d), commit="abc1234")
        self.assertEqual(snap["source"]["commit"], "abc1234")
        self.assertEqual(snap["source"]["files"], 2)  # shape_rules excluido
        ids = [h["id"] for h in snap["hypotheses"]]
        self.assertEqual(ids, ["cat-001", "cat-002"])  # ordenado
        h = snap["hypotheses"][0]
        self.assertEqual(h["entity_types"], ["Host", "Process", "User"])
        self.assertEqual(h["relation_types"], ["Auth", "Execute"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Verificar que fallan**

Run: `cd /c/Users/lsotomayor/sot && python -m unittest tests.test_gh_audit -v`
Expected: FAIL/ERROR con `ModuleNotFoundError: No module named 'gh_catalog'`.

- [ ] **Step 3: Implementar `gh_catalog.py`**

```python
#!/usr/bin/env python3
"""Parse GraphHunter's builtin hypothesis catalog (cat-*.yaml) into a
deterministic snapshot. The cat files are flat `key: value` lines, so no
YAML dependency is needed; shape_rules.yaml is not a hypothesis and is
excluded. Snapshot schema: see build_snapshot."""

import re
from pathlib import Path

_STEP_RE = re.compile(r"\s*-\[([^\]]+)\]->\s*")


def parse_dsl(pattern):
    """'A -[R]-> B -[S]-> C' -> [{'src','rel','dst'}, ...]. ValueError if
    the pattern has no '-[Rel]->' arrows or unbalanced segments."""
    rels = _STEP_RE.findall(pattern)
    nodes = [n.strip() for n in _STEP_RE.split(pattern) if n.strip() and n.strip() not in rels]
    # re.split con grupo intercala los rels; filtrarlos deja los nodos
    if not rels or len(nodes) != len(rels) + 1:
        raise ValueError(f"malformed dsl_pattern: {pattern!r}")
    return [{"src": nodes[i], "rel": rels[i], "dst": nodes[i + 1]}
            for i in range(len(rels))]


def parse_cat_file(text):
    """Flat `key: value` parse; strips surrounding quotes; k_simplicity -> int."""
    out = {}
    for line in text.splitlines():
        if ":" not in line or line.lstrip().startswith("#"):
            continue
        key, _, value = line.partition(":")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        out[key.strip()] = value
    if "k_simplicity" in out:
        out["k_simplicity"] = int(out["k_simplicity"])
    return out


def build_snapshot(catalog_dir, commit):
    hyps = []
    files = sorted(p for p in Path(catalog_dir).glob("cat-*.yaml"))
    for path in files:
        h = parse_cat_file(path.read_text(encoding="utf-8"))
        steps = parse_dsl(h["dsl_pattern"])
        ents = sorted({s["src"] for s in steps} | {s["dst"] for s in steps})
        rels = sorted({s["rel"] for s in steps})
        hyps.append({
            "id": h["id"], "name": h.get("name", ""),
            "mitre_id": h.get("mitre_id", ""),
            "k_simplicity": h.get("k_simplicity", 1),
            "dsl_pattern": h["dsl_pattern"], "steps": steps,
            "entity_types": ents, "relation_types": rels,
        })
    hyps.sort(key=lambda h: h["id"])
    return {"source": {"repo": "GraphHunter",
                       "path": "core/graph-engine/src/catalog/builtin",
                       "commit": commit, "files": len(files)},
            "hypotheses": hyps}
```

Nota sobre `parse_dsl`: si el filtrado de nodos por pertenencia a `rels` resulta frágil (un nodo llamado igual que una relación), reemplazar por doble pasada con `_STEP_RE.split` sin grupo — el test `test_two_step_chain` es el árbitro; ajustar la implementación hasta que los 4 tests pasen sin cambiar los tests.

- [ ] **Step 4: Verificar que pasan**

Run: `python -m unittest tests.test_gh_audit -v`
Expected: `OK` (7 tests). Después `make test` completo: verde.

- [ ] **Step 5: Commit (repo sot)**

```bash
cd /c/Users/lsotomayor/sot
git add scripts/sot_sys/gh_catalog.py tests/test_gh_audit.py
git commit -m "gh_catalog: deterministic parser/snapshot for GraphHunter's hypothesis catalog"
```

---

### Task 4: Analizador de suficiencia `gh_audit.py` (repo sot, TDD)

**Files:**
- Create: `C:\Users\lsotomayor\sot\scripts\sot_sys\gh_audit.py`
- Modify: `C:\Users\lsotomayor\sot\tests\test_gh_audit.py` (añadir clases; no tocar las existentes)

**Interfaces:**
- Consumes: snapshot de la Tarea 3 (`snap["hypotheses"]`).
- Produces: `audit(surface: dict, snapshot: dict) -> dict` con schema:
  `{"results": [{"id", "status", "blind_channels": [{"channel","loss_point","context","witness_type","fix"}], "witness": {...}|None, "reinforcement": [str]}], "transversal": [{"id","status","blind_channels":[...]}]}`.
  Status ∈ {"Sufficient", "InsufficientWithWitness", "Insufficient"}. `HYPOTHESIS_REQUIRES` = canal es requerido por toda hipótesis: `["edge_multiplicity","entity_identity","event_time","field_survival","ingest_completeness","row_completeness","source_coverage"]`. Surface schema: `{"channels": {name: {"fidelity": "full"|"degraded"|"absent", "loss_point"?, "context"?, "witness_type"?, "note", "fix"?}}, "queries_transversal": [{"id","requires":[...]}]}`.

- [ ] **Step 1: Añadir los tests que fallan**

```python
# añadir a tests/test_gh_audit.py
import json

import gh_audit

TOY_FULL = {"channels": {c: {"fidelity": "full", "note": "toy"}
                         for c in gh_audit.HYPOTHESIS_REQUIRES},
            "queries_transversal": []}

TOY_DEGRADED = json.loads(json.dumps(TOY_FULL))
TOY_DEGRADED["channels"]["row_completeness"] = {
    "fidelity": "degraded", "loss_point": "L2", "context": "malformed_row",
    "witness_type": "future_behavior", "note": "toy silent skip",
    "fix": "Fase B journal"}
TOY_DEGRADED["queries_transversal"] = [
    {"id": "loss_reconstruction", "requires": ["row_completeness"]}]

SNAP = {"source": {"repo": "toy", "path": "x", "commit": "abc", "files": 1},
        "hypotheses": [{"id": "cat-001", "name": "t", "mitre_id": "T1",
                        "k_simplicity": 1,
                        "dsl_pattern": "User -[Auth]-> Host",
                        "steps": [{"src": "User", "rel": "Auth", "dst": "Host"}],
                        "entity_types": ["Host", "User"],
                        "relation_types": ["Auth"]}]}


class TestAudit(unittest.TestCase):
    def test_full_surface_is_sufficient(self):
        report = gh_audit.audit(TOY_FULL, SNAP)
        self.assertEqual(report["results"][0]["status"], "Sufficient")
        self.assertEqual(report["results"][0]["blind_channels"], [])

    def test_degraded_channel_yields_witness(self):
        r = gh_audit.audit(TOY_DEGRADED, SNAP)["results"][0]
        self.assertEqual(r["status"], "InsufficientWithWitness")
        self.assertEqual(r["blind_channels"][0]["channel"], "row_completeness")
        self.assertEqual(r["blind_channels"][0]["witness_type"], "future_behavior")
        w = r["witness"]
        self.assertIn("left_history", w)
        self.assertIn("right_history", w)
        self.assertIn("same_observed", w)
        self.assertEqual(w["context"], "malformed_row")
        self.assertEqual(r["reinforcement"], ["Fase B journal"])

    def test_absent_channel_without_witness_template_is_bare_insufficient(self):
        surface = json.loads(json.dumps(TOY_FULL))
        surface["channels"]["event_time"] = {"fidelity": "absent", "note": "toy"}
        r = gh_audit.audit(surface, SNAP)["results"][0]
        self.assertEqual(r["status"], "Insufficient")   # sin witness_type declarado
        self.assertIsNone(r["witness"])
        self.assertEqual(r["blind_channels"][0]["channel"], "event_time")

    def test_transversal_query(self):
        t = gh_audit.audit(TOY_DEGRADED, SNAP)["transversal"][0]
        self.assertEqual(t["id"], "loss_reconstruction")
        self.assertEqual(t["status"], "InsufficientWithWitness")

    def test_deterministic_serialization(self):
        a = json.dumps(gh_audit.audit(TOY_DEGRADED, SNAP), sort_keys=True)
        b = json.dumps(gh_audit.audit(TOY_DEGRADED, SNAP), sort_keys=True)
        self.assertEqual(a, b)
```

- [ ] **Step 2: Verificar que fallan**

Run: `python -m unittest tests.test_gh_audit -v`
Expected: ERROR `No module named 'gh_audit'` en las clases nuevas; las 7 de la Tarea 3 siguen OK.

- [ ] **Step 3: Implementar `gh_audit.py`**

```python
#!/usr/bin/env python3
"""Ingest-sufficiency analyzer for GraphHunter: does the information a
catalog hypothesis needs survive the declared ingest surface?

Offline audit over a DECLARED model (ingest_surface.json authored from the
Block-0 assessment), not a certification of the running system. Verdicts
follow the sot_audit convention: Sufficient; InsufficientWithWitness with a
schematic two-history blindness witness; bare Insufficient (a blind channel
with no declared witness template) that still names the blind channel.
Witness taxonomy per SOT-VM: 'behavior' (base observation already fails) vs
'future_behavior' (insufficiency appears only under a declared context)."""

HYPOTHESIS_REQUIRES = [
    "edge_multiplicity", "entity_identity", "event_time", "field_survival",
    "ingest_completeness", "row_completeness", "source_coverage",
]

# Plantillas esquemáticas de testigo por canal: dos historias de ingesta con
# el mismo estado observado y respuesta distinta. {h} se sustituye por el id.
_WITNESS_TEMPLATES = {
    "edge_multiplicity": {
        "left_history": "source emits Auth(u,h,t) once; poller crashes after "
                        "send, re-polls, row re-ingested (no dedup)",
        "right_history": "source emits two real Auth(u,h,t) events",
        "same_observed": "two identical Auth edges in the graph",
        "differs_on": "any count/multiplicity-sensitive reading of {h}",
    },
    "row_completeness": {
        "left_history": "a matching event for {h} arrives malformed and is "
                        "silently skipped (no diagnostic on fast paths)",
        "right_history": "no such event ever occurred",
        "same_observed": "identical graph; identical (empty) skip diagnostics",
        "differs_on": "ground-truth answer of {h}",
    },
    "field_survival": {
        "left_history": "the field carrying {h}'s entity arrives unmapped and "
                        "is degraded to metadata / dropped as node candidate",
        "right_history": "the entity never appeared in the telemetry",
        "same_observed": "identical node set",
        "differs_on": "path existence for {h}",
    },
    "ingest_completeness": {
        "left_history": "ingest stops mid-file under memory pressure "
                        "(stopped_early) before {h}'s matching rows",
        "right_history": "the file simply ended there",
        "same_observed": "identical graph; no completeness marker on answers",
        "differs_on": "exhaustiveness of {h}'s result",
    },
    "source_coverage": {
        "left_history": "a source's poll window is skipped by the circuit "
                        "breaker while {h}'s matching events occur",
        "right_history": "the source emitted nothing in that window",
        "same_observed": "identical graph and identical answers",
        "differs_on": "ground-truth answer of {h}",
    },
    "ingestion_time": {
        "left_history": "event arrives late (event_time << arrival)",
        "right_history": "event arrives promptly",
        "same_observed": "identical edge (ingested_at_delta hardcoded 0)",
        "differs_on": "late-arrival handling / watermark reasoning for {h}",
    },
    "provenance_stability": {
        "left_history": "mapping edited after ingest; export reads current "
                        "config for old relations",
        "right_history": "relations ingested under the current mapping",
        "same_observed": "identical exported provenance",
        "differs_on": "which mapping actually produced {h}'s evidence",
    },
    "skip_diagnostics": {
        "left_history": "N rows skipped on a typed fast path (stats empty)",
        "right_history": "zero rows skipped",
        "same_observed": "identical ParseStats diagnostics (empty)",
        "differs_on": "reconstructed loss for {h}",
    },
    "completeness_flag": {
        "left_history": "answer computed over a truncated/partial ingest",
        "right_history": "answer computed over complete data",
        "same_observed": "identical answer payload (no possibly_incomplete)",
        "differs_on": "whether {h}'s answer may be treated as exhaustive",
    },
}


def _blind(surface, required):
    out = []
    for name in required:
        ch = surface["channels"].get(name, {"fidelity": "absent", "note": "undeclared"})
        if ch.get("fidelity", "absent") != "full":
            out.append({"channel": name,
                        "loss_point": ch.get("loss_point", ""),
                        "context": ch.get("context", ""),
                        "witness_type": ch.get("witness_type", ""),
                        "fix": ch.get("fix", "")})
    return sorted(out, key=lambda b: b["channel"])


def _witness(blind, query_id):
    for b in blind:
        if b["witness_type"] and b["channel"] in _WITNESS_TEMPLATES:
            t = _WITNESS_TEMPLATES[b["channel"]]
            return {"blind_channel": b["channel"],
                    "witness_type": b["witness_type"],
                    "context": b["context"],
                    "left_history": t["left_history"].format(h=query_id),
                    "right_history": t["right_history"].format(h=query_id),
                    "same_observed": t["same_observed"].format(h=query_id),
                    "differs_on": t["differs_on"].format(h=query_id)}
    return None


def _verdict(surface, required, query_id):
    blind = _blind(surface, required)
    if not blind:
        return {"status": "Sufficient", "blind_channels": [], "witness": None,
                "reinforcement": []}
    witness = _witness(blind, query_id)
    status = "InsufficientWithWitness" if witness else "Insufficient"
    fixes = sorted({b["fix"] for b in blind if b["fix"]})
    return {"status": status, "blind_channels": blind, "witness": witness,
            "reinforcement": fixes}


def audit(surface, snapshot):
    results = []
    for h in snapshot["hypotheses"]:
        r = _verdict(surface, HYPOTHESIS_REQUIRES, h["id"])
        r["id"] = h["id"]
        r["dsl_pattern"] = h["dsl_pattern"]
        results.append(r)
    transversal = []
    for q in surface.get("queries_transversal", []):
        t = _verdict(surface, q["requires"], q["id"])
        t["id"] = q["id"]
        transversal.append(t)
    return {"results": results, "transversal": transversal}
```

- [ ] **Step 4: Verificar que pasan**

Run: `python -m unittest tests.test_gh_audit -v`
Expected: `OK` (12 tests). Después `make test`: verde.

- [ ] **Step 5: Commit (repo sot)**

```bash
cd /c/Users/lsotomayor/sot
git add scripts/sot_sys/gh_audit.py tests/test_gh_audit.py
git commit -m "gh_audit: ingest-sufficiency analyzer with SOT-VM witness taxonomy"
```

---

### Task 5: Superficie declarada + runner + resultados congelados (repo sot)

**Files:**
- Create: `C:\Users\lsotomayor\sot\validation\graphhunter\ingest_surface.json`
- Create: `C:\Users\lsotomayor\sot\scripts\sot_sys\audit_graphhunter.py`
- Create: `C:\Users\lsotomayor\sot\validation\graphhunter\catalog_snapshot.json` (generado)
- Create: `C:\Users\lsotomayor\sot\validation\graphhunter\audit_results.json` (generado)
- Modify: `C:\Users\lsotomayor\sot\tests\test_gh_audit.py` (una clase más)

**Interfaces:**
- Consumes: `gh_catalog.build_snapshot`, `gh_audit.audit`, ids de contextos/transversales del ADR (Tarea 1).
- Produces: los dos JSON congelados que la Tarea 6 lee; runner con contrato CLI: sin args = escribir ambos JSON; `--check` = verificar frescura byte-idéntica; `--refresh-catalog [PATH]` = regenerar snapshot desde el checkout de GraphHunter (default `C:\Users\lsotomayor\GraphHunter`, override por arg o env `GRAPHHUNTER_ROOT` — decisión 2 del spec: ruta configurable).

- [ ] **Step 1: Autorar `ingest_surface.json`**

El modelo declarado de la superficie de ingesta, canal por canal, con la sección del assessment como fuente. Contenido exacto inicial (los `note` citan assessment; los `fix` nombran la fase del Bloque 2 — spec criterio 17):

```json
{
  "system": "GraphHunter ingest pipeline (live sync paths)",
  "declared_from": "GraphHunter docs/architecture/sot-integration-assessment.md @ b9335cf",
  "channels": {
    "entity_identity": {"fidelity": "full", "note": "interner-based vertex dedup preserves identity and merges metadata (S3)"},
    "edge_multiplicity": {"fidelity": "degraded", "loss_point": "L1'", "context": "crash_reingest", "witness_type": "behavior", "note": "append-only edges, no dedup anywhere in the insert path; crash re-poll duplicates real edges (S3)", "fix": "Fase C: GraphDelta idempotente"},
    "row_completeness": {"fidelity": "degraded", "loss_point": "L2", "context": "malformed_row", "witness_type": "future_behavior", "note": "malformed rows silently skipped; Sysmon/Sentinel fast paths leave skip diagnostics empty (S4)", "fix": "Fase B: journal + skip diagnostics"},
    "field_survival": {"fidelity": "degraded", "loss_point": "L3", "context": "unmapped_field", "witness_type": "future_behavior", "note": "sanitize_field_config/auto_field_config_for degrade unmapped fields to metadata or drop them as node candidates (S4)", "fix": "Fase B: sobre canonico versionado"},
    "event_time": {"fidelity": "full", "note": "per-edge timestamps drive causal monotonicity (S3)"},
    "ingestion_time": {"fidelity": "absent", "context": "late_arrival", "witness_type": "future_behavior", "note": "ingested_at_delta hardcoded 0 on all 5 mass-ingest sites; only non-ingest add_relation computes it (S6)", "fix": "Fase B: sobre canonico con event/ingestion time"},
    "ingest_completeness": {"fidelity": "degraded", "loss_point": "L4", "context": "memory_critical", "witness_type": "future_behavior", "note": "stopped_early cuts ingest mid-file with no signal surfaced to answers; MAX_INGEST_LINES dead guard (S5)", "fix": "Coverage fase (spec 17): possibly_incomplete"},
    "source_coverage": {"fidelity": "degraded", "loss_point": "L5", "context": "circuit_breaker", "witness_type": "future_behavior", "note": "watermark/circuit-breaker pipeline exists but is unwired in production; live path has no coverage accounting (S5)", "fix": "Fase C: cablear runtime incremental"},
    "skip_diagnostics": {"fidelity": "degraded", "context": "malformed_row", "witness_type": "future_behavior", "note": "ParseStats drift/skip_reasons/skipped_samples empty on typed fast paths (S4)", "fix": "Fase B: journal + skip diagnostics"},
    "completeness_flag": {"fidelity": "absent", "context": "memory_critical", "witness_type": "future_behavior", "note": "no possibly_incomplete field in any DTO (S11 case 28)", "fix": "Coverage fase (spec 17)"},
    "provenance_stability": {"fidelity": "degraded", "context": "mapping_edit", "witness_type": "future_behavior", "note": "export-time ProvenanceCtx reads current mapping for already-ingested relations - retroactive contamination (S4, labeled inference)", "fix": "Fase B: journal freezes provenance at ingest"}
  },
  "queries_transversal": [
    {"id": "loss_reconstruction", "requires": ["completeness_flag", "skip_diagnostics"]},
    {"id": "exhaustiveness_marking", "requires": ["completeness_flag", "ingest_completeness", "source_coverage"]}
  ]
}
```

- [ ] **Step 2: Test del runner (falla primero)**

```python
# añadir a tests/test_gh_audit.py
class TestRunnerSurface(unittest.TestCase):
    def test_real_surface_loads_and_audits(self):
        root = Path(__file__).resolve().parents[1]
        surface = json.loads((root / "validation" / "graphhunter" /
                              "ingest_surface.json").read_text(encoding="utf-8"))
        for name, ch in surface["channels"].items():
            self.assertIn(ch["fidelity"], {"full", "degraded", "absent"}, name)
            if ch["fidelity"] != "full":
                self.assertTrue(ch.get("witness_type") or True)  # opcional
                self.assertIn("note", ch)
        report = gh_audit.audit(surface, SNAP)
        self.assertEqual({t["id"] for t in report["transversal"]},
                         {"loss_reconstruction", "exhaustiveness_marking"})
```

Run: `python -m unittest tests.test_gh_audit.TestRunnerSurface -v` → FAIL (archivo no existe) hasta escribir el Step 1; después PASS.

- [ ] **Step 3: Implementar `audit_graphhunter.py`** (espejo estructural de `audit_sotos.py`)

```python
#!/usr/bin/env python3
"""Run the GraphHunter ingest-sufficiency audit and emit frozen findings.

    python scripts/sot_sys/audit_graphhunter.py                  # write audit_results.json
    python scripts/sot_sys/audit_graphhunter.py --check          # verify freshness
    python scripts/sot_sys/audit_graphhunter.py --refresh-catalog [PATH]

Inputs: validation/graphhunter/ingest_surface.json (declared model authored
from the Block-0 assessment) and validation/graphhunter/catalog_snapshot.json
(deterministic snapshot of GraphHunter's cat-*.yaml catalog; regenerate with
--refresh-catalog when GraphHunter's catalog changes). Deterministic: same
inputs yield byte-identical JSON. Offline audit over a declared model
(experiment evidence label), not a certification of the running system."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts" / "sot_sys"))

import gh_audit    # noqa: E402
import gh_catalog  # noqa: E402

VAL = REPO_ROOT / "validation" / "graphhunter"
SURFACE = VAL / "ingest_surface.json"
SNAPSHOT = VAL / "catalog_snapshot.json"
RESULTS = VAL / "audit_results.json"
DEFAULT_GH = Path(os.environ.get("GRAPHHUNTER_ROOT",
                                 Path.home() / "GraphHunter"))


def refresh_catalog(gh_root):
    catalog = Path(gh_root) / "core" / "graph-engine" / "src" / "catalog" / "builtin"
    commit = subprocess.run(["git", "-C", str(gh_root), "rev-parse", "--short", "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    snap = gh_catalog.build_snapshot(catalog, commit=commit)
    SNAPSHOT.write_text(json.dumps(snap, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    print(f"wrote {SNAPSHOT.relative_to(REPO_ROOT)} "
          f"({snap['source']['files']} hypotheses @ {commit})")


def build_report():
    surface = json.loads(SURFACE.read_text(encoding="utf-8"))
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    report = gh_audit.audit(surface, snapshot)
    return {"surface_channels": sorted(surface["channels"]),
            "catalog": snapshot["source"],
            "results": report["results"],
            "transversal": report["transversal"]}


def _serialize(report):
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--refresh-catalog", nargs="?", const=str(DEFAULT_GH),
                        metavar="GRAPHHUNTER_PATH")
    args = parser.parse_args(argv)
    if args.refresh_catalog:
        refresh_catalog(args.refresh_catalog)
        return 0
    text = _serialize(build_report())
    if args.check:
        current = RESULTS.read_text(encoding="utf-8") if RESULTS.exists() else ""
        if current != text:
            print("audit_results.json is stale; re-run audit_graphhunter.py",
                  file=sys.stderr)
            return 1
        print("audit_results.json up to date")
        return 0
    RESULTS.write_text(text, encoding="utf-8")
    print(f"wrote {RESULTS.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Generar y congelar**

```bash
cd /c/Users/lsotomayor/sot
python scripts/sot_sys/audit_graphhunter.py --refresh-catalog /c/Users/lsotomayor/GraphHunter
python scripts/sot_sys/audit_graphhunter.py
python scripts/sot_sys/audit_graphhunter.py --check   # Expected: "audit_results.json up to date"
python -m unittest tests.test_gh_audit -v              # Expected: OK (13 tests)
make test                                              # Expected: verde
```

Inspeccionar `audit_results.json`: 30 resultados (uno por cat-*) — se espera que TODOS sean `InsufficientWithWitness` (todo requisito incluye `row_completeness`, degradado) y ambas transversales insuficientes; eso es el hallazgo, no un error (spec §7). Verificar que el snapshot registró 30 hipótesis y el commit de GraphHunter.

- [ ] **Step 5: Commit (repo sot)**

```bash
git add validation/graphhunter/ingest_surface.json validation/graphhunter/catalog_snapshot.json validation/graphhunter/audit_results.json scripts/sot_sys/audit_graphhunter.py tests/test_gh_audit.py
git commit -m "GraphHunter sufficiency audit: declared surface, runner, frozen findings"
```

---

### Task 6: Documento de hallazgos + registro de la serie (repo sot)

**Files:**
- Create: `C:\Users\lsotomayor\sot\validation\graphhunter\graphhunter_sufficiency_audit.md`
- Modify: `C:\Users\lsotomayor\sot\validation\graphhunter\README.md` (estado planned → delivered)
- Modify: `C:\Users\lsotomayor\sot\validation\README.md` (fila: "planned" → descripción real)
- Modify: `C:\Users\lsotomayor\sot\MANIFEST.sha256` (regenerado)

**Interfaces:**
- Consumes: `audit_results.json` congelado (TODO número citado se lee de ahí — regla sotOs: "every number below is read from it"), correspondencia (Tarea 2), taxonomía SOT-VM.

- [ ] **Step 1: Escribir `graphhunter_sufficiency_audit.md`** (inglés; plantilla: `validation/sotos_sufficiency_audit.md`)

Secciones obligatorias:
1. Header: "Fourth entry / companion experiment to `graphhunter_integration.md`"; evidence label `experiment`; regenerate line: `python scripts/sot_sys/audit_graphhunter.py` (+ `--refresh-catalog` para actualizar el catálogo); "findings frozen in `validation/graphhunter/audit_results.json`; every number below is read from it".
2. **The declared surface**: los 11 canales con su fidelity y la sección S* del assessment que los respalda; nota honesta de que la superficie es un modelo declarado autorado desde el assessment de Bloque 0, no instrumentación del sistema corriendo.
3. **Findings**: tabla — como los 30 veredictos de hipótesis son uniformes (mismo conjunto ciego), presentarla agregada: "all 30 catalog hypotheses: InsufficientWithWitness" + la tabla de canales ciegos (canal → loss point → witness type → fix nombrando fase Bloque 2), y las dos transversales con su veredicto. Citar 1-2 testigos esquemáticos completos (el de `row_completeness` y el de `edge_multiplicity` — el segundo es tipo `behavior`, el único).
4. **Honest limits** (patrón sotOs): (a) modelo declarado, no medición — la fidelidad de cada canal es una afirmación del assessment con su etiqueta (una es `inference`: provenance_stability); (b) veredictos uniformes esperables — la señal está en los canales, no en la variación entre hipótesis; (c) los testigos son esquemáticos (dos historias construibles), no trazas ejecutadas contra GraphHunter; (d) el scoring de anomalía/GNN está fuera de B (Bridge C de la correspondencia); (e) no replicación externa.
5. **Baseline for Block 2**: párrafo final — cada fase A–G puede re-correr el runner tras cambiar la superficie declarada y mostrar el cambio de veredicto contra esta línea base (criterio 17 del spec).

- [ ] **Step 2: Actualizar READMEs y MANIFEST**

En `validation/graphhunter/README.md`: reemplazar "Status: design approved, audit not yet run" y la tabla "Planned contents" por la tabla real (4 documentos/datos + runner + resultados, cada uno una línea). En `validation/README.md`: actualizar la fila `graphhunter/` a algo como "ingest-sufficiency audit of GraphHunter against its hypothesis catalog (experiment) — see its README". Regenerar MANIFEST:

```bash
cd /c/Users/lsotomayor/sot && python scripts/write_manifest.py
```

- [ ] **Step 3: Verificar**

Checklist: (a) cada número del documento existe en `audit_results.json` (verificación manual explícita en el reporte); (b) `python scripts/sot_sys/audit_graphhunter.py --check` → "up to date"; (c) `make test` verde; (d) las 5 secciones obligatorias presentes; (e) sección Honest limits menciona los 5 puntos; (f) `bash scripts/verify_all.sh` no se rompe por los archivos nuevos (si el script referencia MANIFEST, debe pasar con el regenerado) — si falla por causas preexistentes ajenas, documentarlo sin ocultarlo.

- [ ] **Step 4: Commit (repo sot)**

```bash
cd /c/Users/lsotomayor/sot
git add validation/graphhunter/graphhunter_sufficiency_audit.md validation/graphhunter/README.md validation/README.md MANIFEST.sha256
git commit -m "GraphHunter sufficiency audit report: frozen findings + series registration"
```

---

## Self-Review (del plan, ya ejecutada)

- **Cobertura del spec (Bloque 1):** ADR con X/S/B/C/R e invariante (T1 ↔ spec §3+§5); correspondencia (T2 ↔ spec Bloque 1 "documento de correspondencia"); runner que parsea cat-*.yaml y emite veredictos con JSON congelado (T3–T5 ↔ spec Bloque 1); documento de auditoría con hallazgos que fijan prioridades del Bloque 2 (T6); criterios 16–17 del spec (entrada de la serie regenerable + re-corrible por fase) cubiertos en T5 (--check) y T6 (Baseline for Block 2). Prioridades S16-R4 del assessment presentes como canales de la superficie (fast-path skips, field-config, stopped_early, ingested_at_delta, possibly_incomplete).
- **Placeholders:** ninguno — cada tarea con código lleva tests y implementación completos; las tareas documentales llevan estructura obligatoria por sección y checklist verificable. La única flexibilidad declarada (ajustar `parse_dsl` si el filtrado es frágil) fija el árbitro: los tests.
- **Consistencia de tipos/nombres:** `parse_dsl`/`parse_cat_file`/`build_snapshot` (T3) usados por `audit_graphhunter.py` (T5) con las mismas firmas; `HYPOTHESIS_REQUIRES` y el schema de `audit()` (T4) consumidos por el runner y el test de superficie (T5); ids `loss_reconstruction`/`exhaustiveness_marking` y los 7 contextos idénticos en ADR (T1), superficie (T5) y hallazgos (T6); `desglose de resultados` en T6 lee el schema exacto de T4.
- **Nota de honestidad pre-registrada:** el resultado esperado (30/30 InsufficientWithWitness uniformes) se declara en T5-Step 4 y se explica en T6 Honest limits (b) — el plan no fabrica variación donde el modelo no la tiene.
