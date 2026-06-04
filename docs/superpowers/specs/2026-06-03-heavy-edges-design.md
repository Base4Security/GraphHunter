# Heavy Edges — weighted-edge analytics (SP-B)

**Fecha:** 2026-06-03
**Estado:** Diseño aprobado — pendiente plan
**Owner:** Lucas
**Iniciativa:** "Mejorar resultados de GraphHunter para datos de firewall" — SP-B de 3 (SP-A entidades ✓ shipped; SP-B este; SP-C temporal/comportamiento pendiente).

## 1. Problema

Tras SP-A, un flujo FortiGate emite ~4 triples; con 89k+ flujos repetidos
(mismo `src→dst:rel_type`) el grafo acumula decenas de miles de aristas
paralelas idénticas. El grouping read-time (`get_neighborhood_grouped`,
`edge_count`, `first_ts/last_ts`) ya colapsa para **display** por vecindario,
pero:
- no hay forma de **cazar/rankear por peso** (volumen) de arista —
  "aristas con >N conexiones", "top por bytes", "alto %resets";
- los agregados existentes son pobres (solo count + first/last ts; sin bytes,
  duración, ni %resets).

## 2. Objetivo

Una **proyección de solo-lectura** que resuma las aristas repetidas por
`(source, dest, rel_type)` con métricas de volumen, rankeada y filtrable,
expuesta como tool analítico dedicado (API + MCP + HTTP). El analista/LLM
pregunta "mostrame las aristas más pesadas / con más resets" sin tocar el
storage ni el DSL.

### No-objetivos (YAGNI / explícito)
- **NO agregar/colapsar en storage** (decisión clave): los `CompactRelation`
  per-evento quedan intactos. La agregación destructiva en ingest/parser
  rompería SP-C (que necesita los timestamps per-evento) y el invariante
  "1 arista = 1 evento" del core. SP-B es no-destructivo a propósito.
- NO extender el DSL con predicados numéricos (alternativa descartada).
- NO resolver memoria por storage (lo cubre el spill store ya existente).

## 3. Decisiones tomadas (no re-debatir)
| Decisión | Valor |
|----------|-------|
| Altitud | read-side, no-destructiva |
| Exposición | tool analítico dedicado (API op + MCP `graph_heavy_edges` + ruta HTTP) |
| Agrupación | por `(source, dest, rel_type)` graph-wide |
| Orden default | `count` desc, `total_bytes` como desempate |
| Storage | sin cambios (`CompactRelation` intacto) |

## 4. Arquitectura

```
graph_heavy_edges(top_n?, min_count?, rel_type?)   [MCP tool / HTTP / API op]
        │
        ▼
  heavy_edges(&graph, opts) -> Vec<HeavyEdge>        [core: analytics.rs, read-only]
        │  full-scan de CompactRelations, group by (src_sid, dst_sid, rel_type_tag),
        │  agrega métricas leyendo meta_store por arista; ordena; trunca a top_n
        ▼
  Vec<HeavyEdge> { source, target, rel_type, count, total_bytes,
                   total_duration_secs, reset_pct, first_ts, last_ts }
```

### 4.1 `HeavyEdge` (core struct, Serialize)
```rust
pub struct HeavyEdge {
    pub source: String,
    pub target: String,
    pub rel_type: String,
    pub count: usize,
    pub total_bytes: u64,
    pub total_duration_secs: u64,
    pub reset_pct: f64,        // 0.0..100.0
    pub first_ts: i64,
    pub last_ts: i64,
}
```

### 4.2 Agregación (por grupo)
Iterando las aristas del grafo, agrupadas por `(source_sid, dest_sid, rel_type_tag)`:
| Métrica | Cómo |
|---|---|
| `count` | nº de aristas del grupo |
| `total_bytes` | Σ `sentbyte` (metadata vía `meta_store`, parse a u64; ausente/no-num → 0) |
| `total_duration_secs` | Σ `duration` (idem) |
| `reset_pct` | `100 * (#aristas con action∈{client-rst,server-rst}) / count` |
| `first_ts` / `last_ts` | min / max `timestamp` |

Genérico: cualquier arista con esa metadata contribuye; sin metadata suma solo
`count` (bytes/duration 0, no cuenta como reset). El `rel_type` string sale del
`rel_type_tag` (mismo mapeo que usa el grouping existente).

### 4.3 Opciones de query (`HeavyEdgesOpts`)
- `top_n: usize` (default 50) — máximo de grupos devueltos tras ordenar.
- `min_count: Option<usize>` — descarta grupos con `count < min_count`.
- `rel_type: Option<String>` — acota a un tipo de relación (ej. "Connect", "SNAT").
- Orden: `count` desc, `total_bytes` desc como desempate.

## 5. Componentes
| Pieza | Archivo | Responsabilidad |
|---|---|---|
| `heavy_edges` + `HeavyEdge` + `HeavyEdgesOpts` | `core/graph-engine/src/analytics.rs` | proyección read-only + struct |
| `graph_heavy_edges` op | `platform/api/src/operations/graph_ops.rs` | wrapper que resuelve sesión y llama al core |
| DTO request/result | `platform/api/src/dto/v1/graph_ops.rs` | `HeavyEdgesRequest` (top_n/min_count/rel_type) |
| MCP tool `graph_heavy_edges` | `platform/mcp/src/tools/graph/heavy_edges.ts` (+ index) | expone al LLM |
| Ruta HTTP | `apps/tauri/src-tauri/src/http/graph.rs` (+ mod.rs) | `GET /heavy_edges` |

## 6. No-destructivo + costo
- Cero escrituras: `heavy_edges` solo lee `CompactRelation` + `meta_store`. El
  storage y los eventos per-evento quedan idénticos (SP-C intacto).
- Costo: O(aristas) scan + lectura de metadata por arista, on-demand (no
  por-tick). Mismo orden de trabajo que el grouping de vecindario, pero
  graph-wide. Aceptable para un query analítico explícito.

## 7. Testing
- **Core (`heavy_edges`):** grafo con un grupo repetido (ej. 4× `A→B Connect`
  con `sentbyte`/`duration`, una con `action=client-rst`) + un grupo menor
  (`A→C` ×1) → assert: grupo A→B tiene `count=4`, `total_bytes=Σ`,
  `reset_pct=25.0`, `first_ts`/`last_ts` correctos; ranking pone A→B antes que
  A→C; `min_count=2` descarta A→C; `rel_type="SNAT"` filtra.
- **Aristas sin metadata:** contribuyen `count`, `total_bytes=0`, no resets.
- **API/MCP/HTTP:** compile + el tool MCP devuelve la lista rankeada;
  `top_n` trunca.

## 8. Out of scope
- SP-C (temporal/comportamiento: beaconing, ráfagas).
- Agregación destructiva en storage / parser.
- Predicados de peso en el DSL.
