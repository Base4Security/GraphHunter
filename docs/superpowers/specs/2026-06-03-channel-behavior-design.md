# Channel Behavior — temporal/behavioral detection (SP-C)

**Fecha:** 2026-06-03
**Estado:** Diseño aprobado — pendiente plan
**Owner:** Lucas
**Iniciativa:** "Mejorar resultados de GraphHunter para datos de firewall" — SP-C de 3 (SP-A entidades ✓, SP-B heavy_edges ✓, SP-C este = el último).

## 1. Problema

SP-B (`heavy_edges`) resume aristas por volumen (count/bytes/%resets agregados),
pero **no captura la dimensión temporal**: cuándo ocurren las conexiones. Un
canal beacon-like (C2: conexiones cada ~N seg con baja varianza) es
indistinguible de una app legítima de alto volumen mirando solo totales — el
caso real Telecarga (94k conexiones en bursts irregulares de 9h) NO es C2, pero
SP-B no lo separa de uno que sí late periódicamente.

## 2. Objetivo

Una proyección read-only `channel_behavior` que, por canal
`(source, dest, rel_type)`, computa métricas **temporales**: regularidad de
inter-arribos (beaconing), clustering de resets (ráfagas), y picos de volumen
por ventana — rankeada/filtrable, expuesta como tool dedicado (op + MCP + HTTP).

### No-objetivos (YAGNI)
- NO re-implementar el volumen agregado (SP-B `heavy_edges` lo cubre).
- NO ScoreComponent / integración al anomaly score (se eligió tool dedicado).
- NO sliding windows (buckets fijos en v1).
- NO storage changes (read-only).

## 3. Decisiones tomadas (no re-debatir)
| Decisión | Valor |
|----------|-------|
| Detecta | beaconing/periodicidad + ráfagas de reset + spikes de volumen |
| Altitud | tool analítico dedicado (op + MCP `graph_channel_behavior` + HTTP), read-only |
| Agrupación | `(source, dest, rel_type)` graph-wide (rel_type recuperado vía `_rel_type`, SP-B) |
| beacon_score | `1 - min(interval_cv, 1.0)` (CV=0 → 1; CV≥1 → 0) |
| Ventanas | buckets fijos `floor(ts / window_secs)` |
| min eventos beacon | `count >= 3` (≥2 intervalos) o beacon_score=0 |
| Defaults | `top_n=50`, `min_count=4`, `window_secs=60`, `sort_by=beacon` |

## 4. Métricas (`ChannelBehavior` struct, Serialize)
```rust
pub struct ChannelBehavior {
    pub source: String,
    pub target: String,
    pub rel_type: String,
    pub count: usize,
    pub first_ts: i64,
    pub last_ts: i64,
    // Beaconing
    pub interval_mean_secs: f64,   // 0.0 if count < 2
    pub interval_cv: f64,          // coef. variation of inter-arrivals; 0.0 if count < 3
    pub beacon_score: f64,         // 1 - min(interval_cv, 1.0); 0.0 if count < 3
    // Reset bursts
    pub max_resets_in_window: usize,
    // Volume spikes (per window_secs bucket)
    pub max_bytes_in_window: u64,
    pub max_count_in_window: usize,
}
```

### 4.1 Cómputo (por canal)
- Recolectar la **serie de timestamps** del canal (todas sus aristas) + `sentbyte`
  (parse u64) + flag reset (`action ∈ {client-rst, server-rst}`).
- **Beaconing:** ordenar timestamps; `intervals[i] = ts[i+1]-ts[i]`.
  `interval_mean = mean(intervals)`; `interval_cv = stddev(intervals)/mean`
  (si mean==0 → cv=0). `beacon_score = 1 - min(interval_cv, 1.0)`.
  Si `count < 3` → `interval_mean=0, interval_cv=0, beacon_score=0`.
- **Ventanas (buckets fijos):** `bucket = ts / window_secs` (entero). Por bucket
  acumular: nº resets, Σ bytes, nº edges. Las métricas `max_*_in_window` = el
  máximo sobre todos los buckets del canal.

### 4.2 Opciones (`ChannelBehaviorOpts`)
- `top_n: usize` (default 50) — máx canales tras ordenar.
- `min_count: Option<usize>` (default 4) — descarta canales con menos aristas.
- `window_secs: u64` (default 60) — tamaño de bucket para resets/volumen.
- `rel_type: Option<String>` — filtra por tipo.
- `sort_by`: `beacon` (default, beacon_score desc) | `resets`
  (max_resets_in_window desc) | `volume` (max_bytes_in_window desc).

## 5. Componentes
| Pieza | Archivo |
|---|---|
| `channel_behavior` + `ChannelBehavior` + `ChannelBehaviorOpts` (+ sort enum) | `core/graph-engine/src/analytics.rs` |
| `ChannelBehaviorRequest` DTO | `platform/api/src/dto/v1/graph_ops.rs` |
| `graph_channel_behavior` op | `platform/api/src/operations/graph_ops.rs` (with_graph_read) |
| MCP tool `graph_channel_behavior` | `platform/mcp/src/tools/graph/channel_behavior.ts` (+ index) |
| Ruta HTTP `GET /channel_behavior` | `apps/tauri/src-tauri/src/http/graph.rs` (+ mod.rs) |

## 6. No-destructivo + costo + límite conocido
- Read-only (`&self`); sin cambios de storage.
- Costo: scan O(aristas) + recolección de timestamps por canal (memoria acotada
  por el canal más grande), on-demand. Mismo orden que `heavy_edges`.
- **Límite heredado de `for_each_edge`:** base-only, excluye tail edges
  post-finalize (grafo Sentinel live). Documentar con NOTE (igual que SP-B);
  cobertura tail = follow-up tracked.

## 7. Testing
- **Beaconing:** canal regular ts=[0,60,120,180] → `interval_cv≈0`,
  `beacon_score≈1.0`; canal irregular ts=[0,5,200,201] → cv alto,
  beacon_score bajo; canal con `count<3` → beacon_score=0.
- **Reset burst:** 3 aristas reset dentro de un `window_secs` → `max_resets_in_window=3`.
- **Volume spike:** bytes concentrados en un bucket → `max_bytes_in_window` correcto.
- **Opts:** `min_count` filtra; `sort_by` cambia el orden; `rel_type` filtra;
  rel_type custom ("SNAT") se etiqueta bien (recovery SP-B).
- API/MCP/HTTP: compile + tool rankea.

## 8. Out of scope
- ScoreComponent / anomaly-score integration.
- Sliding windows / FFT-based periodicity (buckets + CV alcanzan v1).
- Tail-edge coverage en `for_each_edge` (follow-up).
- `temporal_heatmap` Other-label fix (follow-up SP-B).
