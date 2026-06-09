# Snapshot Ingest by Dataset Layer (Option A)

**Fecha:** 2026-06-09
**Estado:** Diseño aprobado — pendiente plan
**Owner:** Lucas
**Relacionado:** habilita el playbook graph-native (`2026-06-08-graph-native-hunting-playbook-design.md`)

## 1. Problema

Cada ingesta de GraphHunter taggea con un `dataset_id` aleatorio (`Uuid::new_v4()`),
y `insert_triples` appendea (1 arista por evento; las entidades dedup-ean por id, las
relaciones no). Re-correr la misma KQL/escenario crea un dataset nuevo → relaciones
duplicadas. Esa **no-idempotencia** (señalada por Diego) es la razón por la que la
ingesta no puede ser el default seguro del hunt: ingestar agresivamente (como exige el
flujo graph-native) acumularía basura cada vez que el LLM repite o refina una query.

## 2. Objetivo

Permitir **ingesta snapshot por capa**: un parámetro `dataset` (nombre de capa) en las
ingestas dirigidas por el LLM. Si se provee, la ingesta **reemplaza** esa capa
(remove + insert); si se omite, mantiene el comportamiento actual (append). Re-correr la
misma query/escenario con el mismo nombre **refresca** en vez de duplicar. Capas con
nombres distintos coexisten y se correlacionan.

Esto vuelve la ingesta segura para repetir, habilitando que el playbook graph-native
ingeste agresivamente sin la objeción de no-idempotencia.

### No-objetivos (YAGNI)
- NO dedup por contenido a nivel evento (opción C descartada: pesada, "mismo evento" difuso).
- NO sesiones scratch efímeras (opción B descartada: pierde correlación cross-escenario).
- NO ownership multi-dataset por entidad (ver §6 limitación conocida; follow-up si hace falta).
- NO cambiar el comportamiento por defecto (omitir `dataset` = exactamente como hoy).

## 3. Decisiones tomadas (no re-debatir)

| Decisión | Valor |
|---|---|
| Mecanismo | reusar `remove_entities_and_relations_by_dataset` (ya existe) + `insert_triples` con id estable |
| Opt-in | **el nombre ES el opt-in de replace** — sin flag `replace` aparte |
| Omitir `dataset` | comportamiento actual (run_kql: Uuid random; node_enrich: tag fijo) — backward-compat |
| Tools afectadas | `node_enrich`, `sentinel_query` (solo con `ingest=true`) |
| Unidad de reemplazo | la capa `dataset` (nombre lógico por query/escenario), no la llamada |

## 4. Cambios por capa

### 4.1 DTOs (`platform/api/src/dto/v1/sentinel.rs`)
- `NodeEnrichRequest`: agregar `dataset: Option<String>` (`#[serde(default, skip_serializing_if = "Option::is_none")]`).
- `RunKqlRequest`: agregar `dataset: Option<String>` (idem).

### 4.2 Op `run_kql` (`platform/api/src/operations/sentinel.rs`)
Solo en el path de ingesta (`ingest != Some(false)`). Reemplazar la asignación de
`dataset_id`:
```rust
let dataset_id = match &req.dataset {
    Some(name) => name.clone(),          // capa estable nombrada
    None => Uuid::new_v4().to_string(),  // comportamiento actual
};
// Si es una capa nombrada, reemplazarla antes de insertar:
if req.dataset.is_some() {
    let mut graph = session.graph.write()?;
    graph.remove_entities_and_relations_by_dataset(&dataset_id)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
}
// ... insert_triples(triples, Some(&dataset_id)) como hoy
```
El registro de `DatasetInfo` usa el mismo `dataset_id` (nombre estable cuando aplica).

### 4.3 Op `node_enrich` (`platform/api/src/operations/sentinel.rs`)
Hoy llama `hydrate_node_filtered_with(..., dataset_tag = "Sentinel Enrich (node)", ...)`.
Cambio:
```rust
let dataset_tag = req.dataset.as_deref().unwrap_or("Sentinel Enrich (node)");
if req.dataset.is_some() {
    if let Ok(mut graph) = session.graph.write() {
        graph.remove_entities_and_relations_by_dataset(dataset_tag)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
    }
}
// pasar dataset_tag a hydrate_node_filtered_with (que inserta con ese tag)
```
(El `session` ya se resuelve arriba en `node_enrich` para leer el entity_type; reusar ese handle.)

### 4.4 HTTP (`apps/tauri/src-tauri/src/http/siem.rs`)
- `NodeEnrichBody`: agregar `dataset: Option<String>` (`#[serde(default)]`); forward a `NodeEnrichRequest`.
- `RunKqlBody`: agregar `dataset: Option<String>` (`#[serde(default)]`); forward a `RunKqlRequest`.

### 4.5 MCP (`platform/mcp/src/tools/`)
- `node/enrich.ts`: input `dataset?: z.string().max(200)`; lo agrega al body si está presente.
- `sentinel/query.ts`: input `dataset?: z.string().max(200)`; lo agrega al body si está presente.
- Describe (ambos):
  > "Name this ingest as a refreshable layer — re-running with the same dataset name REPLACES it instead of duplicating (snapshot). Omit for a one-off append. Use a stable per-scenario/hypothesis name."
- En `sentinel_query`, el `dataset` solo tiene efecto con `ingest=true` (notarlo en el describe).

## 5. Flujo resultante

```
node_enrich(node, dataset="scenarioA-recon")   → remove(scenarioA-recon) + insert  (capa fresca)
node_enrich(node, dataset="scenarioA-recon")   → remove + insert otra vez           (refresca, NO duplica)
sentinel_query(kql, ingest=true, dataset="scenarioA-exfil") → capa separada, coexiste y correlaciona
```
El grafo deja de ser "pila que crece" y pasa a "capas vivas refrescables".

## 6. Limitación conocida (documentar)

`remove_entities_and_relations_by_dataset(X)` borra entidades cuyo `dataset_id == X`. Las
relaciones tienen `ds_tag` propio (se reemplazan limpio), pero una **entidad compartida
cross-source** guarda el `dataset_id` del primer writer. Si la capa X creó la entidad y la
capa Y la referencia, `remove(X)` la sacaría aunque Y la use (las aristas de Y quedan, la
entidad nodo se va y se re-crea en el próximo insert que la toque). Para el caso típico
(sembrar escenario A, refrescar A) no molesta. Follow-up si se vuelve problema: ownership
multi-dataset por entidad (refcount o set de datasets). **Fuera de scope de esta iteración.**

## 7. Testing

- **run_kql replace:** ingestar con `dataset="L"` (mock data) dos veces; el conteo de
  relaciones tras la 2da == tras la 1ra (reemplazó, no duplicó). Sin `dataset`, dos
  ingestas acumulan (comportamiento actual preservado).
- **node_enrich replace:** mismo patrón vía `hydrate_node_filtered_with` con MockTransport;
  re-enrich con el mismo `dataset` no duplica relaciones.
- **Coexistencia:** ingestar capa "A" y capa "B"; `remove`/refresh de "A" no afecta "B".
- **Backward-compat:** `dataset=None` → run_kql usa Uuid random y appendea (tests existentes
  siguen verdes); node_enrich usa el tag fijo como hoy.
- **HTTP/MCP:** compile + tsc; `dataset` opcional fluye end-to-end.

## 8. Out of scope

- Dedup por contenido (opción C).
- Sesiones scratch (opción B).
- Ownership multi-dataset por entidad (limitación §6).
- Auto-derivar el nombre de capa desde la query (el LLM provee el nombre explícito).
- UI para gestionar capas (esto es API/MCP; la UI ya tiene `remove_dataset`).
