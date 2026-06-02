# Sentinel Seed from IoC — MCP cold-start primitive

**Fecha:** 2026-06-02
**Estado:** Diseño aprobado — pendiente plan de implementación
**Owner:** Lucas
**Relacionado:** `2026-06-01-sentinel-live-node-hydration-design.md` (reusa su motor `hydrate_node_with`)

## 1. Problema

GraphHunter arranca con el grafo vacío. Hoy hay tres formas de poblarlo
(polling, KQL ad-hoc / templates, ingesta de archivo), pero **ninguna está
expuesta por MCP**. Un LLM con MCP solo puede cazar sobre data ya ingestada
(`hunt_run`, `node_*`, `graph_summary`) — no puede traerla. Resultado: el LLM
no puede arrancar un hunt en frío; depende de que el analista siembre primero
por la UI.

La hidratación live en expand (spec del 2026-06-01) completa el vecindario de
un nodo **existente**, pero no resuelve el arranque en frío: asume que ya hay
un nodo.

## 2. Objetivo

Un primitivo MCP de **arranque en frío por IoC conocido**: el LLM (o analista
vía LLM) dice "necesito todo sobre la IP X" / "el usuario Y", y GraphHunter
trae de Sentinel todos los eventos que tocan ese indicador en la ventana
elegida, los ingesta (creando el nodo y su vecindario), y devuelve lo
suficiente para empezar a cazar de inmediato.

Cierra el loop end-to-end por MCP:
**`sentinel_seed` (sembrar) → `hunt_run` (cazar) → `node_expand` live (profundizar)**.

### No-objetivos (YAGNI)

- No expone KQL crudo por MCP (el LLM pasa tipo + valor, no KQL).
- No siembra desde categorías temáticas, slices de tabla, ni incidentes
  Sentinel (esas formas quedaron descartadas en brainstorming; el seed es
  por IoC conocido). Pueden ser specs futuros.
- No infiere el tipo de entidad por formato (el LLM lo pasa explícito).
- No siembra multi-IoC en batch (un IoC por llamada).

## 3. Decisiones tomadas (no re-debatir)

| Decisión | Valor |
|----------|-------|
| Forma del seed | IoC conocido (entity_type + value) |
| Tipo de entidad | **Explícito** por el LLM (no inferido) |
| Retorno | outcome (counts) + vecindario (subgrafo) + top anomalías |
| Construcción | **Composición** de `hydrate_node_with` + `expand_node` + sort por score (un motor, dos puertas) |
| Sesión ausente | **Auto-crear** una sesión `"Sentinel Seed: <value>"` (cold-start real en una llamada) |
| Dataset tag | `"Sentinel Seed"` (distinto de `"Sentinel Hydration (live)"` para provenance) |
| top_anomalies | top-5 nodos del vecindario por score, shape `NeighborNode` (sin tipo nuevo) |
| Exposición | tool MCP `sentinel_seed` + ruta `POST /sentinel/seed` |

## 4. Arquitectura

```
sentinel_seed(entity_type, value, lookback?)            [MCP tool, nuevo]
        │  POST /sentinel/seed { entity_type, value, lookback? }
        ▼
  seed_from_ioc(SeedFromIocRequest) -> SeedResult        [nueva op en operations/sentinel.rs]
        │  1. parse entity_type (string) -> EntityType  (parse_entity_type; InvalidInput si desconocido)
        │  2. resolver sesión actual; si no hay -> auto-crear "Sentinel Seed: <value>"
        │  3. resolver creds Azure del entorno (skip si faltan)
        │  4. hydrate_node_with(transport, cache, value, &ty, time_filter, ws, auth)   ← MOTOR EXISTENTE
        │  5. si el nodo `value` existe en el grafo -> expand_node(node_id=value) -> Neighborhood
        │     si no existe (hidratación skip/vacía) -> Neighborhood vacío (center=value)
        │  6. top_anomalies = neighborhood.nodes ordenado por score desc, top 5
        ▼
  SeedResult { hydration, neighborhood, top_anomalies }
```

### 4.1 Componentes

1. **`seed_from_ioc`** — nueva `async fn` en `platform/api/src/operations/sentinel.rs`,
   al lado de `hydrate_node_with` / `run_kql`. Compone; no reimplementa pull.
   El dataset de hidratación se taguea `"Sentinel Seed"` (parametrizar el tag
   en `hydrate_node_with`, o pasar el tag — ver §4.3).

2. **DTOs** en `platform/api/src/dto/v1/sentinel.rs`:
   ```rust
   pub struct SeedFromIocRequest {
       pub session: Option<SessionHandle>,
       pub entity_type: String,     // "IP" | "User" | "Host" | "Process" | "File"
       pub value: String,
       pub time_window: Option<TimeWindow>,
   }
   pub struct SeedResult {
       pub hydration: HydrationOutcome,                 // de graph_hunter_core::analytics
       pub neighborhood: graph_hunter_core::analytics::Neighborhood,
       pub top_anomalies: Vec<graph_hunter_core::analytics::NeighborNode>,
   }
   ```

3. **Ruta HTTP** `POST /sentinel/seed` — handler en
   `apps/tauri/src-tauri/src/http/siem.rs` (junto a `handler_run_kql`).
   Body JSON con `entity_type`, `value`, `lookback` (preset string) o
   `time_window`. Reusa `lookback_to_window` (o su equivalente) para mapear
   preset → `TimeWindow::Preset`.

4. **Tool MCP** `sentinel_seed` en nueva carpeta `platform/mcp/src/tools/sentinel/`.
   Input zod: `entity_type` (enum IP/User/Host/Process/File), `value` (string),
   `lookback` (enum 1h/6h/24h/7d/30d, opcional). Descripción orientada al LLM:
   "Seed the graph from a known Sentinel IoC. Pulls all of its events in the
   lookback window, ingests them, and returns the seeded neighborhood + top
   anomalies. Use this to START a hunt when the graph is empty."
   Registrar la categoría `sentinel` en el índice de tools.

### 4.2 Auto-creación de sesión

Si `resolve_session` no encuentra sesión actual, `seed_from_ioc` crea una vía
el mismo `create_session(CreateSessionRequest { name })` que usan los tests,
con `name = "Sentinel Seed: <value>"`. Esto hace el cold-start posible en una
sola llamada MCP (consistente con el objetivo "GH vacío al inicio"). Si ya hay
sesión, usa esa (no crea otra).

### 4.3 Tag de dataset

`hydrate_node_with` hoy hardcodea el dataset `"Sentinel Hydration (live)"`.
Para distinguir el origen cold-start del drill-down, `seed_from_ioc` necesita
taguear `"Sentinel Seed"`. Opción mínima: añadir un parámetro `dataset_tag:
&str` a `hydrate_node_with` (live-expand pasa `"Sentinel Hydration (live)"`,
seed pasa `"Sentinel Seed"`). Es un cambio compatible y de una línea en el
call site existente.

## 5. Gating y errores

- **`entity_type` desconocido** (no mapea a IP/User/Host/Process/File) →
  `ApiError::InvalidInput` con la lista de tipos válidos.
- **Tipo sin mapeo Sentinel** (Domain/URL/Registry/Service/Any) →
  `hydration.skipped=true` (reason del motor) + `neighborhood` vacío
  (center=value) + `top_anomalies` vacío. Sin error.
- **Sin credenciales Azure** → `skipped` "Azure no configurado" + vacío.
- **Resultado vacío** (IoC ausente en Sentinel) → outcome con 0 counts;
  el nodo no se crea; `neighborhood` con `center=value` y `nodes`/`edges`
  vacíos; `top_anomalies` vacío.
- **Concurrencia** — idéntica a la hidratación: comparte el `RwLock` del grafo
  con el polling, sin lock cruzando `await` (heredado de `hydrate_node_with`).

## 6. Testing

Reusa el `MockTransport` de los tests de hidratación (`operations/sentinel.rs`).

- **seed IP exitoso:** mock devuelve filas SigninLogs; `seed_from_ioc(type="IP",
  value="10.0.0.9")` → `hydration.skipped=false`, `neighborhood.center=="10.0.0.9"`,
  `neighborhood.nodes` no vacío, `top_anomalies` ordenado por score desc.
- **auto-creación de sesión:** llamar seed SIN crear sesión antes → no error,
  y existe una sesión nueva nombrada `"Sentinel Seed: 10.0.0.9"`.
- **tipo sin mapeo:** `type="Domain"` → `skipped=true`, neighborhood vacío, sin error.
- **tipo inválido:** `type="Banana"` → `ApiError::InvalidInput`.
- **sin creds:** sin AZURE_* → `skipped` "credenciales no configuradas".
- **HTTP handler + MCP schema:** verificados por compile (`cargo check` tauri,
  `tsc` mcp). Lookback preset → TimeWindow correcto.

## 7. Out of scope

- Seed por categoría temática / slice de tabla / incidente Sentinel (futuros).
- Inferencia de tipo por formato.
- Batch multi-IoC.
- Exponer `run_kql` / `run_hunting_template` crudos por MCP.
- Cambios de UI (este primitivo es MCP-first; la UI ya tiene KQL ad-hoc).
