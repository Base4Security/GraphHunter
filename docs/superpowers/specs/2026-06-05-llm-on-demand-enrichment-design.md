# LLM On-Demand Enrichment — node_enrich + sentinel_query + sentinel_status

**Fecha:** 2026-06-05
**Estado:** Diseño aprobado — pendiente plan
**Owner:** Lucas

## 1. Problema

Un LLM (Claude Desktop u otro cliente MCP) hoy puede sembrar el grafo desde un
IoC (`sentinel_seed`) y traer **todo** lo de un nodo (`node_expand(live:true)`),
pero no puede:

1. Pedir un **dato específico** de un nodo ("traeme solo los SigninLogs de este
   usuario, últimos 7d") — la hidratación es todo-o-nada.
2. Ejecutar **KQL propio** contra el workspace — `run_kql` existe en motor +
   `POST /kql` pero no está expuesto vía MCP.
3. Ver el **estado de la conexión** Sentinel — `GET /sentinel_status` existe
   pero no hay tool MCP; el LLM opera a ciegas ("not connected" como única señal).

## 2. Objetivo

Tres tools MCP nuevos (catálogo 40 → 43) que habilitan exploración dirigida por
LLM con enriquecimiento on-demand vía KQL a Azure Sentinel, sin polling:

| Tool | Rol |
|---|---|
| `node_enrich` | pull selectivo del SIEM para un nodo (tablas/ventana/cap) |
| `sentinel_query` | KQL libre, modo dual (inspeccionar vs ingestar) |
| `sentinel_status` | estado read-only de la conexión |

## 3. Decisiones tomadas (no re-debatir)

| Decisión | Valor |
|---|---|
| Niveles de control KQL | ambos: estructurado (`node_enrich`) + libre (`sentinel_query`) |
| Forma del estructurado | tool dedicado `node_enrich`; `node_expand(live)` queda intacto |
| Ops de conexión | solo `sentinel_status` (read-only); pause/resume quedan UI/HTTP |
| Semántica `sentinel_query` | modo dual `ingest: bool`; default MCP `false`, default DTO `true` (retro-compat HTTP) |
| Motor `node_enrich` | reusar maquinaria de hidratación + `HydrationFilter` (NO query-builder nuevo) |

## 4. Componentes

### 4.1 `node_enrich`

**Input MCP** (zod):
- `node_id: string` (max 500) — nodo existente del grafo.
- `tables?: string[]` — subset de las tablas mapeadas para el tipo del nodo
  (default: todas, igual que la hidratación actual). Tablas no mapeadas para el
  tipo se reportan en `tables_attempted` sin error.
- `lookback?: "1h"|"6h"|"24h"|"7d"|"30d"` (default 24h — misma enum que seed/expand).
- `max_rows?: number` (1..5000, default 1000) — cap de filas **por tabla**,
  inyectado como `| take N` en el KQL.

**Motor:** nuevo struct `HydrationFilter { tables: Option<Vec<String>>, max_rows: Option<u32> }`
threaded por `hydrate_node_with`:
- Filtra el resultado de `sentinel_entity_targets(ty)` a las tablas pedidas
  (case-insensitive match sobre el nombre de tabla).
- `build_hydration_kql` agrega `| take {max_rows}` cuando hay cap.
- `filter = None` ⇒ comportamiento actual exacto (los call-sites existentes —
  expand-live y seed — pasan `None`; cero cambio de semántica).

**Output:** el `HydrationOutcome` existente (`skipped`, `reason`,
`new_entities`, `new_relations`, `tables_hit`, `tables_attempted`).

**Plumbing:** op `node_enrich` en `platform/api` (DTO `NodeEnrichRequest`),
ruta `POST /node/enrich` en el server axum, tool MCP `node/enrich.ts`
registrado en `nodeTools`.

### 4.2 `sentinel_query`

**Input MCP** (zod):
- `query: string` (max 10_000) — KQL.
- `time_window?: "1h"|"6h"|"24h"|"7d"|"30d"` — mismo soft-sugar que `run_kql` hoy.
- `ingest?: boolean` — **default `false` en la capa MCP** (el tool siempre lo
  envía explícito).
- `max_rows?: number` (1..1000, default 200) — cap de filas devueltas cuando
  `ingest=false` (truncado server-side post-query; se reporta `truncated: bool`).

**Motor/API:** `RunKqlRequest` gana `ingest: Option<bool>` (serde default
`None` ⇒ tratado como `true`, preservando la semántica actual de `POST /kql`
para la UI). Con `ingest=false`:
- Ejecuta el query igual (token, transport, time_window).
- NO llama al parser ni a `insert_triples` — el grafo no cambia.
- Devuelve `{ columns, rows (capped), row_count_total, truncated }`.
Con `ingest=true`: comportamiento actual (parse con formato "sentinel" +
insert), devuelve counts como hoy.

**Plumbing:** mismo `POST /kql` (el DTO crece, retro-compatible), tool MCP
`sentinel/query.ts` registrado en `sentinelTools`.

### 4.3 `sentinel_status`

Wrapper fino sobre `GET /sentinel_status` existente: conectado?, status
(Paused/Polling/...), workspace, watermarks por tabla. Sin cambios de motor.
Tool MCP `sentinel/status.ts` en `sentinelTools`.

## 5. Flujo objetivo (Claude Desktop)

```
sentinel_status                      → ¿hay conexión? ¿paused? (sin polling, OK)
sentinel_seed(IoC)                   → grafo sembrado
hunt_run / node_expand               → exploración local
node_enrich(user, [SigninLogs], 7d)  → el dato puntual que faltaba
sentinel_query(KQL, ingest=false)    → verificar hipótesis sin ensuciar
sentinel_query(KQL, ingest=true)     → confirmado → al grafo
```

## 6. Seguridad / costo

- `sentinel_query` ejecuta KQL arbitrario **con las credenciales ya
  configuradas** (mismo blast radius que `run_kql`/UI hoy; Log Analytics API es
  read-only por diseño — no hay mutación posible del workspace).
- Caps obligatorios: `max_rows` en ambos tools evita respuestas/grafos
  desbordados; `take` se inyecta server-side (no confiamos en que el LLM lo
  ponga en el query para node_enrich).
- `ingest=false` como default MCP minimiza basura en el grafo por queries
  exploratorios.

## 7. Testing

- **Motor (`HydrationFilter`):** mock transport (patrón hydrate/seed tests):
  (a) `tables=["SecurityEvent"]` ⇒ solo ese KQL se ejecuta, las demás tablas
  aparecen en `tables_attempted`; (b) `max_rows` ⇒ el KQL contiene `| take N`;
  (c) `filter=None` ⇒ idéntico a hoy (tests existentes siguen verdes sin tocar).
- **`run_kql` dual:** `ingest=false` ⇒ counts del grafo no cambian y devuelve
  filas truncadas con `truncated=true` cuando aplica; `ingest` ausente ⇒
  ingesta (retro-compat).
- **MCP:** `tsc` limpio + los 3 tools en el registry (43 names).
- **HTTP:** `/node/enrich` responde; `/kql` sin `ingest` se comporta igual que antes.

## 8. Fuera de alcance (YAGNI)

- Pause/resume/connect vía MCP (control del polling queda humano).
- Hunting templates vía MCP.
- Generación asistida NL→KQL (el LLM escribe su KQL).
- Rate-limiting / budget de queries.
- Tail-edge coverage en `for_each_edge` (follow-up ya trackeado).
