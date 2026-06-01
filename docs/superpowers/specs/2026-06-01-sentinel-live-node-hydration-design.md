# Sentinel Live Node Hydration on Expand (Enfoque A)

**Fecha:** 2026-06-01
**Estado:** Diseño aprobado — pendiente plan de implementación
**Owner:** Lucas
**Rama:** `feat/sprint1-ingest-audit` (o rama dedicada a definir en el plan)

## 1. Problema

El polling connector (Modo 1) barre tablas de Sentinel hacia adelante en el
tiempo, acotado por `take batch_size` (default 10.000 filas/tabla/tick). Esto
implica que, en cualquier momento, **el vecindario de un nodo cualquiera del
grafo está incompleto**: tenemos un *sample* de las aristas que tocan a esa
entidad, no todas las que Sentinel realmente tiene. Cuando el analista decide
investigar una entidad concreta (expandirla), necesita la garantía de que el
vecindario que ve refleja **toda** la data de la fuente para esa entidad en la
ventana de trabajo — no solo lo que el polling alcanzó a traer.

Esto **no** es un chequeo de completitud ni una tarea de mantenimiento: es una
**tarea de exploración** que se ejecuta al expandir un nodo (o como parte de un
hunt de GraphHunter).

## 2. Objetivo

Cuando el analista expande un nodo X con el modo "live" activado, GraphHunter
vuelve a Sentinel con un KQL **scopeado a la entidad X**, trae todas las
aristas que la tocan en la ventana del hunt, las ingesta por el mismo pipeline
de ingesta existente, y recién entonces ejecuta la expansión de grafo. El
vecindario resultante es completo respecto a la fuente.

### No-objetivos (YAGNI)

- No reemplaza el polling. Ver §7 (convivencia).
- No hidrata recursivamente vecinos de vecinos: solo el nodo expandido (1 salto
  de pull; la expansión de grafo posterior es la que muestra los vecinos).
- No introduce una ventana temporal nueva: reusa la ventana del hunt/sesión.
- No soporta fuentes no-Sentinel (PCAP, Fortigate, archivo): en esas sesiones
  `live:true` es un no-op suave (§6).

## 3. Decisiones tomadas (no re-debatir)

| Decisión | Valor |
|----------|-------|
| Enfoque | A — `node_expand` con flag `live` (hidrata-y-expande), un solo código path |
| Traducción entidad→KQL | Mapa inverso `EntityType → [(SentinelTable, columnas)]` derivado del parser |
| Ventana temporal | La misma del hunt/sesión (reusa `TimeWindow`) |
| Convivencia con polling | **Paralelo**, sin auto-pause; el `RwLock` del grafo los serializa |
| Scoring tras hidratar | Incremental (no full) — no pelear caro con el polling |
| Watermark del polling | La hidratación **no lo toca** (desacoplados) |
| Dataset de los inserts | Uno rodante único `"Sentinel Hydration (live)"` (no uno por nodo) |
| Exposición | Comando Tauri + MCP tool `node_expand` (flag `live` + `time_window`) |

## 4. Arquitectura

```
node_expand(node_id, live:true, time_window)
        │
        ▼
  hydrate_node(entity_id, entity_type, time_window)        ← nueva operación (platform/api)
        │   por cada (tabla, columnas) del mapa inverso para entity_type:
        │     KQL: <Tabla> | where TimeGenerated <ventana>
        │              | where <Col1> == "X" or <Col2> == "X" | take N
        ▼
  run_sentinel_query → SentinelJsonParser → insert_triples → run_scoring_incremental
        │
        ▼
  expansión de grafo existente (sin cambios) → respuesta + bloque `hydration`
```

### 4.1 Componentes

1. **`sentinel_entity_targets`** — nuevo, co-localizado con `SentinelJsonParser`
   en `core/graph-engine/src/sentinel.rs`. Función pura:

   ```rust
   /// Inverso del mapeo columna→entidad del parser: dónde puede aparecer
   /// una entidad de cada tipo, para construir el WHERE de hidratación.
   fn sentinel_entity_targets(ty: EntityType)
       -> &'static [(SentinelTable, &'static [&'static str])]
   ```

   Co-localizarla con el parser es deliberado: las columnas que devuelve
   **deben** ser el mismo conjunto que el parser lee para ese tipo (§5).

2. **KQL builder de hidratación** — dado `(tabla, columnas, valor, time_filter,
   take)`, produce:
   `Tabla | where TimeGenerated <filtro> | where C1 == "v" or C2 == "v" | take N`.
   Escapa el valor (§6, inyección KQL).

3. **`hydrate_node`** — nueva operación en `platform/api` (al lado de `run_kql`
   en `operations/sentinel.rs`). Resuelve credenciales con el mismo
   `env_or(...)` que `run_kql`, itera los targets, ejecuta cada KQL vía el
   `run_sentinel_query` existente (en `spawn_blocking`), parsea con
   `SentinelJsonParser`, `insert_triples` al grafo de la sesión actual
   (dataset rodante), corre `run_scoring_incremental`. Devuelve conteos
   (`new_entities`, `new_relations`, `tables_hit`, `skipped`).

4. **`node_expand`** — modificado: agrega `live: bool` (default `false`) y
   `time_window: Option<TimeWindow>`. Con `live:true` y sesión Sentinel-capable,
   llama a `hydrate_node` para el nodo objetivo **antes** de la expansión
   existente. Cambios espejo en el comando Tauri y en el MCP tool `node_expand`.

### 4.2 El mapa inverso (estado inicial, ajustable por el owner)

| EntityType | (Tabla, columnas) |
|---|---|
| **User** | (SecurityEvent, [`TargetUserName`,`Account`,`SubjectUserName`]); (SigninLogs, [`UserPrincipalName`,`UserDisplayName`]); (DeviceProcessEvents, [`AccountName`,`InitiatingProcessAccountName`]) |
| **IP** | (SigninLogs, [`IPAddress`]); (DeviceNetworkEvents, [`RemoteIP`]); (CommonSecurityLog, [`SourceIP`,`DestinationIP`]) |
| **Host** | (SecurityEvent, [`Computer`]); (DeviceNetworkEvents, [`DeviceName`]) |
| **Process** | (SecurityEvent, [`NewProcessName`,`ParentProcessName`,`ProcessName`]); (DeviceProcessEvents, [`FolderPath`,`FileName`,`InitiatingProcessFolderPath`]); (DeviceFileEvents, [`InitiatingProcessFolderPath`,`InitiatingProcessFileName`]) |
| **File** | (SecurityEvent, [`ObjectName`]); (DeviceFileEvents, [`FolderPath`,`FileName`]) |

El plan dejará esta tabla como una función con un `TODO` marcado para que el
owner ajuste columnas según su conocimiento de dominio (p.ej. `LocalIP` para
IP, `SHA256` para Process). Son las ~5-10 líneas que definen la completitud
real de cada hidratación.

Nota sobre Process/File: el id de la entidad es el `FolderPath` cuando existe,
si no el `FileName`. El WHERE matchea ambas columnas con `OR` para cubrir el
caso en que el id provino de cualquiera de las dos.

## 5. Test de sincronización (guardrail load-bearing)

Un test en `core/graph-engine` que falla si el parser lee una columna para un
rol de entidad que `sentinel_entity_targets` no incluye. Es lo que evita la
degradación silenciosa: si alguien agrega una columna al parser (p.ej.
`SigninLogs` empieza a leer `AlternateSignInName` como User) y no actualiza el
mapa, la hidratación quedaría incompleta sin error. El test fuerza que ambos
evolucionen juntos.

Implementación: una tabla declarativa de "columnas que el parser lee por
(tabla, rol de entidad)" verificada contra el mapa inverso. Si el parser y la
tabla declarativa divergen, el test rojo. (La tabla declarativa es la fuente
de verdad compartida; tanto el parser como el mapa inverso deben coincidir con
ella.)

## 6. Manejo de errores y seguridad

- **Sesión no-Sentinel / sin credenciales resolvibles:** `live:true` es
  **no-op suave**. El expand procede sobre el grafo local y la respuesta trae
  `hydration: { skipped: true, reason: "..." }`. Nunca rompe el expand.
- **Error de Azure en una tabla:** `warn` + seguir con las otras tablas.
  Hidratación parcial es mejor que ninguna. La respuesta reporta `tables_hit`
  vs `tables_attempted`.
- **Timeout (60s del cliente HTTP):** aislado por tabla — una tabla densa que
  expira no aborta la hidratación de las demás.
- **Resultado vacío:** OK, expand local sin agregados.
- **Inyección KQL:** el valor de la entidad va a un string literal KQL. Nuevo
  `kql_escape(value)` que escapa `"` y `\`. El `validate_url_segment` actual
  cubre la URL del endpoint, **no** el literal — hace falta el escape nuevo.

## 7. Convivencia con el polling (complementario, paralelo)

Polling e hidratación resuelven ejes ortogonales:

- **Polling** = breadth-first, guiado por el tiempo, construye el baseline y
  las anomalías (el punto de entrada del hunt). Acotado por `take`.
- **Hidratación** = depth-first, guiada por la entidad, garantiza completitud
  local del nodo investigado. Acotada por el volumen de esa entidad.

No se descarta el polling: sin baseline no hay nodos interesantes para
expandir (salvo hunts IoC-driven con indicador conocido de antemano).

Runtime:

- Ambos toman `graph.write()` → serializados por el `RwLock`, sin deadlock
  (el P0 de deadlock ya está corregido).
- Hidratación usa scoring incremental para no competir caro.
- No toca el watermark del polling → posible doble-fetch benigno, absorbido
  por el dedup por canonical id. La hidratación solo **agrega** aristas que
  faltaban; las que el polling ya tenía no se recuentan.
- Inserts en el dataset rodante `"Sentinel Hydration (live)"`, contadores
  acumulan por-dataset (sin doble-conteo del total del grafo).

## 8. Testing

- **Sincronización parser↔mapa** (§5) — el guardrail.
- **KQL builder:** escaping del valor, `OR` multi-columna, splice de la
  ventana temporal, `take`.
- **`hydrate_node`** con `SentinelTransport` mockeado (el trait ya existe para
  esto): verifica que un nodo IP dispara los 3 queries esperados, parsea e
  ingesta, y los conteos son correctos. Caso sin credenciales → `skipped`.
- **Regresión `node_expand` con `live:false`:** salida idéntica a hoy
  (el path offline no se altera).
- **Gating:** sesión no-Sentinel + `live:true` → no-op suave con diagnóstico.

## 9. Out of scope

- Hidratación recursiva multi-salto.
- Auto-pause del polling durante la hidratación (decidido: corren en paralelo).
- Ventana temporal configurable por-expand distinta de la del hunt.
- Hidratación desde fuentes no-Sentinel.
- Compartir watermark/token entre el conector y la hidratación.
