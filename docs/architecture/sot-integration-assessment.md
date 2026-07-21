# SOT Integration Assessment

- Fecha: 2026-07-21
- Spec gobernante: `docs/superpowers/specs/2026-07-21-sot-integration-design.md`
- Alcance: inspección de solo lectura; verifica la tabla de reconciliación
  del spec §4 contra código real. Ninguna afirmación sin cita `path:line`;
  lo no verificado se marca **[no verificado]** con razón.

## S1. Resumen ejecutivo
_Pendiente: se completa en la Tarea 9._

## S2. Estructura del workspace (crates, paquetes, módulos)

### Nota metodológica: no existe un Cargo workspace raíz

El comando del plan (`cargo metadata --no-deps --format-version 1` ejecutado
desde `C:\Users\lsotomayor\GraphHunter`) falla:

```
error: could not find `Cargo.toml` in `C:\Users\lsotomayor\GraphHunter` or any parent directory
```

Esto es coherente con `.cargo/config.toml:16-18`, que documenta explícitamente
que el repo no tiene workspace root ("we don't have a workspace root") y que
`.cargo/config.toml` vive en la raíz solo para que cualquier invocación de
`cargo` en cualquier crate lo recoja. En consecuencia, el inventario de abajo
se construyó leyendo cada `Cargo.toml` individual (no hay un `cargo metadata`
único que los liste a todos), localizados con
`find core platform apps crates -iname "Cargo.toml"` desde la raíz del repo.

### (a) Tabla crate → ruta → responsabilidad

| Package (nombre en `Cargo.toml`) | Ruta del manifiesto | Responsabilidad (una línea) |
|---|---|---|
| `graph_hunter_core` | `core/graph-engine/Cargo.toml:2-5` | Motor de grafos de threat hunting: knowledge graphs temporales y búsqueda de rutas guiada por hipótesis. |
| `graph_hunter_gnn` | `core/gnn/Cargo.toml:2-5` | Inferencia/entrenamiento GNN (ONNX Runtime, exportación de corpus AAD), extraído de `graph_hunter_core` por F2.14. |
| `graph_hunter_matcher_ffi` | `core/matcher-ffi/Cargo.toml:2-5` | Forwarder Rust puro para `search_temporal_pattern_simd`; reemplazó el FFI a la librería estática C++ `libgraphmatch` (removida 2026-05-07). |
| `graph_hunter_api` | `platform/api/Cargo.toml:2-5` | Capa de API canónica: estado de sesión/servicio y superficie transporte-agnóstica que serializan Tauri, HTTP y MCP. |
| `graph_hunter_sources` | `platform/sources/Cargo.toml:2-5` | Abstracciones de fuentes de log + conectores Azure (Log Analytics, Data Lake v2, Defender XDR), extraído de core por F2.11. |
| `graph_hunter_siem` | `platform/siem/Cargo.toml:2-5` | Runners de queries SIEM y streaming async para Azure Sentinel y Elasticsearch; extraído de `graph_hunter_cli`. |
| `graph_hunter_parsers` | `platform/parsers/Cargo.toml:2-5` | Implementaciones concretas de `LogParser` (Cognito, FortiAnalyzer, IIS W3C) extraídas de core en F2.10. |
| `graph_hunter_canonical` | `platform/canonical/Cargo.toml:2-5` | Vista canónica OCSF v1.4 + Provenance Extension: proyección pura desde triples `(Entity, Relation, Entity)`. |
| `graph_hunter_dsl` | `platform/dsl/Cargo.toml:2-5` | Parser del DSL de hipótesis + módulos `types`/`hypothesis` (F2.12); sin dependencia de vuelta hacia `graph_hunter_core`. |
| `graph_hunter_vrl` | `platform/vrl/Cargo.toml:2-5` | Compilador determinista `FieldConfig -> VRL` + intérprete mínimo (wedge M3, sin runtime `vrl` embebido). |
| `graph_hunter_constrained_decode` | `platform/constrained-decode/Cargo.toml:2-5` | Validador de gramática del subset VRL y (futuro) adaptador de constrained-decoding para salidas LLM (M6). |
| `graph_hunter_local_llm` | `platform/local-llm/Cargo.toml:2-5` | Seam de LLM local para el "agentic slow lane": trait `LocalLlm`, `MockBackend` por defecto, backend Candle (Phi-3-mini-Q4) tras el feature `candle`. |
| `graph_hunter_cli` | `apps/cli/Cargo.toml:2-5` | Proceso CLI de larga duración con protocolo JSON por stdin/stdout. |
| `graph-hunter-app` (lib `graph_hunter_app_lib`) | `apps/tauri/src-tauri/Cargo.toml:2-7` | Backend Tauri v2 de la app de escritorio (comandos, wiring hacia `graph_hunter_core` con feature `geoip`). Sin campo `description` en el manifiesto. |
| `sentinel-sidecar-client` | `crates/sentinel-sidecar-client/` — **sin `Cargo.toml`** | **[no verificado: crate no existe como package Cargo en esta rama]**. El directorio solo contiene una carpeta `target/` residual (caché de build), sin `Cargo.toml` ni `src/`; confirmado con `find crates/sentinel-sidecar-client -maxdepth 1` (solo devuelve `target`) y con `git ls-files crates/` (sin salida: nada bajo `crates/` está trackeado en `spec/hunt-journal`). Ver también la nota del sidecar .NET en (b): la fuente Rust de este cliente correspondería al mismo trabajo de integración Sentinel, no mergeado a esta rama. |

Las 14 filas con manifiesto cubren la totalidad de lo que `cargo metadata`
listaría si se ejecutara por-crate (no hay forma de invocarlo una sola vez
sin workspace root); la fila 15 (`sentinel-sidecar-client`) documenta su
ausencia verificada en vez de inventar un manifiesto inexistente.

### (b) Paquete MCP (npm) y estado del sidecar .NET

**Paquete npm del MCP** — `platform/mcp/package.json:1-4`:
```json
{
  "name": "@graphhunter/mcp",
  "version": "2.0.0",
  "description": "MCP server exposing GraphHunter tools — v2 orthogonal catalog (37 tools, namespaced). Hard-cut from v1; old flat names removed."
}
```

**Sidecar .NET (`sidecar/dotnet`)** — estado verificado, **contradice la
premisa del brief de la Tarea 1**:

- El working tree en `spec/hunt-journal` sí contiene artefactos de build de
  un proyecto .NET 8 llamado `GraphHunter.Sentinel.Sidecar`
  (`sidecar/dotnet/GraphHunter.Sentinel.Sidecar/bin/Debug/net8.0/graphhunter-sentinel-sidecar.dll`
  y `.exe`, entre otros, listados por
  `find sidecar -iname "*.dll" -o -iname "*.exe"` scoped a `sidecar/`).
- `find sidecar -iname "*.cs"` **sí devuelve resultados**: 13 archivos
  `.cs`, todos bajo `obj/` (p. ej.
  `sidecar/dotnet/GraphHunter.Sentinel.Sidecar/obj/Debug/net8.0/SentinelSidecar.cs`
  y `SentinelSidecarGrpc.cs`, en `obj/Debug/net8.0/`, `obj/Release/net8.0/win-x64/`
  y bajo `GraphHunter.Sentinel.Sidecar.Tests/obj/`). Son stubs generados por
  el compilador de protobuf, no fuente escrita a mano: el encabezado de
  `SentinelSidecar.cs:1-3` dice literalmente
  `// Generated by the protocol buffer compiler.  DO NOT EDIT! // source: sentinel_sidecar.proto`.
  No se encontró ningún `*.csproj` ni `*.sln` (0 resultados para esos dos
  patrones) — es decir, ni siquiera el proyecto .NET tiene manifiesto en el
  working tree, solo la carpeta `obj/` con artefactos de un build previo.
- Pese a esos stubs generados, la conclusión de más alto nivel se mantiene:
  **no hay fuente escrita a mano ni trackeada por git.** `git ls-files sidecar/`
  no devuelve nada — ningún archivo bajo `sidecar/` (ni siquiera los `.cs`
  generados) está trackeado en `spec/hunt-journal`. `git log --all --oneline -- sidecar/`
  tampoco devuelve commits en ningún ref local. `obj/`/`bin/` están gitignorados
  por `.gitignore:83-84`: `sidecar/dotnet/**/bin/`, `sidecar/dotnet/**/obj/`.
- Dato adicional para la pregunta abierta: los stubs revelan que el contrato
  gRPC se define en un archivo `sentinel_sidecar.proto`, pero ese archivo
  **no existe en ningún punto del árbol trackeado**: `git ls-files -- "*.proto"`
  no devuelve resultados. El `.proto` fuente que generó estos stubs no está
  en el repo (ni en esta rama ni en ninguna otra, según lo trackeado) — se
  suma como dato a la pregunta abierta de abajo sobre el origen real de estos
  artefactos.
- El brief de la Tarea 1 asume que el fuente del sidecar "vive en branches
  `feat/sp*-sentinel-*` sin mergear". Se verificó con el comando exacto
  pedido:
  ```
  $ git branch -a --list "*sentinel*"
  ```
  **Salida: vacía (ningún branch coincide)**, sobre el listado completo de
  `git branch -a` (31 branches locales/remotos: `audit/unit-*`,
  `fix/rh-p0-*`, `fix/rh-p1-*`, `main`, `public-release`, `spec/gh-hunt-graph-first`,
  `spec/hunt-journal` (actual), `spec/saas-egress-graph-modeling`, más
  `remotes/origin/*` y `remotes/public/*` — ninguno contiene "sentinel").
  Se confirmó además contra los remotos en vivo, sin modificar refs locales:
  `git ls-remote --heads origin | grep -i sentinel` y
  `git ls-remote --heads public | grep -i sentinel` — ambos sin resultados.
  **Conclusión: la afirmación "branches `feat/sp*-sentinel-*` sin mergear"
  es [no verificado] — no existen tales branches ni en refs locales ni en
  los remotos `origin`/`public` a la fecha de este assessment.** El origen
  real de los binarios y stubs de build presentes en el working tree
  (¿build local manual, artefacto de una sesión de trabajo anterior no
  commiteada, u otro mecanismo?), junto con el paradero del `sentinel_sidecar.proto`
  que los generó (no trackeado en ningún ref), queda como pregunta abierta
  para el Bloque 1 (ver S16).

### (c) Módulos no-Cargo relevantes

| Módulo | Ruta | Contenido / rol |
|---|---|---|
| Frontend Tauri (React/TS) | `apps/tauri/src/` | App React+TypeScript (`apps/tauri/package.json:2` → `"name": "graph-hunter"`); subcarpetas `components/`, `context/`, `hooks/`, `lib/`, `test/`, `types.ts`, `utils/` confirmadas con `Get-ChildItem apps/tauri/src`. |
| Templates de reportes | `templates/` | 5 archivos HTML (`01-WeeklyHunting-Step1.html` … `Step5.html`), confirmados con `find templates -maxdepth 1 -type f`. **Nota:** directorio no trackeado (`git status --porcelain` lo marca `??`) — es parte del WIP no relacionado presente en el working tree; no se modificó. |
| Datos de demo | `demo_data/` | 2 archivos de log (`ambiguous_fields_forti.log`, `ambiguous_iis_for_llm.log`), confirmados con `find demo_data -maxdepth 1 -type f`. **No** está trackeado por git: `git ls-files demo_data/` no devuelve nada y `git status --porcelain demo_data/` tampoco, porque `.gitignore:19` (`*.log`) excluye su contenido — mismo estado no-trackeado que `templates/`, aunque por una regla de gitignore distinta (patrón de extensión, no la carpeta completa). |

## S3. Motor de grafos y modelo de datos

### Metodología

Se leyeron íntegramente `core/graph-engine/src/graph.rs` (3847 líneas),
`core/graph-engine/src/streaming.rs` (2199 líneas), `core/graph-engine/src/relation.rs`,
`core/graph-engine/src/entity.rs`, `core/graph-engine/src/parser.rs` y
`core/graph-engine/src/interner.rs`, más los greps pedidos:

```
rg -n "enum EntityType|enum RelationType|struct RawIngestEvent|struct Entity|struct Relation" core/ platform/ --type rust
rg -n "metadata_offset|rel_type_tag" core/graph-engine/src/ --type rust
```

Hallazgo metodológico previo: `EntityType`/`RelationType` **no están definidos
en `core/graph-engine`** — el crate solo los re-exporta. La definición real
vive en `platform/dsl/src/types.rs` (confirmado con
`pub use graph_hunter_dsl::types::{...}` en `core/graph-engine/src/lib.rs:148`,
y con el propio grep, que los localiza en `platform/dsl/src/types.rs:7` y
`:63`, no en ningún archivo de `core/graph-engine`).

### 1. Tipos actuales (eventos, entidades, relaciones)

**`EntityType`** — `platform/dsl/src/types.rs:6-21`:

```rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum EntityType {
    IP,
    Host,
    User,
    Process,
    File,
    Domain,
    Registry,
    URL,
    Service,
    /// Wildcard: matches any entity type in DFS search.
    Any,
    /// User-defined type name (e.g. from "Rename type" custom field).
    Other(String),
}
```

9 variantes concretas (`IP, Host, User, Process, File, Domain, Registry, URL,
Service`) más dos variantes especiales no contadas como "tipo de entidad
observado": `Any` (comodín de búsqueda DFS) y `Other(String)` (tipo definido
por el usuario). El recuento de 9 queda además verificado por un array
`const` con anotación de tamaño explícita en
`core/graph-engine/src/benchmark.rs:16-26`:
`const ENTITY_TYPES: [EntityType; 9] = [...]` — si alguien añadiera o quitara
una variante sin actualizar ese array, el build fallaría por mismatch de
tamaño, así que el `9` está garantizado por el compilador, no solo contado a mano.

**`RelationType`** — `platform/dsl/src/types.rs:62-81`:

```rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RelationType {
    Auth,
    Connect,
    Execute,
    Read,
    Write,
    DNS,
    Modify,
    Spawn,
    Delete,
    /// Wildcard: matches any relation type in DFS search.
    Any,
    /// User-defined rel type (e.g. "Consent", "Assign", "Forward") used
    /// by cloud-identity and post-compromise patterns. Tag 254 in FFI;
    /// the actual name travels through the meta_store side-table at
    /// insert time. DFS compares on Display strings so matching is
    /// correct even across FFI round-trips.
    Other(String),
}
```

Mismo patrón: 9 variantes concretas + `Any` + `Other(String)`, verificado por
el segundo array de tamaño fijo en `core/graph-engine/src/benchmark.rs:28-38`
(`const RELATION_TYPES: [RelationType; 9] = [...]`). `RelationType::to_u8()`
(`platform/dsl/src/types.rs:122-138`) mapea las 9 variantes concretas a
`0..=8`, `Any` a `255` y `Other(_)` a `254` (un solo tag compartido; el
nombre real se resuelve vía `meta_store`, ver `graph.rs:650-659`).

**Entidad en memoria — `Entity`** (`core/graph-engine/src/entity.rs:30-60`):
struct con `id: String`, `entity_type: EntityType`, `score: f64`,
`metadata: HashMap<String, String>`, `dataset_id: Option<Arc<str>>` y tres
métricas de centralidad (`degree_score`, `betweenness`, `pagerank_score`,
`rarity_score`). `PartialEq`/`Hash` están implementados manualmente
(`entity.rs:100-112`) para comparar solo por `id`, no por el resto de campos.

**Relación "rica" — `Relation`** (`core/graph-engine/src/relation.rs:26-45`):
`source_id: String`, `dest_id: String`, `rel_type: RelationType`,
`timestamp: i64`, `metadata: HashMap<String, String>`,
`dataset_id: Option<Arc<str>>`. Es la forma que ve la API pública
(`add_relation`); nunca se almacena así en el store caliente.

**Relación compacta en el store — `CompactRelation`** (`relation.rs:96-111`,
`#[repr(C)]`, 32 bytes tras el repack de 2026-04-07 documentado en
`relation.rs:74-95`):

```rust
#[repr(C)]
pub struct CompactRelation {
    pub timestamp: i64,       // 8 bytes
    pub metadata_offset: u64, // 8 bytes (0 = no metadata)
    pub source_sid: StrId,    // 4 bytes
    pub dest_sid: StrId,      // 4 bytes
    pub ingested_at_delta: u32, // 4 bytes
    pub dataset_tag: u16,     // 2 bytes
    pub rel_type_tag: u8,     // 1 byte
}
```

`StreamEdge` (`core/graph-engine/src/streaming.rs:109-124`) es
layout-idéntico a `CompactRelation` — un `const _: () = assert!(...)`
(`streaming.rs:132-134`) fuerza en tiempo de compilación que ambos structs
tengan el mismo `size_of`, porque `push_to_streaming`
(`graph.rs:788-796`) hace un `ptr::read` transmutando uno en otro sin
traducción campo a campo.

**Evento crudo de ingesta — `RawIngestEvent`**
(`core/graph-engine/src/parser.rs:42-52`):

```rust
pub struct RawIngestEvent {
    pub src_id: String,
    pub src_type: EntityType,
    pub src_metadata: HashMap<String, String>,
    pub dst_id: String,
    pub dst_type: EntityType,
    pub dst_metadata: HashMap<String, String>,
    pub rel_type: RelationType,
    pub rel_metadata: HashMap<String, String>,
    pub timestamp: i64,
}
```

Forma "plana" pensada para el camino de ingesta de alto rendimiento — evita
la asignación de structs `Entity`/`Relation` anidados que sí paga la forma
legacy `ParsedTriple = (Entity, Relation, Entity)` (`parser.rs:16-18`); el
propio comentario en `parser.rs:20-36` documenta el ahorro (~5
allocations/evento evitadas a 700K ev/s).

### 2. Inserción y deduplicación de vértices

`insert_raw_events` (`core/graph-engine/src/graph.rs:3160-3241`) es el
consumidor de `RawIngestEvent`. Por cada evento:

1. `self.interner.intern(&src_id)` (`interner.rs:61-70`) — si el string ya
   fue interned devuelve el `StrId` existente en O(1) (lookup en el
   `HashMap<Arc<str>, StrId>`); si no, lo agrega y devuelve un `StrId` nuevo.
   Este es el mecanismo real de deduplicación de vértices: la igualdad es
   por **string id exacto**, no por tipo ni por ningún otro campo.
2. Con el `StrId` resuelto, `graph.rs:3185-3198` decide: si
   `self.entities.get_mut(&src_sid)` ya existe (mismo `StrId` ⇒ mismo
   string id ya visto), se llama `Self::merge_metadata(&mut existing.metadata, &src_metadata, &merge_policy)`
   (función en `graph.rs:2549-2573`); si no existe, se construye un `Entity`
   nuevo y se inserta (`new_entities += 1`).

`merge_metadata` itera cada clave entrante y aplica una `MergePolicy`
(`platform/dsl/src/types.rs:187-197`):

```rust
pub enum MergePolicy {
    #[default]
    FirstWriteWins,
    LastWriteWins,
    Append,
}
```

El default usado por todos los caminos de ingesta (`insert_raw_events`,
`insert_triples`, `add_relation`) es `MergePolicy::default()` →
`FirstWriteWins` (`graph.rs:3165`, `3091`, `types.rs:191-192`): en colisión
de metadata, **gana el primer valor visto**; una clave repetida en un evento
posterior no sobrescribe la existente. Confirmado como comportamiento
esperado por el test `ingest_logs_deduplicates_entities`
(`core/graph-engine/src/tests.rs:1507-1532`): dos eventos que referencian
"cmd.exe" producen `entities == 3` (cmd.exe deduplicado + 2 dominios), no 4.

El tipo de entidad (`EntityType`) del **primer** evento que crea el vértice
es el que queda fijado — eventos posteriores con el mismo id no actualizan
`entity_type`, solo hacen merge de `metadata` (`graph.rs:3184-3198` solo
llama a `merge_metadata`, nunca reasigna `entity_type` en la rama
"ya existe").

### 3. Inserción de aristas: clave de identidad — claim del spec CORREGIDO

El spec (vía el comentario en
`core/graph-engine/src/ingest/source_poller.rs:28-31`) afirma:

```
//!   the graph insertion is idempotent at the
//!   `(src_sid, dst_sid, timestamp, rel_type_tag, metadata_offset)`
//!   level so this is safe.
```

**Verificación de la ubicación de la cita:** correcta — ese comentario existe
literalmente en `source_poller.rs:28-31` tal como afirma el brief.

**Verificación de la afirmación semántica: INCORRECTA — corregida.** Se
recorrió el código real de los tres caminos de escritura de aristas y
**no existe ningún chequeo de existencia/deduplicación por clave en ningún
punto del pipeline de inserción**:

- `add_relation` (`graph.rs:423-466`) construye el `CompactRelation` y llama
  `self.push_to_streaming(&compact)?` (línea 462) sin ninguna consulta previa
  a un índice o `HashSet` de claves ya vistas.
- `insert_triples` (`graph.rs:3086-3152`) y `insert_raw_events`
  (`graph.rs:3160-3241`) hacen exactamente lo mismo por cada evento
  (`graph.rs:3145`, `3234`: `self.push_to_streaming(&compact)?`).
- `push_to_streaming` (`graph.rs:788-796`) solo transmuta `CompactRelation` a
  `StreamEdge` y llama `self.streaming.append_edge_checked(...)`
  — ninguna comprobación de duplicados.
- `append_edge_checked` → `try_append_edge` → `append_edge_inner`
  (`streaming.rs:1339-1379`) toma el slot del vértice origen y llama
  `guard.push(edge)` (o inserta en la posición ordenada del *tail* si el
  grafo ya está finalizado) — un `push`/`insert` incondicional en el `Vec`/
  `SmallVec`/`tail` del vértice, sin buscar si ya existe una arista con el
  mismo `(dest_sid, timestamp, rel_type_tag, metadata_offset)`.
- `NeighborList::push` (`streaming.rs:195-221`) es el nivel más bajo: simple
  `sv.push(edge)` / `v.push(edge)` — de nuevo, sin lookup de duplicados.

**Conclusión:** no hay una "clave de identidad efectiva" que el motor
imponga para las aristas. La inserción es **append-only e incondicional**:
cualquier `(src, rel, dst, timestamp, metadata)` que llegue por el pipeline
de ingesta se añade como una arista nueva e independiente, sin importar si
una arista idéntica ya existe. La afirmación de idempotencia en
`source_poller.rs:29` describe una garantía **aspiracional/documental del
diseño de reintento del poller**, no un invariante que el motor de grafos
implemente — es coherente con el comentario análogo (igualmente no
respaldado por código de dedup) en
`core/graph-engine/src/ingest_adapter.rs:43`: *"ingest must stay idempotent
on `(source_id, event_id)`"*, que tampoco corresponde a ningún chequeo real
localizado durante esta auditoría.

**Multiplicidad — SÍ, confirmada con evidencia de código.** Dos eventos
reales entre las mismas entidades (mismo `src`, `dst`, incluso mismo
`rel_type` y `timestamp`) **coexisten** como dos entradas separadas en la
`NeighborList` del vértice origen: no hay ninguna rama de código en
`add_relation`, `insert_triples`, `insert_raw_events`,
`append_edge_checked`/`try_append_edge`/`append_edge_inner` ni
`NeighborList::push` que compare la arista entrante contra las existentes
antes de añadirla. `relation_count()` (`graph.rs:401-403`) delega en
`streaming_edge_count()`, que simplemente suma `len()` de cada
`NeighborList` (`streaming.rs:1411-1423`, `edge_count()`), así que dos
aristas idénticas cuentan como dos, no como una. No se encontró un test que
ejercite explícitamente "misma tripleta exacta insertada dos veces" (el test
más cercano, `ingest_logs_deduplicates_entities` en `tests.rs:1507-1532`,
solo cubre deduplicación de **vértices**: los dos eventos de ese test tienen
destinos distintos — `domain-a.com` y `domain-b.com` — por lo que
`relations == 2` allí no es evidencia de multiplicidad de aristas con clave
idéntica, solo de que se insertan aristas separadas para triples distintos);
la conclusión de multiplicidad se sostiene enteramente en la lectura del
código de inserción citado arriba, no en un test dedicado.

### 4. Temporalidad

El timestamp vive en dos lugares con el mismo valor: `Relation.timestamp: i64`
(`relation.rs:36`, epoch Unix en segundos, ver doc en `relation.rs:29-30`:
*"critical for temporal pattern matching (causal monotonicity
enforcement)"*) y su copia compacta `CompactRelation.timestamp: i64`
(`relation.rs:99`). Es distinto de `ingested_at_delta`
(`relation.rs:103-107`, `CompactRelation`): el primero es el instante del
evento observado (p. ej. hora del log de Sysmon), el segundo es el instante
en que el motor escribió la arista (usado por la API MVCC de snapshot "qué
sabía el grafo en el instante T", `relation.rs:104-106`).

**Orden de inserción vs. orden temporal — no se garantiza en ingesta.** Las
aristas se insertan en el orden en que llegan del pipeline (orden de
llegada del `RawChunk`/parser), no ordenadas por `timestamp`. El propio
motor documenta esto: `edges_sorted: bool` (`graph.rs:122`) arranca en
`false` (`graph.rs:230`) y solo se pone en `true` tras llamar
`sort_edges_by_timestamp()` (`graph.rs:901-946`), que ordena cada
`NeighborList` por timestamp una vez, típicamente al finalizar la ingesta de
una sesión — es una operación explícita post-hoc, no un invariante mantenido
en cada `push`.

**Cómo la usa la monotonía causal del matcher.** El chequeo real de
monotonía está en el comparador de paths del DFS
(`graph.rs:2910-2932`): se arranca `let mut last_timestamp = i64::MIN;`
(línea 2910) y en cada paso del path se exige
`edge.timestamp >= last_timestamp` (línea 2930, no estricto — permite
timestamps iguales, confirmado por el test `search_allows_same_timestamp`
en `tests.rs:553-554` y contradicho si fuera estricto por
`search_enforces_causal_monotonicity`, `tests.rs:515-551`, que sí rechaza un
`Auth` en `t=200` después de un `Connect` en `t=500`). Esta comprobación es
**a nivel de query/matcher, no de storage**: no depende de que las aristas
estén pre-ordenadas — compara el timestamp de cada arista candidata contra
el máximo visto hasta ese punto del path que se está construyendo durante
la búsqueda, por lo que funciona incluso sobre datos insertados
fuera de orden. `sort_edges_by_timestamp()` es una optimización de
rendimiento (permite `partition_point` / binary search por ventana de
tiempo, doc en `graph.rs:896-899`), no una precondición de corrección para
la monotonía causal.

### 5. Spill a disco

El spill de aristas vive en `core/graph-engine/src/streaming.rs` y se activa
por presupuesto de aristas en memoria, no por tamaño en bytes:

- `InMemoryStreamingBackend::with_memory_budget_edges(budget_edges: usize)`
  (`streaming.rs:500-527`): arma un `SpillState` con un contador
  `edges_since_last_spill`. Cuando el contador alcanza `budget_edges`,
  `append_edge`/`try_append_edge` dispara `auto_spill()`
  (`streaming.rs:1318-1333`, chequeo del umbral en `1321-1330`).
  `budget_edges == 0` **desactiva** el auto-spill (`streaming.rs:512-514`).
- **Condición de activación por defecto en producción:** todo
  `GraphHunter::new()` arranca con auto-spill armado a
  **1.000.000 de aristas** (`graph.rs:244-247`:
  `.with_memory_budget_edges(1_000_000)`), justificado en el comentario
  adyacente (`graph.rs:234-243`) para que una sesión EVTX de ~28 GB
  (~30M aristas) dispare el spill en ~30 rondas manejables. Esto contradice
  cualquier lectura de "spill opt-in" — está activo por defecto salvo que un
  caller explícito lo desactive con `with_memory_budget_edges(0)` (usado por
  tests, según el comentario en `graph.rs:241-243`).
- `auto_spill()` (`streaming.rs:1178-1215` para el arranque/snapshot de ruta,
  ver también `streaming.rs:1210-1211` para el incremento de `spill_round`)
  escribe **todas** las `NeighborList` en memoria de golpe a un archivo
  ordenado por timestamp bajo un `tempfile::TempDir` (o un directorio
  externo vía `with_spill_dir_and_budget`, `streaming.rs:533-551`), y
  reemplaza cada slot
  por la variante `NeighborList::Mmap { handle, byte_offset, len }`
  (`streaming.rs:170-180`). Aristas que llegan después promueven
  individualmente `Mmap → Vec` en la primera escritura tras el spill
  (`streaming.rs:190-193, 211-219`), y el siguiente cruce de presupuesto
  vuelve a escribir un archivo nuevo (`spill_round` incrementa,
  `streaming.rs:1210-1211`).
- El spill es "todo o nada" por ronda (no por vértice individual ni por
  antigüedad) — se dispara puramente por el conteo global de aristas
  insertadas desde la última ronda, sin considerar el timestamp del evento
  ni el tamaño real en bytes del proceso.

## S4. Parsers y normalización

### Metodología

Se leyeron íntegramente `core/graph-engine/src/parser.rs` (struct `ParseStats`,
doc de skips), `core/graph-engine/src/generic.rs`,
`platform/api/src/ingestors/mod.rs` (trait `StreamingIngestor`,
`INGESTOR_REGISTRY`, `resolve_ingestor`), `platform/api/src/format_registry.rs`
y `platform/canonical/src/provenance.rs`, más los greps pedidos:

```
rg -n "rows_skipped|skip_reasons|skipped_samples|record_parse_skips" core/ platform/ --type rust
rg -n "sanitize_field_config|auto_field_config_for" platform/api/src/operations/ingestion.rs
Get-ChildItem platform/parsers/src -File | Select-Object Name
```

`Get-ChildItem platform/parsers/src -File` devuelve: `cognito.rs`,
`fortigate.rs`, `forti_analyzer.rs`, `haproxy.rs`, `iis_w3c.rs`, `lib.rs` — es
decir, solo 5 parsers viven en `platform/parsers` hoy; el resto (Sysmon,
Sentinel, generic, CSV) sigue en `core/graph-engine/src`, y EVTX/PCAP/Zeek/
Suricata/NetFlow no son `LogParser` en absoluto sino `StreamingIngestor` en
`platform/api/src/ingestors/`. El propio doc de
`platform/parsers/src/lib.rs:10-25` explica por qué no se movieron los
cuatro restantes: `generic`/`csv_parser` los usan `field_preview.rs` y la
mapping library vía métodos estáticos de `GenericParser`, y `sysmon`/
`sentinel` los ejercitan ~400 tests inline en `graph_hunter_core` que no
pueden cruzar el límite de crate sin duplicar la instancia del trait.

### 1. Ubicación de todos los parsers y mecanismo de auto-detección

Hay **dos registries separados**, no uno:

- **`FORMAT_REGISTRY`** (`platform/api/src/format_registry.rs:164-234`) para
  formatos tabulares/JSON de un solo `LogParser` stateless. `resolve_format_with_ext`
  (`format_registry.rs:254-287`) primero consulta la extensión de archivo
  (`.csv`/`.tsv` → `csv`, `.xml` → `fortianalyzer`), y si no hay hint aplica,
  en orden, cada predicado `detect` del registry top-to-bottom
  (`format_registry.rs:281-285`); `csv` es la entrada final con
  `detect: |_| true` (`format_registry.rs:225-233`) — atrapa todo lo que no
  matcheó antes.
- **`INGESTOR_REGISTRY`** (`platform/api/src/ingestors/mod.rs:126-134`) para
  formatos stateful/binarios vía el trait `StreamingIngestor`.
  `resolve_ingestor` (`ingestors/mod.rs:162-182`) hace magic-byte sniffing:
  lee los primeros 64 bytes del archivo una vez (`read_magic_bytes`,
  `ingestors/mod.rs:140-149`) y llama a `sniff()` de cada ingestor
  registrado; gana la confianza más alta (`max_by_key`, `mod.rs:180`),
  empates se rompen por orden del registry. Devuelve `None` para formatos
  tabulares (`mod.rs:158-161`), y el caller (`load_data_streaming`,
  `platform/api/src/operations/ingestion.rs:827`, llamada en
  `ingestion.rs:955`) cae al `format_registry` tabular en ese caso.

| Formato | Archivo / struct | Detección (`auto`) |
|---|---|---|
| Sysmon (JSON) | `core/graph-engine/src/sysmon.rs:214` (`SysmonJsonParser`) | `format_registry.rs:30-38` `detect_sysmon`: empieza con `[`/`{` y contiene `EventID`/`event_id` + (`UtcTime`\|`Sysmon`\|`Security-Auditing`\|`event_data`) |
| Sentinel (JSON, tablas Log Analytics) | `core/graph-engine/src/sentinel.rs:48` (`SentinelJsonParser`) | `format_registry.rs:40-50` `detect_sentinel`: `"Type"` + una de `SecurityEvent`/`SigninLogs`/`DeviceProcessEvents`/`DeviceNetworkEvents`/`DeviceFileEvents`/`CommonSecurityLog` |
| Generic JSON | `core/graph-engine/src/generic.rs:175` (`GenericParser`) | `format_registry.rs:78-81` `detect_generic_json`: cualquier contenido que empiece con `[`/`{` (fallback JSON después de sysmon/sentinel/cognito/fortigate) |
| CSV | `core/graph-engine/src/csv_parser.rs:27` (`CsvParser`) | `format_registry.rs:225-233`: última entrada del registry, `detect: |_| true` — fallback universal |
| EVTX | `platform/api/src/ingestors/evtx.rs:19` (`EvtxIngestor`, `StreamingIngestor`) | `evtx.rs:49-64` `sniff`: magic `ElfFile\0` → confianza 255; si no, extensión `.evtx` + reapertura del archivo (`file_looks_like_evtx`) → confianza 150 |
| PCAP (y alias `pcapng`) | `platform/api/src/ingestors/pcap.rs:16` (`PcapIngestor`) | `pcap.rs:54-69` `sniff`: magic libpcap `0xa1b2c3d4` → confianza 255; si no, extensión + reapertura (`file_looks_like_pcap`) → confianza 150 |
| Zeek | `platform/api/src/ingestors/zeek.rs:71` (`ZeekIngestor`) | `zeek.rs:109-124+` `sniff`: primera línea parseada como JSON, exige clave `uid` con prefijo `"C"` y/o `id.orig_h` |
| Suricata (`eve.json`) | `platform/api/src/ingestors/suricata.rs:47` (`SuricataIngestor`) | `suricata.rs:81-90` `sniff`: primera línea JSON, campo `event_type` debe ser uno conocido (`is_known_suricata_event`) → confianza 200 |
| NetFlow/IPFIX | `platform/api/src/ingestors/netflow.rs:39` (`NetflowIpfixIngestor`) | `netflow.rs:73-79` `sniff`: primeros bytes interpretados como versión `u16` (5, 9 o 10 vía `detect_version`) → confianza 240 |
| FortiGate | `platform/parsers/src/fortigate.rs:97` (`FortiGateParser`) | `looks_like_fortigate` (`fortigate.rs:160`) vía `format_registry.rs:74-76`/`186-192` `detect_fortigate` |
| FortiAnalyzer (XML) | `platform/parsers/src/forti_analyzer.rs:731` (`FortiAnalyzerXmlParser`) | `format_registry.rs:86-89` `detect_fortianalyzer`: exige declaración `<?xml` **y** elemento raíz `<FortiAnalyzer_Report` |
| HAProxy | `platform/parsers/src/haproxy.rs:26` (`HaproxyParser`) | `looks_like_haproxy` (`haproxy.rs:328`) vía `format_registry.rs:65-67`/`200-206` `detect_haproxy` |
| IIS/W3C | `platform/parsers/src/iis_w3c.rs:18` (`IisW3cParser`) | `format_registry.rs:56-59` `detect_iis`: no empieza con `[`/`{` y `looks_like_iis_w3c` (`iis_w3c.rs:256`) |
| Cognito | `platform/parsers/src/cognito.rs:30` (`CognitoParser`) | `looks_like_cognito` (`cognito.rs:48`) vía `format_registry.rs:52-54` `detect_cognito` |

Ninguna fila queda vacía: las 14 filas pedidas por el brief tienen archivo +
struct + mecanismo de detección citados con `path:line`.

### 2. Rol de la capa canónica (`platform/canonical`) y de `platform/vrl`

**`platform/canonical`** — según su propio doc de crate
(`platform/canonical/src/lib.rs:1-14`): *"no introduce una segunda
representación del grafo"*; expone funciones de proyección puras
(`triple_to_ocsf`/`ocsf_to_triple`, `project.rs`) entre el triple en memoria
`(Entity, Relation, Entity)` y un evento con forma OCSF v1.4 etiquetado con
`ProvenanceCtx`. **Punto crítico verificado: esta proyección se ejecuta en
tiempo de export, no en tiempo de ingesta.** El único call site de
`triple_to_ocsf` en todo `platform/api/src` es
`platform/api/src/operations/export.rs:271`, dentro de `export_events_as_ocsf`
(el comentario de la función auxiliar lo confirma explícitamente:
`export.rs:371` — *"Builds a Provenance Extension context for a relation at
export time"*). El grafo caliente (`core/graph-engine`) sigue almacenando y
operando sobre triples `(Entity, Relation, Entity)` / `CompactRelation` tal
como se documentó en S3; OCSF es una vista derivada, no el modelo de
almacenamiento.

`ProvenanceCtx` (`platform/canonical/src/provenance.rs:14-49`):

```rust
pub struct ProvenanceCtx {
    pub schema_version: String,
    pub source_dataset_id: String,
    pub mapping_id: String,
    pub mapping_version: u32,
    pub mapping_hash: String,
    pub parser_name: String,
    pub confidence: f32,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub raw_event_sha256: String,
    #[serde(default)]
    pub upstream_ids: Vec<String>,
}
```

Los campos pedidos por el brief están todos presentes: `schema_version`
(constante `"ocsf-1.4+gh-prov-0.1"`, `provenance.rs:54`), `source_dataset_id`
(`:18`), `mapping_id`/`mapping_version`/`mapping_hash` (`:22-29`),
`parser_name` (`:32`) y `confidence` (`:36`). `raw_event_sha256` se omite del
wire por completo (no es `""`) cuando los bytes crudos no se retuvieron —
`export.rs:372-373` confirma que hoy siempre es así en export: *"the raw
event bytes are not retained after ingest"* (por eso `provenance_for_relation`
llama `for_vrl`/`for_builtin_parser` con `&[]` en `export.rs:396`/`406`).

**`platform/vrl`** es el compilador `FieldConfig → VRL`
(`platform/vrl/src/compiler.rs:37` `field_config_to_vrl`): toma el
`FieldConfig` declarativo (el mismo que produce el preview de ingesta) y
emite (a) el código fuente VRL determinista y (b) `mapping_hash =
sha256(source)`. Es puramente una función del `FieldConfig` — el propio
doc lo remarca: *"same FieldConfig in, byte-identical source out"*
(`compiler.rs:34-36`). No hay runtime VRL embebido ejecutando estos
programas contra el stream de ingesta hoy (doc del crate en el manifiesto
de S2: *"wedge M3, sin runtime `vrl` embebido"*); su único consumidor
verificado es de nuevo `export.rs:206-219`/`390-398`, que usa
`field_config_to_vrl` para fabricar el `mapping_hash`/`mapping_version`
mostrado en el `ProvenanceCtx` de export — no para transformar eventos en
la ruta de ingesta real.

### 3. Skips silenciosos — contabilidad de `ParseStats` y el claim de los fast-paths

`ParseStats` (`core/graph-engine/src/parser.rs:81-109`) lleva `rows_seen`,
`rows_with_triples`, `rows_skipped`, `per_field_occurrence`, `skip_reasons`
(mapa razón→conteo, `sum(skip_reasons) == rows_skipped` cuando el parser
categoriza), `skipped_samples` (hasta 20 muestras `(raw_json, reason)`
reservoir-sampled) y `drift` (`Option<DriftSnapshot>`).

La vía de "fidelidad completa" es `parse_events_with_stats`
(`core/graph-engine/src/generic.rs:1444-1503`), compartida por
`GenericParser::parse_with_stats` (`generic.rs:1405-1408`) y
`SysmonJsonParser::parse_with_stats` (`sysmon.rs:2164-2167`): por cada
evento acumula `per_field_occurrence`, clasifica el motivo de skip vía
`classify_skip_reason` (`generic.rs:1509-1522+`, tags `empty_row`/
`no_canonical_fields`/`no_anchor`/…), llena `skipped_samples` y siempre
puebla `drift` (`generic.rs:1501`, incondicional, no un `Option` que se deje
en `None`).

**Claim del spec — CONFIRMADO con evidencia directa, no solo inferido del
docstring genérico del trait.** El brief cita
`ingestion.rs:1290-1296` y `parser.rs:222-227`; ambas citas son correctas y
se leyeron íntegras:

- `parser.rs:218-229` (docstring de `parse_raw_with_stats` en el trait
  `LogParser`) advierte en general que los "native overrides" que usan el
  fast-path tipado *"may leave those fields empty and only populate
  rows_seen, rows_with_triples, rows_skipped, and drift"* — nótese que este
  texto genérico sugiere que `drift` sí se poblaría.
- `ingestion.rs:1290-1296` (comentario en el call site real de
  `parser.parse_raw_with_stats`, dentro de `load_data_streaming`) es más
  preciso y ya anticipa la discrepancia: *"Stats fidelity trade-off
  documented on the trait method: drift / per_field_occurrence /
  skip_reasons are empty in the native typed paths."* — aquí `drift` **sí**
  se incluye entre los campos vacíos.
- Verificado contra las dos únicas implementaciones nativas que existen hoy:
  `SysmonJsonParser::parse_raw_with_stats` (`sysmon.rs:2234-2304`) y
  `SentinelJsonParser::parse_raw_with_stats` (`sentinel.rs:1194-1236`).
  Ambas construyen `ParseStats::default()` y solo asignan `rows_seen`,
  `rows_with_triples`, `rows_skipped`; nunca escriben `.per_field_occurrence`,
  `.skip_reasons`, `.skipped_samples` ni `.drift`, que por lo tanto quedan en
  sus valores `Default` (mapas/vector vacíos, `drift: None`). Los propios
  comentarios de esas funciones lo dicen explícitamente: `sysmon.rs:2301-2302`
  — *"per_field_occurrence, skip_reasons, skipped_samples, drift
  intentionally left empty"* — y `sentinel.rs:1189-1193` — *"Per-field
  occurrence + skip classification + drift are left empty"*.
- En `ingestion.rs:1307-1311`/`1316-1319`, el acumulador `drift_accum` solo
  hace `merge` cuando `s.drift` es `Some(d)`; como para Sysmon/Sentinel
  `s.drift` es siempre `None` en la ruta por línea, `drift_accum` nunca
  recibe datos de estos dos formatos por esta vía — consistente con el
  comentario del call site.

**Conclusión sobre la afirmación del spec:** la afirmación
"`drift`/`skip_reasons`/`skipped_samples` quedan vacíos en los fast-paths
Sysmon/Sentinel" queda **confirmada**, con una precisión adicional: la única
inconsistencia menor es que el docstring general del trait
(`parser.rs:222-227`) da a entender que `drift` sí se pobla en "native
overrides" típicos, mientras que las dos únicas implementaciones reales
actuales dejan `drift` vacío también — el comentario puntual en el call site
(`ingestion.rs:1295-1296`) es el que refleja correctamente el comportamiento
verificado, no el docstring genérico del trait.

Esta pérdida de fidelidad es real solo en la ruta de **streaming por
línea** (`parse_raw_with_stats`, la que usa `load_data_streaming`); la ruta
`parse_with_stats` (no-raw) de ambos parsers sigue teniendo fidelidad
completa vía `parse_events_with_stats` — la disyuntiva es "raw + rápido, sin
diagnóstico fino" vs. "con diagnóstico fino, sin el ahorro de allocaciones",
no una pérdida universal e irreversible del dato.

### 4. Sanitización de field-config: qué reescriben y qué pierde el grafo

`sanitize_field_config` (`platform/api/src/operations/ingestion.rs:96-116`)
recorre cada `FieldMapping` de un `FieldConfig` persistido; si el campo
canónico al que apunta (`GenericParser::canonical_field`,
`generic.rs:200`) resuelve a un `canonical_to_entity_type` de `"Skip"`
(`generic.rs:453-474`: `timestamp`, `command_line`, `protocol`,
`source_port`, `target_port`, `action`, `outcome`, `severity`, `message` —
9 campos) y el rol pedido es `Ignore` o `Node`, lo **fuerza** a `Metadata` y
descarta cualquier `entity_type` override (`ingestion.rs:106-113`). Se
invoca sobre configs entrantes en `ingestion.rs:703` y en tests
(`:1752`/`1762`/`1773`/`1783`).

**Qué pierde el grafo:** el propio doc de la función (`ingestion.rs:83-95`)
lo explica con dos ejemplos concretos: un mapping viejo `TIME → Ignore`
haría que `GenericParser::normalize` ya no pueda recuperar el timestamp del
evento, rompiendo `temporal_heatmap`, `temporal_novelty` y `diff_hunts`
(features que dependen de tener `timestamp` real por arista); un mapping
`SEVERITY → Node` explotaría el grafo con una entidad `Severity` por fila.
El sanitizador corrige configs persistidos de antes del fix de semántica de
Phase A, sin pedirle al analista que vuelva a previsualizar manualmente —
pero por diseño es **unidireccional y con pérdida**: un campo marcado
`Ignore`/`Node` sobre uno de los 9 campos "Skip" pierde su intención
original (sea cual sea) y queda fijado a `Metadata`, sin posibilidad
declarativa de recuperarlo salvo edición manual posterior del `FieldConfig`.

`auto_field_config_for` (`ingestion.rs:126-182`) construye un `FieldConfig`
completo desde cero usando la misma heurística del preview UI
(`rich_preview_for_format`, `format_registry.rs:317-349`), para el
one-shot `load_data` sin override del analista. Solo aplica a
`csv`/`generic`/`sysmon`/`sentinel`/`cognito` (`ingestion.rs:127-130`) —
`iis` y `fortianalyzer` quedan fuera porque, según el doc, *"those handle
field mapping themselves"* (`:124-125`). Para cada campo: si el heurístico
por-valor sugiere un tipo, gana ese; si es un campo de timestamp, se
mapea a `"Skip"`; si hay un canonical-default no-Skip, se usa ese; si
ninguno de los anteriores aplica, el default es `"Skip"`/`Metadata`
(`ingestion.rs:161-171`) — el comentario de 2026-05-06 (`:152-160`)
documenta explícitamente el fix de un bug previo (fallback anterior era
`raw_name`, lo que promovía campos numéricos/categóricos desconocidos
como `bytes`/`action`/`count`/`priority` a nodos tipados por su propio
nombre de campo, ensuciando el grafo con "entidades" espurias). El
efecto neto es el mismo tipo de pérdida que `sanitize_field_config`: campos
no reconocidos o de tipo desconocido caen a `Metadata` en vez de convertirse
en nodos — es una elección deliberada de "opt-in explícito" en vez de
"opt-out después de ver basura en el grafo", pero implica que cualquier
campo con semántica de entidad que la heurística no reconozca (nombres no
canónicos, no ingleses fuera de la lista cubierta en `generic.rs`, valores
que no matchean los regex de tipo) se degrada silenciosamente a metadata
plana y no genera aristas/nodos propios salvo edición manual posterior.

### 5. Versionado del normalizador y reproceso de eventos ya ingeridos

**¿Tiene versión el normalizador hoy?** Sí, pero de dos formas distintas y
ninguna es un versionado "por edición del mapping" en el sentido de journal
reproducible:

- `ProvenanceCtx.mapping_version: u32` (`provenance.rs:24`) para parsers
  hand-written se fija en la constante `1` (`provenance.rs:70`,
  `for_builtin_parser`) — no versiona nada, es un placeholder.
- Para mappings VRL, `mapping_version` es en realidad
  `COMPILER_VERSION` (`platform/vrl/src/compiler.rs:8`, valor `1` hoy),
  *no* una versión del `FieldConfig` del usuario — el propio doc lo aclara:
  *"mapping_version is the compiler's own version and is not the
  user-controlled FieldConfig version"* (`compiler.rs:14-15`). Lo que sí
  cambia con cada edición del `FieldConfig` es `mapping_hash =
  sha256(vrl_source)` (`compiler.rs:79-87`), que actúa como identidad de
  contenido, no de versión secuencial.

**¿Un cambio de mapping reinterpreta eventos ya procesados? Evidencia: NO —
confirmado el "no hay journal, así que no hay reproceso" sugerido por el
brief, con dos matices verificados.**

1. **No existe un journal/almacén de eventos crudos para replay general.**
   `DatasetInfo.field_config: Option<FieldConfig>`
   (`platform/api/src/state/session_types.rs:64`) es un único slot mutable
   por dataset, no una lista versionada. Se escribe la primera vez al
   ingerir (`ingestion.rs:1131-1136`, config heurístico aplicado) y puede
   **sobrescribirse** después, sin re-ingesta, cuando se aprueba un draft
   agentic: `promote_field_config_to_latest_dataset`
   (`platform/api/src/operations/agentic_review.rs:197-213`) hace
   `target.field_config = Some(cfg)` (`:211`) sobre el dataset ya existente.
   El único mecanismo de "reproceso" real en todo el código es el DLQ:
   `reingest_dead_letter` (`platform/api/src/operations/dlq.rs:76-221`,
   doc en `dlq.rs:6-12`) — y explícitamente solo re-emite las filas que
   **fallaron el parseo** (dead-lettered), escribiéndolas a un archivo
   temporal y volviendo a correr `load_data_with_config` con el
   `FieldConfig` **actual** del dataset (`dlq.rs:149-192`). Las filas que sí
   produjeron triples y ya están insertadas como `Entity`/`Relation` en el
   grafo (`insert_raw_events`, ver S3 §2) no tienen ningún camino de vuelta:
   no hay bytes crudos retenidos para ellas (confirmado en §2 de esta
   sección: `export.rs:372-373`), así que un cambio de mapping no puede, ni
   en principio, reinterpretarlas — el grafo ya construido con la
   interpretación vieja se queda como está.
2. **Efecto secundario verificado y no documentado como tal: la
   `ProvenanceCtx` de export sí queda "contaminada" retroactivamente.**
   `provenance_for_relation` (`export.rs:376-407`) construye el
   `ProvenanceCtx` de cada relación **en tiempo de export**, no al ingerir,
   leyendo el `FieldConfig` **actual** del dataset vía `vrl_by_dataset`
   (`export.rs:206-219`, construido justo antes de exportar). Como
   `field_config` es un único slot mutable por dataset (punto anterior), si
   el analista edita el mapping después de un ingest inicial, **todas** las
   relaciones de ese dataset —incluidas las que ya se insertaron en el
   grafo bajo la interpretación vieja— se exportan con el `mapping_hash`/
   `mapping_version` del mapping **nuevo**, no del que realmente las generó.
   El grafo (entidades/relaciones/tipos) no se reinterpreta, pero el rastro
   de auditoría OCSF que se exporta sí puede desalinearse silenciosamente
   con la interpretación real que produjo cada arista — no hay ningún test
   localizado que ejercite este escenario (edición de mapping entre ingest
   y export del mismo dataset), por lo que se reporta como hallazgo de
   lectura de código, no como comportamiento confirmado por un test.

## S5. Pipeline de ingesta, persistencia y almacenamiento local

### Metodología

Se leyeron íntegramente `core/graph-engine/src/ingest/{mod,source_poller,parser_task,
writer,channels,batch,overflow,coverage,metrics,cancellation}.rs`,
`core/graph-engine/src/ingest/graph_access.rs`, `core/graph-engine/src/watermark_store.rs`,
`core/graph-engine/src/dlq/mod.rs`, `platform/api/src/operations/dlq.rs`,
`platform/api/src/operations/ingestion.rs` (completo hasta la constante
`WHOLE_FILE_PARSE_LIMIT` y el bloque de guards en las líneas ~900-1500),
`platform/api/src/state/persistence.rs`, `platform/api/src/state/session_binary.rs`,
`platform/api/src/operations/session.rs` (save/load/delete), `platform/sources/src/quota.rs`,
`core/graph-engine/src/drift/store.rs` y `core/graph-engine/src/mapping_library/mod.rs`,
más los greps pedidos (adaptados a la herramienta Grep) y verificaciones de wiring:

```
rg -n "watermark|checkpoint" core/graph-engine/src/ingest/ --type rust
rg -n "sqlite|rusqlite|app_data|session" platform/api/src/ core/graph-engine/src/ --type rust -i
rg -n "WHOLE_FILE_PARSE_LIMIT|MAX_PREALLOC_|CRITICAL_MEMORY_MB|stopped_early" platform/api/src/operations/ingestion.rs
rg -n "SourcePoller::new|GraphWriter::new|ParserTask::new|SqliteWatermarkStore::open\(|OverflowStore::open\(|IngestCancelTree" --glob "*.rs" .
rg -l "std::fs::|tokio::fs::" core/graph-engine/src/ platform/api/src/
```

**Hallazgo metodológico previo, transversal a las 5 preguntas: existen DOS
pipelines de ingesta distintos, no uno.** (1) `load_data_streaming`
(`platform/api/src/operations/ingestion.rs:827-…`), el pipeline
mmap + batch-de-líneas que corre hoy en background thread y es el que
efectivamente mueve bytes cuando un analista carga un archivo — wireado y en
uso. (2) El pipeline de canales tokio `SourcePoller → ParserTask → GraphWriter`
de `core/graph-engine/src/ingest/*` (el que describen `mod.rs` y las preguntas
del brief sobre tamaños de canal/checkpoints/circuit breaker) — código real,
completo, con tests unitarios exhaustivos, pero **no instanciado en ningún
camino de ejecución real**. Verificado exhaustivamente: `SourcePoller::new`,
`GraphWriter::new`, `ParserTask::new`, `IngestCancelTree::new` y el
constructor con archivo real `SqliteWatermarkStore::open(path)` (no
`open_in_memory`) **no tienen ningún call site fuera de sus propios tests
`#[cfg(test)]`**, con una única excepción: `apps/tauri/src-tauri/src/commands/
azure_streaming_smoke.rs`, que el propio encabezado del archivo
(`azure_streaming_smoke.rs:1-28`) documenta como un smoke test que ejercita
las primitivas *"without hitting Azure, without real HTTP, and without
touching the session's real GraphHunter"*, y que lista explícitamente como
**no cubierto**: *"Full `SourcePoller` cycle (needs persistent WatermarkStore
+ live source)"* (`azure_streaming_smoke.rs:25`). Ese comando ni siquiera usa
un directorio de sesión real para `OverflowStore`: abre un
`tempfile::tempdir()` desechable (`azure_streaming_smoke.rs:501-508`).
Confirmación adicional: el propio doc de `GraphAccess` (el trait que el
`GraphWriter` necesita para escribir al grafo real) dice que el implementor
de producción vive en *"Phase 5 in `app/src-tauri/src/ingest`"*
(`core/graph-engine/src/ingest/graph_access.rs:15-16`) — ese directorio
**no existe** en el árbol actual (`find apps/tauri/src-tauri/src -iname
"*ingest*"` solo devuelve `commands/ingestion.rs`, `commands/ingest_status.rs`
y `http/ingest.rs`, todos parte del pipeline (1), no del (2)). Esto no
invalida las respuestas de abajo — el código y sus constantes son reales y
se citan tal cual — pero cualquier lectura debe entender que describen un
subsistema completo y probado que hoy está **dormido**, no el camino que
efectivamente ingiere datos en la app.

### 1. Topología del pipeline streaming: tamaños de canal y backpressure

Topología (`core/graph-engine/src/ingest/mod.rs:8-21`): `SourcePoller` (uno
por fuente) → canal `raw_tx` → `ParserTask` (uno por fuente) → canal
`parsed_tx` → `GraphWriter` único compartido entre todas las fuentes →
`RwLock<GraphHunter>`.

**Tamaños de canal — el claim del spec "bounded 4 / bounded 8" queda
CONFIRMADO literalmente, no aproximado:**

```rust
pub const DEFAULT_RAW_CAPACITY: usize = 4;     // channels.rs:44
pub const DEFAULT_PARSED_CAPACITY: usize = 8;  // channels.rs:47
```

(`core/graph-engine/src/ingest/channels.rs:44,47`). El razonamiento de
dimensionamiento está documentado en el propio archivo
(`channels.rs:19-33`): una página cruda de Log Analytics puede pesar
~50 MB (500K filas × ~100 B), así que `4 × 50 MB = 200 MB` de cola cruda
por fuente en el peor caso; un `ParsedBatch` pesa ~12 MB (25K triples ×
~500 B), así que `8 × 12 MB ≈ 100 MB`. Tres fuentes concurrentes (LA, Data
Lake, Defender XDR) en estado estable encolan ~1 GB total, "well under the
2 GB streaming-backend memory budget" (`channels.rs:29-33`). Ambos
constructores clampan la capacidad a mínimo 1 (`raw_channel`/`parsed_channel`,
`channels.rs:64-73`), y un caller puede pasar una capacidad explícita
distinta del default por fuente.

**Semántica de backpressure — bloquea, no descarta, confirmado.**
`channels.rs:14-17` y `mod.rs:23-32` documentan que ambos canales son
`tokio::sync::mpsc::channel(N)`: `sender.send().await` **bloquea** cuando el
canal está lleno — esa es la señal de backpressure. La cadena documentada:
si el `GraphWriter` se atrasa, `parsed_tx.send` de `ParserTask` bloquea →
`raw_rx.recv` del `ParserTask` se atasca → `raw_tx.send` del `SourcePoller`
bloquea → el poller deja de llamar a Azure. Nunca se descartan datos salvo
que el receptor se cierre explícitamente (`channels.rs:16-17`). Verificado
por test: `raw_channel_blocks_when_full` (`channels.rs:100-110`) — con
capacidad 1, un segundo `try_send` falla mientras el primer mensaje no se
drena; drenar uno libera espacio para el siguiente `try_send`.

**Un solo `GraphWriter`, no uno por fuente** (`mod.rs:34-45`,
`writer.rs:9-16`): el `RwLock` del grafo se toma exclusivamente en escritura;
un writer único serializa el acceso y cede el lock entre chunks
(`tokio::task::yield_now().await`, `writer.rs:202-204`) para que lectores
(hunts, enrichment on-demand) tengan progreso acotado. El propio comentario
lo marca como **apuesta no medida** (`mod.rs:42-45`, `writer.rs:13-15`): si
telemetría de producción mostrara el writer saturado (>80% CPU), Phase 5
añadiría sharding — pero como se documenta arriba, esta ruta (2) no está en
producción hoy, así que esa telemetría no existe.

### 2. Ciclo de vida de una sesión: qué va a SQLite, qué a JSON, rutas de app-data

**Directorio raíz de app-data:** `dirs::data_dir().join("GraphHunter").join("sessions")`
(`platform/api/src/state/persistence.rs:14-18`), creado por `ensure_session_dir`
(`persistence.rs:22-26`). En Windows resuelve a `%APPDATA%\GraphHunter\sessions`
(comentario `persistence.rs:11-12`).

**Archivo por sesión — un solo archivo, no una carpeta:**
`{sessions_dir}/{session_id}.json` (`persistence.rs:51-54`), con
`session_id` validado contra `[A-Za-z0-9_-]{1,128}` para bloquear path
traversal / inyección de NUL (`persistence.rs:34-48`, ver tests
`reject_path_traversal`/`reject_nul_byte`, `persistence.rs:93-96,109-111`).

**El nombre `.json` es engañoso: el contenido real es binario desde
"Heavy-logs #3".** `save_session_blocking` (`platform/api/src/operations/
session.rs:249-391`) siempre escribe el formato binario `GHS1`
(magic `b"GHS1"`, `state/session_binary.rs:57-63`): un header
JSON-encoded (tolerante a cambios de schema, versión 2,
`session_binary.rs:29-30,42-44`) seguido de registros de entidades y
relaciones bincode-encoded, cada uno con longitud explícita
(`session_binary.rs:25-40`), escritos en streaming — memoria pico acotada a
los buffers del writer/reader (unos pocos MB), independiente del tamaño de
la sesión (`session_binary.rs:1-16`, motivado por una sesión EVTX de 28 GB /
~100M entidades que con el loader JSON antiguo materializaba ~10 GB
transitorios). El load path sniffa los primeros 4 bytes: `GHS1` → loader
binario; cualquier otra cosa → loader JSON legacy (`session_binary.rs:18-23`)
— sesiones viejas en JSON real siguen cargando, pero todo save nuevo migra a
binario transparentemente, sin configuración de usuario.

**No hay SQLite para el grafo de la sesión en sí** — ni entidades ni
relaciones se particionan nunca en una base de datos; es siempre este único
archivo (binario o JSON legacy) por `session_id`. SQLite se usa solo para
dos almacenes **adyacentes y separados**, ambos wireados en el arranque de
Tauri (`apps/tauri/src-tauri/src/lib.rs:126-175`):

- **`DriftStore`** — ruta única compartida `<data>/GraphHunter/sessions/
  drift.sqlite` (`lib.rs:134-138`), tablas `drift_batches`/`drift_field_tags`
  (`core/graph-engine/src/drift/store.rs:9-13,25-45`). **Discrepancia
  doc-vs-wiring:** el propio comentario del módulo dice *"records those
  snapshots to a per-session SQLite file"* (`drift/store.rs:4-6`), pero el
  wiring real usa **un solo archivo compartido por todas las sesiones**, no
  uno por `session_id` — mismo patrón de discrepancia doc/código que S3
  documentó para otras partes del sistema.
- **DLQ** — no es SQLite, son shards JSONL bajo el directorio único
  compartido `<data>/GraphHunter/sessions/dlq/` (`lib.rs:155-175`); ver
  detalle en la pregunta 4.

**El almacén de watermarks SQLite (`watermark_store.rs`) nunca se abre con
una ruta real fuera de sus propios tests.** El doc del módulo afirma que
vive en *"`<session_dir>/ops.sqlite`"* (`watermark_store.rs:11-12`), pero
`SqliteWatermarkStore::open(path)` (el constructor file-backed, distinto de
`open_in_memory()`) **no tiene ningún call site fuera del propio
`#[cfg(test)]` de `watermark_store.rs`** (`watermark_store.rs:563,572`) —
verificado por grep exhaustivo en todo el repo. Consistente con el hallazgo
de la Metodología: hoy la app nunca crea un `ops.sqlite` real.

**Artefacto legacy muerto encontrado:** `remove_session_files`
(`operations/session.rs:693-700`) sigue limpiando un directorio sidecar
legacy `{sessions_dir}/{id}/`, cuyo fixture de test nombra un archivo
`sentinel_watermarks.json` (`operations/session.rs:894-905`) — pero un grep
de `sentinel_watermarks` en todo el repo solo devuelve esa referencia de
test/limpieza; no existe ningún escritor de ese archivo en el árbol actual.
Es deuda de borrado retrocompatible, no un mecanismo activo.

**Descartar una sesión** (`delete_session`, `operations/session.rs:401-417`)
es un borrado real de disco (el archivo `.json`-nombrado más el sidecar
legacy si existe), no un archivado ni soft-delete; un `remove_file` fallido
ahora se propaga como error en vez de tragarse silenciosamente
(`operations/session.rs:916-929`, test `remove_session_files_propagates_
real_errors`).

### 3. Checkpoints/watermarks: avance, crash entre `send` y persistencia, gap del circuit breaker

**Cuándo avanza el watermark.** En `poll_one_table`
(`source_poller.rs:309-385`): por cada `(chunk, new_wm)` exitoso del stream,
primero se reenvía el chunk (`raw_tx.send(Ok(chunk)).await`, línea 353) y
**solo después**, si `new_wm != current_wm` (se descartan ecos no-op de la
fuente, línea 364), se persiste vía `watermarks.set(&key, &new_wm)` (línea
365); el contador `watermark_advances` solo se incrementa si el `set` tuvo
éxito (365-369). Errores de la fuente **nunca** avanzan el watermark
(`source_poller.rs:33-37`; test `poller_forwards_source_error_without_
advancing_watermark`, `source_poller.rs:615-682`, confirma
`watermark_advances == 0`).

**Crash entre `send` y persistencia — claim ya verificado y CORREGIDO en
S3, citado aquí sin volver a derivarlo.** El comentario de
`source_poller.rs:24-31` documenta explícitamente el orden (persistencia
del watermark ocurre DESPUÉS de que el envío al canal retorna) y afirma que
un crash en ese intervalo es seguro porque *"the graph insertion is
idempotent at the `(src_sid, dst_sid, timestamp, rel_type_tag,
metadata_offset)` level"*. **S3 §3 de este mismo documento** (citando
`graph.rs:788-796`, `streaming.rs:1339-1379`, `streaming.rs:195-221`) ya
estableció que esa afirmación es **incorrecta**: no existe ningún chequeo de
existencia/deduplicación en el pipeline de inserción de aristas —
`push_to_streaming`/`append_edge_checked`/`NeighborList::push` son appends
incondicionales. Se cita esa conclusión aquí sin repetir la evidencia
completa: la consecuencia directa para el escenario de esta pregunta es que
un crash entre el `send` del chunk y el `watermarks.set` correspondiente, al
reiniciar, re-poll desde el watermark viejo y **re-inserta aristas
duplicadas reales en el grafo**, no un riesgo puramente documental. Nota de
alcance: este escenario de crash-recovery es hoy teórico en el sentido de
que el pipeline que lo protagoniza (`SourcePoller` + `SqliteWatermarkStore`
persistente) no corre en ningún camino real de la app (ver Metodología) — el
único ejercicio de un `SqliteWatermarkStore` file-backed es su propio test
`persists_across_open` (`watermark_store.rs:556-577`).

**Circuit breaker y su gap de cobertura.** `CircuitBreaker`
(`source_poller.rs:76-133`) abre tras `circuit_max_failures` fallas
consecutivas (default `DEFAULT_CIRCUIT_MAX_FAILURES: u32 = 5`,
`source_poller.rs:58`), con backoff inicial `DEFAULT_CIRCUIT_BACKOFF_BASE =
1 s` (línea 61) que dobla por cada falla extra, capado en
`MAX_CIRCUIT_BACKOFF = 5 * 60 s` (línea 64). Mientras está abierto,
`poll_one_table` retorna de inmediato sin llamar `poll_since` en absoluto
(`source_poller.rs:309-315`, contado en `circuit_open_skips`) — confirmado
por el test `poller_opens_circuit_after_n_failures`
(`source_poller.rs:717-808`): el call count de la fuente deja de crecer
mientras el circuito está abierto.

- **El gap real:** `DataCoverage::record` (`ingest/coverage.rs:108-122`)
  solo se alimenta con filas que efectivamente llegaron a insertarse en el
  grafo. Mientras el circuito está abierto no fluye ningún dato para esa
  fuente, así que no se puebla ningún bucket para esa ventana de tiempo.
  `DataCoverage::gaps()` (`coverage.rs:169-198,264-286`) reportaría esa
  ventana como un gap de cobertura **indistinguible** de "la fuente upstream
  genuinamente no tuvo eventos" — el propio propósito documentado del
  módulo es justo evitar esa ambigüedad para el analista
  (`coverage.rs:1-10`: *"the analyst needs to know whether the hypothesis
  genuinely didn't match OR whether we never ingested data"*), pero ni
  `SourcePoller` ni `DataCoverage` cruzan la señal de circuito-abierto contra
  los buckets de cobertura — no hay ningún campo/anotación que distinga
  "gap por breaker" de "gap por fuente vacía". El único lugar donde el
  estado del circuito es observable es `PollerMetricsSnapshot`
  (`circuit_state`/`circuit_open_skips`/`consecutive_failures`,
  `source_poller.rs:222-232`), un snapshot de métricas aparte que
  `DataCoverage` no consulta.

### 4. Almacenamiento local: inventario exhaustivo de "precursores de journal"

| # | Artefacto | Ruta | Formato | Estado |
|---|---|---|---|---|
| 1 | Grafo de sesión | `{data}/GraphHunter/sessions/{id}.json` | Binario `GHS1` (o JSON legacy) | **Real, wireado** (ver §2) |
| 2 | Spill de aristas | tempdir / dir externo vía `with_spill_dir_and_budget` (`streaming.rs:533-551`) | archivo ordenado por timestamp, mmap de vuelta | **Real, activo por defecto** (ya documentado en S3 §5, `streaming.rs:500-527,1178-1215`, `graph.rs:244-247`; citado aquí solo como ítem del inventario, no re-derivado) |
| 3 | Overflow de ingesta | `<session_dir>/ingest_overflow/pending_<ts>_<ctr>.json` (`ingest/overflow.rs:52-53,245-257`) | JSON (no CBOR, pese al plan §8 — justificado en `overflow.rs:22-26`: evitar una dep nueva) | **Código completo, cero call sites productivos** — `OverflowStore::open` solo se llama desde sus propios tests y desde el smoke test Tauri con un `tempfile::tempdir()` desechable (`azure_streaming_smoke.rs:501-508`), nunca desde un `<session_dir>` real |
| 4 | DLQ | `<data>/GraphHunter/sessions/dlq/dlq_<ts>_<ctr>.jsonl` (`dlq/mod.rs:9,37-42`) | JSONL, shard rota a 10 000 registros u 8 MiB (`SHARD_MAX_RECORDS`/`SHARD_MAX_BYTES`, `dlq/mod.rs:41-42`) | **Real, wireado** en el arranque (`lib.rs:155-175`) — pero solo alimentado por los caminos síncronos `load_data`/`load_data_with_config` (`record_parse_skips` en `ingestion.rs:433,755`); el camino background `load_data_streaming` (línea-por-línea, el que de hecho procesa archivos grandes) **nunca llama** `record_parse_skips`/`record_dead_letter` — sus filas descartadas no llegan al DLQ, ver §5 |
| 5 | Watermarks + source_status + enrichment_audit | doc-claimed `<session_dir>/ops.sqlite` (`watermark_store.rs:11-12`) | SQLite (tablas `watermarks`/`source_status`/`enrichment_audit`, `watermark_store.rs:283-316`) | **No wireado** — `SqliteWatermarkStore::open(path)` sin call sites fuera de sus propios tests (ver §2) |
| 6 | Drift de parseo | `<data>/GraphHunter/sessions/drift.sqlite` (único, compartido) (`lib.rs:134-138`) | SQLite (`drift_batches`/`drift_field_tags`, `drift/store.rs:25-45`) | **Real, wireado**, pese a que el doc del módulo dice "per-session" (ver §2) |
| 7 | Mapping library | `<data>/mapping_library/mappings.jsonl` (`mapping_library/mod.rs:19-23`) | JSONL append-only, un `PublishedMapping` por línea | **Real, wireado** — pero fuera del alcance estricto de "journal de ingesta cruda": guarda `FieldConfig`/VRL/provenance aprobados, no eventos crudos; incluido aquí solo por completitud del cruce `std::fs`/`tokio::fs` del Paso 3 |
| 8 | Sidecar legacy de sesión | `{sessions_dir}/{id}/` (p. ej. `sentinel_watermarks.json`) | — | **Muerto** — solo referenciado por el código de limpieza (`operations/session.rs:693-700,894-905`); ningún escritor activo (ver §2) |

**Justificación de cada hit no listado del cruce `rg -l "std::fs|tokio::fs"
core/graph-engine/src/ platform/api/src/`:**

- `core/graph-engine/src/tests.rs` — fixtures de test, no I/O de producción.
- `core/graph-engine/src/planner.rs:896` — `std::fs::read_to_string` lee un
  archivo de calibración de benchmark (solo lectura, ajeno a ingesta/sesión).
- `core/graph-engine/src/catalog/loader.rs` — lee YAML del catálogo de
  hunts desde `$GRAPHHUNTER_CATALOG_DIR`/`~/.graphhunter/catalog/`
  (`catalog/loader.rs:6-8`), solo lectura; es catálogo de patrones de hunt,
  no datos ingeridos.
- `platform/api/src/operations/ingestion.rs` — ya cubierto como el pipeline
  principal (fila 1); sus usos adicionales de `std::fs`/`mmap` abren el
  **archivo fuente del usuario** para lectura (`ingestion.rs:1171-1177,
  1464-1467`), no almacenamiento propio de la app.
- `platform/api/src/operations/graph_ops.rs:66` — `preview_fields` abre el
  archivo fuente del usuario para muestrear nombres de campo (solo lectura,
  archivo de entrada, no almacenamiento de la app).
- `platform/api/src/pcap.rs`, `pcap_preview.rs`, `evtx.rs`,
  `ingestors/mod.rs`, `ingestors/zeek.rs`, `ingestors/suricata.rs`,
  `ingestors/netflow.rs` — todos hacen `File::open`/`metadata()` sobre el
  archivo fuente que el usuario está ingiriendo (magic-byte sniffing,
  tamaño, parseo); son lecturas de entrada, no artefactos que la app
  persista. Sus bloques `#[cfg(test)]` además escriben fixtures temporales
  desechables para los tests del propio ingestor, no escrituras de
  producción.

### 5. Truncamientos: guards con valores exactos y señal que queda

| Guard | Valor exacto | Cita | Qué pasa al activarse | Señal que queda |
|---|---|---|---|---|
| `WHOLE_FILE_PARSE_LIMIT` | 512 MB (`512 * 1024 * 1024`) | `ingestion.rs:81`, comentario `:74-80` | Rama "whole-file" (JSON no line-delimited): archivo por encima del límite se **rechaza entero** (`ingestion.rs:1452-1463`), no se trunca — la rama ni siquiera arranca | `Err(String)` con mensaje accionable, propagado como evento `IngestError` (`dto/v1/ingestion.rs:150-154`); no hay ingesta parcial |
| `CRITICAL_MEMORY_MB` | 256 MB, solo Windows (`#[cfg(target_os = "windows")]`, `ingestion.rs:69-70`) | `ingestion.rs:70`, chequeo en `:1350-1391` vía `GlobalMemoryStatusEx` cada ~20 batches | En la rama streaming línea-por-línea: si RAM física disponible < 256 MB, `stopped_early = true` y se rompe el loop (`:1380-1388`); el batch final (líneas tras el último `\n`) se **salta explícitamente** (`:1401`: *"the remaining data could be gigabytes and would OOM"*) — esas filas finales se pierden silenciosamente del grafo | Solo `tracing::warn!` (`:1381-1384`). **Verificado exhaustivamente (grep de `stopped_early` en todo el archivo, 4 ocurrencias, todas en `:1187-1401`): la variable es local al closure de ingesta y nunca se copia a ningún campo de sesión ni al DTO `LoadResult`/`IngestComplete`** (`dto/v1/ingestion.rs:73-146`, sin campo `truncated`/`stopped_early`) — el operador no tiene ninguna señal en la UI, solo el log |
| `CRITICAL_MEMORY_MB` en Linux/macOS | — | El bloque completo está gateado tras `#[cfg(target_os = "windows")]` (`ingestion.rs:69-70,1351`) | El guard **no existe** fuera de Windows — no hay chequeo de memoria crítica equivalente | Ninguna — no aplica |
| `MAX_INGEST_LINES` | `usize::MAX` (`ingestion.rs:930`) | Comparación en `:1199` | **Nunca se activa en la práctica** — haría falta un archivo con más de `usize::MAX` líneas; el guard queda vestigial/deshabilitado pese a que el código (`stopped_early = true` + warning, `:1200-1206`) sigue wireado para él | N/A (inalcanzable) — corrección si el spec asumía un tope de líneas activo hoy |
| Cuotas Azure (`QuotaLimiter`) | Log Analytics 200/30 s; Defender XDR ~45/60 s; Sentinel Data Lake conservador 120/60 s (`platform/sources/src/quota.rs:8-14`) | `quota.rs:55-97,99-115` | **No es un truncamiento**: `acquire()` bloquea/duerme (`quota.rs:99-115`) hasta que hay token o expira la penalización de un 429 (`penalize()`, `:120-134`); ninguna fila se descarta jamás | No aplica señal de pérdida — se distingue deliberadamente de los guards de arriba porque no hay pérdida de datos. Nota de alcance: el `QuotaLimiter` es real y probado pero solo alcanzable desde tests de `ingest/metrics.rs`, no desde ningún poller corriendo en producción (ver Metodología) |

**Aclaración adicional — no son truncamientos:** `MAX_PREALLOC_ENTITIES =
2_000_000` y `MAX_PREALLOC_RELATIONS = 4_000_000` (`ingestion.rs:63,65`)
solo acotan el tamaño de la heurística de **pre-allocation** de capacidad
(`.min(MAX_PREALLOC_ENTITIES)`/`.min(MAX_PREALLOC_RELATIONS)`,
`ingestion.rs:1141-1147`) para no sobre-reservar memoria cuando el estimado
por tamaño de archivo resulta exagerado; un archivo que produce más
entidades/relaciones que esos topes simplemente hace que el `Vec` interno
haga resize normal más allá de la capacidad pre-reservada — la ingesta no
se rechaza ni se trunca por esta constante.

## S6. Integración Sentinel y sidecar

### Metodología

Se leyeron íntegramente `platform/sources/src/lib.rs` (trait `LogSource`),
`log_analytics.rs`, `data_lake.rs`, `defender_xdr.rs`, `quota.rs`,
`platform/siem/src/sentinel.rs`, `sentinel_streaming.rs`, `elastic.rs`,
`docs/decisions/2026-05-26-sidecar-integration.md`,
`platform/api/src/sentinel_connector.rs`,
`platform/api/src/operations/sentinel.rs` (completo),
`apps/tauri/src-tauri/src/commands/sentinel.rs`,
`apps/tauri/src-tauri/src/http/siem.rs`, y los tools MCP
`platform/mcp/src/tools/sentinel/{query,seed,schema,status}.ts` +
`platform/mcp/src/lib/api-client.ts` + `platform/mcp/src/index.ts`, más
greps de wiring (`sidecar_manager`, `sidecar`, `externalBin`, credenciales
Azure en `platform/mcp/src`).

**Hallazgo metodológico previo, coherente con S2 y S5.** Existen **tres
superficies Sentinel distintas**, no una: (1) el conector en vivo wireado
(`platform/api/src/sentinel_connector.rs` + `platform/siem/src/sentinel_streaming.rs`
+ `operations/sentinel.rs`) — HTTP directo con `reqwest`, es el único camino
que efectivamente mueve datos de Sentinel hoy; (2) la nueva abstracción
`LogSource`/`platform/sources` (Fase 3 del plan de streaming) — código real,
probado, pero **no instanciada en ningún camino de producción**, la misma
conclusión que S5 estableció para el pipeline `SourcePoller`/`ParserTask`/`GraphWriter`
del que `LogSource` es la capa de fuentes; (3) el sidecar .NET, del que **no
existe fuente trackeada** (ver S2), y que — verificado en esta tarea — tampoco
tiene ningún punto de wiring del lado Rust/Tauri. El cliente Rust que hablaría
con ese sidecar tampoco existe como código: `crates/sentinel-sidecar-client`
(nombrado explícitamente aquí porque S6 depende de esa ausencia, no solo de
citarla de pasada) no tiene `Cargo.toml` ni `src/` — el directorio contiene
únicamente una carpeta `target/` residual (caché de build), per el inventario
de S2 (a); no hay, por lo tanto, ni el lado .NET ni el lado Rust del sidecar
disponibles para auditar.

### 1. Ubicación de todas las llamadas a Sentinel/Azure

| Módulo | API de Azure que toca | Invocador (quién lo llama) | Estado |
|---|---|---|---|
| `platform/siem/src/sentinel_streaming.rs::HttpSentinelTransport` (`sentinel_streaming.rs:53-157`) | `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` (`:78-81`, client-credentials) + `POST https://api.loganalytics.io/v1/workspaces/{ws}/query` (`:129-132`) | `platform/api/src/sentinel_connector.rs::polling_loop` (`:176-233`, vía `token_cache.get_or_refresh` + `transport.execute_query`) | **Real, wireado** — es el conector en vivo (streaming por polling) |
| `platform/siem/src/sentinel.rs::run_sentinel_query`/`get_azure_token`/`execute_log_analytics_query` (`sentinel.rs:74-164`, `reqwest::blocking`) | mismos dos endpoints que arriba, síncronos | `platform/api/src/operations/sentinel.rs::run_kql` (`:385-387`, dentro de `spawn_blocking`), y transitivamente `run_hunting_template` (`:884-914`, delega a `run_kql`) | **Real, wireado** — camino ad-hoc/one-shot desde comandos Tauri y MCP (`sentinel_query`) |
| `graph_hunter_siem::HttpSentinelTransport::execute_query` (mismo transporte que la fila 1) | `POST .../query` | `operations/sentinel.rs::hydrate_node_filtered_with` (`:1024`, invocado por `seed_from_ioc`/`node_enrich`) y `discover_schema`/`graph_propose`/`graph_build` (vía `run_kql_rows`, definida más abajo en el mismo archivo, no leída línea a línea en esta tarea pero con la misma firma `SentinelTransport`) | **Real, wireado** — enriquecimiento on-demand + discover/propose/build |
| `platform/sources/src/log_analytics.rs::LogAnalyticsSource` (`log_analytics.rs:152-303,345-499`) | `POST {endpoint}/v1/workspaces/{ws}/query` vía `HttpClient` trait (no `reqwest` directo) | Ningún caller de producción — solo sus propios tests (`log_analytics.rs:526-796`) y, transitivamente, el smoke test Tauri (`azure_streaming_smoke.rs`, ver S5) si se construye ahí | **Código real, NO wireado** (parte de la superficie 2) |
| `platform/sources/src/data_lake.rs::DataLakeV2Source` | `POST https://api.securityplatform.microsoft.com/lake/kql/v2/rest/query` — **nunca se ejecuta**: la doc del módulo (`data_lake.rs:1-23`) dice explícitamente "STUB IMPLEMENTATION" y ambos métodos de datos devuelven `SourceError::Fatal` incondicionalmente (`:92-114`) | Ningún caller de producción | **Stub deliberado, no wireado** |
| `platform/sources/src/defender_xdr.rs::DefenderXdrSource` (`defender_xdr.rs:117-379`) | `POST https://api.security.microsoft.com/api/advancedhunting/run` | Ningún caller de producción — solo sus tests | **Código real, NO wireado** (parte de la superficie 2) |
| `sidecar/dotnet/GraphHunter.Sentinel.Sidecar` (.NET, gRPC per el contrato `sentinel_sidecar.proto` reconstruido de los stubs, ver S2) | Desconocido — **no verificable**: no hay `.cs`/`.csproj` fuente trackeado, así que no hay forma de leer qué API de Azure invocaría | Ninguno confirmado del lado Rust — ver punto 3 de abajo | **[no verificado]: sin fuente, sin wiring localizado** |

Ninguna fila queda sin invocador conocido: las cinco filas "reales" (Rust)
tienen un caller citado con `path:line`, y las dos filas "no wireadas"
(`log_analytics.rs`, `defender_xdr.rs`) declaran explícitamente que su único
consumidor son sus propios tests — consistente con el hallazgo transversal
de S5 de que la superficie `LogSource`/`platform/sources` completa está
dormida en producción. La fila del sidecar se marca **[no verificado]** por
ausencia de fuente, no se inventa un invocador.

### 2. El trait `LogSource` completo: qué cubre y qué le falta a un futuro `SourceConnector`

Firma citada, `platform/sources/src/lib.rs:274-327`:

```rust
#[async_trait]
pub trait LogSource: Send + Sync {
    fn source_id(&self) -> &str;
    fn kind(&self) -> SourceKind;
    fn available_tables(&self) -> &[&'static str];
    async fn check_auth(&self) -> Result<(), SourceError>;
    async fn query_scoped(
        &self,
        scope: QueryScope,
        cancel: CancellationToken,
    ) -> Result<ChunkStream, SourceError>;
    async fn poll_since(
        &self,
        table: &str,
        watermark: Watermark,
        cancel: CancellationToken,
    ) -> Result<PollStream, SourceError>;
}
```

**Lo que ya cubre** (mapeado a los cuatro huecos que el brief pide
verificar):

- **`capabilities()` — NO existe, ni con ese nombre ni equivalente.** No
  hay ningún método en el trait que declare, en runtime, qué puede hacer
  una fuente concreta (soporta backfill, soporta `poll_since`, tablas
  opcionales vs. obligatorias, límites de tasa propios). Lo más cercano es
  `available_tables()` (`lib.rs:288`), que solo enumera tablas, no
  capacidades de query. La consecuencia es visible en el propio código:
  `DataLakeV2Source` (el stub) implementa el trait completo pero sus dos
  métodos de datos siempre fallan en runtime (`data_lake.rs:92-114`) — un
  caller que itere `Vec<Arc<dyn LogSource>>` no tiene forma de preguntar
  "¿esta fuente realmente sirve datos?" antes de invocarla; debe intentar
  la llamada y interpretar el `SourceError::Fatal` resultante.
- **Backfill explícito — NO existe como operación separada.** El trait
  solo tiene `query_scoped` (drill-down puntual acotado a una entidad +
  ventana) y `poll_since` (avance incremental por watermark, `lib.rs:311-326`).
  No hay un tercer método tipo `backfill(range, table)` para "traer todo lo
  que ocurrió en esta ventana histórica, sin acotar a una entidad ni a un
  watermark en curso". El propio doc de `poll_since` (`lib.rs:312-320`)
  dice que "si no hay data nueva, el stream termina inmediatamente — el
  loop externo es responsable de dormir y reinvocar" — es decir, backfill
  masivo tendría que simularse invocando `poll_since` repetidamente con un
  watermark manual, no es una operación de primera clase.
- **Id nativo del evento — NO existe en ningún tipo del trait.** `RawChunk`
  (`lib.rs:182-201`) carga bytes crudos + `table` + `encoding` +
  `fetched_at` + `watermark_candidate`; no hay un campente `native_event_id`
  ni nada equivalente al `_id`/`RecordId` que Log Analytics o Defender XDR
  devuelven por fila. La deduplicación de eventos (si se necesitara) tendría
  que reconstruirse del lado del parser, después de decodificar `rows`, no
  antes — el trait no expone un identificador estable por evento a nivel de
  transporte.
- **`event_time` vs `ingestion_time` — parcialmente presente, asimétrico.**
  `RawChunk.fetched_at` (`lib.rs:192-194`, epoch-ms) es la única noción de
  tiempo de ingesta que el trait modela, y es responsabilidad del
  **transporte** (se computa con `now_epoch_ms()` en cada implementación,
  p. ej. `log_analytics.rs:305-311`, `defender_xdr.rs:193-199`), no del
  trait en sí. El `event_time` real (`TimeGenerated`/`Timestamp` de cada
  fila) vive **dentro** de `rows: Bytes` sin decodificar — el trait no lo
  extrae ni lo tipa; ver punto 4 más abajo para lo que pasa con esta
  distinción río abajo, en el parser y el motor de grafos.

**Conclusión:** el trait cubre bien el *transporte* (auth, paginación,
watermark, backpressure vía streams) pero deja sin resolver exactamente los
cuatro huecos que el brief anticipaba, y ninguno de los dos —
`capabilities()`/backfill explícito — tiene ni siquiera un stub o comentario
`// TODO` en el código leído; son ausencias silenciosas, no deuda declarada.

### 3. El sidecar .NET

**Qué hace (según la única fuente disponible: la nota de decisión, no
código).** `docs/decisions/2026-05-26-sidecar-integration.md:10-11` lo
describe como un "Sentinel Sidecar escrito en .NET 8 (proceso separado,
comunicación vía IPC con el host Tauri)". Los 13 stubs generados por
protobuf documentados en S2 (`SentinelSidecar.cs`, `SentinelSidecarGrpc.cs`)
confirman que el protocolo real es **gRPC** (no stdio JSON-RPC como sugiere
otra parte de la misma nota de decisión — ver discrepancia abajo), generado
desde un contrato `sentinel_sidecar.proto` que no está en el árbol
trackeado (S2). El propósito funcional (qué haría el sidecar frente a
Sentinel) no es verificable: sin `.cs`/`.csproj` de mano, no hay forma de
leer qué endpoints de Azure invocaría ni qué lógica de KQL/polling
implementaría — se marca **[no verificado]: sin fuente**.

**Discrepancia de protocolo dentro de la propia nota de decisión.** La
sección 4.2 del decision doc (`2026-05-26-sidecar-integration.md:144-149`)
describe la comunicación como "IPC (stdio JSON-RPC)" y basa el argumento
legal de "mere aggregation" de la GPL-FAQ en que el sidecar corre como
"proceso separado" lanzado con `tauri-plugin-shell`/`Command::new`. Pero
los stubs `.cs` generados (S2) son inequívocamente gRPC (`SentinelSidecarGrpc.cs`,
encabezado "Generated by the protocol buffer compiler"). Ambos hechos no
son necesariamente contradictorios (gRPC puede correr sobre un socket local
entre dos procesos separados, lo cual seguiría calificando como "mere
aggregation" bajo el mismo argumento legal), pero el texto de la nota
mezcla dos descripciones de transporte distintas sin reconciliarlas — se
reporta como inconsistencia documental, no como hallazgo de código.

**Por qué proceso separado (justificación GPL).** La nota lo explica en
detalle (`2026-05-26-sidecar-integration.md:124-149`): el proyecto es
GPL-3.0, pero varios NuGets que el sidecar consumiría (`Microsoft.Azure.Kusto.Language`,
paquetes `Azure.*`, el runtime .NET 8 self-contained) están bajo Microsoft
Software License Terms, no OSI-aprobada. Si el sidecar estuviera *linkeado
estáticamente* al host Rust/Tauri, la GPL-3.0 trataría la combinación como
obra derivada y exigiría relicenciar todo el binario combinado bajo GPL —
incompatible con los términos de Microsoft. Ejecutarlo como proceso
separado que se comunica por IPC lo hace, según la FAQ de la GPL citada en
la nota ("Mere aggregation"), un agregado de dos programas independientes,
cada uno con su propia licencia — de ahí la obligación arquitectónica de
mantenerlo fuera del proceso del host.

**Estado real del fuente — corrige la premisa del brief de esta tarea, en
la misma dirección que S2 ya corrigió la premisa de la Tarea 1.** El brief
de esta tarea (heredado del brief de la Tarea 1) pide citar `git branch -a`
para las ramas `feat/sp*-sentinel-*` sin mergear. **S2 ya ejecutó
exactamente ese comando** (`git branch -a --list "*sentinel*"`) y su
salida fue **vacía** — ninguna de las 4 ramas que
`docs/decisions/2026-05-26-sidecar-integration.md:20-27` enumera
explícitamente por nombre y SHA (`feat/sp1-sentinel-sidecar-foundation`,
`feat/sp2-alt-polling-differential`, `feat/sp3-kql-parser-offline`,
`feat/sp4-sentinel-management`) existe hoy en `git branch -a` ni en
`git ls-remote --heads origin/public`. Esta tarea no repite el comando
(ya verificado en S2) pero sí señala la implicación adicional: la nota de
decisión, fechada 2026-05-26, describe un estado de 4 branches "con
tracking en origin" que **ya no está presente** — o esas ramas fueron
borradas/squasheadas tras mergear (sin que el merge resultante sea
localizable: `git log --all --oneline -- sidecar/` tampoco devuelve nada,
per S2), o el estado que describe la nota nunca llegó a materializarse tal
cual en el remoto observable hoy. En cualquier caso, **hoy no hay fuente
`.cs`/`.csproj` en ningún ref accesible**, solo los 13 stubs generados bajo
`obj/` (S2) — el sidecar es, para efectos de este assessment, código que
no se puede auditar.

**Wiring del lado Rust/Tauri y qué pasa cuando falla — no hay `sidecar_manager`
en ningún lugar.** El brief pide citar `sidecar_manager` para describir la
degradación ante fallo. Se buscó exhaustivamente:

```
grep -rn "sidecar_manager" --include="*.rs" .    →  0 resultados en todo el repo
grep -rin "sidecar"        apps/tauri/src-tauri/src  →  solo comentarios en
                                                          state.rs:5,27 ("sidecar"
                                                          usado como metáfora del
                                                          AppState de Tauri, sin
                                                          relación con el .NET sidecar)
grep -in "externalBin|sidecar" apps/tauri/src-tauri/tauri.conf.json → 0 resultados
```

No existe ningún `externalBin` en `tauri.conf.json`, ningún
`Command::new`/`tauri_plugin_shell` que lance el binario del sidecar, ni
ningún módulo Rust que hable el protocolo gRPC hacia él. Los únicos
artefactos relacionados con el sidecar en el working tree son binarios
(`apps/tauri/src-tauri/binaries/graphhunter-sentinel-sidecar.{dll,exe,deps.json}`,
gitignorados) — residuos de un build .NET previo, no un componente que la
app Tauri invoque en ningún camino de código trackeado. **Conclusión: no
hay degradación que describir porque no hay invocación que degradar** — el
"qué pasa cuando falla" del brief no tiene respuesta de código porque el
sidecar, en el estado actual del repo, nunca se lanza. Esto es coherente
con el hallazgo del punto 1: la superficie Sentinel que efectivamente
mueve datos hoy es el HTTP directo (`reqwest` contra Log Analytics vía
`sentinel_connector.rs`/`operations/sentinel.rs`), no el sidecar — el
sidecar, si algún día se landea (per el plan multi-PR de la sección 2 de
la nota de decisión), sería una ruta adicional/alternativa, no la que la
app usa hoy.

### 4. `event_time` vs `ingestion_time`: ¿existe la distinción? ¿dónde se pierde?

**Existe a nivel de tipo, pero se pierde en la práctica para todo el
camino de ingesta que Sentinel usa.** Los dos campos existen en el motor
de grafos (ya documentado en S3 §4): `Relation.timestamp`/`CompactRelation.timestamp`
(`event_time`, el instante que el log reporta) y
`CompactRelation.ingested_at_delta` (`ingestion_time`, pensado para la API
MVCC "qué sabía el grafo en el instante T", `relation.rs:104-106`).

- **`event_time` sí se extrae correctamente para Sentinel.**
  `SentinelJsonParser::extract_timestamp` (`core/graph-engine/src/sentinel.rs:96-109`)
  parsea `TimeGenerated` o, si falta, `Timestamp` (el campo que usan las
  tablas Defender XDR) vía `parse_timestamp` (`sentinel.rs:55-71`, acepta
  varios formatos ISO 8601) y ese valor alimenta `Relation::new(..., timestamp)`
  en cada uno de los ~15 parsers de eventos del archivo (p. ej.
  `sentinel.rs:249,296,303,324,417,472,522,554`). Si el campo falta o no
  parsea, se emite un `eprintln!` de warning (`sentinel.rs:103,108`) y el
  evento se descarta (no hay entrada en `ParseStats.skip_reasons` para este
  caso específico — es un `eprintln!` a stderr, no contabilizado).
- **`ingestion_time` se descarta sistemáticamente para el camino que
  Sentinel usa.** Todo dato de Sentinel entra al grafo vía
  `graph.insert_triples(...)` — confirmado en los tres call sites
  productivos: `sentinel_connector.rs:256` (polling loop en vivo),
  `operations/sentinel.rs:488` (`run_kql`, ingest ad-hoc) y
  `operations/sentinel.rs:800` (`graph_build`), más `insert_triples`
  también dentro de `hydrate_node_filtered_with` (`operations/sentinel.rs:1033`,
  usado por `seed_from_ioc`/`node_enrich`). **`insert_triples`
  (`core/graph-engine/src/graph.rs:3086-3152`) hardcodea
  `ingested_at_delta: 0` en la construcción del `CompactRelation`
  (`graph.rs:3141`)** — no `encode_ingested_at(now_seconds())`, sino la
  constante `0`, literalmente. `insert_raw_events` (`graph.rs:3160-3244`,
  usado por el pipeline de parsers de alto rendimiento, no por Sentinel)
  hace exactamente lo mismo (`graph.rs:3230: ingested_at_delta: 0`), igual
  que `ingest_logs_with_policy` (`graph.rs:2586-2660`, ver `graph.rs:2646`)
  e `ingest_logs_chunked` (`graph.rs:2948-3046`, ver `graph.rs:3012`). Un
  grep dedicado de `ingested_at_delta` sobre todo `graph.rs` encuentra un
  **quinto** sitio, fuera del camino de ingesta pero con el mismo patrón:
  `compact_before` (`graph.rs:3371-…`), al reconstruir el store tras
  compactar aristas viejas, también reconstruye cada `CompactRelation` con
  `ingested_at_delta: 0` (`graph.rs:3451`) — es decir, incluso una arista
  que alguna vez hubiera tenido un `ingested_at_delta` real (vía
  `add_relation`) lo pierde si el grafo pasa por una compactación. Con este
  quinto sitio, el conteo verificado de construcciones de `CompactRelation`
  que hardcodean `ingested_at_delta: 0` es **cinco** (`graph.rs:2646, 3012,
  3141, 3230, 3451`), no tres — la cifra "tres" más abajo se refiere
  específicamente a los call sites de Sentinel que invocan `insert_triples`
  (una función distinta de estos cinco sitios de construcción), no a este
  conteo de hardcodeos.
  **El único call site que sí computa el valor real** es `add_relation`
  (`graph.rs:423-466`, línea `458: ingested_at_delta: encode_ingested_at(now_seconds())`)
  — una API de una sola relación a la vez que ningún camino de Sentinel
  invoca (confirmado por grep de `.add_relation(` en todo el repo: sus
  callers de producción están fuera de `operations/sentinel.rs` y
  `sentinel_connector.rs`; el resto de los ~40 archivos que la usan son
  tests/benches).
- **Consecuencia:** para toda arista que entra al grafo vía Sentinel (en
  vivo, ad-hoc KQL, hydratación de nodo, o el graph_build de propuestas),
  `event_time` es correcto pero `ingestion_time` es una constante `0`
  indistinguible entre sí para todas las aristas de todos los datasets —
  la distinción del brief "¿existe?" es: existe el campo y el mecanismo
  (`add_relation` lo demuestra), pero **se pierde específicamente en el
  camino masivo (`insert_triples`/`insert_raw_events`/`ingest_logs*`) que
  es exactamente el que toda ingesta real (Sentinel incluida) usa**. Es el
  mismo patrón de "función helper correcta, call site equivocado" que S3
  documentó para la idempotencia de aristas (`source_poller.rs:29` vs. la
  ausencia real de dedup) — el mecanismo MVCC de `ingested_at_delta`
  existe en el tipo y en un solo call site, pero no en los que importan
  en producción.

## S7. Inventario exhaustivo de KQL

### Metodología

`rg` no está disponible en el PATH del entorno de esta tarea; el barrido se
hizo con el tool `Grep` (mismo motor ripgrep por debajo), reproduciendo los
tres comandos del brief:

1. `kql` (case-insensitive) sobre `core/`, `platform/`, `apps/`, `crates/`,
   filtrado a `*.rs|*.ts|*.tsx|*.js` → **51 archivos** (3 en `core/`, 30 en
   `platform/`, 18 en `apps/`, 0 en `crates/`).
2. Los idioms KQL (`TimeGenerated|SecurityEvent|SigninLogs|
   DeviceProcessEvents|summarize|project |\| where |let `) sobre
   `platform/mcp/src/*.ts` → 6 archivos; 4 de ellos no estaban ya en (1):
   `server.ts`, `tools/node/enrich.ts`, `tools/ingest/invariants_hypothetical.ts`,
   `lib/api-client.ts`.
3. `kql` (case-insensitive) directo sobre los 5 archivos ya verificados en el
   spec §1 (`sentinel/query.ts`, `graph/{propose,build,path,neighbors}.ts`) —
   los 5 ya estaban cubiertos por (1).

Universo total: **55 archivos** (51 + 4). `crates/sentinel-sidecar-client`
se verificó aparte (0 coincidencias de `kql` en todo el directorio) — consistente
con S6, que documenta que ese crate no tiene `Cargo.toml` ni `src/` propio.

Cada archivo del universo aparece abajo como fila de tabla (función/símbolo
con genera/ejecuta real) o como exclusión justificada (comentario, tipo
espejo sin lógica, falso positivo del patrón, o test).

### Tabla exhaustiva — motor de grafos (`core/graph-engine`)

| Función/símbolo | Archivo:línea | Genera o ejecuta | Propósito | Destino Fase A |
|---|---|---|---|---|
| `kql_escape` | `core/graph-engine/src/sentinel.rs:1281` | Genera — escapa `"`/`\` para interpolar un valor en un literal KQL | Recolección (sanitización de entrada, no semántica) | Conector |
| `build_hydration_kql` | `core/graph-engine/src/sentinel.rs:1294-1310` | Genera `"{table} | {time_filter} | {col1==v or col2==v...} | take {take}"` | Recolección: selección de tabla + filtro de tiempo (precondición: `time_filter` debe empezar con `where`, línea 1291) + predicado de columna + paginación (`take`). Sin `join`/`summarize`. | Conector — es la primitiva de hidratación on-demand que usa `platform/api/src/operations/sentinel.rs:1023` |

**Archivos de `core/graph-engine` sin fila propia (excluidos con motivo):**

| Archivo | Motivo de exclusión |
|---|---|
| `core/graph-engine/src/analytics.rs:2276` | Comentario de doc sobre `find_paths` ("chains that in KQL would need repeated joins are one precomputed walk here") — comparación de prosa, no genera/ejecuta KQL |
| `core/graph-engine/src/watermark_store.rs:20,96` | Comentarios de doc: `:20` sobre el formato `last_timestamp` ("ISO-8601 for KQL"), `:96` sobre `WatermarkKey` ("KQL sources leave it empty"); ninguno genera ni ejecuta KQL |

### Tabla exhaustiva — transporte Sentinel (`platform/siem`, `platform/sources`)

| Función/símbolo | Archivo:línea | Genera o ejecuta | Propósito | Destino Fase A |
|---|---|---|---|---|
| `run_sentinel_query` (query por defecto) | `platform/siem/src/sentinel_streaming.rs:69-90` | Ejecuta `"SecurityEvent | where TimeGenerated > ago(24h) | take 10000"` cuando `query` viene vacía | Recolección — tabla fija + ventana de tiempo + `take` | Conector — transporte HTTP síncrono del camino ad-hoc (S6 fila 2) |
| `KqlQueryBuilder::build` | `platform/siem/src/sentinel.rs:223-253` | Genera `"{table} | {where TimeGenerated ...} | order by TimeGenerated asc | take {batch_size}"`; resuelve el filtro de tiempo por prioridad watermark > `initial_time_window_filter` > `ago(24h)` (comentario `:228-233`) | Recolección — es el corazón del polling en vivo: tabla + watermark + `order by` + `take`. Sin `join`/`summarize` (confirmado en tests `sentinel.rs:363-405`). | Conector — llamado desde `platform/api/src/sentinel_connector.rs:221` (ver fila siguiente); éste es el mecanismo real detrás de S6 |
| `platform/siem/src/lib.rs` | `lib.rs:12` | Ninguno — solo reexporta `HttpSentinelTransport, KqlQueryBuilder, SentinelPollingConfig, SentinelTokenCache` | N/A | Exclusión: archivo de reexport, sin lógica propia |
| `LogAnalyticsSource::build_scoped_query` / `build_poll_query` / `escape_kql` | `platform/sources/src/log_analytics.rs:188,221,334` | Genera `"{table} | where TimeGenerated between (...)  | order by TimeGenerated asc | take {cap}"` (scoped) y `"{table} | where TimeGenerated > {wm} | order by TimeGenerated asc | take {cap}"` (poll) | Recolección — mismo patrón que `KqlQueryBuilder` pero sobre el trait `HttpClient` en vez de `reqwest` directo | Conector — es la abstracción `LogSource` (Fase 3 del plan de streaming); **S6 ya estableció que no tiene ningún invocador de producción**, solo sus propios tests (`log_analytics.rs:526-796`) — candidata natural al `SourceConnector` de Fase A, pero hoy dormida |
| `DefenderXdrSource::build_scoped_query` / `build_poll_query` / `escape_kql` | `platform/sources/src/defender_xdr.rs:147,172,216` | Mismo patrón que la fila anterior, con `Timestamp` en vez de `TimeGenerated` (comentario `:13-14`, verificado en test `:448` que confirma la ausencia de `TimeGenerated`) | Recolección | Conector — mismo estado que la fila anterior: código real, **no wireado en producción** (S6) |
| `DataLakeV2Source` (stub) | `platform/sources/src/data_lake.rs:4,20,53,98` | Ninguno ejecutable — la doc del módulo dice explícitamente "NOT the full end-to-end KQL v2 impl" (`:4`) y ambos métodos de datos son `SourceError::Fatal` incondicional (per S6, `:92-114`) | N/A (stub) | Conector — reservado para el `KQL v2 REST` endpoint (`:20`), pendiente de implementación real |

**Archivos de `platform/siem`/`platform/sources` sin fila propia (excluidos con motivo):**

| Archivo | Motivo de exclusión |
|---|---|
| `platform/sources/src/lib.rs:62,101,130` | Comentarios de doc del trait `LogSource`: `:62` sobre `SourceKind::DataLakeV2` ("Sentinel Data Lake v2 KQL endpoint"), `:101` sobre `QueryScope` ("KQL \`where\` clause"), `:130` sobre `max_rows_per_table` ("KQL \`take\`"); ninguno genera ni ejecuta KQL — son referencias descriptivas en la definición del trait que un futuro `SourceConnector` implementará |

### Tabla exhaustiva — orquestación (`platform/api`)

Esta es la capa más grande: `platform/api/src/operations/sentinel.rs` concentra
la mayoría del KQL generado/ejecutado del sistema.

| Función/símbolo | Archivo:línea | Genera o ejecuta | Propósito | Destino Fase A |
|---|---|---|---|---|
| `run_kql` | `operations/sentinel.rs:320-533` | Ejecuta **KQL arbitraria** provista por el analista/LLM contra Log Analytics (vía `run_sentinel_query`, `:385-387`) | **Semántica de hipótesis** — el texto es libre; nada impide `join`/`summarize` escritos por quien llama. El único control es el §4.7 fallback gate (`extract_propose_payload`/`kql_graph_advisory`, ver abajo), que bloquea el modo *inspect* si detecta proyección de columnas de tipo entidad, no si detecta agregación | **Escape hatch** — es el endpoint `/kql` completo |
| `apply_time_window_sugar` | `operations/sentinel.rs:1395-1412` | Genera — antepone `where TimeGenerated > ...` al KQL del analista solo si no lo trae ya (idempotente) | Recolección (azúcar sintáctica de ventana de tiempo) | Escape hatch (parte de `run_kql`) |
| `extract_take_limit` | `operations/sentinel.rs:1419-1437` | Ninguno — parsea (no genera) el último `take N` del KQL ya escrito, por regex de posición | Recolección (metadata de paginación para el cap de visualización) | Escape hatch (parte de `run_kql`) |
| `kql_graph_advisory` / `extract_propose_payload` | `operations/sentinel.rs:1991-2029` | Ninguno — heurística de texto sobre el KQL del analista (detecta `project`/columnas de tipo entidad) para decidir el fallback gate §4.7 | Gate de recolección vs. hipótesis: nudge hacia `graph_propose`, no genera KQL nuevo | Escape hatch (parte de `run_kql`) |
| `discover_schema` — `usage_kql` | `operations/sentinel.rs:577-582` | Genera y ejecuta `"Usage | {time_filter} | summarize IngestionMB = sum(Quantity), LastIngested = max(TimeGenerated) by DataType | where IngestionMB >= {min_mb} | order by IngestionMB desc"` | **Caso límite documentado**: usa `summarize`, pero es metadata de descubrimiento de schema (qué tablas existen y cuánto ingresan), no correlación entre entidades — no es semántica de hipótesis de hunt | Conector (discovery), con nota explícita de que usa agregación |
| `discover_schema` — `sample_kql` | `operations/sentinel.rs:616-621` | Genera y ejecuta `"{name} | {time_filter} | take {sample_rows}"` por tabla, para clasificar campos (`classify_table_fields`) | Recolección (muestreo) | Conector |
| `build_proposals` — `materialization_kql` | `operations/sentinel.rs:1839-1844` | Genera `"{table}\n| {time_filter}\n| project {fields}"` | **Recolección deliberada** — comentario explícito `render_hunting_template` (`:2035-2042`, aplica también aquí por diseño): las plantillas materializadoras **no agregan a propósito** para que el motor de grafos, no KQL, haga la correlación | Conector |
| `estimate_probe_kql` | `operations/sentinel.rs:1759-1776` | Genera y ejecuta `"{materialization_kql}\n| summarize Rows = count(), Entities = dcount({anchor})"` | Estimación de costo/tamaño antes de `graph_build` — usa `summarize` pero solo para un conteo agregado de fila/entidad distinta, no para definir relaciones | Conector (probe de costo), con la misma nota de agregación que `usage_kql` |
| `graph_build` (dispatch de `materialization_kql`) | `operations/sentinel.rs:716-746` | Ejecuta el `materialization_kql` de la propuesta aprobada vía `run_kql_rows` | Recolección (ver fila `build_proposals`) | Conector |
| `render_hunting_template` / `run_hunting_template` / `preview_hunting_template` | `operations/sentinel.rs:884-914, 2043-2109` | Genera 4 plantillas fijas (`FailedLogonBurst`, `LateralMovement`, `EncodedPowerShell`, `SuspiciousDns`) con `where`/`project`/`order by`/`take`; ejecuta vía `run_kql` (`:901`) | Recolección deliberada — comentario `:2035-2042`: versiones anteriores usaban `summarize` y se cambiaron explícitamente para no pre-cazar en KQL. **Nota**: `SuspiciousDns` (`:2096`) usa `extend Tld = tolower(extract(@"\.([a-z]+)$", 1, Name))` — una columna derivada (regex + lowercase), sigue siendo proyección de fila, no correlación entre entidades | Conector (plantillas de recolección temática) |
| `hydrate_node_with` / `hydrate_node_filtered_with` (llama `build_hydration_kql`) | `operations/sentinel.rs:924,946,1023` | Ejecuta, por tabla mapeada, el KQL de `build_hydration_kql` (core) | Recolección | Conector |
| `seed_from_ioc_with` / `seed_from_ioc` | `operations/sentinel.rs:1084,1111-1168` | Delega en `hydrate_node_with` | Recolección (cold-start) | Conector |
| `node_enrich` | `operations/sentinel.rs:1173-1241` | Delega en `hydrate_node_filtered_with` con filtro de tablas/`max_rows` | Recolección | Conector |
| `run_kql_rows` / `cap_kql_rows` | `operations/sentinel.rs:1379-1390,1443-1452` | `run_kql_rows` ejecuta un KQL ya construido; `cap_kql_rows` solo trunca filas ya devueltas (JSON), no toca KQL | Recolección / post-proceso, respectivamente | Conector (helpers internos) |
| `expand_node_live` | `operations/graph_ops.rs:646-679` | Genera `time_filter` vía `TimeWindow::kql_filter()` y delega en la hidratación en vivo | Recolección | Conector |
| `TimeWindow::kql_filter` / `as_kql` | `platform/api/src/dto/v1/sentinel.rs:36,62-66` | Genera la cláusula `"where TimeGenerated > ago({lookback})"` o `datetime(...)` | Recolección (DTO compartido por todos los call sites de arriba) | Conector (tipo compartido) |
| `build_kql_ioc_set` | `operations/export.rs:603-...` | Genera un snippet KQL (`let IPs = datatable(...)[...]`) como **formato de exportación** ("paste into an Azure Sentinel hunting query", `:625`) | No es ejecutado por GraphHunter ni define semántica de hipótesis del sistema — es un artefacto de salida para que el analista lo pegue en Sentinel | **Fuera de alcance del conector** — permanece como función de exportación de IOCs, no interactúa con Sentinel |
| polling loop (`KqlQueryBuilder::build` + `execute_query`) | `platform/api/src/sentinel_connector.rs:221-269` | Ejecuta, por tabla configurada, el KQL de `KqlQueryBuilder::build` (siem) | Recolección — confirma el camino sync/polling de S6 | Conector |

**Archivos de `platform/api` sin fila propia (excluidos con motivo):**

| Archivo | Motivo de exclusión |
|---|---|
| `platform/api/src/format_registry.rs:7` | Mención en comentario a `cmd_run_kql`; sin código que genere/ejecute KQL |
| `platform/api/src/dto/v1/graph_ops.rs:180` | Comentario de doc (`/// Time window for the hydration KQL`) sobre un campo `time_window`; el campo en sí es un DTO reenviado, no genera KQL |
| `platform/api/src/dto/v1/geoip.rs:77` | Mensaje advisory textual (`"Raw KQL bypasses GraphHunter's correlated, persistent graph."`) mostrado al analista cuando el grafo está vacío; no genera ni ejecuta KQL |
| `platform/api/src/operations/graph_meta.rs:328` | Comentario de doc sobre `post_graph_overlap` (recibe entidades ya extraídas de un resultado KQL por el llamador MCP); la función no toca KQL |
| `platform/api/src/operations/schema.rs:264` | Entrada de un registro de endpoints (`ep("/export_iocs", ...)`) con texto descriptivo que menciona KQL; es un catálogo de documentación de API, no código que genere/ejecute KQL |

### Tabla exhaustiva — servidor MCP (`platform/mcp/src`)

Todos los tools MCP son clientes HTTP del backend Rust (`ctx.api.post(...)`);
ninguno construye el texto KQL — eso ocurre en `platform/api` (tabla
anterior). Consistente con S10 (el proceso MCP no conoce credenciales
Azure).

| Función/símbolo | Archivo:línea | Genera o ejecuta | Propósito | Destino Fase A |
|---|---|---|---|---|
| `sentinelQuery.execute` | `tools/sentinel/query.ts:34-50` | Reenvía el KQL libre del analista a `POST /kql` (`:44,49`) | **Semántica de hipótesis** — punto de entrada MCP del escape hatch; el texto de `query` (línea 6) es completamente libre | **Escape hatch** |
| `nodeEnrich.execute` | `tools/node/enrich.ts:31-48` | Reenvía `{node_id, tables, lookback, max_rows, dataset}` a `POST /node/enrich` | Recolección (el KQL real se genera en `hydrate_node_filtered_with`, tabla `platform/api`) | Conector (passthrough) |
| `graphPropose.execute` | `tools/graph/propose.ts:28-44` | Reenvía `selected_fields`/`lookback` a `POST /graph/propose`; la descripción (`:31`) menciona "materialization_kql" solo como referencia informativa | Recolección (metadata de propuesta) | Conector (passthrough) |
| `graphBuild.execute` | `tools/graph/build.ts:24-40` | Reenvía `proposal_id`/`lookback`/`enrich`/`merge_mode` a `POST /graph/build` | Recolección | Conector (passthrough) |
| `graphPath.execute` | `tools/graph/path.ts:31-48` | Reenvía `from_entity`/`to_entity`/etc. a `POST /graph/path`; la descripción (`:34`) solo **compara** la traversal con lo que "en KQL necesitaría varios joins" — no genera ni ejecuta KQL | N/A — "Pure graph read — no Sentinel round-trip" (cita textual `:34`) | N/A |
| `graphNeighbors.execute` | `tools/graph/neighbors.ts:28-44` | Reenvía `entity`/`degree`/etc. a `POST /graph/neighbors`; la descripción (`:31`) también compara contra "otra KQL" solo en prosa | N/A — pura lectura de grafo, sin round-trip a Sentinel | N/A |
| `exportTool` (kind=`iocs`, format=`kql_ioc_set`) | `tools/export.ts:6-16` | Reenvía `kind`/`format` (incluye la opción de string `'kql_ioc_set'`, línea 15) al backend; no genera el snippet KQL en TS | Recolección/exportación (ver `build_kql_ioc_set`) | Conector (passthrough hacia una función fuera de alcance del conector) |
| `composeNudge` (case `sentinel_query`) | `lib/nudge-composer.ts:18-42` | Genera texto de advisory en inglés natural que **menciona** KQL ("Consider node_expand before another KQL", `:36`; "None of this KQL's entities...", `:40`) para orientar al LLM | N/A — nudge textual, no genera/ejecuta KQL | N/A |
| `LONG_TEXT_KEYS` (incluye `"kql"`, `"kql_executed"`) | `lib/content.ts:66-74` | Declara claves de passthrough para que el sanitizador de respuestas MCP no trunque el eco del KQL ya ejecutado | N/A — infraestructura de sanitización, no genera/ejecuta | N/A (queda con el MCP, no forma parte del conector) |

**Archivos de `platform/mcp/src` sin fila propia (excluidos con motivo):**

| Archivo | Motivo de exclusión |
|---|---|
| `platform/mcp/src/lib/metrics.ts:4` | Comentario: contrasta "GraphHunter como grafo" vs. "proxy delgado sobre Sentinel KQL"; solo cuenta métricas de uso de tools, no toca KQL |
| `platform/mcp/src/resources/graph-recent-pivots.ts:14` | Comentario de doc sobre el cap de filas de "resultados KQL enormes"; el recurso solo expone pivots pendientes de expandir, no genera/ejecuta KQL |
| `platform/mcp/src/lib/entity-extractor.ts:14` | Comentario: "prefer expanding them over generating a fresh KQL"; la función extrae entidades de texto, no construye KQL |
| `platform/mcp/src/server.ts:15,53` | Falso positivo del patrón `let ` (declaraciones genéricas `let requestCounter`, `let parsedInput`); no relacionado con KQL |
| `platform/mcp/src/lib/api-client.ts:74,129` | Falso positivo del patrón `let ` (`let res: Response`); no relacionado con KQL |
| `platform/mcp/src/tools/ingest/invariants_hypothetical.ts:27` | Falso positivo de la palabra inglesa "project" ("project the resulting triples"); no es la keyword KQL `project` |
| `platform/mcp/tests/contract/journal-registered.test.ts:65,96` | Test — fixture con `kql: "SecurityEvent | take 10"` para verificar el registro del journal |
| `platform/mcp/tests/content.test.ts:25,33` | Test — verifica que `kql_executed` sobrevive el passthrough de `LONG_TEXT_KEYS` |

### Tabla exhaustiva — Tauri (`apps/tauri/src-tauri`, `apps/tauri/src`)

| Función/símbolo | Archivo:línea | Genera o ejecuta | Propósito | Destino Fase A |
|---|---|---|---|---|
| `handler_run_kql` | `http/siem.rs:42-71` | Delega en `api.run_kql(...)` (`:48-59`) tras un timeout de 120s | Recolección de plumbing — delegación pura al escape hatch | Escape hatch |
| ruta `/kql` | `http/mod.rs:405-406` | Registra `handler_run_kql` en el router Axum | N/A (routing) | Escape hatch (parte del server HTTP local) |
| `handler_expand` | `http/journal.rs:169-246` | Re-ejecuta vía `api.run_kql` el KQL **ya almacenado** de un hunt (`:180-210`), luego filtra localmente por valor con `filter_rows` (no-KQL, `:232`) | Recolección (replay de una query ya aprobada; el filtrado post-hoc es Rust puro, no KQL) | Escape hatch (mismo mecanismo que `run_kql`, capa de journal) |
| `cmd_run_kql` | `commands/sentinel.rs:69-74` | Delega en `api.run_kql(params)` | Recolección de plumbing | Escape hatch |
| `cmd_run_hunting_template` | `commands/sentinel.rs:87-94` | Delega en `api.run_hunting_template(params)` | Recolección (plantilla fija) | Conector |
| `cmd_preview_hunting_template` | `commands/sentinel.rs:100-104` | Delega en `preview_hunting_template` (Rust) para renderizar sin ejecutar — alimenta el toggle "ver KQL" | Recolección (solo render, sin round-trip) | Conector |
| `cmd_export_iocs` | `commands/export.rs:78-84` | Delega en `api.export_iocs(...)` (incluye el formato `kql_ioc_set` → `build_kql_ioc_set`) | Ver fila `build_kql_ioc_set` | Fuera de alcance del conector |
| `summarize_query` / `aggregate_columns` | `journal/summarize.rs:202-236,255-...` | Ninguno — agrega/post-procesa **filas ya devueltas** por `/kql` (JSON ya materializado) para compactar la entrada del journal (distribución de valores por columna) | No es KQL: es agregación en Rust sobre datos ya recolectados, para compactación de contexto LLM, no para definir hipótesis del hunt | N/A — vive en la capa de journal/observabilidad, no en el conector |
| `classify_kind` (case `"/kql"` → `"query"`) | `journal/interpret.rs:5-31` | Ninguno — clasifica el endpoint por prefijo de path | N/A (routing/plumbing del journal) | N/A |
| `AdhocKqlSection` + toggle "ver KQL" | `apps/tauri/src/components/ingest/SentinelConnectForm.tsx:417-577,807-873` | UI: un `<textarea>` (`:847-849`) donde el analista escribe KQL libre (placeholder de ejemplo `:849` incluye `where EventID == 4625`); el toggle "ver KQL" (`:552,572-577`) invoca `cmd_preview_hunting_template` (`:443-453`) | **Semántica de hipótesis** en el textarea libre (superficie de entrada sin restricción); recolección en el toggle de preview (solo muestra la plantilla ya renderizada) | Escape hatch (textarea) / Conector (preview de plantilla) |
| `runAdhocKql` | `apps/tauri/src/components/DatasetsLeftPanel.tsx:394-433` | Invoca el comando Tauri `cmd_run_kql` (`:400-409`) con el texto libre del analista | **Semántica de hipótesis** — es el disparador frontend del escape hatch | Escape hatch |
| invocación de `cmd_run_hunting_template` | `apps/tauri/src/components/DatasetsLeftPanel.tsx:450-480` | Invoca la plantilla predefinida y actualiza `lastKqlSummary` | Recolección | Conector |
| `KqlPreview` | `apps/tauri/src/components/ActivityLogLeftPanel.tsx:10-58` | Muestra/copia el KQL ya ejecutado en el log de actividad (solo lectura) | N/A — observabilidad | N/A |
| listener `"kql-executed"` | `apps/tauri/src/hooks/useSentinelEvents.ts:107-116` | Ninguno — escucha el evento emitido por el backend (`KqlQueryExecutedEvent`) y lo agrega al log | N/A — observabilidad | N/A |
| opción de menú `kql_ioc_set` | `apps/tauri/src/components/ExportMenu.tsx:51` | UI: selecciona el string de formato `"kql_ioc_set"`; no genera KQL | N/A | Fuera de alcance del conector (passthrough) |
| `KqlQueryExecutedEvent` / `KqlResult` (interfaces TS) | `apps/tauri/src/types.ts:718-735` | Tipos espejo del backend, sin lógica | N/A | N/A (tipos) |
| `KqlQueryExecutedEvent` / `KqlResult` (structs Rust) | `apps/tauri/src-tauri/src/types.rs:106-113,117-124` | Tipos espejo, sin lógica | N/A | N/A (tipos) |
| registro del comando `cmd_run_kql` | `apps/tauri/src-tauri/src/lib.rs:360` | Ninguno — registra el comando en el builder de Tauri | N/A | Escape hatch (parte del wiring) |

**Archivos de `apps/tauri` sin fila propia (excluidos con motivo):**

| Archivo | Motivo de exclusión |
|---|---|
| `apps/tauri/src-tauri/src/journal/store.rs:343,349,361` | `"/kql"` aparece solo como endpoint de ejemplo en tests; `JournalStore` es genérico por endpoint, sin lógica específica de KQL |
| `apps/tauri/src-tauri/src/journal/redact.rs:38,49` | `redact_secrets` (`:13-29`) es genérico por clave (`secret`/`token`/`password`); `"kql"` solo aparece como dato de ejemplo en el test `redacts_azure_secret_and_tokenish_keys` |
| `apps/tauri/src-tauri/src/journal/capture.rs:108-238` | `build_event` (`:27`) es genérico por endpoint; todas las coincidencias de `"kql"`/`"/kql"` están dentro de `#[cfg(test)]` |

### Verificación de exhaustividad (Step 3)

Se re-corrió el barrido del Step 1 (comando 1: `kql` case-insensitive sobre
`core/`, `platform/`, `apps/`, `crates/`) más el barrido de idioms sobre
`platform/mcp/src` (comando 2). Reconciliación fila por fila contra las
tablas y exclusiones de arriba:

- **Core (3/3 archivos clasificados):** `analytics.rs:2276` y
  `watermark_store.rs:20,96` son exclusión (comentario), `sentinel.rs` tiene
  2 filas.
- **Platform (30/30 archivos clasificados):** 19 con fila propia (algunas
  con múltiples símbolos, como `operations/sentinel.rs` con 14 filas),
  5 exclusiones documentadas en `platform/api` (`format_registry.rs`,
  `dto/v1/graph_ops.rs`, `dto/v1/geoip.rs`, `operations/graph_meta.rs`,
  `operations/schema.rs`), 3 exclusiones en `platform/mcp` (`metrics.ts`,
  `graph-recent-pivots.ts`, `entity-extractor.ts`), 1 exclusión en
  `platform/sources` (`lib.rs:62,101,130` — comentarios de doc del trait
  `LogSource`; corregido tras revisión, ver nota abajo), 2 exclusiones de
  test (`journal-registered.test.ts`, `content.test.ts`). Total: 19 + 5 + 3
  + 1 + 2 = 30.
- **Apps (18/18 archivos clasificados):** 15 con fila propia, 3 exclusiones
  documentadas (`journal/store.rs`, `journal/redact.rs`, `journal/capture.rs`).
- **Idiom-only del comando 2 (4/4 archivos clasificados):** `node/enrich.ts`
  tiene fila propia; `server.ts`, `lib/api-client.ts` e
  `ingest/invariants_hypothetical.ts` son falsos positivos documentados.
- **`crates/` (0 archivos con KQL, confirmado):** `sentinel-sidecar-client`
  no tiene código fuente propio (S6); no aporta filas ni exclusiones porque
  no hay archivo `.rs`/`.ts` que grepear dentro de él.

**Cero archivos sin clasificar.** Los 55 archivos del universo (51 del
comando 1 + 4 nuevos del comando 2) están o bien en una tabla con al menos
una fila, o bien en una lista de exclusión con motivo explícito.

**Nota de corrección (post-revisión):** una primera versión de esta sección
omitía `platform/sources/src/lib.rs` — el archivo coincide con el barrido
`kql` case-insensitive (comentarios de doc en `:62`, `:101`, `:130` sobre el
trait `LogSource`) pero no tenía fila ni exclusión, dejando el conteo
"30/30" técnicamente incorrecto (29/30 real). Se verificaron las tres líneas
citadas por el revisor (`grep -n`/lectura directa) y se agregó como
exclusión en la tabla de `platform/siem`/`platform/sources`; el conteo de
esta sección ya refleja las 30 filas correctas. También se verificó la cita
de `build_kql_ioc_set`: el texto `"paste into an Azure Sentinel hunting
query"` está en `export.rs:625` (confirmado con `grep -n` y lectura directa
con numeración de línea), no en `:624` como se señaló en la revisión — la
cita original de esta sección (`:625`) era correcta y se deja sin cambios.

### Síntesis: recolección vs. semántica de hipótesis, y destino en Fase A

- **KQL de recolección legítima** (mayoría de las filas): selección de
  tabla, filtro `TimeGenerated`/watermark, `project` de columnas, `order by`,
  `take`/paginación. Ejemplos: `KqlQueryBuilder::build`, `build_hydration_kql`,
  `render_hunting_template`. El comentario de diseño en
  `operations/sentinel.rs:2035-2042` documenta que esto es una decisión
  **deliberada**: versiones anteriores de las plantillas usaban `summarize`
  y se cambiaron explícitamente para no pre-cazar en KQL, dejando la
  correlación al motor de grafos. Destino: **conector**.
- **Casos límite con `summarize` que no son semántica de hipótesis de hunt**:
  `usage_kql` (descubrimiento de volumen por tabla) y `estimate_probe_kql`
  (conteo de costo antes de materializar). Ambos agregan, pero sobre
  metadata operacional (cuántas filas/tablas hay), no sobre relaciones entre
  entidades. Destino: **conector**, con la agregación documentada como
  excepción explícita a la regla de "solo recolección".
- **KQL que sí define semántica de hipótesis (viola la regla)**: únicamente
  el texto libre que el analista escribe en el escape hatch —
  `sentinel_query` (MCP) → `run_kql` (API) → `handler_run_kql`/`cmd_run_kql`
  (Tauri) → `AdhocKqlSection`/`runAdhocKql` (frontend). Nada en el sistema
  restringe ese texto a operadores de recolección; el único gate (§4.7,
  `kql_graph_advisory`/`extract_propose_payload`) detecta proyección de
  columnas de tipo entidad, no agregación o joins. Destino: **escape hatch**
  — se mantiene como vía explícita y logueada (no se elimina, porque el
  propio diseño §4.7 lo declara una salida deliberada), pero debe quedar
  fuera del conector de Fase A y seguir marcado como tal en la UI/MCP.
- **KQL generado como formato de salida, no de consulta**: `build_kql_ioc_set`
  (exporta IOCs como snippet KQL para pegar en Sentinel). No ejecuta contra
  Sentinel ni define hipótesis del sistema. Destino: **fuera de alcance del
  conector** — permanece como función de exportación.
- **Nada calificó para "eliminar"**: no se encontró KQL muerto, no
  alcanzable, o redundante que debiera borrarse sin más — incluso el stub
  `DataLakeV2Source` y las fuentes `LogSource` no wireadas (`log_analytics.rs`,
  `defender_xdr.rs`) son candidatas activas al conector de Fase A, no código
  a eliminar (ver S6 para el estado "no wireado" de esas dos).

## S8. Superficie del servidor MCP

### Metodología

Inventario de código (no ejecución): `platform/mcp/src/tools` (recursivo),
`platform/mcp/src/resources`, y el árbol de registro
(`registry.ts` → `server.ts` → `index.ts`). Los 51 tools listados abajo son
exactamente los que `registry.ts` concatena; se verificó sumando el tamaño
de cada array de namespace (`sessionTools`(1) + `graphTools`(14) +
`nodeTools`(7) + `huntTools`(4) + `catalogTools`(1) + `tagsTools`(1) +
`notesTools`(1) + `journalTools`(1) + `scoresTools`(1) + `reviewTools`(1) +
`ingestTools`(11) + `sentinelTools`(5) + `enrichTools`(1) + `exportTools`(1)
+ `publishTools`(1) = **51**) contra un grep independiente del patrón
`name:\s*"` sobre `platform/mcp/src/tools/**` (también 51 coincidencias,
`platform/mcp/src/tools/sentinel/schema.ts` aporta 2: `schema_discover` y su
alias deprecado `sentinel_schema`). Esta cifra de 51 es consistente con
S10, que ya citó "76 fuentes .ts" para todo `platform/mcp/src` (tools +
resources + lib + entrypoint), verificado de nuevo aquí con
`find platform/mcp/src -name "*.ts" | wc -l` → `76`.

Cross-referencia con S7: la tabla "servidor MCP" de S7
(`sot-integration-assessment.md:1462-1493`) ya estableció que **todos** los
tools MCP son clientes HTTP puros del backend Rust local
(`ctx.api.post/get(...)`, `platform/mcp/src/lib/api-client.ts`) — ninguno
construye texto KQL en TypeScript. La tabla de abajo no repite ese análisis
línea por línea; para cada tool indica el endpoint HTTP invocado y, cuando
ese endpoint ejecuta o genera KQL según S7 o S6, lo señala con "→ ver S7".
El grep de `registerPrompt|server\.prompt|\.prompt\(` sobre
`platform/mcp/src` dio **0 resultados** — el servidor no expone ningún MCP
*prompt*, solo *tools* y *resources* (ver punto 2).

### 1. Tabla completa de tools MCP

Todos invocan `ctx.api.<method>(<path>, ...)` (`platform/mcp/src/lib/api-client.ts`),
es decir HTTP hacia el servidor local de GraphHunter (`http://127.0.0.1:37891`
por defecto, `index.ts:21`) — nunca KQL directo ni una librería de dominio
in-process. La columna "Invoca" cita el path HTTP; "Clasificación" indica si
ese path, aguas abajo, toca KQL (citando la fila de S7 correspondiente) o es
grafo/dominio puro.

**Namespace `session` (`tools/session/`)**

| Tool | Archivo:línea | Invoca | Clasificación |
|---|---|---|---|
| `session_check` | `session/check.ts:5` | `GET /health` (`:14`) | Dominio puro (liveness) |

**Namespace `graph` (`tools/graph/`, 14 tools)**

| Tool | Archivo:línea | Invoca | Clasificación |
|---|---|---|---|
| `graph_summary` | `graph/summary.ts:5` | `GET /graph_summary` (`:14`) | Dominio puro |
| `graph_entity_types` | `graph/entity_types.ts:15` | `GET /entity_type_counts` o `GET /entity_types` (`:24-25`, según `with_counts`) | Dominio puro |
| `graph_relation_schema` | `graph/relation_schema.ts:5` | `GET /relation_schema` (`:14`) | Dominio puro |
| `graph_subnet_analysis` | `graph/subnet_analysis.ts:6` | `GET /subnet_analysis` (`:15`) | Dominio puro (analytics, no Sentinel) |
| `graph_temporal_heatmap` | `graph/temporal_heatmap.ts:16` | `GET /temporal_heatmap` (`:27`) | Dominio puro |
| `graph_datasets` | `graph/datasets.ts:5` | `GET /datasets` (`:14`) | Dominio puro |
| `graph_path_nodes` | `graph/path_nodes.ts:5` | `GET /path_nodes` (`:14`) | Dominio puro |
| `graph_heavy_edges` | `graph/heavy_edges.ts:12` | `GET /heavy_edges` (`:25`) | Dominio puro |
| `graph_channel_behavior` | `graph/channel_behavior.ts:14` | `GET /channel_behavior` (`:29`) | Dominio puro |
| `graph_propose` | `graph/propose.ts:29` | `POST /graph/propose` (`:42`) | **KQL** — genera propuesta de `materialization_kql` → ver S7 fila `build_proposals`/`materialization_kql` (`operations/sentinel.rs:1839-1844`) y fila MCP `graphPropose.execute` (S7:1473) |
| `graph_build` | `graph/build.ts:25` | `POST /graph/build` (`:38`) | **KQL** — ejecuta el `materialization_kql` aprobado → ver S7 fila `graph_build` (`operations/sentinel.rs:716-746`) y fila MCP `graphBuild.execute` (S7:1474) |
| `graph_neighbors` | `graph/neighbors.ts:29` | `POST /graph/neighbors` (`:42`) | Dominio puro — S7 ya cita la descripción del tool (`:31`) como "pura lectura de grafo, sin round-trip a Sentinel" (S7:1476) |
| `graph_path` | `graph/path.ts:32` | `POST /graph/path` (`:46`) | Dominio puro — ídem, "Pure graph read — no Sentinel round-trip" citado en S7:1475 |
| `graph_anomaly` | `graph/anomaly.ts:23` | `POST /graph/anomaly` (`:36`) | Dominio puro (scoring del motor) |

**Namespace `node` (`tools/node/`, 7 tools)**

| Tool | Archivo:línea | Invoca | Clasificación |
|---|---|---|---|
| `node_get` | `node/get.ts:10` | `GET /node_details` (`:19`) | Dominio puro |
| `node_score_explanation` | `node/score_explanation.ts:9` | `GET /explain_score` (`:18`) | Dominio puro |
| `node_search` | `node/search.ts:11` | `GET /search` (`:23`) | Dominio puro |
| `node_expand` | `node/expand.ts:35` | `GET /expand` o `GET /expand_grouped` (`:52`); con `live=true` (solo `mode=raw`) añade `params.live="true"` (`:47-49`) | Mixto: sin `live`, dominio puro; con `live=true` dispara hidratación en vivo — el mismo mecanismo `expand_node_live` de S7 (`operations/graph_ops.rs:646-679`, tabla "orquestación", genera `time_filter` vía `TimeWindow::kql_filter()`). Este archivo no contiene los idioms de KQL que buscó el grep de S7 (por eso no aparece en la tabla MCP de S7), pero el endpoint que invoca sí es KQL de recolección fija, no analista |
| `node_events` | `node/events.ts:32` | `GET /events_for_node` (sin paginar, `:42`) o `GET /events_paginated` (`:50`) | Dominio puro |
| `node_subgraph` | `node/subgraph.ts:42` | `POST /export_subgraph` (`output=file`, `:52-56`) o `POST /subgraph` (`output=inline`, `:59-63`) | Dominio puro |
| `node_enrich` | `node/enrich.ts:32` | `POST /node/enrich` (`:46`) | **KQL** — hidratación filtrada vía `hydrate_node_filtered_with` → S7 fila `nodeEnrich.execute` (S7:1472) y fila `node_enrich` (`operations/sentinel.rs:1173-1241`) |

**Namespace `hunt` (`tools/hunt/`, 4 tools)**

| Tool | Archivo:línea | Invoca | Clasificación |
|---|---|---|---|
| `hunt_parse` | `hunt/parse.ts:13` | `POST /parse_dsl` (`:22`) | Dominio puro (parser DSL) |
| `hunt_run` | `hunt/run.ts:22` | `POST /run_hunt` (`:37`) | Dominio puro — **motor de grafos** (`GraphHunterApi::run_hunt`); ver criterio 25.11 en S9 |
| `hunt_results` | `hunt/results.ts:18` | `GET /hunt_results` (`:32`) | Dominio puro |
| `hunt_diff` | `hunt/diff.ts:15` | `POST /diff_hunts` (`:24`) | Dominio puro |

**Namespace `catalog` (`tools/catalog/`, 1 tool)**

| Tool | Archivo:línea | Invoca | Clasificación |
|---|---|---|---|
| `catalog_get` | `catalog/get.ts:15` | `GET /catalog` o `GET /catalog/status` (`:27`, según `include`), + `GET /catalog/diagnostics` (`:32`, si `include` contiene `diagnostics`) | Dominio puro (catálogo MITRE ATT&CK) |

**Namespace `tags` (`tools/tags/index.ts`, 1 tool compuesto)**

| Tool (op) | Archivo:línea | Invoca | Clasificación |
|---|---|---|---|
| `tags` (op=add) | `tags/index.ts:36,45-48` | `POST /tag` (`:48`) | Dominio puro |
| `tags` (op=remove) | `tags/index.ts:50-53` | `POST /untag` (`:53`) | Dominio puro |
| `tags` (op=list) | `tags/index.ts:55-58` | `GET /tags` (`:58`) | Dominio puro |

**Namespace `notes` (`tools/notes/index.ts`, 1 tool compuesto)**

| Tool (op) | Archivo:línea | Invoca | Clasificación |
|---|---|---|---|
| `notes` (op=add) | `notes/index.ts:20,30-32` | `POST /notes` (`:32`) | Dominio puro |
| `notes` (op=list) | `notes/index.ts:33-34` | `GET /notes/list` (`:34`) | Dominio puro |

**Namespace `journal` (`tools/journal/index.ts`, 1 tool compuesto, 5 ops)**

| Tool (op) | Archivo:línea | Invoca | Clasificación |
|---|---|---|---|
| `journal` (op=start) | `journal/index.ts:49,59-60` | `POST /journal/start` (`:60`) | Dominio puro |
| `journal` (op=list) | `journal/index.ts:62-63` | `GET /journal/list` (`:63`) | Dominio puro |
| `journal` (op=get) | `journal/index.ts:65-68` | `GET /journal/:id` (`:67`) | Dominio puro |
| `journal` (op=stats) | `journal/index.ts:69-72` | `GET /journal/:id/stats` (`:71`) | Dominio puro |
| `journal` (op=expand) | `journal/index.ts:73-77` | `POST /journal/:id/expand` (`:76`) | **KQL, acotado** — el handler (`http/journal.rs:169-246`, ya citado en S7:1500) re-ejecuta vía `api.run_kql` el KQL **ya almacenado** de ese hunt; el body del tool solo lleva `{value, column, limit}` (sin campo KQL), y el filtrado post-resultado es Rust puro (`filter_rows`, `journal.rs:145-162`). No es el analista escribiendo KQL nuevo — ver veredicto §2 abajo |
| `journal` (op=export) | `journal/index.ts:78-94` | `GET /journal/:id` (`:93`, reutiliza el mismo endpoint que op=get y devuelve solo `record.events`) | Dominio puro — el comentario (`:80-92`) documenta por qué el tool NO usa el endpoint separado `POST /journal/export` (streaming NDJSON incompatible con el content layer del MCP) |

**Namespace `scores` (`tools/scores/recompute.ts`, 1 tool)**

| Tool | Archivo:línea | Invoca | Clasificación |
|---|---|---|---|
| `scores_recompute` | `scores/recompute.ts:6` | `POST /compute_scores` (`:15`) | Dominio puro |

**Namespace `review` (`tools/review/index.ts`, 1 tool compuesto)**

| Tool (op) | Archivo:línea | Invoca | Clasificación |
|---|---|---|---|
| `review` (op=approve) | `review/index.ts:27,37-39` | `POST /agentic_review_approve` (`:39`) | Dominio puro (ingesta) |
| `review` (op=reject) | `review/index.ts:41-45` | `POST /agentic_review_reject` (`:45`) | Dominio puro |
| `review` (op=list) | `review/index.ts:47-50` | `POST /agentic_review_list` (`:50`) | Dominio puro |

**Namespace `ingest` (`tools/ingest/`, 11 tools)**

| Tool | Archivo:línea | Invoca | Clasificación |
|---|---|---|---|
| `ingest_negotiate` | `ingest/negotiate.ts:26` | `POST /ingest_negotiate` (`:39`) | Dominio puro |
| `ingest_parser_generate` | `ingest/parser_generate.ts:20` | `POST /parser_generate` (`:32`) | Dominio puro |
| `ingest_canonical_map` | `ingest/canonical_map.ts:15` | `POST /canonical_map` (`:26`) | Dominio puro |
| `ingest_regression_test` | `ingest/regression_test.ts:23` | `POST /mapping_regression_test` (`:34`) | Dominio puro |
| `ingest_invariants_live` | `ingest/invariants_live.ts:16` | `POST /check_invariants` (`:27`) | Dominio puro |
| `ingest_invariants_hypothetical` | `ingest/invariants_hypothetical.ts:25` | `POST /invariant_check_hypothetical` (`:36`) | Dominio puro — S7 marca `:27` de este archivo como falso positivo del grep de KQL (la palabra inglesa "project", no la keyword) |
| `ingest_schema_drift` | `ingest/schema_drift.ts:15` | `POST /schema_drift_detect` (`:26`) | Dominio puro |
| `ingest_dead_letters` (op=list) | `ingest/dead_letters.ts:55,65-71` | `POST /list_dead_letters` (`:71`) | Dominio puro |
| `ingest_dead_letters` (op=purge) | `ingest/dead_letters.ts:73-85` | `POST /purge_dead_letters` (`:85`) | Dominio puro |
| `ingest_dead_letters` (op=retry) | `ingest/dead_letters.ts:87-91` | `POST /reingest_dead_letter` (`:91`) | Dominio puro |
| `ingest_fetch_shared_mappings` | `ingest/fetch_shared_mappings.ts:21` | `POST /fetch_shared_mappings` (`:34`) | Dominio puro |
| `ingest_publish_mapping` | `ingest/publish_mapping.ts:14` | `POST /publish_mapping` (`:25`) | Dominio puro |
| `ingest_pcap_preview` | `ingest/pcap_preview.ts:35` | `POST /pcap_preview` (`:44`) | Dominio puro |

(`ingest/field_config_schema.ts` no es un tool — exporta `fieldConfigSchema`,
un `z.object` compartido por `ingest_negotiate`/`ingest_publish_mapping`/
`ingest_canonical_map`; no tiene `name`/`execute` propios, `field_config_schema.ts:3-6`.)

**Namespace `sentinel` (`tools/sentinel/`, 5 tools)**

| Tool | Archivo:línea | Invoca | Clasificación |
|---|---|---|---|
| `sentinel_seed` | `sentinel/seed.ts:17` | `POST /sentinel/seed` (`:28`) | **KQL** — hidratación cold-start vía `hydrate_node_with`/`seed_from_ioc` → ver S7 fila `nodeEnrich.execute`-análoga `sentinel_seed.execute` (S7:1775-1779, sección S10) y fila `seed_from_ioc_with`/`seed_from_ioc` (`operations/sentinel.rs:1084,1111-1168`) |
| `schema_discover` | `sentinel/schema.ts:51-59` (stability: `experimental`) | `POST /sentinel/schema` (`:48`) | **KQL, caso límite** — dispara `usage_kql`/`sample_kql` (S7: `operations/sentinel.rs:577-582,616-621`), que agregan (`summarize`) pero solo metadata de descubrimiento de tablas, no semántica de hipótesis (documentado así en S7) |
| `sentinel_schema` | `sentinel/schema.ts:64-73` (stability: `deprecated`, alias pre-rename) | mismo `execute`/mismo `POST /sentinel/schema` que `schema_discover` (`:38-48`) | Igual que arriba — alias deprecado, no endpoint distinto |
| `sentinel_query` | `sentinel/query.ts:35` | `POST /kql` (`:49`) | **KQL libre — escape hatch** → S7 fila `sentinelQuery.execute` (S7:1471): reenvía el texto de `query` (línea 6 del input) completamente libre a `run_kql`. Ver veredicto §2 abajo |
| `sentinel_status` | `sentinel/status.ts:7` | `GET /sentinel_status` (`:16`) | Dominio puro (estado del conector, no ejecuta KQL) |

**Namespace `enrich` (`tools/enrich.ts`, 1 tool)**

| Tool | Archivo:línea | Invoca | Clasificación |
|---|---|---|---|
| `enrich` (target_type=ip) | `enrich.ts:18,27-29` | `POST /enrich_ip` (`:29`) | Dominio puro (GeoIP); `target_type` `domain`/`hash`/`url` lanzan `NotImplemented` en TS sin llamar a la API (`:31-33`) |

**Namespace `export` (`tools/export.ts`, 1 tool compuesto)**

| Tool (kind/format) | Archivo:línea | Invoca | Clasificación |
|---|---|---|---|
| `export` (kind=hunt, format=sigma) | `export.ts:59,86-96` | `POST /save_hypothesis_as_sigma` (`:92`) | Dominio puro (compila DSL a Sigma, no toca Sentinel) |
| `export` (kind=hunt, format≠sigma) | `export.ts:97-105` | `POST /export_hunt_results` (`:102`) | Dominio puro |
| `export` (kind=iocs) | `export.ts:107-112` | `POST /export_iocs` (`:110`) | **KQL como formato de salida** cuando `format="kql_ioc_set"` (`export.ts:15`) → S7 fila `exportTool` (S7:1477) y `build_kql_ioc_set` (`operations/export.rs:603`): genera un snippet KQL para pegar en Sentinel, no lo ejecuta — "fuera de alcance del conector" per S7 |
| `export` (kind=ocsf) | `export.ts:113-118` | `POST /export_ocsf` (`:116`) | Dominio puro |

**Namespace `publish` (`tools/publish.ts`, 1 tool compuesto)**

| Tool (target) | Archivo:línea | Invoca | Clasificación |
|---|---|---|---|
| `publish` (target=sentinel_watchlist) | `publish.ts:62,73-84` | `POST /publish_iocs_to_sentinel` (`:84`) | Dominio puro (push de IoCs ya tageados, no genera/ejecuta KQL) |
| `publish` (target=jira\|servicenow) | `publish.ts:86-100` | `POST /file_ticket` (`:100`) | Dominio puro |

**Total: 51 tools** (contando cada `op`/`kind`/`format` de los 8 tools
compuestos — `tags`, `notes`, `journal`, `review`, `ingest_dead_letters`,
`export`, `publish`, `schema_discover`/`sentinel_schema` — como una sola
fila de registro cada uno, que es como los cuenta `registry.ts`).

### 2. Resources y prompts expuestos

**Resources (`platform/mcp/src/resources/`, 3 + 1 agregador):**

| Resource | URI | Archivo:línea | Contenido |
|---|---|---|---|
| Registrador | — | `resources/index.ts:12-20` | `registerResources` llama a los 3 de abajo y devuelve sus URIs; no es un resource propio |
| Resumen de grafo | `graph://summary` | `resources/graph-summary.ts:4-21` | Totales por tipo, fuentes ingeridas con frescura, datasets activos, hunts activos, pivots recientes (`client.getSummary`, timeout 800ms). Descripción explícita: "Read this at the start of any hunting conversation" (`:6-9`) |
| Hunts activos | `graph://active-hunts` | `resources/graph-active-hunts.ts:4-24` | `active_hunts` del mismo `GraphStateClient.getSummary()` — resultados DFS cacheados por ejecución |
| Pivots recientes | `graph://recent-pivots` | `resources/graph-recent-pivots.ts:4-24` | Últimas 20 entidades añadidas vía `sentinel_seed` o expandidas vía `node_expand`; la descripción (`:6-8`) sugiere explícitamente preferir `node_expand` sobre "generating a fresh KQL" para entradas con `expanded=false` |

Los tres comparten el mismo `GraphStateClient` (HTTP hacia el backend local,
mismo patrón que los tools) y degradan a `{error: "graph_summary unavailable"}`
o listas vacías si el timeout de 800ms se agota, sin romper el registro
(`graph-summary.ts:14-16`, `graph-active-hunts.ts:12-13`,
`graph-recent-pivots.ts:12-13`).

**Prompts: ninguno.** Grep `registerPrompt|server\.prompt|\.prompt\(` sobre
todo `platform/mcp/src` → **0 resultados**. El servidor MCP de GraphHunter
expone únicamente `tools` (51) y `resources` (3); no usa la primitiva
`prompts` del protocolo MCP.

### 3. Veredicto por tool contra la regla de diseño (spec §2)

La regla ("Regla principal de diseño",
`docs/superpowers/specs/2026-07-21-sot-integration-design.md:51-61`):

- **La fuente responde:** ¿qué eventos están disponibles?
- **GraphHunter (el motor) responde:** ¿qué significan esos eventos en el
  modelo causal y qué caminos satisfacen una hipótesis?
- **El MCP responde:** ¿qué operaciones del motor debe invocar el agente?
- KQL vive únicamente dentro del conector de Sentinel y solo para
  recolección — nunca para definir la semántica final de una hipótesis
  (`:58-61`).

**Veredicto general (47 de 51 tools cumplen sin matices):** cada tool MCP
de la tabla del punto 1, salvo las tres excepciones abajo, hace exactamente
lo que la regla le asigna al MCP — reenvía un `POST`/`GET` con parámetros
tipados a un endpoint de dominio (`platform/api`), sin decidir él mismo qué
significa el grafo ni construir texto de consulta. Esto es consistente con
la conclusión de S7 (`sot-integration-assessment.md:1464-1467`): "Todos los
tools MCP son clientes HTTP... ninguno construye el texto KQL."

**Violación real de la regla: `sentinel_query`.** Es el único tool cuyo
parámetro de entrada (`query`, `sentinel/query.ts:6`, ya citado en S7:1471)
es texto KQL completamente libre que el analista/LLM redacta y que la
capa de dominio ejecuta casi sin filtrar (S7 ya estableció que el único
gate, `kql_graph_advisory`/`extract_propose_payload`, detecta proyección de
columnas de tipo entidad, no agregación/joins — S7:1433,1591-1593). Esto
permite que, a través del MCP, alguien defina la semántica de una hipótesis
(`join`/`summarize` arbitrarios) **fuera** del motor de grafos — exactamente
lo que la regla prohíbe ("nunca para definir la semántica final de una
hipótesis"). Es una violación conocida y deliberada: el propio diseño la
llama *escape hatch*, la mantiene logueada (journal captura `/kql`,
`http/mod.rs:405-406,419-425`) y S7 ya la marca como "fuera del conector de
Fase A" (S7:1593-1596). No es un hallazgo nuevo; este veredicto lo confirma
desde el ángulo de la superficie MCP.

**Zona gris, no violación: `journal` (op=expand).** Reutiliza el mismo
mecanismo de ejecución (`api.run_kql`, `http/journal.rs:199-210`) pero está
acotado: el tool no acepta un campo de KQL en su input (`journal/index.ts:4-42`,
solo `value`/`column`/`limit`), y re-ejecuta el KQL **ya almacenado y
aprobado** de ese hunt — el filtrado adicional por valor ocurre en Rust
puro (`filter_rows`, `journal.rs:145-162`), no en KQL nuevo. No permite al
agente introducir semántica nueva vía el MCP; hereda la clasificación de
"recolección" del KQL ya ejecutado previamente, no la de hipótesis nueva.

**Sin violación, caso de exportación: `export` (kind=iocs,
format=kql_ioc_set).** Genera un snippet KQL como **artefacto de salida**
para que el analista lo pegue manualmente en Sentinel
(`build_kql_ioc_set`, S7:1449,1477) — nunca se ejecuta contra Sentinel
desde GraphHunter ni define la semántica de ninguna hipótesis del sistema.
Fuera del alcance de la regla (no es una consulta).

**Casos límite de recolección, consistentes con la regla:**
`node_enrich`/`sentinel_seed` (hidratación de forma fija,
`hydrate_node_with`/`hydrate_node_filtered_with`), `graph_propose`/
`graph_build` (materialización deliberadamente sin agregación — nota de
diseño citada en S7:2035-2042/1439), `schema_discover`/`sentinel_schema`
(descubrimiento de metadata de tablas, agregación documentada como
excepción explícita en S7:1437,1581-1586) y `node_expand` con `live=true`
(hidratación en vivo vía `expand_node_live`). Los cinco tocan KQL aguas
abajo, pero siempre KQL de **recolección** (selección de tabla, filtro de
tiempo, proyección, paginación) generado server-side con forma fija — el
MCP nunca decide esa forma, solo pasa parámetros tipados (`lookback`,
`tables`, `max_rows`, etc.), cumpliendo la regla.

**El motor decide, no el MCP: `hunt_run`/`catalog_get`.** `hunt_run` reenvía
la hipótesis DSL del analista a `GraphHunterApi::run_hunt`
(`platform/api/src/operations/hunt.rs:101`) — es el motor, no el MCP ni
KQL, quien decide "qué caminos satisfacen la hipótesis", exactamente el
reparto de responsabilidad que la regla exige. `catalog_get` solo lee un
catálogo de hipótesis pre-construidas (MITRE ATT&CK); no ejecuta ni decide
nada.

## S9. API HTTP y comandos Tauri

### Metodología

Lectura completa de `apps/tauri/src-tauri/src/http/mod.rs` (501 líneas,
router Axum) y `http/journal.rs` (312 líneas). Grep
`invoke_handler|generate_handler` sobre `apps/tauri/src-tauri/src/` → único
resultado en `lib.rs:250` (`invoke_handler(tauri::generate_handler![...])`,
bloque `lib.rs:250-369`). Conteo de comandos Tauri verificado con
`grep -rEn "pub (async )?fn cmd_" apps/tauri/src-tauri/src/commands/ | wc -l`
→ **102**, y con un conteo separado del bloque `generate_handler!` (102
líneas `commands::...` entre `lib.rs:250` y `:369`) — ambos coinciden.
Grep `GraphHunterApi` sobre `platform/api/src/lib.rs`, `platform/mcp/src/`
y `apps/tauri/src-tauri/src/` confirma el patrón de S7/S10: el struct vive
en `platform/api/src/lib.rs:117-119` (comentario `:110-116`: "Cada método es
la única implementación autoritativa de su operación — los transportes no
contienen lógica de negocio"); el MCP nunca lo importa directamente (solo
vía HTTP, `ApiClient`); Tauri lo inyecta como `State<Arc<GraphHunterApi>>`
en 76 sitios de `commands/*.rs` (`grep -n "State<Arc<GraphHunterApi>>" ... | wc -l`).

### 1. Rutas HTTP completas

**Autenticación:** `auth_middleware` (`http/mod.rs:72-105`) exige
`Authorization: Bearer <api_token>` (comparación de tiempo constante,
`subtle::ConstantTimeEq`, `:92-96`) en **todas** las rutas excepto 4,
exentas explícitamente en `mod.rs:81`: **`/`, `/health`, `/metrics`,
`/v1/schema`**. El comentario de código (`:78-80`) documenta por qué
`/metrics` está exento: los scrapers de Prometheus típicamente no envían
bearer tokens, y el server solo escucha en localhost por defecto. Además,
`journal_capture_skips` (`:110-112`) excluye de la captura obligatoria del
journal (no de la auth) a `/`, `/health`, `/metrics` y cualquier ruta que
empiece con `/journal` — para no journalear las propias lecturas del
journal.

`build_app` (`mod.rs:337-445`) registra **86 líneas `.route(...)`**, de las
cuales 4 pares son alias con slash final del mismo handler
(`/subgraph`+`/subgraph/`, `/run_hunt`+`/run_hunt/`, `/notes`+`/notes/`,
`/kql`+`/kql/`) → **82 paths únicos**. Todas las rutas abajo requieren
Bearer salvo las 4 marcadas "NO" en la columna Auth. La columna
"Clasificación" cruza contra S7 cuando el handler toca KQL.

| Método | Path | Handler (módulo) | Auth | Clasificación |
|---|---|---|---|---|
| GET | `/` | `misc::handler_api_root` (`mod.rs:340`) | NO | Infra |
| GET | `/health` | `misc::handler_health` (`:341`) | NO | Infra (usado por `session_check` MCP) |
| GET | `/v1/schema` | `misc::handler_schema` (`:342`) | NO | Infra (schema de la API) |
| GET | `/metrics` | `misc::handler_metrics` (`:418`) | NO | Infra (Prometheus) |
| GET | `/entity_types` | `graph::handler_entity_types` (`:343`) | Sí | Dominio puro |
| GET | `/relation_schema` | `graph::handler_relation_schema` (`:344`) | Sí | Dominio puro (usado por `graph_relation_schema` MCP) |
| GET | `/explain_score` | `hunt::handler_explain_score` (`:345`) | Sí | Dominio puro (usado por `node_score_explanation` MCP) |
| GET | `/search` | `graph::handler_search` (`:346`) | Sí | Dominio puro (usado por `node_search` MCP) |
| GET | `/expand` | `graph::handler_expand` (`:347`) | Sí | Mixto — hidratación en vivo si `live=true` (ver S8, `node_expand`) |
| GET | `/node_details` | `graph::handler_node_details` (`:348`) | Sí | Dominio puro (usado por `node_get` MCP) |
| POST | `/subgraph` (+`/subgraph/`) | `graph::handler_subgraph` (`:349-350`) | Sí | Dominio puro (usado por `node_subgraph` MCP, `output=inline`) |
| GET | `/events_for_node` | `graph::handler_events_for_node` (`:351`) | Sí | Dominio puro (usado por `node_events` MCP) |
| POST | `/run_hunt` (+`/run_hunt/`) | `hunt::handler_run_hunt` (`:352-353`) | Sí | Dominio puro — **motor** (`api.run_hunt`, ver criterio 25.11 abajo); usado por `hunt_run` MCP y `cmd_run_hunt` Tauri |
| GET | `/hunt_results` | `hunt::handler_hunt_results` (`:354`) | Sí | Dominio puro (usado por `hunt_results` MCP) |
| POST | `/diff_hunts` | `hunt::handler_diff_hunts` (`:355`) | Sí | Dominio puro (usado por `hunt_diff` MCP) |
| POST | `/notes` (+`/notes/`) | `notes::handler_create_note` (`:356-357`) | Sí | Dominio puro (usado por `notes` op=add MCP) |
| GET | `/notes/list` | `notes::handler_list_notes` (`:358`) | Sí | Dominio puro (usado por `notes` op=list MCP) |
| GET | `/notes/:id` | `notes::handler_get_note_by_id` (`:359`) | Sí | Dominio puro — **sin consumidor MCP** (solo alcanzable hoy vía la ruta HTTP; el tool `notes` no expone op=get) |
| GET | `/graph_summary` | `graph::handler_graph_summary` (`:360`) | Sí | Dominio puro (usado por `graph_summary` MCP y el resource `graph://summary` vía `GraphStateClient`) |
| GET | `/graph/summary` | `graph_meta::handler_graph_summary` (`:361`) | Sí | Dominio puro — ruta **distinta** de `/graph_summary`; **sin consumidor MCP** identificado (ningún tool de la tabla S8 la invoca) |
| POST | `/graph/overlap` | `graph_meta::handler_graph_overlap` (`:362`) | Sí | Dominio puro — **sin consumidor MCP**; S7 la cita (`operations/graph_meta.rs:328`) como receptora de entidades ya extraídas de un resultado KQL por el llamador, sin tocar KQL ella misma |
| GET | `/entity_type_counts` | `graph::handler_entity_type_counts` (`:363`) | Sí | Dominio puro (usado por `graph_entity_types` MCP, `with_counts=true`) |
| GET | `/temporal_heatmap` | `anomaly::handler_temporal_heatmap` (`:364`) | Sí | Dominio puro (usado por `graph_temporal_heatmap` MCP) |
| GET | `/subnet_analysis` | `anomaly::handler_subnet_analysis` (`:365`) | Sí | Dominio puro (usado por `graph_subnet_analysis` MCP) |
| POST | `/enrich_ip` | `anomaly::handler_enrich_ip` (`:366`) | Sí | Dominio puro (usado por `enrich` MCP) |
| GET | `/catalog` | `catalog::handler_catalog` (`:367`) | Sí | Dominio puro (usado por `catalog_get` MCP, `include=[]`) |
| GET | `/catalog/status` | `catalog::handler_catalog_with_status` (`:368`) | Sí | Dominio puro (usado por `catalog_get` MCP, `include` contiene `status`) |
| GET | `/catalog/diagnostics` | `catalog::handler_catalog_diagnostics` (`:369`) | Sí | Dominio puro (usado por `catalog_get` MCP, `include` contiene `diagnostics`) |
| POST | `/tag` | `tags::handler_tag_entity` (`:370`) | Sí | Dominio puro (usado por `tags` op=add MCP) |
| POST | `/untag` | `tags::handler_untag_entity` (`:371`) | Sí | Dominio puro (usado por `tags` op=remove MCP) |
| GET | `/tags` | `tags::handler_list_tagged` (`:372`) | Sí | Dominio puro (usado por `tags` op=list MCP) |
| POST | `/export_iocs` | `export::handler_export_iocs` (`:373`) | Sí | Ver S8 — `kql_ioc_set` es formato de salida, no ejecución (usado por `export` kind=iocs MCP) |
| POST | `/publish_iocs_to_sentinel` | `export::handler_publish_iocs_to_sentinel` (`:374`) | Sí | Dominio puro (usado por `publish` target=sentinel_watchlist MCP y `cmd_publish_iocs_to_sentinel` Tauri) |
| POST | `/save_hypothesis_as_sigma` | `export::handler_save_hypothesis_as_sigma` (`:375`) | Sí | Dominio puro (usado por `export` kind=hunt,format=sigma MCP y `cmd_save_hypothesis_as_sigma` Tauri) |
| POST | `/file_ticket` | `export::handler_file_ticket` (`:376`) | Sí | Dominio puro (usado por `publish` target=jira\|servicenow MCP y `cmd_file_ticket` Tauri) |
| GET | `/datasets` | `misc::handler_list_datasets` (`:377`) | Sí | Dominio puro (usado por `graph_datasets` MCP) |
| GET | `/path_nodes` | `graph::handler_path_nodes` (`:378`) | Sí | Dominio puro (usado por `graph_path_nodes` MCP) |
| POST | `/export_subgraph` | `export::handler_export_subgraph` (`:379`) | Sí | Dominio puro (usado por `node_subgraph` MCP, `output=file`) |
| POST | `/export_ocsf` | `export::handler_export_ocsf` (`:380`) | Sí | Dominio puro (usado por `export` kind=ocsf MCP) |
| POST | `/check_invariants` | `invariants::handler_check_invariants` (`:381`) | Sí | Dominio puro (usado por `ingest_invariants_live` MCP) |
| POST | `/ingest_negotiate` | `ingest::handler_ingest_negotiate` (`:382`) | Sí | Dominio puro (usado por `ingest_negotiate` MCP) |
| POST | `/pcap_preview` | `ingest::handler_pcap_preview` (`:383`) | Sí | Dominio puro (usado por `ingest_pcap_preview` MCP y `cmd_pcap_preview` Tauri) |
| POST | `/canonical_map` | `ingest::handler_canonical_map` (`:384`) | Sí | Dominio puro (usado por `ingest_canonical_map` MCP) |
| POST | `/parser_generate` | `ingest::handler_parser_generate` (`:385`) | Sí | Dominio puro (usado por `ingest_parser_generate` MCP) |
| POST | `/schema_drift_detect` | `ingest::handler_schema_drift_detect` (`:386`) | Sí | Dominio puro (usado por `ingest_schema_drift` MCP) |
| POST | `/mapping_regression_test` | `ingest::handler_mapping_regression_test` (`:387`) | Sí | Dominio puro (usado por `ingest_regression_test` MCP) |
| POST | `/invariant_check_hypothetical` | `invariants::handler_invariant_check_hypothetical` (`:388`) | Sí | Dominio puro (usado por `ingest_invariants_hypothetical` MCP) |
| POST | `/agentic_review_list` | `agentic::handler_agentic_review_list` (`:389`) | Sí | Dominio puro (usado por `review` op=list MCP) |
| POST | `/agentic_review_approve` | `agentic::handler_agentic_review_approve` (`:390`) | Sí | Dominio puro (usado por `review` op=approve MCP) |
| POST | `/agentic_review_reject` | `agentic::handler_agentic_review_reject` (`:391`) | Sí | Dominio puro (usado por `review` op=reject MCP) |
| POST | `/list_dead_letters` | `dlq::handler_list_dead_letters` (`:392`) | Sí | Dominio puro (usado por `ingest_dead_letters` op=list MCP) |
| POST | `/reingest_dead_letter` | `dlq::handler_reingest_dead_letter` (`:393`) | Sí | Dominio puro (usado por `ingest_dead_letters` op=retry MCP) |
| POST | `/purge_dead_letters` | `dlq::handler_purge_dead_letters` (`:394`) | Sí | Dominio puro (usado por `ingest_dead_letters` op=purge MCP) |
| POST | `/publish_mapping` | `ingest::handler_publish_mapping` (`:395`) | Sí | Dominio puro (usado por `ingest_publish_mapping` MCP) |
| POST | `/fetch_shared_mappings` | `ingest::handler_fetch_shared_mappings` (`:396`) | Sí | Dominio puro (usado por `ingest_fetch_shared_mappings` MCP) |
| POST | `/parse_dsl` | `hunt::handler_parse_dsl` (`:397`) | Sí | Dominio puro (usado por `hunt_parse` MCP y `cmd_parse_dsl` Tauri) |
| GET | `/events_paginated` | `graph::handler_events_paginated` (`:398`) | Sí | Dominio puro (usado por `node_events` MCP, paginado) |
| GET | `/expand_grouped` | `graph::handler_expand_grouped` (`:399`) | Sí | Dominio puro (usado por `node_expand` MCP, `mode=grouped`) |
| GET | `/heavy_edges` | `graph::handler_heavy_edges` (`:400`) | Sí | Dominio puro (usado por `graph_heavy_edges` MCP) |
| GET | `/channel_behavior` | `graph::handler_channel_behavior` (`:401`) | Sí | Dominio puro (usado por `graph_channel_behavior` MCP) |
| POST | `/export_hunt_results` | `export::handler_export_hunt_results` (`:402`) | Sí | Dominio puro (usado por `export` kind=hunt MCP) |
| POST | `/enable_anomaly_scoring` | `anomaly::handler_enable_anomaly_scoring` (`:403`) | Sí | Dominio puro — **sin consumidor MCP**; `hunt_run.ts:24` documenta explícitamente que este "latch" quedó reemplazado por el parámetro `scoring` per-call, "no longer load-bearing" |
| POST | `/compute_scores` | `anomaly::handler_compute_scores` (`:404`) | Sí | Dominio puro (usado por `scores_recompute` MCP y `cmd_compute_scores` Tauri) |
| POST | `/kql` (+`/kql/`) | `siem::handler_run_kql` (`:405-406`) | Sí | **KQL libre — escape hatch** (S7:1498, `http/siem.rs:42-71`, delega en `api.run_kql`); usado por `sentinel_query` MCP y `cmd_run_kql` Tauri |
| POST | `/node/enrich` | `siem::handler_node_enrich` (`:407`) | Sí | **KQL** de hidratación (usado por `node_enrich` MCP) |
| POST | `/sentinel/seed` | `siem::handler_seed_from_ioc` (`:408`) | Sí | **KQL** de hidratación cold-start (usado por `sentinel_seed` MCP) |
| POST | `/sentinel/schema` | `siem::handler_discover_schema` (`:409`) | Sí | **KQL** de discovery (usado por `schema_discover`/`sentinel_schema` MCP) |
| POST | `/graph/propose` | `siem::handler_graph_propose` (`:410`) | Sí | **KQL** de propuesta de materialización (usado por `graph_propose` MCP) |
| POST | `/graph/build` | `siem::handler_graph_build` (`:411`) | Sí | **KQL** ejecutado (usado por `graph_build` MCP) |
| POST | `/graph/neighbors` | `graph::handler_graph_neighbors` (`:412`) | Sí | Dominio puro — lectura pura de grafo (usado por `graph_neighbors` MCP) |
| POST | `/graph/path` | `graph::handler_graph_path` (`:413`) | Sí | Dominio puro — ídem (usado por `graph_path` MCP) |
| POST | `/graph/anomaly` | `graph::handler_graph_anomaly` (`:414`) | Sí | Dominio puro (usado por `graph_anomaly` MCP) |
| POST | `/sentinel/resume` | `siem::handler_sentinel_resume` (`:415`) | Sí | Dominio puro — **sin consumidor MCP** (solo `cmd_sentinel_resume` Tauri) |
| POST | `/sentinel/pause` | `siem::handler_sentinel_pause` (`:416`) | Sí | Dominio puro — **sin consumidor MCP** (solo `cmd_sentinel_pause` Tauri) |
| GET | `/sentinel_status` | `siem::handler_sentinel_status` (`:417`) | Sí | Dominio puro (usado por `sentinel_status` MCP) |
| POST | `/journal/start` | `journal::handler_start` (`:419`) | Sí | Dominio puro (usado por `journal` op=start MCP) |
| POST | `/journal/close` | `journal::handler_close` (`:420`) | Sí | Dominio puro — **sin consumidor MCP** (el tool `journal` no expone op=close) |
| GET | `/journal/list` | `journal::handler_list` (`:421`) | Sí | Dominio puro (usado por `journal` op=list MCP) |
| POST | `/journal/export` | `journal::handler_export` (`:422`) | Sí | Dominio puro — **sin consumidor MCP** (streaming NDJSON; `journal/index.ts:80-92` documenta por qué el tool usa `/journal/:id` en su lugar) |
| GET | `/journal/:id` | `journal::handler_get` (`:423`) | Sí | Dominio puro (usado por `journal` op=get **y** op=export MCP) |
| GET | `/journal/:id/stats` | `journal::handler_stats` (`:424`) | Sí | Dominio puro (usado por `journal` op=stats MCP) |
| POST | `/journal/:id/expand` | `journal::handler_expand` (`:425`, cuerpo en `journal.rs:169-246`) | Sí | **KQL acotado** — re-ejecuta el KQL ya almacenado del hunt vía `api.run_kql` (`journal.rs:197-210`); usado por `journal` op=expand MCP. Ver veredicto S8 §2 |
| — | (fallback) | `misc::fallback_404` (`:426`) | Sí (auth corre antes del fallback) | Infra |

### 2. Comandos Tauri registrados y su operación `GraphHunterApi`

El bloque `invoke_handler(tauri::generate_handler![...])` (`lib.rs:250-369`)
registra **102 comandos**, uno por función `#[tauri::command]` en
`apps/tauri/src-tauri/src/commands/*.rs` (verificado 1:1 — 85 `pub fn cmd_`
+ 17 `pub async fn cmd_` = 102). La inmensa mayoría delega en un único
método de `GraphHunterApi` (el "façade canónico", `platform/api/src/lib.rs:110-119`);
un pequeño grupo (`perf`, `memory`, `ingest_status`, `azure_streaming_smoke`,
`cmd_preview_hunting_template`) no toca `GraphHunterApi` en absoluto — son
introspección de proceso o renderizado puro. Tabla por archivo:

**`commands/session.rs` (6):** `cmd_create_session`→`api.create_session`(`:26`) · `cmd_list_sessions`→`api.list_sessions()`(`:34`) · `cmd_load_session`(`:43`, async)→`api.load_session`(`:48`) · `cmd_save_session`(`:58`, async)→`api.save_session`(`:63`) · `cmd_delete_session`→`api.delete_session`(`:73`) · `cmd_get_current_session`→`api.get_current_session()`(`:81`).

**`commands/entity.rs` (18):** `cmd_get_entity_types_in_graph`→`api.get_entity_types_in_graph`(`:30`) · `cmd_get_entity_types_for_node_neighbours`→`api.get_entity_types_for_node_neighbours`(`:67`) · `cmd_get_entity_type_counts`→`api.get_entity_type_counts`(`:78`) · `cmd_get_relation_schema`→`api.get_relation_schema`(`:44`) · `cmd_explain_score`→`api.explain_score`(`:55`) · `cmd_get_entities_by_type`→`api.get_entities_by_type`(`:87`) · `cmd_get_entities_by_type_paginated`→`api.get_entities_by_type_paginated`(`:101`) · `cmd_get_node_ids_by_relation_type`→`api.get_node_ids_by_relation_type`(`:115`) · `cmd_get_path_nodes`→`api.get_path_nodes`(`:128`) · `cmd_add_path_node`→`api.add_path_node`(`:137`) · `cmd_remove_path_node`→`api.remove_path_node`(`:149`) · `cmd_get_notes`→`api.get_notes`(`:160`) · `cmd_create_note`→`api.create_note`(`:173`) · `cmd_update_note`→`api.update_note`(`:187`) · `cmd_delete_note`→`api.delete_note`(`:200`) · `cmd_tag_entity`→`api.tag_entity`(`:219`) · `cmd_untag_entity`→`api.untag_entity`(`:237`) · `cmd_list_tagged`→`api.list_tagged`(`:250`).

**`commands/ingestion.rs` (5):** `cmd_preview_ingest`→`api.preview_ingest`(`:27`) · `cmd_pcap_preview`→`api.pcap_preview`(`:42`) · `cmd_load_data`→`api.load_data`(`:54`) · `cmd_load_data_streaming`→`api.load_data_streaming`(`:92`) · `cmd_ingest_siem`(async)→`api.ingest_siem`(`:69`).

**`commands/dataset.rs` (4):** `cmd_list_datasets`→`api.list_datasets`(`:20`) · `cmd_remove_dataset`→`api.remove_dataset`(`:31`) · `cmd_rename_type_in_dataset`→`api.rename_type_in_dataset`(`:47`) · `cmd_dataset_entity_types`→`api.dataset_entity_types`(`:61`).

**`commands/graph_ops.rs` (17):** `cmd_get_graph_stats`→`api.get_graph_stats`(`:34`) · `cmd_run_hunt`→`api.run_hunt`(`:49-62`, ver criterio 25.11 abajo) · `cmd_run_hunt_batch`→`api.run_hunt_batch`(`:92`) · `cmd_get_hunt_page`→`api.get_hunt_page`(`:110`) · `cmd_diff_hunts`→`api.diff_hunts`(`:139`) · `cmd_get_subgraph`→`api.get_subgraph`(`:189`) · `cmd_search_entities`→`api.search_entities`(`:208`) · `cmd_expand_node`(async)→`api.expand_node_live`/`api.expand_node`(`:243,245`, según `live`) · `cmd_get_node_details`→`api.get_node_details`(`:283`) · `cmd_get_graph_summary`→`api.get_graph_summary`(`:296`) · `cmd_compute_scores`→`api.compute_scores`(`:307`) · `cmd_get_events_for_node`→`api.get_events_for_node`(`:155`) · `cmd_get_events_paginated`→`api.get_events_paginated`(`:171`) · `cmd_expand_node_grouped`→`api.expand_node_grouped`(`:260`) · `cmd_get_simd_isa`→`api.runtime_info().simd_isa`(`:342`) · `cmd_preview_fields`→`api.preview_fields`(`:318`) · `cmd_load_data_with_config`→`api.load_data_with_config`(`:330`).

**`commands/dsl.rs` (5):** `cmd_parse_dsl`→`api.parse_dsl`(`:65`) · `cmd_get_catalog`→`api.get_catalog()`(`:73`) · `cmd_get_catalog_with_status`→`api.get_catalog_with_status`(`:84`) · `cmd_get_catalog_diagnostics`→`api.get_catalog_diagnostics()`(`:93`) · `cmd_load_catalog_hypothesis`→`api.load_catalog_hypothesis`(`:102`).

**`commands/ai_commands.rs` (9):** `cmd_ai_check_config`→`api.ai_check_config()`(`:25`) · `cmd_ai_set_key`→`api.ai_set_key`(`:33`) · `cmd_ai_set_provider`→`api.ai_set_provider`(`:45`) · `cmd_ai_propose_hypothesis`(async, `:56`) · `cmd_ai_analyze_graph`(async)→`api.ai_analyze_graph`(`:79`) · `cmd_ai_analyze_graph_conversation`(async)→`api.ai_analyze_graph_conversation`(`:98`) · `cmd_ai_chat`(async)→`api.ai_chat`(`:115`) · `cmd_ai_clear_conversation`→`api.ai_clear_conversation`(`:126`) · `cmd_ai_get_conversation`→`api.ai_get_conversation`(`:135`).

**`commands/analytics.rs` (13):** `cmd_get_temporal_heatmap`→`api.get_temporal_heatmap`(`:36`) · `cmd_get_timeline_data`→`api.get_timeline_data`(`:50`) · `cmd_compute_betweenness`→`api.compute_betweenness`(`:62`) · `cmd_compute_pagerank`→`api.compute_pagerank`(`:78`) · `cmd_compute_composite_scores`→`api.compute_composite_scores`(`:99`) · `cmd_compact`→`api.compact`(`:115`) · `cmd_test_http_api`→`api.test_http_api()`(`:128`) · `cmd_enable_anomaly_scoring`→`api.enable_anomaly_scoring`(`:139`) · `cmd_update_anomaly_weights`→`api.update_anomaly_weights`(`:152`) · `cmd_get_anomaly_config`→`api.get_anomaly_config`(`:164`) · `cmd_load_gnn_model`→`api.load_gnn_model`(`:177`) · `cmd_compute_gnn_scores`→`api.compute_gnn_scores`(`:188`) · `cmd_gnn_model_status`→`api.gnn_model_status()`(`:198`).

**`commands/export.rs` (4):** `cmd_export_subgraph`→`api.export_subgraph`(`:26`) · `cmd_export_hunt_results`→`api.export_hunt_results`(`:45`) · `cmd_export_iocs`→`api.export_iocs`(`:84`) · `cmd_export_ocsf`→`api.export_ocsf`(`:66`).

**`commands/invariants.rs` (1):** `cmd_check_invariants`→`api.check_invariants`(`:19`).

**`commands/sentinel_publish.rs` (1):** `cmd_publish_iocs_to_sentinel`(async)→`api.publish_iocs_to_sentinel`(`:32`).

**`commands/sigma_save.rs` (1):** `cmd_save_hypothesis_as_sigma`→`api.save_hypothesis_as_sigma`(`:27`).

**`commands/ticket_file.rs` (1):** `cmd_file_ticket`(async)→`api.file_ticket`(`:31`).

**`commands/perf.rs` (1):** `cmd_get_perf_status`(`perf.rs:54`) → **sin `GraphHunterApi`** (no toma `api: State<...>`; lee flags de proceso).

**`commands/ingest_status.rs` (3):** `cmd_get_ingest_engine_status`(`:60`) → **sin `GraphHunterApi`** · `cmd_debug_emit_synthetic_llm_proposal`(`:257`) → **sin `GraphHunterApi`** (usa `tauri::AppHandle` para emitir eventos sintéticos) · `cmd_request_llm_proposal`(async, `:130`) → toma `api: State<Arc<GraphHunterApi>>` pero orquesta directamente `negotiate_field_config`/`default_backend` (`platform/api/operations/negotiation`, `local_llm`) en vez de llamar a un único método `GraphHunterApi::*`.

**`commands/memory.rs` (1):** `cmd_get_memory_status`(`memory.rs:54`) → **sin `GraphHunterApi`** (telemetría de memoria del proceso).

**`commands/azure_streaming_smoke.rs` (1):** `cmd_azure_streaming_smoke_test`(async, `:172`) → **sin `GraphHunterApi`** (smoke test del plan de streaming, marcado `#[allow(deprecated)]` en su registro, `lib.rs:364-365`).

**`commands/enrichment.rs` (2):** `cmd_enrich_ip`(async)→`api.enrich_ip`(`:24`) · `cmd_get_subnet_analysis`→`api.get_subnet_analysis`(`:34`).

**`commands/sentinel.rs` (9):** `cmd_sentinel_connect`(async, `:29`)→`api.sentinel_connect`(`:33`) · `cmd_sentinel_disconnect`(async, `:40`)→`api.sentinel_disconnect()`(`:43`) · `cmd_sentinel_status`→`api.sentinel_status()`(`:51`) · `cmd_sentinel_resume`→`api.sentinel_resume()`(`:57`) · `cmd_sentinel_pause`→`api.sentinel_pause()`(`:63`) · `cmd_sentinel_check_env`→`api.sentinel_check_env()`(`:80`) · `cmd_run_kql`(async, `:69`)→`api.run_kql`(`:73`) · `cmd_run_hunting_template`(async, `:87`)→`api.run_hunting_template`(`:91`) · `cmd_preview_hunting_template`(`:100-108`) → **sin `GraphHunterApi`**: llama directo a la función libre `preview_hunting_template(template, &window)` (Rust, sin `api: State<...>` en la firma), coherente con S7 (`operations/sentinel.rs:2043-2109`, `cmd_preview_hunting_template` en S7:1503).

**Reconciliación del conteo:** por archivo, 6 (`session`) + 18 (`entity`) +
5 (`ingestion`) + 4 (`dataset`) + 17 (`graph_ops`) + 5 (`dsl`) + 9
(`ai_commands`) + 13 (`analytics`) + 4 (`export`) + 1 (`invariants`) + 1
(`sentinel_publish`) + 1 (`sigma_save`) + 1 (`ticket_file`) + 1 (`perf`) +
3 (`ingest_status`) + 1 (`memory`) + 1 (`azure_streaming_smoke`) + 2
(`enrichment`) + 9 (`sentinel`) = **102**, igual al total registrado en
`lib.rs:252-368`. De esos 102: **95** delegan en una única llamada
`api.<método>(...)` claramente identificada arriba; **6** no tocan
`GraphHunterApi` en absoluto (`cmd_get_perf_status`,
`cmd_get_ingest_engine_status`, `cmd_debug_emit_synthetic_llm_proposal`,
`cmd_get_memory_status`, `cmd_azure_streaming_smoke_test`,
`cmd_preview_hunting_template`); y **1** (`cmd_request_llm_proposal`) sí
recibe `State<Arc<GraphHunterApi>>` pero orquesta directamente varias
piezas de más bajo nivel (`negotiate_field_config`, `default_backend`) en
vez de delegar en un único método de la fachada — 95 + 6 + 1 = 102.

### 3. Criterio 25.11 — ¿invocan frontend y MCP el mismo código del core para hipótesis?

**Respuesta: SÍ**, con evidencia directa de ambas rutas de código:

1. **Ruta frontend:** `apps/tauri/src/components/HypothesisBuilder.tsx:213`
   invoca `invoke<HuntResults>("cmd_run_hunt", ...)`, que Tauri despacha a
   `cmd_run_hunt` (`apps/tauri/src-tauri/src/commands/graph_ops.rs:42-67`).
   Ese comando parsea el JSON de la hipótesis y llama
   `api.run_hunt(RunHuntRequest { session: None, hypothesis, time_window,
   max_results: Some(10_000), scoring: None, dedup_mode: None })`
   (`graph_ops.rs:49-62`).
2. **Ruta MCP:** el tool `hunt_run` (`platform/mcp/src/tools/hunt/run.ts:22-43`)
   reenvía `{hypothesis_dsl, scoring}` a `POST /run_hunt`
   (`run.ts:37-41`), que el router Axum despacha a
   `hunt::handler_run_hunt` (`apps/tauri/src-tauri/src/http/hunt.rs:95-123`).
   Ese handler parsea el DSL (`graph_hunter_core::parse_dsl`, `:100-104`) y
   llama `api_clone.run_hunt(graph_hunter_api::dto::hunt::RunHuntRequest {
   session: None, hypothesis: hypothesis_for_search, time_window: None,
   max_results: Some(10_000), scoring, dedup_mode: None })`
   (`hunt.rs:113-120`).

**Ambas rutas convergen en la misma función:** `GraphHunterApi::run_hunt`
(`platform/api/src/operations/hunt.rs:94,101`, único `impl` del método en
todo el crate — verificado con `grep -n "pub fn run_hunt\b" platform/api/src`
→ una sola coincidencia). No hay dos implementaciones del motor de
búsqueda de hipótesis; hay un solo método autoritativo
(`platform/api/src/lib.rs:114-116`: "Each method is the single
authoritative implementation of its operation — transports contain no
business logic") invocado desde dos transportes distintos (comando Tauri
directo vs. HTTP vía MCP).

**La única diferencia es un campo del request, no el código ejecutado:**
`cmd_run_hunt` siempre pasa `scoring: None` (semántica v1: decide el
scorer *sticky* de la sesión — comentario explícito
`graph_ops.rs:55-58`: "Tauri command keeps v1 semantics — sticky session
scorer decides. The MCP `hunt.run` is the path that exposes the per-call
override"), mientras que `handler_run_hunt` reenvía el `scoring` que trae
el body del tool MCP (`hunt.rs:109,118`, per-call override — ver también
`hunt_run.ts:17`: "Replaces the stateful `enable_anomaly_scoring` latch").
Es una diferencia de **parámetro de invocación**, no de implementación:
mismo dispatcher del planner, mismo motor de grafos, mismo camino de
scoring dentro de `run_hunt` (`operations/hunt.rs:101-133`) para ambos
transportes.

## S10. Errores, reintentos y autenticación

### Metodología

Continuación directa de S6: mismos archivos ya leídos íntegramente
(`sentinel_connector.rs`, `operations/sentinel.rs`, `sentinel_streaming.rs`,
`sentinel.rs`, `platform/sources/src/{lib,log_analytics,defender_xdr,quota,backoff}.rs`),
más `apps/tauri/src-tauri/src/http/siem.rs` completo y los tools MCP
`platform/mcp/src/tools/sentinel/{query,seed}.ts` + `lib/api-client.ts` +
`index.ts`. Grep exhaustivo de credenciales Azure sobre todo
`platform/mcp/src`:

```
grep -rn "azure_tenant_id|azure_client_id|azure_client_secret|workspace_id" platform/mcp/src
  → 0 resultados en las 76 fuentes .ts del servidor MCP
```

### 1. Errores y reintentos: política por fuente

**Hallazgo transversal: hay dos políticas de reintento completamente
separadas y no unificadas — una vieja (wireada) y una nueva (dormida).**

**(A) Camino en vivo wireado — `sentinel_connector.rs::polling_loop`
(`platform/api/src/sentinel_connector.rs:106-373`).** Es el único lugar
del repo donde Sentinel tiene un loop de reintento real ejecutándose en
producción:

- **Backoff:** exponencial manual, no la librería reusable de
  `platform/sources::backoff` (esa es parte de la superficie 2, dormida —
  ver S6). Fórmula (`sentinel_connector.rs:202-205`):
  `base = 2^consecutive_errors.min(8)`, capado en
  `MAX_BACKOFF_SECS = 300` (`:35`), con jitter multiplicativo uniforme en
  `[0.5, 1.0]` (`:204`). `consecutive_errors` se resetea a `0` tras
  **cualquier** poll exitoso de **cualquier** tabla (`:302`), no por
  tabla — un error en una tabla dispara backoff para el ciclo completo del
  conector, no solo para esa tabla.
- **`Retry-After`: NO se honra en el camino en vivo.**
  `HttpSentinelTransport::execute_query` (`sentinel_streaming.rs:122-156`)
  trata cualquier status no-2xx igual: `format!("query failed: {} {}", status, body)`
  (`:147-150`) — un 429 con `Retry-After: 30` produce el mismo string de
  error genérico que un 500 o un 400; no hay ninguna rama que extraiga el
  header. El backoff que sigue (2^n con jitter) es ciego al valor real que
  el servidor pidió esperar.
- **Circuit breaker: solo para auth, no para el resto de errores.**
  `MAX_AUTH_FAILURES = 3` (`:38`) — tras 3 fallos consecutivos
  clasificados como auth (`e.contains("401") || e.contains("403") || e.contains("token")`,
  `:183`), el conector se detiene por completo (`Disconnected`, `:193-195`)
  y exige reconexión manual del analista (`sentinel_connect` de nuevo). Para
  cualquier otro tipo de error (network, schema, 429, 5xx) **no hay
  circuit breaker** — el loop reintenta indefinidamente con el backoff
  exponencial descrito arriba, sin límite de intentos ni de tiempo total.
- **`run_kql`/`discover_schema`/`graph_propose`/`graph_build`/`hydrate_node_*`
  (`operations/sentinel.rs`, camino ad-hoc/one-shot): CERO reintentos.**
  Cada uno hace una única llamada HTTP (vía `run_sentinel_query` en
  `spawn_blocking` para `run_kql`, o `transport.execute_query` para
  hydratación) y, si falla, propaga el error inmediatamente como
  `ApiError::Upstream` (`operations/sentinel.rs:390-393`) o
  `tracing::warn!` sin abortar el resto de tablas (hydratación,
  `:1039,1041,1046,1048`, per-tabla best-effort). No hay backoff, no hay
  `Retry-After`, no hay circuit breaker en este camino — es responsabilidad
  del caller (UI/MCP) decidir si reintentar.
- **Errores hacia DLQ vs pérdida — el camino Sentinel nunca escribe al
  DLQ.** Se grepeó `record_dead_letter`/`record_parse_skips`/`dead_letter`
  sobre `operations/sentinel.rs`: **0 resultados**. Esto es consistente con
  el hallazgo de S5 (`platform/api/src/operations/dlq.rs`, wireado en
  `lib.rs:155-175`): el DLQ solo se alimenta desde los caminos síncronos de
  archivo (`load_data`/`load_data_with_config`, `ingestion.rs:433,755`).
  Para Sentinel, dos clases de pérdida silenciosa distinta: (a) filas que
  el parser no logra convertir a triples — `polling_loop` las detecta
  (`if triples.is_empty()`, `sentinel_connector.rs:244-252`) y emite un
  evento `sentinel-error` a la UI, pero **no las persiste en ningún
  lado** — no hay bytes crudos retenidos, se pierden; (b) fallos de
  `graph.insert_triples` ("Spill store error", `:273-280`) — también solo
  emitido como evento, la porción de filas de esa tabla en ese ciclo de
  poll se pierde (el watermark de esa tabla no avanza si `next_query_start`
  no llegó a computarse, pero las filas ya extraídas del response no se
  reintentan ni se guardan).

**(B) Camino nuevo `LogSource`/`platform/sources` — dormido, no invocado
en producción (ver S6 y S5).** Aquí sí existe una taxonomía de error
disciplinada y honrada:

- `SourceError` (`platform/sources/src/lib.rs:208-236`) distingue `Auth`,
  `Throttled(Duration)`, `Timeout`, `Truncated`, `Schema(String)`,
  `Network(String)`, `Fatal(String)` — siete variantes con semántica de
  reintento documentada en cada doc-comment (`:209-235`).
  `log_analytics.rs::map_http_status_to_source_error` (`:501-510`) y su
  equivalente en `defender_xdr.rs` (`:381-390`) **sí** parsean
  `Retry-After` del response (`resp.retry_after()`,
  `http_client.rs:141-147`, solo forma delta-seconds) y lo empaquetan en
  `SourceError::Throttled(retry_after.unwrap_or(Duration::from_secs(60)))`.
- El `QuotaLimiter` (`platform/sources/src/quota.rs`) es un token-bucket
  por `(source_kind, tenant_id)` con soporte de penalización explícita por
  `Retry-After` (`penalize()`, `:120-134`, extiende pero nunca acorta una
  penalización existente) y quotas documentadas por superficie
  (`quota.rs:8-14`): Log Analytics 200/30s, Defender XDR ~45/60s, Data Lake
  120/60s conservador. **Ninguno de estos límites se aplica hoy al camino
  (A)** — `HttpSentinelTransport`/`run_sentinel_query` no instancian ni
  consultan ningún `QuotaLimiter`; es exclusivo de la superficie 2.
- Métricas: `PollerMetricsSnapshot` (citado en S5, `source_poller.rs:222-232`)
  expone `circuit_state`/`circuit_open_skips`/`consecutive_failures` — pero,
  igual que el resto de la superficie 2, solo alcanzable desde tests.

**Tabla resumen por fuente:**

| Fuente | Camino en producción hoy | Backoff | `Retry-After` | Circuit breaker | DLQ |
|---|---|---|---|---|---|
| Log Analytics (polling en vivo) | `sentinel_connector.rs` | 2^n·jitter, cap 300s, reset global | No honrado (tratado como error genérico) | Solo 3-strike auth | No — pérdida silenciosa (evento UI) |
| Log Analytics (ad-hoc KQL / discover / propose / build / hydrate) | `operations/sentinel.rs` | Ninguno | No aplica (sin retry) | Ninguno | No |
| Defender XDR / Data Lake v2 / Log Analytics (vía `LogSource`) | Ninguno — superficie dormida | N/A (no ejecuta) | Parseado y modelado (`SourceError::Throttled`) pero nunca alcanzado en runtime | N/A | N/A |
| Elasticsearch (`platform/siem/src/elastic.rs`) | `run_elastic_query`, mismo patrón síncrono que `sentinel.rs` | Ninguno (no leído en detalle; mismo `reqwest::blocking` sin retry visible en las líneas revisadas) | No | No | No |

### 2. Autenticación: dónde viven las credenciales, quién las conoce

**Dónde viven.** Cuatro variables `AZURE_*` (`AZURE_TENANT_ID`,
`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_WORKSPACE_ID`) leídas del
entorno de proceso del **host Tauri/Rust** vía `std::env::var` en múltiples
puntos: `platform/siem/src/sentinel.rs:82-85` (fallback de
`run_sentinel_query` cuando no se pasa `auth` explícito),
`operations/sentinel.rs:52-61` (`env_or`, usado por `run_kql`,
`discover_schema`, `graph_build`, `sentinel_connect`) y
`operations/sentinel.rs:85-94` (`resolve_azure_creds`, usado por
`seed_from_ioc`/`node_enrich`, **sin** posibilidad de override explícito —
solo env). No hay keyring ni almacén cifrado de credenciales en ningún
archivo leído — es texto plano en variables de entorno del proceso, más
opcionalmente un archivo `.env` (mencionado en el mensaje de error de
`env_or`, `operations/sentinel.rs:58: "not set in .env"`).

**También se pueden pasar explícitos desde la UI, por request.** Los DTOs
`SentinelConnectRequest`/`RunKqlRequest`/`SchemaDiscoverRequest`/
`GraphProposeRequest`/`GraphBuildRequest` aceptan campos opcionales
`azure_tenant_id`/`azure_client_id`/`azure_client_secret`/`workspace_id`
que, si no están vacíos, **ganan sobre el env var** (`env_or`,
`operations/sentinel.rs:52-61`: `if !explicit.is_empty() { return Ok(explicit) }`).
El HTTP handler correspondiente (`apps/tauri/src-tauri/src/http/siem.rs`)
expone estos mismos campos como `Option<String>` con `#[serde(default)]`
en `RunKqlBody` (`:17-38`), `SchemaDiscoverBody` (`:73-93`),
`GraphProposeBody` (`:127-145`) y `GraphBuildBody` (`:178-195`) — es decir,
la UI del frontend Tauri **sí puede** enviar credenciales explícitas por
request en vez de depender solo del env del proceso. `sentinel_check_env`
(`operations/sentinel.rs:296-314`) existe exactamente para que esa UI
autopueble el formulario, devolviendo el secreto enmascarado
(`azure_client_secret_masked`, `:301-306`) sin exponerlo completo.
**Excepción notable:** `SeedBody` (`http/siem.rs:228-234`) y
`NodeEnrichBody` (`:264-275`) — los endpoints HTTP para `sentinel_seed`/
`node_enrich` — **no tienen ningún campo de credenciales Azure en su
struct**; para esos dos, la única fuente posible es
`resolve_azure_creds()` leyendo el env del proceso host, sin excepción.

**¿El MCP conoce credenciales de Azure? Respuesta: NO — con evidencia
directa, no por ausencia de prueba.**

1. **Grep exhaustivo sobre las 76 fuentes `.ts` del servidor MCP
   (`platform/mcp/src/**`, conteo verificado con
   `find platform/mcp/src -name "*.ts" | wc -l` → `76`) para
   `azure_tenant_id|azure_client_id|azure_client_secret|workspace_id`:
   0 resultados.** Ninguno de los nombres de campo que transportan
   credenciales Azure aparece en ningún archivo del proceso MCP.
2. **El tool `sentinel_query`** (`platform/mcp/src/tools/sentinel/query.ts:43-50`)
   construye el body que envía a `POST /kql` únicamente con
   `{ kql, ingest, lookback, max_rows, dataset, acknowledge_fallback }`
   (`:44-49`) — ningún campo de credencial.
3. **El tool `sentinel_seed`** (`platform/mcp/src/tools/sentinel/seed.ts:26-29`)
   envía `{ entity_type, value, lookback }` a `POST /sentinel/seed` — y,
   como se documentó arriba, ese endpoint HTTP (`SeedBody`) ni siquiera
   tiene un slot para credenciales: aunque el MCP quisiera pasarlas, no
   habría dónde ponerlas.
4. **El único "token" que el cliente HTTP del MCP conoce es el bearer de
   la API local de GraphHunter, no un token de Azure AD.**
   `ApiClientConfig` (`platform/mcp/src/lib/api-client.ts:17-22`) tiene un
   campo `token: string` que `authHeaders()` (`:28-29`) convierte en
   `Authorization: Bearer <token>` — pero ese token autentica al MCP
   **contra el propio servidor HTTP local de GraphHunter**
   (`cfg.baseUrl`, por defecto `http://127.0.0.1:37891`), no contra Azure.
   Confirmado por el origen de ese valor: `platform/mcp/src/index.ts:21-22`
   —
   ```ts
   const API_BASE = process.env.GRAPHHUNTER_API_URL || "http://127.0.0.1:37891";
   const API_TOKEN = process.env.GRAPHHUNTER_API_TOKEN || "";
   ```
   Los únicos env vars que el proceso MCP lee son
   `GRAPHHUNTER_API_URL`/`GRAPHHUNTER_API_TOKEN`/`GRAPHHUNTER_MCP_DEBUG`
   (`:21-24`) y `GH_MCP_ENRICH` (`:47`) — ningún `AZURE_*`.
5. **Conclusión mecánica:** el proceso Node.js del MCP es un cliente HTTP
   puro del backend Tauri/Rust; nunca recibe, construye ni reenvía
   credenciales Azure. Cuando un analista invoca `sentinel_query`/
   `sentinel_seed` desde el MCP, las credenciales que efectivamente se
   usan son las que el **host Rust** ya tiene resueltas de su propio
   entorno de proceso (`AZURE_*` env vars) — el MCP corre en un proceso
   Node separado (paquete npm independiente, S2) sin acceso compartido a
   ese entorno, y su superficie de tool no expone ningún parámetro por el
   cual una credencial Azure podría transitar desde el LLM/MCP hacia el
   backend. Esto responde el criterio de aceptación 25.2 del encargo con
   evidencia directa de código, no por inferencia.

### 3. Throttling: el quota limiter por tenant y sus métricas

`QuotaLimiter` (`platform/sources/src/quota.rs:35-179`) es un token-bucket
con refill fraccional por segundo y penalización explícita:

- **Construcción:** `QuotaLimiter::new(capacity, refill_per_second)`
  (`:59-70`) arranca con el bucket lleno (primeras `capacity` llamadas sin
  espera). Configs documentadas por superficie (`:8-14`, comentario de
  módulo): Log Analytics `(200, 200.0/30.0)`, Defender XDR `(45, 45.0/60.0)`,
  Data Lake v2 `(120, 2.0)` conservador (no hay número oficial de
  Microsoft, es una estimación del propio equipo).
- **`try_acquire`/`acquire`:** no-bloqueante vs. bloqueante
  (`:78-115`) — `acquire()` hace `loop { try_acquire() ... sleep(wait) }`
  hasta obtener token, cancelable por el caller envolviendo en
  `tokio::select!` con un `CancellationToken` (comentario de doc, no
  forzado por el tipo).
- **`penalize(duration)` (`:120-134`):** para cuando el servidor responde
  429 con `Retry-After`. Extiende una penalización existente si la nueva
  es más tardía, nunca la acorta (`:126-129`, test
  `penalize_extends_but_does_not_shrink`), y drena el bucket a `0` al
  aplicar la penalización — "belt-and-suspenders" para no permitir un
  burst apenas expire la ventana (`:130-133`).
- **Métricas expuestas:** `available()` (`:137-142`, cuenta de tokens
  actual, para dashboards) y `penalty_remaining()` (`:146-156`, `Option<Duration>`
  si hay penalización activa). Ambos son getters puros — no hay un
  emisor de eventos/métricas Prometheus-style conectado a ellos en el
  código leído; quedarían disponibles para que un caller los exponga, pero
  ningún caller de producción los consulta (consistente con el punto 1
  arriba: `QuotaLimiter` es exclusivo de la superficie `LogSource`
  dormida).
- **No aplica al camino en producción.** Como ya se estableció en S5 y se
  reafirma en el punto 1 de esta sección: el conector en vivo
  (`sentinel_connector.rs`) y el camino ad-hoc (`operations/sentinel.rs`)
  no instancian ningún `QuotaLimiter` — el único mecanismo de throttling
  que corre hoy contra Azure real es el backoff exponencial genérico del
  polling loop (2A arriba), que reacciona a *cualquier* error de la misma
  forma, no específicamente a 429/quota. En la práctica, esto significa
  que GraphHunter hoy puede exceder la cuota real de Log Analytics (200
  queries/30s) sin que ningún limitador local lo prevenga proactivamente —
  solo reacciona después de que Azure ya devolvió el error.

## S11. Tests existentes (Sentinel, parsers, búsqueda, MCP)
_Pendiente: se completa en la Tarea 8._

## S12. Suposiciones de Azure filtradas al resto del código
_Pendiente: se completa en la Tarea 8._

## S13. Diagrama textual: arquitectura actual
_Pendiente: se completa en la Tarea 9._

## S14. Diagrama textual: arquitectura objetivo
_Pendiente: se completa en la Tarea 9._

## S15. Verificación de la tabla de reconciliación del spec §4
_Pendiente: se completa en la Tarea 9._

## S16. Riesgos y preguntas abiertas para el Bloque 1
_Pendiente: se completa en la Tarea 9._
