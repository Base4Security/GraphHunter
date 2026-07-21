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
_Pendiente: se completa en la Tarea 3._

## S5. Pipeline de ingesta, persistencia y almacenamiento local
_Pendiente: se completa en la Tarea 4._

## S6. Integración Sentinel y sidecar
_Pendiente: se completa en la Tarea 5._

## S7. Inventario exhaustivo de KQL
_Pendiente: se completa en la Tarea 6._

## S8. Superficie del servidor MCP
_Pendiente: se completa en la Tarea 7._

## S9. API HTTP y comandos Tauri
_Pendiente: se completa en la Tarea 7._

## S10. Errores, reintentos y autenticación
_Pendiente: se completa en la Tarea 5._

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
