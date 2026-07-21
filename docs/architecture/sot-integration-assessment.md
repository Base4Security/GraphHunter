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
_Pendiente: se completa en la Tarea 5._

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
