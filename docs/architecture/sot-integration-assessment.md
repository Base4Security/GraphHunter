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
_Pendiente: se completa en la Tarea 2._

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
