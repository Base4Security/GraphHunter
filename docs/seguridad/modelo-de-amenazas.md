# Modelo de amenazas — Graph Hunter

| | |
|---|---|
| Versión | 1 — 2026-11-03 |
| Método | STRIDE por componente, sobre el código de `chore/baseline-adecuacion` |
| Alcance | App de escritorio (Tauri), API HTTP local, servidor MCP, parsers, sesiones, conectores SIEM, LLM, sidecars |
| Requisito | N3 — modelado de amenazas (política 00, checklist pre-publicación) |
| Revisión | `PENDIENTE:` revisor de seguridad (política 06) — *célula* |

Cada afirmación cita el archivo y la línea donde se verificó. Se actualiza antes
de cada release y cuando cambia un límite de confianza (nueva ruta HTTP, nuevo
tool MCP, nuevo parser, nuevo proveedor externo).

## 1. Qué se protege

| Activo | Dónde vive | Por qué importa |
|---|---|---|
| Logs de clientes ingeridos (SIEM, WAF, VPN, IdP) | Memoria, sesiones, journal, DLQ | Datos de clientes, sensibilidad alta |
| Evidencia de investigaciones (datos personales de terceros) | Igual que arriba | Datos personales, sensibilidad alta |
| Credenciales de Azure/Sentinel, Elastic, Jira, ServiceNow, LLM | Variables de entorno y `.env` | Acceso a los tenants de clientes |
| Token de la API local | Memoria del proceso | Llave de todas las rutas con efectos |
| Integridad de los hallazgos | Grafo, sesiones, journal | Un hallazgo alterado lleva a una decisión equivocada en un incidente |
| Tenant de Sentinel del cliente | Externo | El sistema puede escribir en él (watchlists de IOC) y ejecutar KQL |

## 2. Límites de confianza

```
 Analista ──UI──► WebView (CSP) ──IPC──► Núcleo Tauri ─────────────┐
                                                                   │
 Cliente MCP (LLM) ──stdio──► Servidor MCP ──HTTP+Bearer──► API HTTP local (127.0.0.1:37891)
                                                                   │
 Archivos de log (no confiables) ─────► Parsers ──► Grafo ─────────┤
 Sesiones en %APPDATA% ──────────────► Lector de sesión ───────────┤
                                                                   ├──► Sentinel / Defender / Azure (HTTPS)
                                                                   ├──► Jira / ServiceNow (HTTPS)
                                                                   ├──► Proveedores LLM (HTTPS)
                                                                   └──► Sidecar TPCSA (127.0.0.1:37892, sin auth)
```

Hay dos fronteras que el diseño tiene que tratar como hostiles. La primera es el
**contenido de los logs**: lo produce el atacante que se está investigando. La
segunda es el **LLM** que maneja el MCP: puede seguir instrucciones metidas en ese
contenido.

## 3. Lo que ya está bien

- **Puerto y token de la API.** Escucha en loopback por defecto (`apps/tauri/src-tauri/src/http/mod.rs:591`).
  - El token Bearer es un UUIDv4 por proceso (`lib.rs:89-90`) y se compara en tiempo constante con `subtle` (`http/mod.rs:96-99`).
  - En los logs solo aparece enmascarado (`lib.rs:91-100`).
- **Rutas de archivo por HTTP.** Se rechazan por defecto si no hay `GRAPHHUNTER_INGEST_ROOT` (`platform/api/src/paths.rs:107-124`).
  - Cuando se aceptan, se canonicalizan y se verifica la contención por componentes. Se rechazan UNC, NUL y nombres de dispositivo.
  - La ruta inexistente y la ruta fuera de la raíz devuelven la misma respuesta (`paths.rs:156-243`), así que no sirven para averiguar qué existe.
- **Ids de sesión.** Se restringen a `[A-Za-z0-9_-]` (`platform/api/src/state/persistence.rs:34-54`). No hay ruta para cargar sesiones desde un path arbitrario.
- **Publicaciones externas.** Publicar IOC en Sentinel y abrir tickets exige feature flag más `confirm` (`operations/sentinel_publish.rs:31-37`, `operations/ticket.rs:15-23`).
- **Tauri.** Tiene permisos mínimos: `core:default` y `dialog`, sin fs, shell, http ni updater. La CSP es estricta: `script-src 'self'`.
- **Sin TLS deshabilitado.** No hay código propio que lo desactive y no se encontró telemetría.
- **Secretos.** Solo por entorno. Los tokens de Azure se cachean en memoria (`platform/sources/src/token_cache.rs:116-125`).
- **Journal.** Redacta las claves con nombre de secreto (`journal/redact.rs:3-10`).
- **Sesiones con bincode.** Son bincode con serde, sin `unsafe` ni zero-copy. Un archivo malicioso da a lo sumo DoS o contenido falso, no corrupción de memoria.

## 4. Amenazas

Prioridad: **Alta** = explotable hoy con impacto en datos o en el tenant del
cliente; **Media** = requiere una condición adicional; **Baja** = impacto acotado.

| # | STRIDE | Amenaza | Evidencia | Prioridad | Estado |
|---|---|---|---|---|---|
| T1 | I, T | **Path traversal en el id del journal.** `JournalStore::read` hacía `base.join(id)` sin validar, y el id llega de `GET /journal/:id`, `/stats`, `/expand` y `POST /journal/export`. Con `..` o una ruta absoluta se leen `meta.json`/`events.jsonl` fuera del directorio; `/expand` además re-ejecuta el KQL guardado en esos eventos, por fuera del gate del escape hatch | `apps/tauri/src-tauri/src/journal/store.rs:255-260`, `http/journal.rs:31-33, 70-100` | Alta | **Corregido** en este cambio: mismo criterio que los ids de sesión, con test |
| T2 | E, T, I | **Prompt injection vía logs → tools MCP con efectos.** El contenido de los logs llega al LLM sin delimitar ni marcar como no confiable; `sanitizeApiResponse` solo trunca y deja pasar enteros `command_line`, `raw_sample`, `kql`. El mismo LLM puede invocar KQL crudo, ingest, purga de DLQ, aprobar revisiones y publicar | `platform/mcp/src/lib/content.ts:22-186` | Alta | Abierta → A2, A3 |
| T3 | E | **KQL crudo habilitado por defecto.** `/kql` ejecuta cualquier consulta contra el workspace del cliente salvo que `GRAPHHUNTER_KQL_ESCAPE_HATCH` sea falso; combinado con T2, un log puede inducir consultas arbitrarias con la identidad del analista | `platform/api/src/kql_flags.rs:35-43` | Alta | Abierta → A3 |
| T4 | S, I | **Bind configurable a cualquier interfaz sin aviso.** `GRAPHHUNTER_API_HOST=0.0.0.0` expone la API a la red; con `GRAPHHUNTER_API_TOKEN` fijo (necesario para el MCP), el token deja de ser efímero | `http/mod.rs:591, 617`; `lib.rs:89-90` | Media | Abierta → A4 |
| T5 | I | **CORS `allow_origin(Any)`.** Hoy lo contiene el token Bearer (una página web no lo conoce), pero cualquier fuga del token lo vuelve usable desde cualquier sitio | `http/mod.rs:563-568` | Media | Abierta → A5 |
| T6 | I | **`/metrics` sin autenticación.** Expone métricas de drift | `http/mod.rs:85`, `http/misc.rs:76-88` | Baja | Abierta → A5 |
| T7 | D | **Sesión maliciosa agota memoria.** Longitudes `u32` del archivo se usan directo para `vec![0u8; len]` y el conteo `u64` de entidades para `reserve` sin tope; no hay `Limit` de bincode | `platform/api/src/state/session_binary.rs:282-284, 322-323, 364-365`; `operations/session.rs:480-486` | Media (el archivo tiene que estar en `%APPDATA%`) | Abierta → A6 |
| T8 | D, T | **Parsers sobre datos hostiles.** Lectura entera a memoria y mmap de archivos de hasta 2 GiB por HTTP, sin tope por Tauri; ~260 líneas `unsafe` en el motor (SIMD, `ptr::read`, mmap); evtx, pcap-parser, quick-xml de terceros | `operations/ingestion.rs:535, 1679, 2136`; `core/graph-engine/src/{graph,streaming,simd_rust,index_storage}.rs` | Media | Abierta → A7 |
| T9 | I | **Datos sensibles en disco sin cifrar.** Journal (parámetros de cada request, hasta 5 filas crudas por respuesta), DLQ con `raw_event` completo, sesiones con el grafo entero; la redacción es solo por nombre de clave | `journal/capture.rs:39-71`, `journal/summarize.rs:12-15`, `core/graph-engine/src/dlq/mod.rs:71-83` | Media | Abierta → A8 |
| T10 | S, I | **Sidecar TPCSA sin autenticación** y con `Content-Length` sin tope; host configurable | `sidecar/tpcsa-certify/server.py:70-88` | Media | Abierta → A9 |
| T11 | I | **Clave de Gemini en la query string** (`?key=`): queda en logs de proxies | `platform/api/src/ai.rs:482-487` | Baja | Abierta → A10 |
| T12 | T | **`.env` por búsqueda hacia arriba desde el directorio actual.** El directorio desde el que se lanza la app decide qué credenciales y flags se cargan | `apps/tauri/src-tauri/src/lib.rs:33-51` | Baja | Abierta → A10 |
| T13 | T | **Distribución sin firma.** No hay workflow de release, firma de código ni verificación de integridad; el sidecar .NET tiene binarios sin fuente versionada y la verificación SHA-256 del script de descarga es un stub | `.github/workflows/`, `tauri.conf.json`, `tools/fetch-sidecar-binaries.sh:4-25` | Alta para software distribuido | Abierta → A11 |
| T14 | R | **El journal es el único registro de auditoría y es editable** por cualquier proceso del usuario; no hay encadenamiento ni firma | `journal/store.rs` | Baja | Aceptable en uso local; revisar si se usa como evidencia |

## 5. Acciones

| # | Acción | Cubre | Prioridad |
|---|---|---|---|
| A1 | Validar ids del journal | T1 | Hecho |
| A2 | En el MCP, envolver todo contenido proveniente de logs en un bloque marcado como no confiable, y exigir confirmación humana (no `confirm: true` puesto por el LLM) en los tools con efectos fuera del grafo: KQL, publicar, tickets, purgar DLQ, aprobar revisiones | T2 | Alta |
| A3 | KQL escape hatch **apagado por defecto**; `/journal/:id/expand` sujeto al mismo gate | T2, T3 | Alta |
| A4 | Rechazar un host que no sea loopback salvo con un flag explícito (`GRAPHHUNTER_API_ALLOW_REMOTE=1`) y advertencia al arrancar | T4 | Media |
| A5 | CORS limitado al origen de la WebView; `/metrics` detrás del token | T5, T6 | Media |
| A6 | Topes en el lector de sesión: `hdr_len` y largo de registro máximos, `Limit` de bincode, `reserve` acotado por el tamaño real del archivo | T7 | Media |
| A7 | Fuzzing (`cargo-fuzz`) de los parsers y del lector de sesión; tope de tamaño también en el camino Tauri | T8 | Media |
| A8 | Definir retención del journal y la DLQ, opción de desactivarlos y redacción por valor (no solo por clave) | T9 | Media |
| A9 | Token compartido o socket local para el sidecar; tope de `Content-Length` | T10 | Media |
| A10 | Clave de Gemini por header `x-goog-api-key`; `.env` solo desde el directorio de configuración de la app | T11, T12 | Baja |
| A11 | Workflow de release con firma de binarios (Windows y macOS), checksums publicados y SBOM; fuente del sidecar .NET en el repo o fuera del bundle | T13 | Alta antes de la próxima distribución |

## 6. Lo que no se pudo determinar

- Puerto, autenticación y privilegios del sidecar .NET: no hay fuente en el repo.
- Cómo se generan y firman los binarios distribuidos hoy (probablemente a mano).
- Límite de profundidad de `simd-json` y patrones de regex del extractor de
  entidades del MCP (`platform/mcp/src/lib/entity-extractor.ts`).
- Orden efectivo CORS/auth en el preflight: se infirió del orden de capas, no se
  probó en ejecución.
