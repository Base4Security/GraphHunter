# Session Body Versioning + Fail-Loud

**Fecha:** 2026-06-10
**Estado:** Diseño aprobado — pendiente plan
**Owner:** Lucas
**Relacionado:** continúa el fix del header (`61762b4`, header JSON tolerante). Este cubre la otra mitad: el body.

## 1. Problema

El formato binario de sesiones (`GHS1`) ahora tiene **header JSON v2** (tolerante a evolución
de structs, arreglado en `61762b4`), pero el **body** (arrays de entities/relations) sigue en
**bincode** (`write_entities`/`write_relations` → `bincode::serialize`; `EntityReader`/
`RelationReader` → `bincode::deserialize`). bincode es posicional y no tolera drift de schema.

Consecuencia: cuando cambie el layout de `Entity`, `Relation` o `CompactRelation`, toda sesión
binaria guardada antes va a **listar bien** (el header JSON lee) pero **fallar al cargar** — el
body deserializa mal. Hoy el usuario vería un error críptico (`bincode: io error`) o, peor,
datos basura silenciosos. Es la misma clase de bug que tenía el header, pospuesta al body.

## 2. Objetivo

Que un body incompatible **falle ruidoso con un mensaje accionable** en vez de un error
críptico, y que el formato del body esté **versionado explícitamente** para gatear la carga.
Defensa en dos capas: versión declarada (intención) + mapeo de errores de deserialización
(síntoma), para cubrir el caso de "olvidé bumpear la versión".

### No-objetivos (YAGNI)
- NO migrar/recuperar bodies viejos (declinado por el usuario).
- NO fingerprint automático de structs (se eligió versión manual + red de seguridad).
- NO tocar el formato JSON de sesiones (ya tolerante por serde).
- NO hacer el body self-describing/JSON (perdería el ~5x de tamaño/velocidad que motivó el binario).
- NO carga parcial / best-effort (se eligió hard-fail).

## 3. Decisiones tomadas (no re-debatir)

| Decisión | Valor |
|----------|-------|
| Política ante body incompatible | **hard-fail** con mensaje claro (sin grafo parcial) |
| Detección | **versión manual** (`BODY_FORMAT_VERSION` en header) + **red de seguridad** (mapear errores de deserialización del body a mensaje claro) |
| Default para archivos sin el campo | `1` (no hubo cambio de struct del body entre el fix del header y este) |
| Alcance | solo el body del formato binario; header y JSON-sessions intactos |

## 4. Componentes

### 4.1 Constantes de versión (`platform/api/src/state/session_binary.rs`)
```rust
/// Layout version of the binary BODY (entity/relation bincode arrays).
/// Bump when Entity / Relation / CompactRelation (or anything they
/// serialize) changes in a way that breaks bincode round-trip.
pub const BODY_FORMAT_VERSION: u32 = 1;

/// Oldest body version this build can still deserialize. Raise this when
/// a body change drops backward compatibility with older saved sessions.
pub const MIN_SUPPORTED_BODY_VERSION: u32 = 1;
```
(`FORMAT_VERSION` = 2 sigue siendo la versión del *frame/header*; es independiente del body.)

### 4.2 Campo en el header
En `SessionHeader` (serializado como JSON v2):
```rust
    /// Layout version of the entity/relation body that follows the header.
    /// Absent in files written before body versioning → defaults to 1
    /// (no body struct change occurred between the JSON-header fix and the
    /// introduction of this field).
    #[serde(default = "default_body_format_version")]
    pub body_format_version: u32,
```
con `fn default_body_format_version() -> u32 { 1 }`. `write_header` se llama con un
`SessionHeader` cuyo `body_format_version = BODY_FORMAT_VERSION` (lo setea `save_session_blocking`).

### 4.3 Gate de compatibilidad (helper en `session_binary.rs`)
```rust
/// Returns Ok if a body declaring `version` can be read by this build,
/// else an `IncompatibleBody` error with the actionable bounds.
pub fn check_body_compatible(version: u32) -> Result<(), BinaryError> {
    if version > BODY_FORMAT_VERSION || version < MIN_SUPPORTED_BODY_VERSION {
        return Err(BinaryError::IncompatibleBody {
            found: version,
            min: MIN_SUPPORTED_BODY_VERSION,
            max: BODY_FORMAT_VERSION,
        });
    }
    Ok(())
}
```

### 4.4 Error type
Nueva variante en `BinaryError`:
```rust
    IncompatibleBody { found: u32, min: u32, max: u32 },
```
Display:
- si `found > max`: *"session was saved by a newer GraphHunter build (body format v{found}; this build supports up to v{max}) — update to open it"*
- si `found < min`: *"session was saved with an incompatible older data format (body v{found}; minimum supported v{min}) — it cannot be loaded"*

### 4.5 Aplicación en la carga (`operations/session.rs::load_binary_into_graph`)
Después de `read_header`:
```rust
crate::state::session_binary::check_body_compatible(header.body_format_version)
    .map_err(|e| ApiError::InvalidInput(format!("session '{}': {e}", header.name)))?;
```
Y la **red de seguridad**: el bucle que lee entities/relations (vía `EntityReader`/
`RelationReader`) mapea cualquier `BinaryError::Bincode` (y `Truncated`) a:
```
ApiError::InvalidInput(format!(
    "session '{}' data could not be read — it was likely saved by an incompatible \
     GraphHunter version (body format mismatch): {e}", header.name))
```
en vez de propagar el bincode crudo. (El nombre de la sesión viene del header ya leído.)

## 5. Testing

- **Drift sim (gate, futuro):** construir un archivo cuyo header JSON declare
  `body_format_version = 999`; `load_session_blocking` → `Err(InvalidInput)` cuyo mensaje
  contiene "newer GraphHunter build" y "v999". No panic.
- **Red de seguridad (deserialize falla):** escribir un header v2 válido + un body con un
  record de length-prefix válido pero bytes de payload corruptos → load → `Err(InvalidInput)`
  con el mensaje "could not be read … incompatible … body format mismatch", sin panic.
- **Round-trip:** `save_session_blocking` → `load_session_blocking` de una sesión con
  entidades/relaciones reales: éxito; el header escrito tiene `body_format_version = 1` y se
  relee igual.
- **Default backward-compat:** un header JSON SIN el campo `body_format_version` (simulando un
  archivo escrito entre el fix del header y este) deserializa con `body_format_version == 1`
  y `check_body_compatible` lo acepta.
- `check_body_compatible`: unit test directo de los tres caminos (ok / too-new / too-old —
  el too-old se ejercita pasando `0`).

## 6. Componentes / archivos

| Pieza | Archivo |
|---|---|
| `BODY_FORMAT_VERSION`, `MIN_SUPPORTED_BODY_VERSION`, `check_body_compatible`, `BinaryError::IncompatibleBody`, campo `body_format_version` + default fn | `platform/api/src/state/session_binary.rs` |
| Setear `body_format_version` al guardar | `platform/api/src/operations/session.rs` (`save_session_blocking`, donde construye `SessionHeader`) |
| Gate + red de seguridad al cargar | `platform/api/src/operations/session.rs` (`load_binary_into_graph`) |

## 7. Notas de compatibilidad

- Archivos con header v2 pero sin `body_format_version` → default 1 → cargan (su body ES v1).
- Header v1 (bincode legacy) ya quedó abandonado/borrado; no es objetivo de este spec.
- Cuando se haga un cambio real a `Entity`/`Relation`/`CompactRelation`: bumpear
  `BODY_FORMAT_VERSION` (y, si se rompe compat, `MIN_SUPPORTED_BODY_VERSION`). Las sesiones
  viejas entonces hard-fallan con mensaje claro (comportamiento deseado).

## 8. Out of scope

- Recuperación/migración de bodies de versiones previas.
- Versionado del header (ya es JSON tolerante).
- Cambios al matcher / a los structs Entity/Relation en sí.
