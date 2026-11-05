# Regla de proyección: procedencia → grafo de ataque

Estado: borrador v0 · 2026-11-04 · área I+D

Especifica cómo los eventos de telemetría (capa de procedencia, OCSF) crean,
confirman o retiran aristas del grafo de ataque (capa estilo BloodHound). Es el
único componente del estado dinámico G_t que hoy no existe en ningún módulo.
Los demás contratos (esquema OCSF, `GraphDelta`, certificados) se especifican
aparte.

La regla es una función pura y determinista: el mismo evento, con la misma
tabla de identidades, produce siempre los mismos cambios. Eso la hace
reproducible en Rust (motor) y en Python (investigación) contra los mismos
casos de conformidad (`conformidad/proyeccion.json`).

## 1. Las dos capas

| Capa | Qué dice | De dónde sale | Ejemplo de arista |
|---|---|---|---|
| Ataque | "controlar `u` permite adquirir `v`" | snapshot de BloodHound + esta proyección | `HasSession(h → u)` |
| Procedencia | "pasó tal evento en tal momento" | parsers de Graph Hunter (triples → OCSF) | `User -[Auth]-> Host` |

Las aristas de ataque usan la semántica y la dirección de BloodHound:
`HasSession` va del host al usuario (controlar el host da las credenciales del
usuario); `AdminTo` y `CanRDP` van del usuario al host.

## 2. Estado de una arista de ataque

Cada arista de ataque `(src, kind, dst)` lleva:

| Campo | Tipo | Significado |
|---|---|---|
| `origins` | conjunto de `snapshot` / `observed` | quién la sostiene |
| `support` | conjunto de `event_id` | eventos que la sostienen (solo `observed`) |
| `first_seen`, `last_seen` | epoch ms | primera y última evidencia observada |
| `expires_at` | epoch ms o nulo | fin de validez de la evidencia observada (ver §5) |
| `confidence` | `confirmed` / `inferred` | `confirmed` si un evento la muestra ejercida; `inferred` si solo la habilita |

Una arista existe en G_t mientras tenga origen `snapshot`, o tenga origen
`observed` con `support` no vacío y `expires_at` no vencido.

## 3. Salida: `AttackDelta`

La proyección de un evento produce cero o más `AttackDelta`:

| Operación | Efecto |
|---|---|
| `Assert(edge, event_id, confidence, ttl)` | agrega `observed` y `event_id` a `support`; actualiza `last_seen` y `expires_at` |
| `Retract(edge, event_id)` | saca el soporte de las aristas que ese evento sostenía (lo usa un `Tombstone`) |
| `Close(edge, at)` | fija `expires_at = at + grace` (fin de sesión); si no hay sesión observada, no emite nada |
| `Unresolved(reason, event_id)` | el evento aplicaría pero no se pudo resolver una identidad (§6) |

Cada `AttackDelta` se identifica por `(event_id, índice)`. Aplicar dos veces el
mismo es un no-op, igual que `GraphDelta` (`core/graph-engine/src/delta.rs`).
Un envelope `Correction` se trata como `Retract` del evento original más la
proyección del corregido. `Skipped` no proyecta nada.

El oráculo dinámico consume estos deltas: un `Assert` sobre una arista nueva es
una inserción (caso fácil para caminos mínimos); un vencimiento o un `Retract`
que deja la arista sin origen es un borrado (caso difícil).

## 4. Tabla de reglas v0

Notación: `u` usuario, `h` host destino del evento, `lt` = `logon_type_id`
(numeración OCSF, que coincide con la de Windows 4624).

| # | Evento OCSF | Condición | Salida | Confianza | TTL |
|---|---|---|---|---|---|
| R1 | Authentication 3002, LOGON | éxito; `lt` ∈ {2, 10, 11, 12} | `Assert HasSession(h → u)` | confirmed | sesión: hasta `Close` + gracia |
| R2 | Authentication 3002, LOGON | éxito; `lt` = 10 | además `Assert CanRDP(u → h)` | confirmed | largo (permiso, no sesión) |
| R3 | Authentication 3002, LOGON | éxito; `lt` ∈ {4, 5} (batch, servicio) | `Assert HasSession(h → u)` | inferred | sesión |
| R4 | Authentication 3002, LOGON | éxito; `lt` = 9 (NewCredentials) | `Assert HasSession(h → u)` | inferred | sesión |
| R5 | Authentication 3002, LOGON | éxito; `lt` ∈ {3, 8} (red) | nada en v0 | — | — |
| R6 | Authentication 3002, LOGON | fallo | nada | — | — |
| R7 | Authentication 3002, LOGOFF | — | `Close HasSession(h → u)` | — | — |
| R8 | Process Activity 1007, LAUNCH | `actor_user = u` en host `h`; `u` no es cuenta de sistema | `Assert HasSession(h → u)` | inferred | corto |
| R9 | cualquier envelope `Tombstone` | — | `Retract` de lo que proyectó ese `event_id` | — | — |

Decisiones y motivos:

- **R1–R4.** Los logons interactivos, remotos interactivos, cacheados, de
  servicio, batch y NewCredentials dejan material de credenciales en el host;
  por eso equivalen a una sesión de BloodHound. Los dos primeros se observan
  ejercidos (`confirmed`); los otros dependen de la configuración del host
  (`inferred`). *Verificar contra la documentación de Microsoft y contra el
  colector de sesiones de BloodHound antes de la v1.*
- **R5.** Un logon de red (tipo 3) normalmente no deja credenciales
  reutilizables en el host. Es evidencia de `AdminTo` solo si viene con
  privilegios administrativos; eso necesita eventos que hoy no se parsean (§7).
- **R7.** Cerrar sesión no borra de inmediato las credenciales de memoria; por
  eso `Close` aplica una gracia configurable en vez de retirar la arista.
- **R8.** Un proceso corriendo como `u` en `h` implica un token de `u` en `h`.
  Es evidencia más débil que un logon y se excluyen las cuentas de sistema
  (`SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, cuentas de máquina `…$`), mirando
  la cuenta y no el dominio (`NT AUTHORITY\SYSTEM` es `SYSTEM`).

Parámetros (valores por defecto a calibrar, no medidos):

| Parámetro | Defecto | Uso |
|---|---|---|
| `session_grace_ms` | 8 h | gracia tras `Close` |
| `session_ttl_ms` | 24 h | vencimiento de una sesión sin `Close` |
| `process_ttl_ms` | 1 h | vencimiento de R8 |
| `permission_ttl_ms` | 30 d | vencimiento de R2 |

## 5. Tiempo

- El tiempo de una arista observada es el `time` del evento, no el de ingesta.
- Eventos fuera de orden: un `Assert` con `time` anterior a `last_seen` solo
  puede bajar `first_seen`; nunca adelanta `expires_at`. Así el resultado no
  depende del orden de llegada.
- El vencimiento lo dispara la marca de agua del flujo (el máximo `time`
  aplicado), no el reloj de pared. Reprocesar un día histórico da el mismo
  G_t que procesarlo en vivo.

## 6. Resolución de identidades

Es el punto más frágil. Los parsers nombran un usuario como `DOMINIO\usuario`
(NetBIOS) y un host por `Computer` (FQDN o nombre corto); BloodHound usa
`USUARIO@DOMINIO.DNS`, `HOST.DOMINIO.DNS` y SIDs.

Reglas:

1. Si el evento trae SID (`UserRef.uid`), se usa el SID. Es la única identidad
   exacta.
2. Si no, se normaliza: un nombre `DOMINIO\usuario` (la forma de los parsers
   de Windows) aporta el dominio NetBIOS; minúsculas; NetBIOS → dominio DNS usando la tabla de
   dominios del snapshot de BloodHound; host corto → FQDN solo si hay un único
   candidato en el snapshot.
3. Si no hay un único candidato, se emite `Unresolved` y no se crea nada.
   **Nunca se adivina:** un `HasSession` sobre el host equivocado inventa un
   camino de ataque.
4. Las identidades sin resolver se cuentan por fuente; un porcentaje alto
   indica un problema de parser o de snapshot, no un ataque.

## 7. Prerrequisitos en el código actual

Detectados al leer el código el 2026-11-04. Estado al 2026-11-05: P1 y P2
resueltos en el PR #164; P3, P5 y P6 resueltos para el parser Sysmon/Security
(el de Sentinel sigue pendiente); P4 sigue abierto.

| # | Problema | Dónde | Efecto en la proyección |
|---|---|---|---|
| P1 | `AuthenticationEvent` no tiene `logon_type_id`; el parser lo guarda en `metadata["logon_type"]` pero `triple_to_ocsf` no lo copia | `platform/canonical/src/ocsf/mod.rs`, `project/mod.rs` | sin tipo de logon no se puede distinguir R1 de R5 |
| P2 | Un logon fallido se marca `metadata["success"] = "false"` en Sysmon/Security y `metadata["status"]` en Sentinel; la proyección a OCSF solo lee `status` | `core/graph-engine/src/sysmon.rs`, `sentinel.rs` | un 4625 de Sysmon llegaría como logon sin estado y podría crear una sesión falsa |
| P3 | No hay LOGOFF: 4634/4647 no se parsean | `sysmon.rs` | R7 nunca se dispara; las sesiones solo vencen por TTL |
| P4 | No se parsean 4672 (privilegios especiales), 4697/7045 (servicio instalado) ni altas a grupos (4728/4732/4756) | parsers de Windows | no hay evidencia observada de `AdminTo` ni de cambios de membresía (v1) |
| P5 | El `UserRef.uid` (SID) no se completa desde 4624 | `sysmon.rs` | la regla 1 de §6 casi nunca aplica |
| P6 | `ProcessActivityEvent` no tiene host (`device`); el parser lo guarda en `metadata["computer"]` del proceso | `ocsf/mod.rs`, `sysmon.rs` | R8 no sabe en qué host corre el proceso |

P1, P2 y P6 tocan el esquema canónico y un parser (área de revisión humana
obligatoria según `CLAUDE.md`).

## 8. Fuera de alcance de v0

- `AdminTo` observado (necesita P4).
- Cambios de membresía de grupos y de ACL en vivo (necesitan eventos de AD).
- Alcanzabilidad de red (`Connect` host → host) como capa propia.
- Probabilidades de detección por arista: las fijan los solvers de defensa, no
  esta regla.

## 9. Conformidad

Implementación de referencia en Python: `research/gtdin/proyeccion.py`.
Implementación del motor en Rust: crate `platform/attack-projection`
(`cargo test --manifest-path platform/attack-projection/Cargo.toml`).


`conformidad/proyeccion.json` lista casos de entrada (evento OCSF + tabla de
identidades) y la salida esperada (`AttackDelta`). Toda implementación debe
pasarlos todos. Los valores son sintéticos (dominio `corp.example`, IPs de
documentación), según las reglas de datos del repo. Los casos ya usan los
campos que agregan P1 y P6 (`logon_type_id`, `device.hostname`).
