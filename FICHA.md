# Ficha de sistema — Graph Hunter

> Plantilla de origen: `Dev-Baseline/plantillas/ficha-sistema.md`. Los niveles y
> respuestas marcados como propuesta los confirma la célula con el dueño.

| | |
|---|---|
| Nombre | Graph Hunter |
| Descripción en una línea | Motor de threat hunting sobre grafos, app de escritorio + API local + MCP |
| Área responsable | I+D |
| **Dueño** (persona nombrada) | `PENDIENTE:` — *Lucas Sotomayor, a confirmar* |
| Suplente / contacto ante incidente | `PENDIENTE:` |
| ¿Un único desarrollador? | Sí (propuesta) — aplica RA-1 de la política 01, sección 10 |
| Repositorio | `lsotomayorb4/Graph-Hunter` (privado, cuenta personal: versión de desarrollo, se migra a la organización) y `Base4Security/GraphHunter` (público, repo de la organización) |
| Última revisión de esta ficha | 2026-11-02 |

## Clasificación

| | |
|---|---|
| Nivel de alcance | **N3 — propuesta** |
| Elevado por la célula | No |
| Confirmado por la célula | No |

### Criterios de aplicabilidad

| # | Criterio | ¿Se cumple? | Nivel mínimo | Razón |
|---|---|---|---|---|
| C1 | Multi-persona | No (propuesta) | N1 | Un desarrollador con asistencia de IA |
| C2 | Multi-área | A relevar | N1 | ¿Lo usa el SOC u otra área para servicios? |
| C3 | Información sensible | **Sí** | N2 | Procesa logs de clientes y evidencia con datos personales de terceros |
| C4 | Acceso privilegiado | Sí | N2 | Guarda credenciales de Sentinel/Azure con acceso a workspaces de clientes |
| C5 | Criticidad operativa | A relevar | N2 | Depende de si se usa en investigaciones entregadas a clientes |
| C6 | Acción automática | A relevar | N2 | Agentes con herramientas vía MCP; hoy no ejecutan acciones sobre sistemas externos |
| C7 | Acceso de terceros | **Sí** | N3 | Código público y binarios distribuidos a terceros; API HTTP y MCP expuestos en localhost |

> `PENDIENTE:` C7 para software **distribuido** (lo instala un tercero en su
> máquina) no es lo mismo que un servicio publicado. Ver la propuesta de
> mejora al baseline sobre este caso. — *célula*

## Datos que procesa

| Tipo de dato | ¿Personales? | ¿De clientes? | Sensibilidad |
|---|---|---|---|
| Logs de SIEM, WAF, VPN, IdP | Sí (usuarios, IPs) | Sí | Alta |
| Evidencia de investigaciones de fraude | Sí (CUIL, nombres, domicilios, cuentas) | Sí | Alta |
| Credenciales de SIEM | No | Sí | Secreto |

## Estado operativo

| | |
|---|---|
| ¿En producción? | Publicado (release 1.x, Black Hat Arsenal) |
| Destino de despliegue | Escritorio del usuario; sin servidor propio |
| ¿Acceso de terceros? | Sí — ver C7 |
| Usuarios / consumidores | Analistas de Base4 y comunidad open source |

## Stack

| | |
|---|---|
| Lenguaje y versión | Rust edition 2024; TypeScript 5.7; Python (entrenamiento) |
| Framework | Tauri v2, React 19 |
| Base de datos | Ninguna (sesiones en archivo binario) |
| Dependencias externas relevantes | ONNX Runtime, Azure/Sentinel API, SDK MCP |

## Desarrollo asistido por IA

| | |
|---|---|
| ¿Se usa IA para desarrollar? | Sí |
| ¿Tiene archivo de contexto versionado? | `CLAUDE.md` |
| Herramientas utilizadas | Claude Code — `PENDIENTE:` confirmar que está homologada (ADR-0004) |

## Consumo de servicios de IA en runtime

> `PENDIENTE:` completar si alguna instalación de Base4 consume IA de facturación
> variable (agentes vía MCP con un proveedor pago). — *dueño*

## Controles

> "Bloquea" significa que el job falla en rojo. Que eso impida mergear depende
> del ruleset de `main` (ver plan de adecuación): hoy no hay ninguno.

| Control | Dónde | ¿Bloquea? | Periodicidad | Última ejecución |
|---|---|---|---|---|
| Revisión de código obligatoria | Ruleset de `main` | **No existe** — hay commits directos y merges locales | por PR | — |
| Tests Rust (15 crates, Linux y Windows) | `rust-ci.yml` | Sí | por PR que toca Rust | 2026-11-02, local: parsers 155, graph-engine 1028, api 664 |
| Tests y tipos TypeScript (app y MCP) | `ts-py-ci.yml` | Sí | por PR | 2026-11-02, local: vitest 15, MCP 40 |
| Tests Python (sidecar) | `ts-py-ci.yml` | Sí | por PR | 2026-11-02, local: 5 |
| Formato (rustfmt) | `rust-ci.yml` | Sí | por PR | 2026-11-02 |
| Linter (clippy) | `rust-ci.yml` | **No** — advertencias acumuladas | por PR | |
| Secret scanning (gitleaks, historial completo) | `baseline.yml` | Sí | por PR | 2026-11-02, local: 1015 commits, 0 hallazgos |
| Vulnerabilidades en dependencias Rust (cargo-audit) | `rust-ci.yml` | Sí | por PR | 2026-11-02, local: 0 en 15 crates |
| Licencias, crates vetados, unmaintained/unsound (cargo-deny) | `rust-ci.yml` | **No** — hallazgos abiertos | por PR | |
| Vulnerabilidades npm | `ts-py-ci.yml` | App: altas y críticas. MCP: solo críticas | por PR | 2026-11-02, local: app 0, MCP 1 alta |
| Vulnerabilidades Python (pip-audit) | `ts-py-ci.yml` | Sí, salvo `field_role_classifier` | por PR | 2026-11-02, local: 4 en transformers |
| Lockfiles al día (`--locked`) | `rust-ci.yml` | Sí | por PR | |
| Actualización de dependencias | Dependabot | — | semanal | |
| SAST (CodeQL: Rust, TS, Python, Actions) | `sast.yml` | Solo con la regla de code scanning del ruleset | por PR + semanal | Pendiente de primera corrida |
| Análisis de vulnerabilidades del sistema | — | **No** | | |
| Backup y prueba de restauración | N/A — sin datos persistentes del lado servidor | | | |
| Modelado de amenazas (N3) | — | **No** | | |
| Análisis dinámico o pentest (N3) | — | **No** | | |

## Excepciones vigentes

| Control | Motivo de la excepción | Aprobada por | Vence |
|---|---|---|---|
| | | | |

## Plan de adecuación

| Brecha | Acción | Responsable | Fecha objetivo |
|---|---|---|---|
| Datos reales del corpus de fraude (CUIL, nombres, domicilios, CVU, IDs de operación), emails personales y de empleados, e IPs de clientes e investigaciones en tests y docs de `origin` | Hecho 2026-11-02: reemplazados por sintéticos en el árbol y en todo el historial (`git filter-repo --replace-text`, push forzado de las 21 ramas y el tag de `origin`). Verificado: 0 valores originales, 0 CUIL reales, gitleaks limpio. `Base4Security/GraphHunter` no los tenía. Queda: GitHub conserva los commits viejos en `refs/pull/*` (163 PR) y en caché; se eliminan solo pidiéndolo a GitHub Support o borrando el repo personal tras la migración | Dueño | `PENDIENTE:` pedido a GitHub Support o borrado del repo personal |
| Repo privado en cuenta personal, sin protección de rama posible (plan Free) | Es la versión de desarrollo; el dueño la migra a la organización (ADR-0002) | Dueño | En curso |
| `main` sin protección en `Base4Security/GraphHunter` | Ruleset: sin push directo, PR obligatorio, checks requeridos (`Secret scanning`, `audit`, `frontend`, `mcp`, `python`, `rust-ci-ok`), regla de code scanning | Admin de la org | `PENDIENTE:` |
| `rust-ci.yml` filtraba por rutas: en un PR sin Rust sus checks no corrían y no podían ser requeridos | Hecho: filtro movido al job `changes` y job agregador `rust-ci-ok`, que siempre termina y es el que se marca como requerido | Dueño | Hecho 2026-11-02 |
| Clippy no bloqueante (199 advertencias en graph-engine, 161 en api, 25 en tauri y parsers…) | Corregir por crate y quitar `continue-on-error` | Dueño | `PENDIENTE:` |
| cargo-deny no bloqueante: unmaintained, unsound, licencias sin declarar, un crate rechazado en tauri. Además el paso nunca había corrido (argumentos en orden incorrecto) | Triage por crate; excepciones con fecha en `deny.toml` | Dueño | `PENDIENTE:` |
| MCP: `zod` 3 tiene una vulnerabilidad alta (GHSA-mrhx-c7xc-m3w5); se corrige en 4.x | Migrar a zod 4 y subir el umbral de `npm audit` a `high` | Dueño | `PENDIENTE:` |
| `transformers` <5 en `training/field_role_classifier` con 4 advisories | Migrar a 5.x o aceptar formalmente (código de entrenamiento offline) | Dueño | `PENDIENTE:` |
| Sin modelado de amenazas (N3) | Modelar API local, MCP, parsers y carga de sesiones | Dueño + rol de seguridad | `PENDIENTE:` |
| Sin análisis de vulnerabilidades periódico del binario distribuido | Definir con la célula (el baseline no cubre software distribuido) | Dueño + célula | `PENDIENTE:` |
