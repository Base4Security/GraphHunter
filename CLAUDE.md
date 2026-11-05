# Graph Hunter

> Contexto para asistentes de IA. Sigue la plantilla
> `Dev-Baseline/plantillas/CLAUDE.md.template` (política 02, desarrollo asistido
> por IA). Se versiona como cualquier otro archivo del repo.

Motor de threat hunting sobre grafos: ingiere logs (CSV, JSON/JSONL, Sentinel,
parsers propios por fuente), arma un grafo de entidades y relaciones y permite
cazar con un DSL de hipótesis, scoring GNN y agentes vía MCP. Se distribuye como
app de escritorio (Tauri) y como API HTTP local + servidor MCP.

| | |
|---|---|
| Área responsable | I+D (idi@base4security.com) |
| Dueño | `PENDIENTE:` persona nombrada — *Lucas Sotomayor, a confirmar* |
| Nivel de alcance | `PENDIENTE:` propuesta N3 — ver [FICHA.md](FICHA.md) |
| ¿Acceso de terceros? | Sí: código público en `Base4Security/GraphHunter` y binarios que instalan terceros |

## Stack

- **Lenguaje:** Rust 1.99.1 fijado en `rust-toolchain.toml`, edition 2024 (15 crates independientes, sin workspace raíz)
- **App de escritorio:** Tauri v2 + React 19 + TypeScript 5.7 + Vite 6 (`apps/tauri`)
- **Servidor MCP:** TypeScript (`platform/mcp`)
- **Auxiliares:** Python para entrenamiento de modelos (`training/`) y el sidecar
  `sidecar/tpcsa-certify`; .NET en `sidecar/dotnet`
- **Persistencia:** sesiones en archivo binario propio (`session_binary.rs`), sin base de datos
- **Gestor de dependencias:** cargo (un `Cargo.lock` por crate; el CI compila con `--locked`), npm (`package-lock.json`), pip con versiones exactas: se edita `requirements.in` y se regenera `requirements.txt` con `uv pip compile` (el comando está en la cabecera del archivo)

## Cómo se trabaja acá

```bash
# Correr la app local
cd apps/tauri && npm install && npm run tauri dev

# Tests de un crate (no hay workspace: siempre con --manifest-path o desde el crate)
cargo test --manifest-path platform/api/Cargo.toml

# Gate antes de mergear: chequeo de capas + tests
make pre-merge

# Linter y formato (los dos bloquean en CI; pre-merge ya los incluye)
make clippy
make fmt-check

# Frontend y MCP
cd apps/tauri && npx tsc --noEmit && npm test
cd platform/mcp && npm run build && npm run test:contract

# Secret scanning (mismo comando que el CI)
gitleaks git . --config .gitleaks.toml --redact
```

Todo cambio pasa tests y linter antes de proponerse. Si un test falla, se
arregla o se reporta; no se desactiva ni se marca `#[ignore]` para que pase.

## Convenciones del proyecto

- `core/` es el motor (grafo, GNN, matcher) y no depende de `platform/`. Lo
  verifica `make layering`.
- Un parser por fuente en `platform/parsers/src/<fuente>.rs`, registrado en
  `platform/api/src/format_registry.rs`. El doc del módulo explica las decisiones
  de identidad (qué campo es el id de cada entidad).
- Commits estilo conventional (`feat(api): …`, `fix(mapping): …`), en español,
  describiendo el cambio y no la actividad.
- Escribir código que se lea como el que ya está: misma densidad de comentarios,
  mismos nombres, mismo idioma de los comentarios del archivo.

## Datos que maneja este sistema

| Tipo de dato | Sensibilidad |
|---|---|
| Logs de seguridad de clientes (SIEM, WAF, VPN, IdP) | Alta — datos de clientes |
| Evidencia de investigaciones (p. ej. fraude: CUIL/CUIT, nombres, domicilios, CBU/CVU) | Alta — datos personales de terceros |
| Credenciales de SIEM (Azure/Sentinel) | Secreto — solo por entorno, ver `.env.example` |
| Datos de demo (`demo_data/`) | Sintéticos |

**No incluir en prompts, ejemplos, tests, fixtures ni docs:** credenciales,
tokens, datos de clientes, ni identificadores de personas reales (CUIL/CUIT,
nombres, domicilios, cuentas, emails, IPs públicas de clientes). Para tests de
parsers se arma la muestra a mano con valores sintéticos: CUIL que no exista en
el corpus, IPs de documentación (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
emails `@example.com`. El corpus real vive fuera del repo y no se copia adentro.

## Qué NO tocar

- Secretos y `.env` con valores.
- Formato binario de sesión y `body_format_version` sin bump de versión y test
  de compatibilidad: rompe sesiones guardadas de los usuarios.
- Esquema de ids de entidades de un parser (p. ej. `Person` por CUIL sin
  prefijo en `bind_psp` y `certero`): si cambia uno, los datasets dejan de unirse
  en silencio.
- El remoto `public` (`Base4Security/GraphHunter`): no se hace push sin pedido
  explícito. Las ramas de trabajo van a `origin`.
- `PENDIENTE:` otros módulos críticos — *dueño*

## Qué requiere revisión humana obligatoria

- Autenticación de la API HTTP local (token) y del servidor MCP.
- Manejo de credenciales de SIEM.
- Parsers de entrada (son la superficie que recibe datos no confiables).
- Deserialización de sesiones y de archivos cargados por el usuario.
- Llamadas a LLM de facturación variable (`platform/local-llm`, agentes).

## Consumo de IA en runtime

> `PENDIENTE:` confirmar si alguna instalación de Base4 llama a un proveedor de
> IA de consumo variable en operación. Si sí, completar proveedor, presupuesto,
> umbral de corte y dónde está el límite (política 03). — *dueño*

Cualquier cambio que pueda aumentar el consumo de tokens (más llamadas, modelo
más grande, más contexto, reintentos) se declara en el PR con una estimación.

## Definición de terminado

- [ ] Tests y linter en verde.
- [ ] El autor puede explicar cada línea del diff.
- [ ] Sin secretos ni datos reales.
- [ ] Si toca un área de revisión obligatoria, hay revisor humano asignado.
- [ ] Si cambia el consumo de IA, está declarado en el PR.
