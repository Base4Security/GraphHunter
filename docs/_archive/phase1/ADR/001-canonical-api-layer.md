# ADR-001 — Canonical API Layer: consolidación y ruptura del ciclo CLI↔API

- **Fecha**: 2026-04-23
- **Estado**: propuesto
- **Decisión**: consolidar `graph_hunter_api` como *única* superficie pública hacia glue, extraer `Sentinel streaming` a un crate `platform/siem`, y versionar los DTOs con semver.

## Contexto

Fase 0 detectó:
1. `graph_hunter_api/Cargo.toml` depende de `graph_hunter_cli` **como librería** para reusar `cli::siem::sentinel_streaming`. Esto crea un ciclo lógico: `api → cli → core` y `api → core`.
2. `graph_hunter_cli` no pasa por la API: va directo a `graph_hunter_core`. Bifurca el "camino de ingesta".
3. `app/src-tauri/src/http_api.rs` (1 662 LOC) y 91 Tauri commands exponen **la misma superficie** que `graph_hunter_api` pero sin versionar.
4. MCP, Tauri, y CLI son los 3 consumidores esperables. Hoy sólo MCP y Tauri son "bien educados".

## Decisión

### D1 — Extraer `Sentinel streaming` a crate `platform/siem`

- Nuevo crate: `platform/siem/` con la lógica hoy en `graph_hunter_cli/src/siem/sentinel_streaming.rs` (y `sentinel.rs`, `elastic.rs` si aplica).
- Dependen de él: `platform/api` y `apps/cli`.
- Resultado: `platform/api` ya **no depende** de `apps/cli`. Ciclo roto.

### D2 — `apps/cli` pasa a ser cliente de `platform/api`

Dos sub-opciones consideradas:

- **D2.a** (elegida): CLI usa `platform/api` directamente como librería in-proc (no HTTP). Mantiene performance, simplifica código.
- **D2.b** (descartada): CLI como cliente HTTP del Tauri API. Añade dependencia operacional (server corriendo) y latencia de serialización. No justifica complejidad adicional.

Consecuencia: el CLI queda como *otro front-end* del mismo `GraphHunterApi`, igual que Tauri.

### D3 — `graph_hunter_api` se versiona con semver público

- Crate version pasa a 1.0.0 cuando se completa Fase 4.
- DTOs versionados por módulo (`dto/v1/...`, eventualmente `dto/v2/...`).
- Breaking changes requieren nueva major.
- `GraphHunterApi::VERSION` constante expuesta para introspección desde MCP.

### D4 — `http_api.rs` de Tauri se parte en routers por dominio

- `http_api/routes/hunt.rs`, `http_api/routes/ingest.rs`, etc.
- Cada router delega a una operation de `platform/api`.
- **Glue puro**: routers no contienen lógica de dominio.

### D5 — Lógica en `commands/ingestion.rs` (727 LOC) migra a `platform/api/operations/ingestion`

- Los Tauri commands quedan como shims 1:1 como el resto.
- Test de parity cubre el contrato.

## Consecuencias positivas

- Ciclo arquitectural eliminado.
- Versionado explícito reduce sorpresas a consumidores.
- Cualquier nuevo front-end (web app, IDE extension, etc.) consume `platform/api` sin reinventar.
- MCP queda como un "cliente más", no un caso especial.

## Consecuencias negativas / costos

- Reorganización de 3 crates (`api`, `cli`, nuevo `siem`). Tiempo estimado Fase 2: ~1-2 días de trabajo mecánico + verificación de tests.
- Compatibility: si algún consumidor externo importa `graph_hunter_cli` como lib (improbable), se rompe. Mitigar con re-export pass-through por 1 versión.

## Alternativas consideradas

- **Dejar el ciclo y documentarlo**: rechazado; bloquea refactors profundos.
- **Mover `Sentinel streaming` al `core`**: rechazado; es plataforma (conector externo), no núcleo.
- **Mover CLI dentro del crate `api` como binario**: rechazado; el CLI merece tener su propio Cargo y lifecycle.

## Referencias

- PAIN_POINTS §2 (ciclo)
- PAIN_POINTS §3 (asimetría Tauri commands)
- CURRENT_STATE §2 (grafo de deps)
