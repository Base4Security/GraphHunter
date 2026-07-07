# Sentinel Connect Paused-by-Default (pause/resume polling)

**Fecha:** 2026-06-02
**Estado:** Diseño aprobado — pendiente plan de implementación
**Owner:** Lucas
**Relacionado:** `2026-06-01-sentinel-live-node-hydration-design.md`, `2026-06-02-sentinel-seed-from-ioc-design.md` (el combo connect-pausado + seed es el flujo objetivo)

## 1. Problema

Hoy `sentinel_connect` (`platform/api/src/operations/sentinel.rs`) hace
`tokio::spawn(polling_loop(...))` de inmediato: **conectar es arrancar el
polling**. El loop poolea a los ~2s del arranque (no tiene estado de pausa).
El analista no puede conectarse a Sentinel sin disparar el tráfico de polling
cada 30s.

Esto choca con los flujos nuevos (cold-start por `sentinel_seed`, drill-down
con live hydration): a veces querés conectar para sembrar/cazar puntualmente,
sin vigilancia continua.

## 2. Objetivo

Desacoplar "conectar" de "polear": al conectar, el conector queda **pausado
(idle)** por defecto; el polling se arranca/pausa explícitamente
(start/stop). El estado incremental (watermarks) se conserva a través de
pause/resume.

### No-objetivos (YAGNI)

- No expone pause/resume por MCP (solo UI + HTTP). El LLM usa `sentinel_seed`
  / KQL; el polling es control del analista.
- No persiste la preferencia (siempre arranca pausado; no hay setting).
- No cambia la semántica del polling en sí (take/watermark/intervalo intactos).

## 3. Decisiones tomadas (no re-debatir)

| Decisión | Valor |
|----------|-------|
| Modelo | Pausa/resume: el conector vive siempre; un flag controla si poolea |
| Default | **Pausado por defecto** — conectar nunca arranca el polling solo (cambio de comportamiento) |
| Mecanismo | Enfoque A: señal `watch::<bool>` que el `polling_loop` gatea al tope de cada iteración (un solo spawn en connect; watermarks persisten) |
| Control | UI (comando Tauri + botón) + ruta HTTP. NO MCP. |
| Fase al conectar | `Ready` (huntable, sin ingesta viva) |
| Fase en resume | `LiveTail` |
| Fase en pause | `Ready` |

## 4. Arquitectura (Enfoque A)

Un `tokio::sync::watch::channel<bool>` ("paused"): el handle guarda el
`Sender`, el loop recibe el `Receiver`.

```
sentinel_connect
   ├─ pause channel inicial = true (pausado)
   ├─ spawn polling_loop(..., pause_rx)        // una sola vez
   ├─ handle { ..., pause_tx }                  // guarda el sender
   ├─ status = Paused;  phase = Ready           // NO fuerza LiveTail
   └─ emit sentinel-connected { paused: true }

sentinel_resume:  pause_tx.send(false);  phase = LiveTail
sentinel_pause:   pause_tx.send(true);   phase = Ready
sentinel_disconnect:  cancel (sin cambios) — rompe el loop aun en pausa
```

### 4.1 Cambio en `polling_loop`

Recibe `pause_rx: watch::Receiver<bool>`. Al tope de cada iteración, antes
del delay/poll existente:

```rust
while *pause_rx.borrow() {
    let _ = status_tx.send(ConnectorStatus::Paused);
    tokio::select! {
        _ = cancel.cancelled() => {
            let _ = status_tx.send(ConnectorStatus::Disconnected);
            emitter.emit(event_names::SENTINEL_STATUS, serde_json::json!({"disconnected": true}));
            return;
        }
        _ = pause_rx.changed() => {}   // resume → re-evalúa el while
    }
}
// ...resto del tick existente (token + tablas + ingest + scoring)...
```

El `SentinelWatermarkStore` vive en la misma instancia del loop, así que
sobrevive pause/resume: al resumir, el polling continúa incremental
(`where TimeGenerated > datetime(W)`), no re-polea desde cero.

### 4.2 Componentes

| Pieza | Archivo | Cambio |
|---|---|---|
| `ConnectorStatus::Paused` | `platform/api/src/sentinel_connector.rs` | nueva variante del enum (serde tag) |
| `SentinelConnectorHandle.pause_tx` | `platform/api/src/sentinel_connector.rs` | `watch::Sender<bool>` |
| `polling_loop(..., pause_rx)` | `platform/api/src/sentinel_connector.rs` | param + gating while-paused |
| `sentinel_connect` | `platform/api/src/operations/sentinel.rs` | pause channel=true, pasar rx, guardar tx, quitar `set_phase(LiveTail)` → `Ready` |
| `sentinel_resume` / `sentinel_pause` | `platform/api/src/operations/sentinel.rs` | nuevas ops: flip watch + set phase |
| `cmd_sentinel_resume` / `cmd_sentinel_pause` | `apps/tauri/src-tauri/src/commands/sentinel.rs` | comandos Tauri |
| `POST /sentinel/resume` `/sentinel/pause` | `apps/tauri/src-tauri/src/http/{siem.rs,mod.rs}` | rutas HTTP |
| botón toggle | `apps/tauri/src/components/ingest/SentinelConnectForm.tsx` | start/pause + estado visual (badge Paused/Polling) |

## 5. Errores e idempotencia

- `resume`/`pause` sin conector activo → `ApiError::InvalidState`
  ("No Sentinel connector is running. Connect first.").
- `resume` cuando ya está activo / `pause` cuando ya está pausado → no-op
  (re-enviar el mismo valor al `watch` es inofensivo; el loop no cambia).
- `disconnect` durante pausa → el `select!` sobre `cancel` rompe el loop
  limpio. Sin cambios en `sentinel_disconnect`.
- `SentinelConnectedEvent` gana `paused: bool` (=true) para que la UI
  renderice el estado inicial correcto.

## 6. Testing

- **Loop pause-gating (test principal, `MockTransport`):** spawnear
  `polling_loop` con `pause_rx` inicial `true` → tras una ventana de tiempo,
  0 queries registradas por el mock. Flip a `false` (resume) → empiezan las
  queries. Flip a `true` (pause) → paran. El loop es genérico sobre
  `SentinelTransport`, mockeable (mismo patrón que los tests de hidratación).
- **Watermark persistencia:** tras resume→pause→resume, el watermark de una
  tabla se conserva (la query incremental usa `datetime(W)`, no `ago(24h)`).
- **Status transitions:** `Paused` → (resume) → `Polling`/`Connected` →
  (pause) → `Paused`, observadas en el `status_rx`.
- **Tauri/HTTP/botón:** compile + smoke. `resume` sin conector → InvalidState.

## 7. Out of scope

- Pause/resume por MCP.
- Persistir la preferencia de arranque (siempre pausado).
- Auto-resume tras N minutos o tras seed (descartado: delayed auto-start no
  fue el modelo elegido).
- Cambios al algoritmo de polling (take/watermark/intervalo).
