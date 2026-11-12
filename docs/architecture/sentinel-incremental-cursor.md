# Sentinel incremental cursor — ingestion_time, drain, y cobertura SOT

Cómo el conector de polling de Sentinel (`platform/api/src/sentinel_connector.rs`)
extrae eventos incrementales con solo credenciales de Log Analytics, sin perder
datos y sin presentar un grafo incompleto como exhaustivo.

## El bug que se corrigió

El cursor viejo era `where TimeGenerated > datetime({watermark}) | order by
TimeGenerated asc | take N`, avanzando el watermark al máximo `TimeGenerated`
del batch. **`TimeGenerated` es el tiempo del evento.** Log Analytics ingesta
los logs con minutos de retraso y **fuera de orden**: una fila que entra al
workspace *después* de que el watermark avanzó, pero con un `TimeGenerated`
anterior, cae por debajo del `>` y **se pierde para siempre**. Con eventos
tardíos (típico en Sentinel), esto come datos en silencio — el operador no
puede distinguir "no hubo eventos" de "me salté eventos". En términos SOT: es
un **testigo de ceguera** — un observable real que el observador omite sin
saberlo.

## El fix: cursor por tiempo de ingesta

```kql
{table}
| extend _ingest_ts = coalesce(ingestion_time(), TimeGenerated)
| where _ingest_ts > datetime({watermark})
| order by _ingest_ts asc
| take {batch_size}
```

`ingestion_time()` es el momento en que la fila se volvió consultable, y **solo
crece**: una fila nueva siempre recibe un `_ingest_ts` mayor que cualquiera ya
procesada, así que el `>` estricto **nunca se saltea una llegada tardía**. El
watermark ahora avanza sobre `_ingest_ts` (`normalize_response`), no sobre
`TimeGenerated`.

- **`coalesce(ingestion_time(), TimeGenerated)`** degrada con gracia: una tabla
  sin política de ingestion-time (raro; default-on en tablas estándar) vuelve a
  cursor por tiempo de evento *solo para esa tabla*, sin romperse.
- **`_ingest_ts` es solo para el cursor.** Cada fila conserva su `TimeGenerated`
  original — el parser lo necesita para los timestamps de las aristas. Columnas
  desconocidas no molestan al `SentinelJsonParser`.

### Por qué `>` estricto sin solapamiento ni dedup

El insert path live es append-only (sin dedup de aristas). Con `>` estricto
sobre `_ingest_ts` **no se re-leen filas**, así que no se duplican aristas y no
se depende del dedup idempotente (que en el path live está apagado). La
correctitud viene de la **monotonía** del tiempo de ingesta, no de tapar
duplicados. Residual único: si > `batch_size` filas comparten el mismo tick
exacto de `ingestion_time` justo en el corte de un batch, la sobrante se
saltearía — despreciable, y el drain (abajo) hace que los cortes de batch solo
ocurran cuando ya se está al día.

## Drain: ponerse al día dentro de un poll

Antes, el conector traía **un batch por intervalo de poll** — con backlog, nunca
alcanzaba el presente. Ahora cada tabla **drena** hasta ponerse al día: repite
la query (avanzando el watermark) hasta que un batch devuelve menos de
`batch_size` filas (o vacío, o el cursor no avanzó, o el backstop
`MAX_DRAIN_ITERS`). Es *cancel-aware* y no sostiene el lock del grafo entre
iteraciones.

## Cobertura SOT: los huecos son observables

El cursor evita la pérdida *silenciosa*, pero una fuente puede quedar ciega por
otras razones (auth falla, error de tabla, transporte caído). SOT exige que una
ventana ciega sea **distinguible** de una genuinamente vacía en la respuesta del
observador. El conector ahora registra cobertura por-fuente (gated por
`GRAPHHUNTER_SOURCE_COVERAGE`, no-op si está off), con id `sentinel:{table}`:

- **Éxito** de una tabla → `record_covered` (avanza el marcador).
- **Fallo** (transporte/normalize) → `record_failure` + `record_missing`.

Así, un hunt posterior reporta `missing_sources` en su `AnswerCoverage` (Fase F)
cuando una tabla está ciega — el analista sabe que el grafo puede estar
incompleto. Cierra el lazo entre "el conector tuvo un problema" y "la respuesta
del hunt lo declara".

## Límites honestos

1. **El watermark store es en memoria** (`SentinelWatermarkStore`). Al reiniciar
   el conector, re-backfillea desde la ventana inicial. Persistir los watermarks
   (la `ops.sqlite` hoy sin usar) es trabajo futuro.
2. **`ingestion_time()` requiere política de ingestion-time** en la tabla
   (default-on en tablas estándar); `coalesce` degrada esa tabla a tiempo de
   evento si falta.
3. **Cambio contenido:** solo el path async incremental (el conector). El path
   sync one-shot (`run_kql`, `ingest_siem`, `ingest_query` del CLI, hydration) no
   se tocó — ahí la query la escribe el caller.

## Guía para el path one-shot (`ingest_siem` / `ingest_query`)

Si poleás con query provista por vos (no el conector), escribila igual —
cursor por tiempo de ingesta, no de evento:

```kql
{table}
| extend _it = ingestion_time()
| where _it > datetime({ultimo_next_query_start})
| order by _it asc
| take N
```

…y cursorea sobre el `next_query_start` que devuelve la respuesta, **nunca sobre
`TimeGenerated`**. Es la misma filosofía SOT que el conector aplica solo.
