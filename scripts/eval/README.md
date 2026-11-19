# scripts/eval

Banco de pruebas para responder con datos, y no de memoria, si Graph Hunter
aporta algo frente a consultar los logs crudos con SQL. Todo el dato es
sintético (rangos IP de documentación, dominios `example`).

```bash
# 1. 300k eventos tipo Sysmon con una intrusión plantada entre ruido
python scripts/eval/gen_synthetic_sysmon.py 300000 /tmp/eval/syn300k.jsonl

# 2. Línea base: las mismas preguntas con DuckDB (pip install duckdb)
python scripts/eval/duckdb_baseline.py /tmp/eval/syn300k.jsonl

# 3. Graph Hunter sin UI
export GRAPHHUNTER_API_TOKEN=local-eval
cargo run --release --manifest-path platform/server/Cargo.toml -- --ingest-root /tmp/eval &
python scripts/eval/gh_client.py load /tmp/eval/syn300k.jsonl
python scripts/eval/gh_client.py hunt "User -[Execute]-> Process -[Spawn]-> Process -[DNS]-> Domain"
python scripts/eval/gh_client.py hunt "Process -[Spawn]-> Process -[Connect]-> Host" anomaly

# 4. De punta a punta por MCP (levanta el servidor solo)
node scripts/eval/mcp_e2e.mjs platform/mcp/dist/src/index.js \
  platform/server/target/release/graph-hunter-server /tmp/eval /tmp/eval/syn300k.jsonl
```

## Tres fuentes

El mismo incidente visto además por un firewall (sólo IPs) y un proveedor de
identidad (usuarios como `usuario@corp.example`):

```bash
python scripts/eval/gen_synthetic_sysmon.py 60000 /tmp/eval/syn60k_guid.jsonl
python scripts/eval/gen_multisource.py /tmp/eval
python scripts/eval/duckdb_multisource.py /tmp/eval /tmp/eval/syn60k_guid.jsonl

# el servidor necesita la equivalencia de dominios para unir las cuentas
export GRAPHHUNTER_DOMAIN_ALIASES=CORP=corp.example
python scripts/eval/gh_multisource.py /tmp/eval
```

## Versión difícil, con puntaje

El mismo incidente con las trampas de una red real: una oficina asociada
(`203.0.113.7`) desde la que inician sesión cuentas legítimas y que los equipos
internos visitan, conexiones entrantes (RDP, `Initiated=false`), una dirección
reutilizada (`10.20.206.10` es de `WS-150` hasta las 12:00 y de `SRV-07`
después) y renovaciones DHCP. Es determinístico (`hash()` de Python no lo es,
y `gen_synthetic_sysmon.py` lo usa para el ruido). `truth.json` trae la verdad.

```bash
python scripts/eval/gen_hard.py /tmp/eval/hard
export GRAPHHUNTER_API_TOKEN=local-eval GRAPHHUNTER_DOMAIN_ALIASES=CORP=corp.example
cargo run --release --manifest-path platform/server/Cargo.toml -- --ingest-root /tmp/eval/hard &
cd scripts/eval && python score_hard.py /tmp/eval/hard     # sale con 1 si falla un control
python duckdb_hard.py /tmp/eval/hard                       # la misma pregunta en SQL
```

`duckdb_hard.py` fija `TimeZone = 'UTC'`: sin eso el join por hora compara
`TIMESTAMPTZ` (firewall) con `TIMESTAMP` (Sysmon) en la zona de la máquina y
culpa al equipo equivocado sin dar error.

Resultados y conclusiones: `docs/evaluacion/2026-11-16-utilidad-graph-hunter.md`.

La verdad de la intrusión plantada está al final de `gen_synthetic_sysmon.py`:
víctima `WS-042` / `user042`, movimiento lateral a `SRV-07` con `svc-backup`,
C2 en `c2.badactor.example` y `callback.badactor.example`. Una respuesta que
nombre a otro usuario u otro host es una cadena que no ocurrió.
