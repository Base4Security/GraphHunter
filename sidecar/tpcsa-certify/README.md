# tpcsa-certify — certificado de optimalidad para `reconstruct_chain`

El greedy en Rust (`core/tpcsa-core`) es el producto: corre en segundos y
va en el camino interactivo. Este sidecar es el **auditor**: resuelve la
formulación expandida en tiempo del TPCSA con HiGHS (`highspy`, sin PuLP:
PuLP mapeaba el límite de tiempo a "Optimal") y devuelve un certificado que
Graph Hunter muestra tal cual. Nunca corre por defecto.

```bash
cd sidecar/tpcsa-certify
python -m venv .venv && .venv/Scripts/activate   # o source .venv/bin/activate
pip install -r requirements.txt
# versiones exactas; se regenera desde requirements.in con:
# uv pip compile requirements.in --universal --python-version 3.12 -o requirements.txt
python server.py --port 37892 --max-arcs 50000
```

`POST /certify` recibe `{instance, k, time_limit, gap, warm_start}` (la
instancia **podada** que devuelve `reconstruct_chain` con `certify: true`;
el bosque del greedy va como incumbente inicial) y responde:

| `status` | Significado |
|---|---|
| `Optimal` | óptimo certificado; `gap` ≤ el pedido |
| `TimeLimit` | mejor incumbente al vencer `time_limit`, con `gap` |
| `Infeasible` | el modelo no tiene solución (no debería ocurrir: el bosque vacío siempre es factible) |
| `InvalidNumerics` | HiGHS reportó una solución que la re-verificación independiente rechaza. **Nunca presentar.** |
| `TooLarge` | la instancia supera `--max-arcs`; el greedy queda sin certificado |
| `Error` | excepción; `message` la describe |

Graph Hunter lo ubica por `TPCSA_CERTIFY_URL` (default
`http://127.0.0.1:37892/certify`). Si no responde, `certificate.status` es
`Unavailable` y la reconstrucción sigue siendo válida.

Memoria: ~250k variables por 50k arcos podados (≈ 4 GB); con 12 GB llega a
~300k arcos.

Tests: `python -m pytest` en este directorio.
