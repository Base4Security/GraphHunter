# Demo Black Hat Europe — de fragmentos a cadena (TPCSA)

**Fecha:** 2026-09-03 · **Duración objetivo:** 6 minutos · **Script:** `scripts/demo_tpcsa.py`
**Dataset:** NODLINK hw20 (`anomaly.json`, 1.09 M eventos ETW, 20 h, cadena Sangfor de 43 procesos).

## Mensaje

Hoy Graph Hunter encuentra *fragmentos*: un `certutil` que baja algo, un
`nbtscan`, un `PAExec`. La pregunta del analista es otra: **qué pasó**, en
qué orden, desde dónde, y a través de qué proceso que nadie marcó.
`reconstruct_chain` responde eso con un árbol time-respecting, un punto de
entrada, conectores y, si se pide, un certificado de optimalidad.

## Guion

1. **Carga (5 s).** Antes del evento, dejar hw20 como sesión guardada:
   `tpcsa_bench --etw hw20/anomaly.json --seeds 0 --save-session tpcsa-demo-hw20`
   (imprime el id). En vivo: `python scripts/demo_tpcsa.py --session-id <id> --k 2`.
   La ingesta en vivo (`--trace`) también funciona, pero exige arrancar la app
   con `GRAPHHUNTER_INGEST_ROOT` apuntando al directorio del archivo (política
   de ingesta remota) y tarda ~60 s; la sesión guardada carga en 2 s.
   Mencionar: ~9,9 k entidades, ~1,08 M relaciones; identidad de proceso
   `PID|imagen|generación`, dirección causal.
2. **Fragmentos (1 min).** Siete tácticas, una hipótesis DSL por imagen de
   proceso (`Process -[Spawn]-> Process {name="certutil"}`; el DSL no tiene
   alternancia regex, `~` es "contiene"). Cada match es un proceso hijo con una
   táctica: 46 seeds en hw20. Punto a remarcar: *son islas*. Ninguna dice cómo
   se conectan ni por dónde entró el actor.
3. **Reconstrucción (2 min).** Una llamada a `/reconstruct_chain` con esos
   seeds. Leer la salida de arriba hacia abajo:
   - `ties` primero: si no está vacío, hay dos hipótesis y se muestran ambas.
   - Árbol 1: **punto de entrada** (`4452|unknown|0`, un proceso cuyo start
     no está en la traza) y su instante; luego los arcos en orden causal.
   - **Conectores**: los `cmd` envolventes que ningún template marca pero de
     los que cuelga toda la cadena (`1996|cmd|0`: 24 detecciones en su
     subárbol; `4360|cmd|0`: 22). Si se omite la hipótesis de `agent`, el
     agente C2 `4128|agent|0` aparece él mismo como conector con 10 PowerShell
     colgando: es el hallazgo que los matches no dan (variante para mostrar en
     vivo: quitar `agent` de la lista y volver a correr).
   - `dropped`: las detecciones que no encajan en la historia causal se
     quedan afuera en vez de forzarse (es la diferencia con SteinerLog/NODLINK).
4. **Segundo punto de entrada (1 min).** Con `--k 1` desaparece el segundo
   implante; con `--k 2` vuelve. En win10 esto son los dos `sangforcat`.
5. **Certificado (1 min, opcional).** `--certify` con el sidecar levantado
   (`python sidecar/tpcsa-certify/server.py`): `Optimal`, gap 0.0, ~18 s en
   hw20. Decir explícitamente: el greedy es el producto, el certificado es la
   auditoría, y nunca se muestra una solución que `verify` rechace.

## Números para tener a mano (medidos 2026-09-03)

| | hw20 | win10 |
|---|---|---|
| eventos | 1,084,177 | 1,876,517 |
| poda | → 13 k–92 k arcos | → 173 k–288 k arcos |
| P / R de nodos (árbol 1) | 0.94–0.97 / 0.72–0.84 | 0.69–0.73 / 0.70–0.79 |
| recall de arcos `start` | 0.74–0.89 | 0.67–0.79 |
| tiempo de reconstrucción | 1.4–5.4 s | 26–60 s |
| certificado | Optimal, gap 0 (seed 0) | pendiente (>50 k arcos, subir `--max-arcs`) |

## Qué NO decir

- No presentar un solo árbol "para simplificar" (`k=1` pierde el segundo implante).
- No dar métricas agregadas del bosque: precisión por árbol.
- No mostrar un certificado `InvalidNumerics` ni una solución que `verify` rechace.
- No atribuir tácticas a precedencia dura: solo ordenan el ranking.

## Si la app no está disponible

`platform/api/target/release/tpcsa_bench --etw hw20/anomaly.json --scores hw20_scores.json --top 400 --k 3 --separation`
reproduce el flujo completo sin la app (detector proxy en lugar de templates).

## Transcripción de la corrida real (2026-09-03, app de escritorio, sesión guardada)

```
Fragments (one hypothesis per tactic):
  T1071  command-and-control      3 paths  certutil:2 agent:1
  T1087  discovery               13 paths  nbtscan:1 ipconfig:3 whoami:1 ARP:1 PING:1 systeminfo:1 tasklist:2 net:3
  T1021  lateral-movement         6 paths  PAExec:3 wmic:3
  T1110  credential-access        1 paths  WinBrute:1
  T1547  persistence             11 paths  reg:6 schtasks:1 sc:4
  T1562  defense-evasion          2 paths  taskkill:1 netsh:1
  T1059  execution               10 paths  powershell:10

46 seeds -> /reconstruct_chain (k=2)
pruning: 1,084,177 -> 9,263 arcs | objective 147.00 | 2 tree(s)

=== tree 1: entry point 4452|unknown|0 (process) at +107.349s | tactics [c2, credential-access,
    defense-evasion, discovery, execution, lateral-movement, persistence] | prize 290.0 cost 43.0
    collected 29 detections, dropped 17
    CONNECTOR 1996|cmd|0: 2 detections hang directly off it (24 in its subtree)
    CONNECTOR 4360|cmd|0: 1 detection (22 in its subtree)
    +107.349s  4452|unknown|0 -[start]-> 4696|cmd|0 -[start]-> 3432|ipconfig|0
    +117.810s  4452|unknown|0 -[start]-> 2124|cmd|0 -> whoami, ARP, ipconfig, PING
    +127.854s  4452|unknown|0 -[start]-> 1996|cmd|0 -> taskkill, certutil (+127.9s),
               4360|cmd|0 -> 4128|agent|0 (+143.9s)
    +163..194s 4128|agent|0 -> 10 x powershell -> reg x6, netsh
    +184.7s    4128|agent|0 -> 4320|cmd|0 -> WinBrute
    +204.7s    4128|agent|0 -> 4772|cmd|0 -> nbtscan
    +215..225s 4128|agent|0 -> 2284|cmd|0 -> PAExec ; 3988|cmd|0 -> PAExec

=== tree 2: entry point 3492|unknown|0 at +50172s | tactics [c2, discovery, lateral-movement]
    | prize 100.0 cost 34.0 | collected 10, dropped 36
    cmd -> net, certutil, WMIC, systeminfo, tasklist  (14 h despues; hipotesis competidora, rango 2)
```
