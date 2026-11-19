# ¿Sirve Graph Hunter usado por MCP? Evaluación medida

Fecha: 2026-11-16. Rama: `feat/headless-server`.

La pregunta era si Graph Hunter, usado por un agente a través de MCP, aporta
algo que el mismo agente no consiga consultando los logs crudos con SQL
(DuckDB). Se respondió midiendo, no razonando: datasets sintéticos con una
intrusión plantada cuya verdad se conoce, las mismas preguntas por los dos
caminos, y arreglando lo que la medición fue mostrando. Todo es reproducible
con `scripts/eval/` (ver el final).

## Respuesta corta

- **Para una sola fuente, DuckDB gana** en velocidad y peso por dos órdenes de
  magnitud, y responde bien. Graph Hunter no compite ahí ni debería.
- **Tal como estaba al empezar, Graph Hunter no era confiable**: su función
  distintiva (caza por caminos) devolvía cadenas que no ocurrieron, y la
  consulta que más justifica un grafo —cruzar fuentes en un nodo común— daba
  error 500.
- **Después de los arreglos de esta rama, responde bien las dos cosas**: la
  atribución que fallaba y la correlación entre tres fuentes con un patrón de
  una línea. Su ventaja real frente a SQL no es la respuesta (DuckDB llega a la
  misma) sino que el patrón no depende del esquema de cada fuente, el ranking de
  rarezas sale sin escribir nada, y hay sesión persistente y journal.
- **Sigue siendo lento y pesado** al ingerir, y sin identificador de instancia
  de proceso la atribución de usuario no es confiable.

## Método

Dos escenarios, ambos sintéticos (rangos IP de documentación, dominios
`example`).

**Una fuente.** 300.000 eventos tipo Sysmon de 220 equipos y 180 usuarios, con
ruido deliberadamente parecido al ataque (administradores que corren
`powershell`, `cmd`, `net use`; Outlook y Chrome resolviendo DNS). Intrusión
plantada: phishing en `WS-042` con `user042`, robo de credenciales, PsExec a
`SRV-07` con `svc-backup`, dropper, beacon y C2. Dos variantes: sin y con
`ProcessGuid` (Sysmon real siempre lo trae).

**Tres fuentes.** El mismo incidente (60.000 eventos Sysmon) más un firewall
perimetral que sólo conoce IPs (40.002 flujos) y un proveedor de identidad que
nombra a los usuarios `usuario@corp.example` (8.004 inicios de sesión). La IP
de C2 `203.0.113.42` es respuesta DNS y destino en Sysmon, destino en el
firewall y origen de un inicio de sesión de `svc-backup` en el IdP.

Los usuarios no están atados a un equipo: cualquier equipo ve a muchos. Es el
caso difícil para atribuir (servidores compartidos, jump hosts); en estaciones
de un solo usuario varios de los problemas de abajo pesan menos.

## Mediciones

### Una fuente, 300.000 eventos

| | Graph Hunter al empezar | Graph Hunter ahora (con `ProcessGuid`) | DuckDB |
|---|---|---|---|
| Carga | 26–29 s, 191 MB | 62–66 s, ~830 MB | 0,4 s |
| ¿Quién corrió el proceso que consultó el C2? | 10.000 caminos truncados; **un usuario equivocado, distinto en cada corrida** | 6 caminos, **sólo `user042`** | 1 fila correcta, 0,02 s |
| Artefactos raros (`top_anomalies`) | 10/10 | 10/10 | 4/4 con un `GROUP BY` |
| Movimiento lateral | sale primero | sale primero (6.755 aristas; ver muestreo) | árbol completo con línea de comandos |
| Hunt con scoring de anomalía | timeout y servidor colgado | 1,7 s | — |

Sin `ProcessGuid` el id cae a `equipo|imagen`: ya no mezcla equipos ni trunca,
pero atribuye el C2 a 19–30 usuarios, porque varios corren la misma imagen en
el mismo equipo.

Costo de escribir la consulta: para llegar a las respuestas de DuckDB hubo que
corregir la sintaxis SQL tres veces; el hunt es una línea. Es un costo real de
la vía SQL, aunque menor.

### Tres fuentes

| | Graph Hunter al empezar | Graph Hunter ahora | DuckDB |
|---|---|---|---|
| Carga | 28 s | 25 s | 0,4 s |
| Flujos del firewall visibles como `IP → IP` | 5.480 de 40.002 | 40.002 | todos |
| `svc-backup` | dos nodos (`corp\svc-backup` y `svc-backup@corp.example`) | un nodo (con el alias de dominio declarado) | hay que saber unirlos |
| «Cuenta que inició sesión desde una IP a la que también se conecta un equipo interno» | **error 500** | 1 resultado, el plantado, 0,01–0,04 s | 1 fila correcta, 0,06 s |
| Lo que hay que saber para preguntarlo | — | tipos y relaciones del grafo | qué columna es la IP en cada fuente, y desarmar `QueryResults` |

El patrón en Graph Hunter:

```
User u -[Auth]-> IP i; Domain d -[Resolve]-> IP i; Process p -[DNS]-> Domain d
```

devuelve `svc-backup@corp.example · 203.0.113.42 · c2.badactor.example ·
beacon.exe`. El equivalente en SQL son unas 15 líneas con un `UNION` por fuente.

Persistencia: guardar la sesión de tres fuentes tarda 0,2 s; tras reiniciar el
servidor se recarga en 0,4 s y los hunts dan lo mismo. El journal registró los
17 pasos de la sesión.

## Qué estaba mal y qué se hizo

Cada punto se encontró midiendo y tiene un test que lo fija.

### Bloqueantes para usarlo por MCP

1. **Dependía de la app abierta.** El servidor HTTP vivía dentro del crate de
   Tauri. Se extrajo a `platform/server` (binario `graph-hunter-server`); la app
   embebe el mismo router y comparte el arranque
   (`graph_hunter_server::bootstrap`), de modo que no pueden divergir.
2. **El MCP no podía levantar nada.** Con `GRAPHHUNTER_SERVER_BIN`, el MCP
   arranca el servidor, genera el token y lo apaga al salir.
3. **Un hunt lento colgaba el servidor.** El timeout sólo dejaba de esperar; la
   búsqueda seguía bajo el lock del grafo y ni `/health` respondía. Se agregó
   cancelación cooperativa en el motor (`graph_hunter_core::cancel`); ahora
   devuelve 504 y libera. No cubre los operadores LFTJ ni el de huecos.
4. **Resultados del hunt anterior.** Tras un hunt fallido, `hunt_results`
   seguía sirviendo los caminos viejos. Ahora queda vacío.

### Respuestas equivocadas

5. **Identidad de `Process`.** El id era la ruta de la imagen: `powershell.exe`
   era un nodo para toda la red y un camino unía aristas reales de equipos
   distintos. Ahora es `equipo|guid|imagen`, con `equipo|imagen` si la fuente no
   identifica la instancia (`process_identity`).
6. **`ProcessGuid` como nodo.** El mapeo automático convertía cada GUID en un
   nodo `Process`; el top de anomalías pasaba a ser sólo GUIDs.
7. **Rareza por instancia.** Con un nodo por ejecución, cada `cmd.exe` parecía
   raro. La rareza (estructural y del `AnomalyScorer`) se calcula por imagen.
8. **Respuestas DNS como dominios.** `QueryResults` y `QueryType` entraban como
   nodos `Domain`. Como el primer origen que nombra un id fija su tipo, las IPs
   ya resueltas quedaban tipadas `Domain` y el 86 % de los flujos del firewall
   dejaba de coincidir con `IP -[Connect]-> IP`. Ahora son aristas
   `Domain -[Resolve]-> IP`, que además es lo que une lo que ve el endpoint (un
   nombre) con lo que ve el firewall (una dirección).
9. **Muestreo del mapeo.** El mapeo de campos se armaba con los primeros ~200
   eventos. Un campo poco frecuente quedaba fuera para todo el archivo:
   `DestinationHostname` (2 % de los eventos) se perdía y con él las 6.755
   aristas `Process -[Connect]-> Host`. Ahora la muestra incluye además todo
   evento que traiga un campo no visto.
10. **Patrones convergentes rechazados.** El DSL acepta patrones unidos por
    variables (`A a -[R]-> B b; C c -[S]-> B b`) y el motor tiene el operador
    para ejecutarlos, pero la validación aplicaba la regla de cadena a todo y los
    rechazaba con «type mismatch». Es la consulta que cruza fuentes; no se podía
    ejecutar. Ahora valida según la forma y va siempre al operador que la
    entiende.
11. **Una cuenta, dos nodos.** `CORP\usuario` y `usuario@corp.example` no se
    unían. No se pueden unir adivinando (se fusionarían las cuentas locales
    homónimas de cada equipo), así que la equivalencia se declara:
    `GRAPHHUNTER_DOMAIN_ALIASES=CORP=corp.example`. Sin declarar, nada cambia.

### Señales que no llegaban al agente

12. **Pie de contexto del MCP.** No mandaba el token: 401 siempre, «(unavailable)»
    en cada respuesta. Corregido; además decía «0 nodos» hasta 30 s después de
    ingerir y listaba nueve fuentes «unknown» en cada respuesta.
13. **Advertencia de patrón no discriminante.** La API la calculaba y la capa
    HTTP la descartaba.
14. **Relaciones definidas por el usuario sin nombre.** `relation_schema` las
    listaba con nombre vacío, y es ahí donde el agente aprende qué relaciones
    existen.
15. **Búsqueda arbitraria.** `node_search` cortaba una lista sin ordenar: al
    buscar un equipo podía devolver sólo procesos de ese equipo y no el equipo.
    Ahora va primero la coincidencia exacta y el orden es determinista.
16. **El agente no conocía la sintaxis de unión.** La descripción de `hunt_run`
    sólo mostraba cadenas. Ahora explica `;` y las variables.

### Encontrados por la revisión de seguridad de los commits

17. **El patrón de grafo no se podía cancelar.** El enumerador por árbol no
    consultaba el token; un patrón sin nodo selectivo en común podía recorrer
    un producto cartesiano sin que el timeout lo detuviera.
18. **Muestra de campos sin tope.** Un log donde cada evento inventa un campo la
    volvía tan grande como el archivo. Se acotó, y al alcanzar el tope se
    registra un aviso: sin eso, rellenar un log con campos basura era una forma
    silenciosa de sacar un campo real del mapeo. El aviso todavía no llega a la
    respuesta de la ingesta.
19. **Separador dentro de un componente del id.** Una imagen registrada como
    `x|C:\Windows\System32\svchost.exe` se puntuaba con la rareza de svchost.
    El separador se codifica.

### Tests cuya expectativa cambió

No son ajustes mecánicos; conviene revisarlos.

- `graph_summary_caches_within_30s_window`: fijaba que el resumen siguiera
  desactualizado tras cambiar de sesión.
- `demo_data_all_presets_produce_results`: exigía un `Spawn` de PsExec en la
  estación a `dropper.exe` en el DC. Un `Spawn` ya no cruza de equipo; el salto
  es la arista `Connect`.
- `demo_office_spawn_sysmon`: esperaba 22 caminos; son 8. Los otros 14 iban a
  nodos basura (punto 8). Verificado a mano contra los eventos del fixture.
- 11 aserciones de id en los tests de Sysmon (`equipo|imagen`).

## Lo que sigue mal

- **Rendimiento de ingesta.** 25 s para 100.000 eventos y ~830 MB para 300.000
  con identidad por instancia. DuckDB carga lo mismo en menos de medio segundo.
  Para volúmenes grandes de una sola fuente, SQL es la herramienta.
- **Atribución sin identificador de instancia.** Con `equipo|imagen` un camino
  `User → Process → …` dice «en este equipo», no «este usuario».
- **El tipo de un nodo lo fija quien lo nombra primero.** Se arregló la causa
  que más pegaba (punto 8), pero el mecanismo sigue: dos fuentes que tipen
  distinto un mismo id cambian en silencio qué hunts coinciden. Falta, como
  mínimo, contar esos conflictos al ingerir y devolverlos.
- **Equipo ↔ IP.** No hay arista entre un equipo y su dirección, así que un
  flujo de firewall (por IP) no se une con el equipo de Sysmon salvo por el
  destino. No se agregó a propósito: `SourceIp` es la IP local sólo en
  conexiones salientes, y en eventos de autenticación `Computer` es el servidor
  y la IP es la del cliente; una regla genérica fabricaría direcciones.
- **`datasets_used`** informa 1 en los patrones convergentes aunque crucen dos o
  tres fuentes.
- **Agregaciones.** Contar, agrupar por tiempo, percentiles: Graph Hunter tiene
  herramientas fijas, no una consulta libre. Ahí SQL es más expresivo. Una
  salida razonable es exponer los eventos de la sesión a SQL en vez de competir.
- **Costo por sesión.** Las 66 herramientas eran ~18.000 tokens de definiciones
  en cada sesión. Desde los grupos de herramientas (`GRAPHHUNTER_MCP_TOOLS`) se
  cargan 21 por defecto, ~4.100 tokens. Medido en una sesión real de Claude
  Code con la misma tarea: 1,95 → 1,79 USD. El ahorro es chico porque el
  contexto de esa sesión rondaba los 97.000 tokens y casi todo lo demás venía
  del entorno del usuario (otros plugins y servidores MCP), no de Graph Hunter.
- **Sesiones guardadas antes de esta rama** conservan los ids viejos de proceso;
  hay que reingerir.
- **El paper** (`docs/paper/*.tex`) afirma ids `host\process:pid:timestamp`. No
  fue el formato del código antes ni lo es ahora; queda para la fe de erratas o
  la revisión.
- **Revisión humana pendiente** (`CLAUDE.md`): esta rama toca parsers, esquema
  de ids y el manejo del token (el launcher del MCP lo genera y lo pasa por
  entorno; `graph-hunter-server` imprime en stderr el que genera él).

## Cuándo usar cada cosa

- **Una fuente, pregunta de conteo o de filtro:** DuckDB.
- **Varias fuentes y la pregunta es «qué tienen en común»:** Graph Hunter. El
  patrón se escribe una vez y vale para cualquier fuente que mapee a los mismos
  tipos.
- **Triage inicial sin hipótesis:** `graph_summary` de Graph Hunter; el top de
  rarezas señaló los artefactos plantados sin escribir nada.
- **Investigación que dura varios días o que hay que poder auditar:** Graph
  Hunter, por la sesión persistente y el journal.

## Verificación

Motor 1057, API 667, servidor 63, DSL 35, Tauri 14, MCP 45 (2 se saltan porque
requieren una API viva), medido tras integrar `main`. rustfmt y clippy limpios en
los crates tocados; capas limpias; `cargo build --locked` del servidor y de la
app OK.

## Cómo reproducirlo

Ver `scripts/eval/README.md`. En resumen:

```bash
python scripts/eval/gen_synthetic_sysmon.py 300000 /tmp/eval/syn300k.jsonl
python scripts/eval/gen_synthetic_sysmon.py 60000  /tmp/eval/syn60k_guid.jsonl
python scripts/eval/gen_multisource.py /tmp/eval

python scripts/eval/duckdb_baseline.py /tmp/eval/syn300k.jsonl
python scripts/eval/duckdb_multisource.py /tmp/eval /tmp/eval/syn60k_guid.jsonl

export GRAPHHUNTER_API_TOKEN=local-eval GRAPHHUNTER_DOMAIN_ALIASES=CORP=corp.example
cargo run --release --manifest-path platform/server/Cargo.toml -- --ingest-root /tmp/eval &
python scripts/eval/gh_client.py load /tmp/eval/syn300k.jsonl
python scripts/eval/gh_client.py hunt "User -[Execute]-> Process -[Spawn]-> Process -[DNS]-> Domain"
python scripts/eval/gh_multisource.py /tmp/eval
```

La verdad plantada está al final de `gen_synthetic_sysmon.py` y en la cabecera
de `gen_multisource.py`. Una respuesta que nombre a otro usuario u otro equipo
es una cadena que no ocurrió.
