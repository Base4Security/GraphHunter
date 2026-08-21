# Subgraph matching: dónde estamos vs. el estado del arte

**Fecha:** 2026-08-16
**Propósito:** nivelar la maquinaria de matching de GraphHunter contra las
soluciones conocidas al problema NP-completo de subgraph isomorphism, e
identificar qué integrar. Todo lo "nuestro" está anclado a `archivo:línea`.
Las citas externas llevan `[V]` = verificar contra fuente primaria antes de
usar en el paper (venue/año de memoria, no confiar).

---

## 0. Primero: cuál es *nuestro* problema, exactamente

No resolvemos subgraph isomorphism clásico. Resolvemos **matching de
patrones sobre un grafo dirigido, tipado y temporal**, que es una variante
con tres diferencias que importan para elegir algoritmo:

1. **Homomorfismo con perilla de inyectividad, no isomorfismo puro.** Por
   defecto un vértice del patrón puede mapear a cualquier vértice del dato;
   `k_simplicity` (`hypothesis.rs`) acota cuántas veces un mismo vértice del
   dato puede reaparecer en un camino. k=1 ≈ camino simple (inyectivo);
   k>1 permite reuso. El SI clásico exige inyectividad global (all-different
   sobre todos los vértices) — nosotros la relajamos a propósito.

2. **Orden temporal parcial.** Cada arista tiene timestamp; un match válido
   exige monotonía causal `τ(eᵢ₊₁) ≥ τ(eᵢ)`, relajable por δ (skew) y por
   gaps ≤ g (logs perdidos). Esto es una restricción que el SI clásico no
   tiene y que **poda muchísimo** — es nuestra mayor ventaja estructural.

3. **Predicados tipados en vértices y aristas.** `User -[Auth {error=...}]->
   IP {geo="AR"}`. Filtros de igualdad/regex/in sobre metadata, no solo
   compatibilidad de etiquetas.

**Consecuencia:** la literatura de SI puro (VF3, Glasgow) optimiza para lo
que a nosotros nos sobra (inyectividad global sobre grafos densos sin
tiempo) y no modela lo que a nosotros nos define (el orden temporal). La
literatura que más nos aplica es la de **join worst-case-optimal** +
**temporal motif matching**. Lo digo al principio porque cambia qué vale la
pena integrar.

---

## 1. Qué tenemos hoy (auditado)

### 1.1 Motor de ejecución: DFS backtracking con podas + operadores especializados

Entry point `search_temporal_pattern` (`graph.rs:1125`). Un **planner**
(`planner.rs`) elige operador físico:

| Operador | Cuándo | Estado |
|---|---|---|
| **DFS backtracking** | default, cualquier forma | maduro; AMAC-interleaved + prefetch (`dfs_match_amac_chunk`), variante anomaly-ranked con poda A* admisible (`dfs_match_smart`, `graph.rs:~2100`) |
| **LFTJ (Leapfrog Triejoin)** | 4-clique homogénea, tras `GRAPHHUNTER_LFTJ_PLANNER=1` | worst-case-optimal, `lftj.rs`; **off by default**; K5/C6 solo cuentan, no enumeran |
| **Yannakakis** | CQ acíclica, `GRAPHHUNTER_YANNAKAKIS=1` | `yannakakis.rs`; memoización de bags |

### 1.2 Podas (filtering) — esto es lo fuerte

En orden de aplicación en `search_temporal_pattern` (`graph.rs:1197-1237`):

1. **NLF (Neighborhood Label Filter)** — `nlf.rs`. Histograma de etiquetas a
   1 hop por vértice; descarta arranques que no tienen el vecino que el
   primer paso exige. O(1) por vértice. Es exactamente el filtro NLF de la
   familia TurboISO/CFL.
2. **k-hop reachability (D5)** — `khop_reach.rs`. Bitmap de tipos alcanzables
   en ≤ MAX_DEPTH hops + cotas temporales `min_first/max_first`. Descarta
   arranques que no pueden llegar al tipo final. Es una condición necesaria
   de alcanzabilidad etiquetada, no del path completo.
3. **Semi-join bidireccional (D2-lite)** — `semijoin.rs`. Para cadenas
   lineales, dos pasadas (forward + backward) de semi-join sobre bitsets de
   candidatos por posición. **Es la fase de poda de Yannakakis restringida a
   cadenas.** Verifica la secuencia alternante tipo/relación completa —lo que
   NLF y k-hop no hacen— pero **no aplica la restricción temporal** (la valida
   el DFS después). Default ON.
4. **Symmetry breaking (B9)** — `symmetry::analyze` (`graph.rs:1237`). Para
   cadenas palindrómicas fuerza dirección canónica y halva el output.
5. **Poda temporal por adyacencia ordenada** — `edge_range_sid`
   (`graph.rs:2673`): CSR ordenado por `(src, ts)`, `partition_point` da el
   piso temporal en O(log deg) en vez de escanear O(deg). Es el sucesor
   temporal por binary search.
6. **Poda A* admisible top-k** (solo `dfs_match_smart`): completitud
   optimista, poda ramas que probadamente no entran al top-k por score.

### 1.3 Lo que NO tenemos (confirmado por grep, no por memoria)

- **Sin reordenamiento dinámico de variables.** El DFS recorre los pasos en
  orden de autoría. No hay ordenamiento por conectividad-a-lo-ya-mapeado
  (RI), ni por cardinalidad de candidatos (DAF/CFL), ni cost-based.
- **Sin conflict-directed backjumping ni nogood learning** (Glasgow). El
  backtrack es cronológico: falla el paso i, vuelve a i-1, aunque la causa
  real esté en i-3.
- **Enumeración por escaneo, no por intersección** en el DFS. Iteramos
  vecinos y testeamos; no intersectamos listas de candidatos ordenadas. La
  intersección worst-case-optimal solo existe en el path LFTJ (off, y solo
  para clique/ciclo).
- **Sin índice de candidatos comprimido** estilo CECI/CFL (auxiliary data
  structure que materializa las regiones candidatas una vez y las reusa).
- **Sin propagación de all-different** (arc-consistency / counting). La
  inyectividad se chequea puntualmente con un scan lineal sobre el path
  (`graph.rs:~2074`), no se propaga como restricción.

---

## 2. El estado del arte, por familia

### 2.1 Tree-search + reglas de factibilidad
Ullmann (1976) → **VF2** (Cordella et al. `[V TPAMI 2004]`) → **VF3**
(Carletti et al. `[V TPAMI 2018]`). Estado de mapeo parcial + reglas de
factibilidad (core / look-ahead 1-2 niveles). VF3 agrega clasificación de
nodos y un **orden de matching precomputado** por probabilidad/rareza, y
gana en grafos densos y grandes. **Relevancia para nosotros: media.** Las
reglas de look-ahead de VF3 son una versión de nuestras podas; su orden
precomputado es justo lo que nos falta (§1.3).

### 2.2 Orden estático por conectividad
**RI / RI-DS** (Bonnici et al. `[V BMC Bioinformatics 2013]`). Casi sin
estructuras auxiliares; toda la fuerza está en un **orden de variables** que
prioriza vértices del patrón muy conectados a los ya mapeados. Barato y
sorprendentemente competitivo. **Relevancia: alta** — es el cambio de mayor
impacto/menor costo que podríamos hacer (ver §4.1).

### 2.3 Filter → Order → Enumerate (la línea mainstream)
GraphQL (2008) → **TurboISO** (Han et al. `[V SIGMOD 2013]`, candidate
region + clases de equivalencia de vecindario) → **CFL-Match** (Bi et al.
`[V SIGMOD 2016]`, descomposición core-forest-leaf, posterga el producto
cartesiano de las hojas) → **CECI** (`[V SIGMOD 2019]`, compact embedding
cluster index) → **DAF / DP-iso** (Han et al. `[V SIGMOD 2019]`, DP entre
árboles-de-camino + **failing-set pruning** + orden de matching adaptativo).
El estudio empírico canónico es Sun & Luo `[V VLDB 2020]` "In-Memory
Subgraph Matching: An In-depth Study", que muestra que **la combinación
filtro+orden+intersección** domina, no un algoritmo puntual.
**Relevancia: alta.** El *failing-set pruning* de DAF es un primo pobre-
hombre del backjumping que podríamos adaptar; el índice de candidatos de
CECI/CFL es lo que reemplazaría nuestro escaneo por intersección.

### 2.4 Constraint programming
**Glasgow Subgraph Solver** (McCreesh et al. `[V]`). Modela SI como CSP:
variable por vértice del patrón, dominio = candidatos, restricción
all-different + adyacencia. Propagación **counting-based** (cuenta vecinos
por grado/etiqueta para podar dominios), **conflict-directed backjumping**,
**restarts + nogood recording**. Es el más robusto en instancias difíciles
(grafos con mucha simetría, no-match caros). Soporta induced/non-induced y
largest-common-subgraph. **Relevancia: media-alta** — su backjumping y
propagación son exactamente nuestros dos huecos más grandes, pero portar el
paradigma CSP entero es caro y choca con el orden temporal (habría que
modelar el tiempo como restricción, no trivial).

### 2.5 Worst-case optimal joins (WCOJ) — nuestra familia natural
NPRR (2012) → **Leapfrog Triejoin** (Veldhuizen `[V ICDT 2014]`) → Generic
Join (Ngo et al.) → factorized DBs (Olteanu-Závodný) → **EmptyHeaded**
(Aberger et al. `[V SIGMOD 2017]`, WCOJ + intersección SIMD) → GraphflowDB /
extensiones temporales. Cota AGM: enumeran en tiempo óptimo respecto del
tamaño máximo posible del output, **sin materializar productos intermedios**
— clave en patrones cíclicos (triángulos, cliques) donde el join binario
explota. Yannakakis (1981) cubre el caso acíclico en O(|D|+|OUT|).
**Relevancia: máxima.** Ya tenemos LFTJ (`lftj.rs`) y Yannakakis
(`yannakakis.rs`), pero **apagados y de alcance angosto**. Este es el eje
donde ya estamos en la cancha correcta; falta activar y ampliar.

### 2.6 Temporal-specific (lo que casi nadie combina con lo anterior)
Motifs temporales: Kovanen et al.; **Paranjape-Benson-Leskovec**
(`[V WSDM 2017]`, conteo de motifs con ventana δ); **Mackey et al.**
(`[V 2018]`, backtracking cronológico para subgraph iso temporal);
Redmond-Cunningham. El δ-temporal window de esta línea **es exactamente
nuestro WITHIN/SKEW/GAP**. **Relevancia: máxima y es nuestra oportunidad de
contribución**: casi toda la literatura de SI ignora el tiempo, y casi toda
la de temporal motifs cuenta en vez de enumerar-con-predicados-tipados.
Nosotros hacemos las dos cosas. Ese cruce es el hueco publicable.

---

## 3. Nivelación: dónde estamos ahead / level / behind

| Dimensión | GraphHunter | SOTA | Veredicto |
|---|---|---|---|
| Poda por vecindario (NLF) | ✅ `nlf.rs` | TurboISO/CFL | **level** |
| Poda alcanzabilidad etiquetada | ✅ k-hop `khop_reach.rs` | DAF path-trees | level (los path-trees de DAF son más finos) |
| Poda secuencia completa | ✅ semi-join `semijoin.rs` | Yannakakis full | level en cadenas, **behind** en grafos |
| WCOJ / intersección | ◐ LFTJ off, clique-only | EmptyHeaded, Graphflow | **behind** (tenemos el motor, apagado) |
| Orden de variables | ⛔ fijo | RI, DAF, VF3 | **behind** — hueco #1 |
| Backjumping / nogoods | ⛔ cronológico | Glasgow, DAF failing-set | **behind** — hueco #2 |
| Índice de candidatos | ⛔ escaneo | CECI/CFL/CECI | **behind** |
| **Restricción temporal** | ✅ δ, gaps, WITHIN | casi nadie | **ahead** |
| **Predicados tipados** | ✅ metadata pred. | pocos | **ahead** |
| Explicabilidad | ✅ path = cadena de anclas | n/a | **ahead** (decisión de diseño) |

Resumen honesto: **estamos level en filtering, ahead en lo temporal/tipado,
y behind en ordering + búsqueda inteligente (backjumping) + intersección
activada.**

---

## 4. Qué integrar — propuestas rankeadas por impacto/costo

### 4.1 Orden de variables por conectividad (estilo RI) — **ALTO impacto, BAJO costo**
El cambio de mejor ratio. Hoy recorremos los pasos en orden de autoría; RI
demuestra que reordenar el patrón para expandir primero por los vértices más
restringidos (más conectados a lo ya mapeado, menor cardinalidad de
candidatos) recorta el árbol de búsqueda drásticamente, sin estructuras
nuevas. Para nosotros: reordenar los `steps` (o elegir el vértice de arranque
y la dirección de expansión) usando las estadísticas que **ya calculamos**
(NLF histogram, k-hop, cardinalidad de `type_index`). Cuidado: el reorden
debe respetar la cadena temporal — no es libre como en SI puro. Cae en
`planner.rs` + la selección de `start_sids`. Es el ítem "reordenamiento
dinámico de poda" que la hoja de ruta marcó como hueco genuino.

### 4.2 Activar y ampliar WCOJ (LFTJ/Yannakakis) — **ALTO impacto, MEDIO costo**
Ya está construido y apagado (patrón built-not-wired). Dos frentes:
(a) que el planner enrute a Yannakakis toda CQ acíclica por default cuando
gane (no solo bajo env flag); (b) ampliar LFTJ más allá de la 4-clique
homogénea — que consulte los filtros de tipo por paso (hoy no lo hace,
`planner.rs:27-31`) para poder enrutar ciclos y patrones densos generales.
Este es el eje donde el paper puede reclamar "worst-case-optimal temporal
matching", que casi nadie tiene.

### 4.3 Failing-set / conflict-back-jumping liviano (estilo DAF) — **MEDIO impacto, MEDIO costo**
No hace falta el CSP entero de Glasgow. El *failing-set pruning* de DAF es
adaptable: cuando un paso falla, registrar qué vértices ya-mapeados
causaron la falla y saltar el backtrack por encima de los que no
contribuyeron. Encaja en el DFS actual sin cambiar el paradigma. Ataca
directo el hueco #2.

### 4.4 Índice de candidatos comprimido (estilo CECI) — **MEDIO impacto, ALTO costo**
Materializar las regiones candidatas una vez por query y enumerar por
intersección en vez de escaneo. Es el cambio más grande; probablemente no
vale hasta medir (D3.1 de la hoja de ruta: ¿dónde se rompe el DFS hoy?).
**Diferir hasta tener el benchmark de techo real.**

### 4.5 Encuadre temporal como contribución — **para el paper, no es código**
El cruce §2.6 (enumeración temporal tipada con δ/gaps) es donde la
literatura tiene el hueco. Posicionar el motor ahí —no como "otro SI solver"
sino como "temporal typed subgraph matching con tolerancias de deployment"—
es la jugada de framing del Paper A. RI/Glasgow/DAF van al related work como
lo que optimizan (inyectividad global sin tiempo) y por qué no es nuestro
caso.

---

## 5. Recomendación de orden

1. **4.1 (orden de variables)** — mayor impacto por unidad de esfuerzo, cae
   en el planner, respeta la cadena temporal. Empezar acá.
2. **4.2 (activar WCOJ)** — desbloquea el claim fuerte del paper; ya está
   construido.
3. **Medir** (D3.1) antes de 4.3/4.4 — no optimizar la búsqueda sin saber
   dónde se rompe hoy. El harness de benchmarks (`docs/BENCHMARKS.md`,
   `bench --plant N`) es la herramienta para eso: ya mide latencia vs escala
   con y sin señal plantada.
4. **4.3 (failing-set)** solo si la medición muestra que el backtrack
   cronológico es el cuello.
5. **4.4 (índice de candidatos)** diferido hasta que 1-3 no alcancen.

## 6. Medición D3.1 — dónde se rompe el DFS hoy (2026-08-16)

Ejecutado antes de optimizar, con `bench --sweep` (ER a grado medio fijo
10, L=3, escala pura sin señal, 15 corridas/punto, release, en este host
— Ryzen 5 PRO 5650U, ver `reference_bench_host`).

| n | aristas | p50 | p95 | mem approx |
|---|---:|---:|---:|---:|
| 1K | 9.925 | 133 µs | 215 µs | 4,7 MB |
| 5K | 49.522 | 841 µs | 1,3 ms | 23 MB |
| 10K | 99.870 | 1,9 ms | 12 ms | 47 MB |
| 25K | 250.613 | 7,5 ms | 9,8 ms | 118 MB |
| 50K | 500.185 | 18 ms | 22 ms | 235 MB |
| 100K | 999.037 | 33 ms | 48 ms | 470 MB |
| 250K | 2.498.604 | **121 ms** | 134 ms | 1,17 GB |

**Hallazgos:**

1. **La latencia crece ~O(|E|^1,2), ligeramente superlineal.** Aristas ×251
   (10K→2,5M), p50 ×908 (133µs→121ms). No es densificación (grado medio
   fijo en 10): es crecimiento real del trabajo de búsqueda.
2. **El cuello es el trabajo de búsqueda (scan), no la memoria ni la
   emisión.** `approx_memory` sobreestima ~15× (usa 470 B/arista; el CSR
   real es ~32 B), así que la RAM real a 2,5M aristas es ~80-100 MB, no 1,17
   GB — memoria no es la restricción. Y emitir 20 caminos plantados agrega
   ~6µs sobre el scan de un grafo de 1K: **el scan domina, la emisión no.**
3. **Techo interactivo:** p50 < 100 ms hasta ~200K nodos / 2M aristas. Para
   el objetivo E3 CADETS del plan (2,855M nodos / 5,893M aristas),
   extrapolando ~O(E^1,2): **una consulta de 3 hops ≈ 340 ms p50** — al
   límite de interactivo; un catálogo de 20-30 hipótesis ≈ 7-10 s.
4. **Límite del arnés:** el generador ER es O(n²) en el doble loop, así que
   barrer más allá de ~250K queda dominado por la *generación*, no por el
   search. Para empujar el barrido más arriba hace falta un generador
   sparse.

**Conclusión que fija el orden:** el lever es **achicar el árbol de
búsqueda**, no la memoria. Eso valida arrancar por **#4.1 (orden de
variables)** — es exactamente lo que reduce el trabajo que acá crece
superlinealmente. La medición confirma la recomendación de §5.

## 7. Incremento 1 hecho + medición del gate del incremento 2 (2026-08-16)

**Incremento 1 (Diseño C) — hecho** (`4308e0c`). `selectivity_join_tree`
reemplaza el orden GYO por uno greedy por cardinalidad de bag para
hipótesis forma-Graph, dentro de `enumerate_tree`. Result-set preservado
(gate por test de paridad en 3 órdenes + el star end-to-end). De paso se
tapó un panic latente de `JoinTree::build` en hipergrafos desconectados.

**Medición estructural del catálogo (gate del incremento 2).** Antes de
construir la reversión de cadenas (incremento 2, con su CSR temporal
inverso nuevo), medí qué fracción de los 32 patrones del catálogo built-in
—los que los analistas corren— son *tail-rare* (destino más selectivo que
origen, único caso donde la reversión rinde).

| Clase | Patrones | Reverse rinde? |
|---|---|---|
| **Forma-Graph** (donde ayuda el incremento 1) | **0 de 32** | — el catálogo es 100% cadenas |
| Head-anchored (User→…→tipo abundante) | 001,002,003,004,012,029,032 | no-op |
| Simétricas por tipo (P→P, Host→Host, U→…→U) | 007,008,010,011,013,014,015,016,024 | depende de predicados/corpus, no del tipo |
| Single-step (n=1, nada que reordenar) | 017-023,026-028,031 (~10) | N/A |
| **Potencialmente tail-rare** | 005,006,025 | **sí — un puñado, y aun así depende del corpus** |

**Conclusión (disciplina antes de construir):**

1. **El catálogo no tiene ni un patrón forma-Graph**, así que el incremento
   1 es un no-op sobre todo lo shipeado hoy — su beneficio es *latente*,
   listo para cuando se autoren hipótesis estrella/árbol (el DSL todavía no
   las expresa, ver docstring de `yannakakis.rs`). No es esfuerzo tirado:
   de-riesga el operador Yannakakis (ítem #2) y tapó un panic real.
2. **El catálogo es abrumadoramente head-anchored o simétrico.** Las
   cadenas genuinamente tail-rare son 3 de 32, y aun esas dependen de que
   el corpus haga raro al tipo destino. **Esto confirma el prior del panel:
   el incremento 2 (reversión + índice inverso, contra una postura de
   memoria sensible) sería no-op en la gran mayoría y ayudaría a un puñado.**
3. **Recomendación revisada:** *no* construir el incremento 2 sobre esta
   evidencia. El lever real contra el cuello medido O(|E|^1.2) es el **ítem
   #2 (activar/ampliar WCOJ)** — LFTJ es worst-case-optimal y ataca los
   patrones densos/cíclicos donde el join binario explota, que es
   exponent-facing, no re-enraizado de constante. El usuario ya lo rankeó
   siguiente.

*Salvedad honesta:* esta medición usa un prior de selectividad por tipo
(qué tipos son raros en grafos de amenazas), no cardinalidades medidas. El
número definitivo necesita instrumentar el corpus AD-CAP en vivo. Pero la
señal es lo bastante fuerte —0 formas-Graph, 3/32 tail-rare— como para
desprioritizar el incremento 2 sin ese número.

## 8. Verificación adversarial de WCOJ (2026-08-16) — el ítem #2 se invierte

Fui a **activar** WCOJ (ítem #2). La auditoría lo dio vuelta.

**Primero, el roadmap estaba desactualizado:** WCOJ no está apagado. Las dos
apps shipeadas prenden `LFTJ_PLANNER`, `K4_LFTJ` y `YANNAKAKIS` al arrancar
(`apps/cli/src/main.rs:108`, `apps/tauri/src-tauri/src/lib.rs:65`).

**Segundo, no existía ni un test de paridad.** Los tests verificaban que el
planner *enrutara*, nunca qué *devolvía*. Escribí los que faltaban
(`core/graph-engine/tests/lftj_dfs_parity.rs`) y encontraron el defecto de
fondo.

### 8.1 Arreglado: "la forma no es la intención" (`c9dad27`)

Una cadena homogénea de 6 pasos `T -[r]-> T` es la forma normal de escribir
"un camino de 6 saltos", y también la cantidad de aristas de un 4-clique. El
planner despachaba por esa coincidencia **sola**, así que en configuración
de producción quien pedía un camino recibía **cliques**. Igual a 3 pasos
(triángulo) y 10 (K5). El planner con costos era peor: usaba `||`, así que
la forma sola habilitaba al operador como candidato.

Las rutas estructurales ahora exigen el marcador explícito del autor además
de la forma — patrón que **ya existía** en `is_homogeneous_c6_shape` y que
las otras tres rutas se habían salteado.

### 8.2 Arreglado: el batch perdía δ y gaps (`569384f`)

`run_hunt_batch` (`platform/api/src/operations/hunt.rs:540`) llamaba al
planner directo, salteando el guard que impide enrutar hipótesis con δ>0 o
g>0 a operadores que ignoran esas tolerancias. La rama Yannakakis del mismo
batch tenía el mismo hueco por otra razón: **reimplementa**
`yannakakis_dispatch` en espacio de API en vez de llamarlo, y la copia se
había desincronizado.

### 8.3 NO arreglado — registrado, no parcheado a ciegas

Los 4 auditores dieron **"no seguro para default-on"** en los 4 operadores.
Dos hallazgos quedan abiertos porque tocarlos requiere decisiones de diseño:

1. **Las rutas name-marker no verifican forma alguna.**
   `looks_like_triangle()` (`platform/dsl/src/hypothesis.rs:387`) es
   `name.contains("triangle")`. Una hipótesis de **un solo paso** llamada
   "Lateral pivot (triangle)" se enruta al enumerador de triángulos — y hay
   tests del repo que documentan justamente eso. Angostar esto rompería
   hipótesis autoradas existentes, así que necesita decisión de producto.

2. **La semántica temporal difiere del DFS — VERIFICADO** (2026-08-16, tests
   propios en `core/graph-engine/tests/triangle_temporal_semantics.rs`, no
   solo el reporte de la auditoría). Las cuatro se reproducen, cada una con
   un control que aísla la variable:
   - *Estrictez*: exige `t_bc > t_ab` y `t_ac > t_bc`
     (`lftj_query.rs:424,431`); el piso del DFS es no estricto. Un triángulo
     con timestamps iguales en saltos consecutivos es válido para el DFS y lo
     descarta el operador. **No es exótico:** las fuentes estampan eventos
     causalmente ordenados dentro del mismo segundo, y nuestro parser CDM
     redondea nanosegundos a segundos justamente por compatibilidad del motor.
   - *Ventana*: medio-abierta sobre la primera arista (`t_ab >= t_hi` se
     rechaza, `lftj_query.rs:409`) contra el borde superior inclusivo del DFS.
   - *Cobertura de ventana*: solo se chequea `t_ab`; `t_bc` y `t_ac` nunca.
     Un triángulo cuyas aristas 2ª y 3ª caen **fuera** de la ventana pedida se
     emite igual. **Esta sobre-reporta** — devuelve un match que la ventana
     del analista excluía — y es la más peligrosa de las dos de ventana.
   - *Multi-arista*: `MinTimestampMap` guarda solo el mínimo por par
     (`lftj_query.rs:70-72`), así que prueba **un** triple en vez de preguntar
     si **alguna** combinación de aristas paralelas respeta el tiempo. Con
     `t_ab=10`, `t_bc∈{5,20}`, `t_ac=30`, el triángulo válido (10,20,30) se
     descarta porque `min(t_bc)=5` falla. Las aristas paralelas entre el mismo
     par son la norma en telemetría real.

   **Severidad, calibrada y no asumida:** todos los casos requieren una
   hipótesis marcada explícitamente con `triangle`. Tras el fix de §8.1 una
   cadena de 3 pasos sin marcador va al DFS (fijado por un quinto test), y
   **ningún patrón del catálogo built-in es una cadena homogénea de 3 pasos**.
   O sea: el default shipeado **no** diverge en silencio; quien opta
   explícitamente por el operador rápido obtiene otra semántica temporal. Es
   una tarea de alineación de correctitud, no un incidente.

   Los tests asertan la conducta **actual** (divergente), así que alinear el
   enumerador los pondrá en rojo con un mensaje que lo explica — la divergencia
   no puede arreglarse en silencio ni reaparecer sin que nadie lo note.

**Conclusión revisada del ítem #2:** no ampliar el ruteo a WCOJ. El
prerequisito es alinear la semántica temporal de los enumeradores con la del
DFS y hacerlos conscientes de los filtros por paso. **Angosto le gana a
incorrecto.**

## 9. Alineación de la semántica temporal (2026-08-16) — `575e44f`

**Las cuatro divergencias del triángulo están cerradas.** El enumerador de
triángulos responde ahora la misma pregunta temporal que el DFS.

| # | Antes | Ahora |
|---|---|---|
| 1 Estrictez | `>` estricto | `≥`, como el piso del DFS |
| 2 Ventana | `[lo, hi)` | `[lo, hi]` inclusivo — **corregido en los 10 sitios**, incluidos K4/K5/C6 |
| 3 Cobertura | solo `t_ab` | **todas** las aristas |
| 4 Multi-arista | solo el mínimo por par | `successor(par, piso)` sobre **todas** las paralelas |

La pieza estructural es `MinTimestampMap::successor`: además del mínimo,
guarda todos los timestamps por par (CSR paralelo al trie) y devuelve el
menor ≥ un piso. Los enumeradores lo recorren *greedy*, que es óptimo para
una restricción de cadena — tomar la arista admisible más temprana en cada
paso deja el rango más ancho para el siguiente, así que si el greedy falla
ninguna otra elección funciona. `successor` subsume además el arreglo 1,
porque "≥ el piso" **es** la comparación no estricta.

Costo honesto: `ts_values` guarda un `i64` por **arista** en vez de uno por
par. No hace falta ordenar — la adyacencia streaming ya está ordenada por
timestamp, así que cada par queda ascendente por construcción (con
`debug_assert` para que el invariante no se pudra en silencio).

**El gate es una referencia independiente por fuerza bruta**, escrita en el
archivo de tests sin compartir código con ningún enumerador. El test
preexistente `lftj_matches_naive_baseline` compara cuatro implementaciones
del **mismo** predicado: sirve para un error de tipeo, nunca para una
premisa compartida equivocada — y una premisa compartida equivocada es
exactamente lo que eran estos cuatro defectos. La referencia enuncia la
semántica desde cero y se contrasta sobre 40 grafos pseudoaleatorios
deterministas, densos justo en lo que rompía: aristas paralelas, timestamps
repetidos y ventanas.

**Una aserción preexistente tuvo que cambiar, y la razón importa.** El test
base afirmaba que partir el rango temporal y unir los resultados de las
sub-ventanas reconstruye el total. Eso valía **solo** porque la ventana se
aplicaba únicamente a `t_ab`, de modo que cada triángulo caía en exactamente
una sub-ventana sin importar dónde estuvieran sus otras aristas — o sea, la
propiedad era un *síntoma* de la divergencia 3. Con la ventana en todas las
aristas, un triángulo que cruza el borde no cae en ninguna mitad y la unión
es un subconjunto estricto. El DFS se comporta igual. La aserción ahora
verifica **solidez** (ninguna sub-ventana puede reportar un triángulo que el
rango completo no tenga) en vez de completitud.

### 9.1 Alcance y lo que queda abierto

Esto alinea el **triángulo**. K4/K5/C6 reciben el arreglo 2 (el patrón de
ventana compartido) pero **siguen con 1, 3 y 4**, y permanecen apagados por
flag.

Y la auditoría encontró un quinto defecto **solo en K4**, que bloquea su
arreglo de estrictez: las variantes SIMD **carecen de las guardas de
distinción** que sí tiene la baseline naive (`c != b`, `d != b && d != c`).
Hoy las comparaciones estrictas las enmascaran por accidente — un `d == b`
fuerza `t_ad == t_ab`, que la desigualdad estricta rechaza. **Relajar la
estrictez en K4 sin agregar esas guardas haría aflorar tuplas degeneradas
con self-loops** que la variante naive rechaza, rompiendo la paridad entre
variantes. El arreglo de estrictez de K4 debe shipear junto con las guardas
explícitas.

## Apéndice: citas a verificar antes del paper
Todas las marcadas `[V]` arriba — VF2/VF3 (TPAMI), RI (BMC Bioinformatics
2013), TurboISO (SIGMOD 2013), CFL-Match (SIGMOD 2016), CECI (SIGMOD 2019),
DAF/DP-iso (SIGMOD 2019), Sun & Luo (VLDB 2020), Glasgow Subgraph Solver
(McCreesh et al.), Leapfrog Triejoin (Veldhuizen, ICDT 2014), EmptyHeaded
(SIGMOD 2017), Paranjape-Benson-Leskovec (WSDM 2017), Mackey et al. (2018).
Verificar venue/año/autores contra fuente primaria — están de memoria.
