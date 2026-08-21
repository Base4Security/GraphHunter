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

## Apéndice: citas a verificar antes del paper
Todas las marcadas `[V]` arriba — VF2/VF3 (TPAMI), RI (BMC Bioinformatics
2013), TurboISO (SIGMOD 2013), CFL-Match (SIGMOD 2016), CECI (SIGMOD 2019),
DAF/DP-iso (SIGMOD 2019), Sun & Luo (VLDB 2020), Glasgow Subgraph Solver
(McCreesh et al.), Leapfrog Triejoin (Veldhuizen, ICDT 2014), EmptyHeaded
(SIGMOD 2017), Paranjape-Benson-Leskovec (WSDM 2017), Mackey et al. (2018).
Verificar venue/año/autores contra fuente primaria — están de memoria.
