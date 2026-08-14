# Hoja de ruta de mejoras — auditada contra el código

**Fecha:** 2026-08-13
**Método:** cada ítem propuesto se verificó contra el árbol actual con referencias `archivo:línea`. Nada en este documento se acepta por plausibilidad.
**Evidencia de demanda:** dos ciclos de hunting reales sobre el mismo corpus AD-CAP / Keycloak (284.781 eventos, investigación CSIRT, adversario confirmado) se usan como experimento natural sobre qué bloquea la entrega de valor:

- **Ciclo 1 (2026-08-12)** — 5 fases, primera pasada.
- **Ciclo 2 (2026-08-14)** — re-hunt sobre los mismos datos con metadata de aristas, GeoIP/ASN y el fix de `events_for_node`. Resultado: ventana de la campaña 07-22→07-29 corregida a **07-11→07-31**, 4 → 20 IPs adversariales, 3 → 22 cuentas con acceso exitoso. Informe: `informes-a/2026-08-14-adcap-rehunt-hallazgos.md`.

Las filas marcadas **[C2]** abajo son huecos que el segundo ciclo obligó a rodear a mano.

---

## 0. Hallazgo central: el problema no es capacidad faltante, es capacidad sin activar

Cinco subsistemas independientes, el mismo modo de falla — **construidos, benchmarkeados y dejados apagados**:

| Subsistema | Estado real | Por qué no rinde |
|---|---|---|
| GeoIP / ASN | `core/graph-engine/src/geoip.rs` completo: MaxMind MMDB offline + fallback ip-api.com. Feature `geoip` **sí** compilada en `platform/api` y en la app Tauri | `geoip_provider` se inicializa en `None` (`platform/api/src/lib.rs:137-138`) y **nada lo bootstrapea** → `capabilities.geoip=false` (`operations/geoip.rs:36-40`) |
| SIMD / LFTJ / Yannakakis | AVX2 con dispatch en runtime (`simd_rust.rs:32`), joins worst-case-optimal, memoización de prefijos con presupuesto de bytes | Todo detrás de env flags que **default off** y exigen literal `1`/`true` (`planner.rs:481-485`) → el hunt por defecto corre DFS sin SIMD |
| GNN | Harness ONNX + DirectML completo (`core/gnn/src/npu_scorer.rs`), extracción de features, gate de calidad ≥0.80, slider W5 en UI | **No se shipea ningún `.onnx`** — `resolve_gnn_model_path` falla (`operations/anomaly.rs:116-139`) y `w5_gnn_threat` default = **0.0** |
| Active learning | `core/gnn/src/aad_training_export.rs:46-71` exporta `TrainingExample` desde `labels: HashMap<String,String>`; el docstring dice que la fuente prevista es `tag_entity` | **Solo lo llaman sus propios unit tests.** Ninguna operación, tool MCP ni ruta HTTP lo invoca |
| Metadata de aristas | `FieldRole::Metadata` existía en el FieldConfig | Era un **no-op documentado** → `metadata_keys: []` invalidó 5 de 6 patrones del catálogo en el hunt real. **Arreglado 2026-08-12** (`c7338e8`) |

Esto contradice frontalmente el principio ya establecido del proyecto: *todo trabajo de performance debe ser plug-and-play, default-on al arranque y con badge visible, sin configuración manual de entorno*.

**Consecuencia para la planificación:** la Fase 1 no debe ser "construir optimizaciones nuevas". Debe ser **activación**. Son días de trabajo para un salto de capacidad mayor que el de la Fase 1 + Fase 2 propuestas juntas.

---

## 1. Auditoría ítem por ítem

Leyenda: ✅ ya existe · ◐ parcial · ⛔ ausente · ✖ rechazado (con razón)

### 1.1 Escalabilidad y rendimiento

| Ítem propuesto | Estado | Evidencia |
|---|---|---|
| Grafos distribuidos (Spark GraphX / Faunus) | ✖ | Faunus está deprecado desde ~2015 (absorbido por Titan→JanusGraph). Además existe spill-to-mmap con presupuesto de 1 GiB (`index_storage.rs:1-30`). **Nadie midió dónde se rompe hoy.** |
| Compactación temporal automática | ⛔ | Hueco genuino. Mantener, prioridad media. |
| Búsqueda bidireccional | ◐ | El **semi-join bidireccional ya existe** como poda: pasada forward + backward sobre bitsets (`semijoin.rs:139-166`), **default ON**. Falta solo la enumeración meet-in-the-middle. El 80% barato ya está. |
| Índice compuesto temporal-tipado | ◐ | `khop_reach` ya combina alcanzabilidad por etiqueta **con cotas temporales** (`min_first`/`max_first`, `khop_reach.rs:88-93`); CSR ordenado por timestamp con búsqueda binaria (`graph.rs:2646-2651`); histograma NLF de etiquetas a 1 hop. |
| Aceleración GPU | ◐ | DirectML existe pero **solo para GNN**, opt-in, fuera de `default`. Sin CUDA. Y `w5=0`, así que hoy acelera nada. |

### 1.2 Optimización del algoritmo de búsqueda

| Ítem propuesto | Estado | Evidencia |
|---|---|---|
| Early termination k-top | ✅ | `max_results` cap (default 10.000, `graph.rs:1131`), contador `AtomicUsize` chequeado por frame del DFS (`graph.rs:2135-2137`), y min-heap acotado en `search_temporal_pattern_smart` (`graph.rs:1723`). |
| Parallel expansion por semillas | ✅ | rayon `par_iter`/`par_chunks` con umbrales (`graph.rs:1230-1284`). El "single-core" del planteo es el benchmark del paper, no el código. |
| Caching de sub-caminos | ◐ | Memoización de prefijos Yannakakis con presupuesto e invalidación por `mutation_version` (`state/session.rs:247-258`), cache de bags y de resultados canónicos. **Ausente en el DFS por defecto.** |
| Reordenamiento dinámico de poda | ⛔ | El orden es fijo (`graph.rs:2200-2251`). Existe un planner de costos pero para elegir *operador*, no para ordenar predicados. Hueco genuino, valor modesto. |
| Beam search con pruning adaptativo | ✖ | **Sería un retroceso.** Ya existe una poda estilo A\* **admisible** (`graph.rs:2038-2057`): calcula una completitud optimista y solo poda ramas que *probadamente* no entran al top-k. Beam search es lossy — cambiaría una garantía por velocidad en un camino que no es el cuello de botella. |

### 1.3 Modelado de dominio

| Ítem propuesto | Estado | Evidencia |
|---|---|---|
| Tipado extendido de entidades | ✅ | `EntityType::Other(String)` + `Any` ya existen (`platform/dsl/src/types.rs:7-21`); el `ConfigurableParser` deja asignar tipos arbitrarios. Container/Pod/API/Database ya son expresables. |
| Ingesta en streaming | ✅ | `load_data_streaming` + conector Sentinel con watermarks + `run_scoring_incremental`. |
| Sesión como entidad de primera clase (meta-grafos) | ⛔ | **Alto valor. [C2]** En el hunt real `sessionId` fue el artefacto más probatorio: la continuidad de sesión entre IPs fue la prueba estructural de operador único. El ciclo 2 lo confirmó por la vía dura: el CSV **trae** columna `sessionId`, pero el grafo solo tiene `IP`/`URL`/`User`, así que las 60.145 sesiones (12.695 multi-IP) hubo que reconstruirlas con un script sobre el crudo. Con la entidad, es una consulta: `Session -[Uses]-> IP` agrupado por sesión. |
| Aristas con rango temporal `[τ_ini, τ_fin]` | ⛔ | **Alto valor, subvalorado en el planteo.** La distinción decisiva del hunt fue *sesión sostenida de 87 min con 26 renovaciones* vs *validación rápida de 1,3 min*. Eso es literalmente una arista con duración; hoy se reconstruyó a mano. |
| Relaciones transitivas | ⛔ | Hueco genuino, sin evidencia de demanda todavía. |

### 1.4 Puntuación y priorización

| Ítem propuesto | Estado | Evidencia |
|---|---|---|
| Anomaly scoring contextual (baseline por entidad) | ⛔ | **LA brecha.** Todo es global: `log_max_freq` de todo el grafo (`anomaly.rs:150-155`), `tau_min/tau_max` globales (`:157-175`), percentiles sobre todas las entidades. Única excepción: `structural_anomalies` acepta `node_class` para z-score por grupo de pares (`analytics.rs:2397-2430`). **Esto es lo que volvió inútil a `cat-021`.** |
| Active learning | ◐ | El sustrato está construido y **colgando sin cablear** (ver §0). No es construir, es conectar. |
| Ensemble de GNN (GCN+GAT+GraphSAGE) | ✖ | Prematuro: no hay **ningún** modelo entrenado, `w5=0`, no se shipea `.onnx`, el gate rechaza <0.80 de accuracy. Ensamblar tres arquitecturas sin haber entrenado una es optimizar la variable equivocada. **El cuello de botella son los labels.** |
| XAI (SHAP/LIME) | ✖ | `explain_score` ya devuelve narrativa + desglose por componente + percentiles + pares (`analytics.rs:1289-1362`). En el hunt real se citó textual para adjudicar el BFF. SHAP sobre un modelo heurístico es innecesario; sobre un GNN inexistente, imposible. |
| Feature engineering automatizado (AutoML) | ✖ | Destruiría la explicabilidad, que es un **claim de producto fijado por test** (`tests.rs:6978-6993`: *"scoring explicable sin GNN"*). |

### 1.5 Integración con inteligencia externa

| Ítem propuesto | Estado | Evidencia |
|---|---|---|
| Feed de IoCs (STIX/TAXII/MISP) **entrante** | ⛔ | Solo existe la dirección **saliente**: `build_stix21`, `build_misp_csv` (`operations/export.rs:522,603`). `threat_intel: false` es un literal hardcodeado (`operations/geoip.rs:40`). Sin matching de IOC en ingesta y sin boost de score. |
| Mapeo MITRE ATT&CK automático | ◐ | Cada patrón del catálogo lleva `mitre_id` (T1078 etc., `catalog/mod.rs:41-55`), pero **validado solo por forma de regex** — acepta `T9999`, que no existe. Sin tácticas, sin nombres de técnica, sin export a Navigator, y no participa del scoring. |
| Export a SOAR / ticketing | ✅ | `file_ticket` → Jira/ServiceNow reales; `publish_iocs_to_sentinel` → watchlists de Azure; Sigma/OCSF/STIX/MISP como formatos. Los tres con triple gate (env + `confirm` + `dry_run`). |
| Federated learning cross-SOC | ✖ | Muy prematuro. Requiere primero tener un modelo y labels. |

### 1.6 Usabilidad

| Ítem propuesto | Estado |
|---|---|
| Generación automática de hipótesis | ✅ vía LLM cloud (`platform/api/src/ai.rs`, OpenAI/Anthropic/Google con loop agéntico) — apagado salvo que se cargue API key |
| Copilot IA | ✅ servidor MCP con ~60 tools + propuesta de hipótesis por LLM |
| Feedback loop al SOC | ✅ ver §1.5 |
| Visualización jerárquica / comparación lado a lado | ⛔ huecos de UI genuinos, no auditados en esta pasada |

### 1.7 Limitaciones críticas

| Ítem | Estado | Nota |
|---|---|---|
| Betweenness estática ignora temporalidad | ◐ real — y además **se saltea por encima de 2.000 entidades** (`platform/api/src/scoring.rs:11`), así que en grafos reales muchas veces ni corre |
| Eventos fuera de orden | ⛔ hueco genuino, barato, relevante para streaming |
| Detección de patrones emergentes (no supervisada) | ⛔ lo más cercano es el z-score de `structural_anomalies` |
| Dependencia de GNN pre-entrenado | n/a — no hay modelo |

### 1.8 Faltantes que la evidencia exige y el planteo no incluye

| Ítem nuevo | Justificación |
|---|---|
| **Guarda de precisión por patrón** | `cat-021` devolvió **4.996 caminos sobre 4.627 usuarios** y se declaró "falso positivo sistémico". Hoy existe la guarda del modo de falla **opuesto** — `check_catalog_compatibility` detecta "este patrón nunca puede matchear" (`catalog/mod.rs:105-164`) — pero nada detecta "matcheó a toda la población, o sea no discrimina". El hunt real disparó **ambos** modos de falla; solo uno estaba protegido. |
| **Resolución de identidad** **[C2]** | Entidades indexadas por string exacto; `add_entity` **rechaza** duplicados (`graph.rs:445-459`), sin tabla de alias. El parser de Sentinel elige UPN *o* DisplayName con fallback (`sentinel.rs:337-341`) → dos nodos por persona. En el hunt: 5.136 usernames / 4.627 userIds / 1.551 emails para la misma población. El ciclo 2 lo exhibió en vivo: `IMPERSONATE` y `realm_disabled` devolvieron nodos `User` con **UUID** (`29ab57e4-…`) mientras el resto de las consultas devolvía **emails** — la misma persona en dos nodos según qué campo traía el evento. Hubo que reconstruir el mapa `uuid → username` fuera de la herramienta para poder nombrar a las víctimas. |
| **Conciencia de cobertura/retención** | El hunt tuvo que anotar a mano "11 días sin evaluar". Debería ser un caveat generado por la máquina. Sustrato parcial: `ingest_coverage`, `stopped_early`. |
| **Eventos de un solo extremo desaparecen del grafo** **[C2]** | Una relación necesita dos entidades, así que un evento con IP pero sin usuario **no produce arista y es invisible a toda consulta**. En el corpus AD-CAP son 642 eventos (0,23%): 243 `LOGIN_ERROR`, 159 `LOGOUT_ERROR`, 120 `RESET_PASSWORD_ERROR`, 100 `REGISTER_ERROR`. **399 de los 401 `realm_disabled` caen ahí** — o sea que el corte del realm del 24-07, el evento de contención más importante del incidente, es inconsultable desde el grafo y hubo que ir al CSV crudo. No es un bug del ingest: es una consecuencia del modelo de datos, y hoy la pérdida es **silenciosa**. |

---

## 2. Hoja de ruta reordenada

Criterio de orden: **evidencia de demanda × costo**, no elegancia técnica.

### Track 0 — Activación (días, no semanas)

Encender lo que ya está pago. Mayor salto de capacidad por unidad de esfuerzo de todo el documento.

- **A0.1** Bootstrapear el proveedor GeoIP: shipear o resolver los `.mmdb` de GeoLite2, inicializar `geoip_provider`, badge de capacidad en UI → `geoip:true, asn:true`. *Desbloquea: caracterización de IOCs, detección de hosting/VPN, y vuelve viable el viaje imposible.*
- **A0.2** Auditar los flags default-off (`LFTJ_*`, `YANNAKAKIS`, `SEMIJOIN`, `AMAC`): benchmarkear y promover a default-on los que ganan. Cumplir el principio plug-and-play.
- **A0.3** Decidir el GNN: entrenar y shipear el `.onnx` siguiendo `docs/GNN_STRATEGY.md` Fase 1 (ya escrita: DARPA TC E3 CADETS, 2-3 semanas) **o** retirar la UI de GNN. Hoy hay superficie de producto que no hace nada.
- **A0.4** Cablear `export_training_examples` ← `tag_entity`: convierte cada engagement en corpus etiquetado. Es el sustrato de A0.3 y del active learning.
- **A0.5** ✅ Metadata de aristas — hecho 2026-08-12.

### Track 1 — Precisión analítica (lo que el hunt real pidió)

- **B1.1** Baseline contextual por entidad (rareza y novedad temporal relativas a la propia historia de la entidad, no al grafo entero). *Mata la clase de FP de `cat-021`.*
- **B1.2** Guarda de precisión por patrón: si un patrón matchea > N% de la población, marcarlo no-discriminante en vez de devolver miles de caminos.
- **B1.3** Resolución de identidad (username/userId/email → una identidad, con normalización consistente). **Decidido:** se emite como *propuesta* de fusión por API/MCP para que la confirme el analista o el asistente AI; nunca fusión automática.
- **B1.4** Sesión como entidad de primera clase + aristas con rango temporal.
- **B1.5** **Eventos de un solo extremo: dejar de perderlos en silencio.** Hoy un evento con IP y sin usuario no genera arista y desaparece sin dejar rastro. Tres piezas, en orden de costo:
  1. **Contabilizarlos.** El resumen de ingesta debe reportar `single_endpoint_events` con desglose por tipo de evento, igual que hoy reporta `double_encoded_row`. Barato, y convierte una pérdida silenciosa en un dato visible. *Esto solo ya habría evitado que el corte del realm pasara inadvertido dos ciclos.*
  2. **Hacerlos consultables.** Materializar el evento como propiedad temporal de la entidad que sí existe (una serie de eventos colgada del nodo `IP`), de modo que `events_for_node` los devuelva aunque no haya arista. No requiere cambiar el modelo de relaciones.
  3. **Evaluar la arista a entidad sintética.** `IP -[Auth {error=...}]-> Realm` cuando el evento nombra un realm/cliente pero no un usuario. Decidir recién después de (1), con el conteo real a la vista — puede no valer el ruido que agrega al grafo.

  *Evidencia: `informes-a/2026-08-14-adcap-rehunt-hallazgos.md` §8.4. 642 eventos perdidos, entre ellos 399 de los 401 `realm_disabled` del incidente.*

### Track 2 — Cerrar el loop de inteligencia

- **C2.1** STIX/TAXII/MISP **entrante** + matching de IOC en ingesta + sexto componente de score. El header de `scoring/components.rs:6` ya anticipa exactamente esto como componente futuro, y el vocabulario STIX/MISP ya está implementado del lado saliente.
- **C2.2** ATT&CK real: tácticas, nombres de técnica, validación contra el catálogo oficial (hoy acepta `T9999`), export a Navigator. Ahora es viable mapear **aristas** a TTPs porque ya llevan metadata.
- **C2.3** Buffer de reordenamiento para eventos fuera de orden.

### Track 3 — Medir antes de optimizar

- **D3.1** Benchmark del techo real de un solo nodo: ¿dónde se rompe efectivamente? Un día de trabajo.
- **D3.2** Solo entonces elegir entre: compactación temporal, enumeración meet-in-the-middle, reordenamiento dinámico de poda, memoización en el DFS por defecto.
- **D3.3** Distribuido: **solo** si un engagement real se bloquea contra el techo medido. Meter dependencia de cluster mata el diferenciador de binario único / air-gapped.

---

## 3. Rechazados, con razón

| Ítem | Razón |
|---|---|
| Beam search | Retroceso frente a la poda admisible ya existente: cambia una garantía por velocidad en un camino que no es cuello de botella |
| SHAP / LIME | `explain_score` ya entrega narrativa + atribuciones + percentiles + pares, y se usó tal cual en el informe real |
| AutoML de features | Destruye la explicabilidad, que es un claim de producto fijado por test |
| Ensemble de GNN | Antes hay que entrenar uno. El cuello de botella son los labels, no la arquitectura |
| Spark GraphX / Faunus | Faunus está muerto hace una década; y mata el posicionamiento de binario único offline |
| Federated learning | Prematuro por dos escalones |

---

## 4. Decisiones — resueltas 2026-08-13

1. **GeoLite2**: ✅ **se shipean** los `.mmdb`. Preserva la historia air-gapped.
2. **GNN**: ✅ **entrenar**. Dataset DARPA TC E3 CADETS descargado y pipeline corrido.
3. **Umbral de la guarda de precisión (B1.2)**: ✅ **20%**, con `MIN_POPULATION = 50` para no advertir sobre grafos de demo (`platform/api/src/operations/precision.rs`).
4. **Resolución de identidad**: ✅ **propuesta al analista o al asistente AI vía API/MCP**, no fusión automática. Fusionar mal es peor que no fusionar.

## 5. Bitácora de evidencia de campo

| Fecha | Ítem | Qué lo confirmó |
|---|---|---|
| 2026-08-12 | Metadata de aristas | `metadata_keys: []` invalidó 5 de 6 patrones del catálogo. Arreglado (`c7338e8`). |
| 2026-08-12 | B1.2 guarda de precisión | `cat-021`: 4.996 caminos sobre 4.627 usuarios, declarado falso positivo sistémico. |
| 2026-08-14 | `events_for_node` | Cortaba en la primera arista de cada vecino: escondía un `UPDATE_PASSWORD` detrás de un `VERIFY_EMAIL`. Arreglado, +48% de eventos en el bloque Latitude.sh y dos víctimas nuevas. |
| 2026-08-14 | B1.3 identidad | `IMPERSONATE`/`realm_disabled` devolvieron UUIDs donde el resto devolvía emails. |
| 2026-08-14 | B1.4 sesiones | 60.145 sesiones reconstruidas fuera de la herramienta; `sessionId` está en la fuente pero no en el grafo. |
| 2026-08-14 | **B1.5 eventos sin contraparte** | 642 eventos invisibles, entre ellos 399 de los 401 `realm_disabled` del corte de contención del 24-07. |
| 2026-08-14 | A0.1 GeoIP/ASN | Sin ASN no se detecta que `206.223.232.0/24` y `103.50.33.0/24` son el mismo AS396356 — el hallazgo que reabrió la ventana del incidente once días. |
