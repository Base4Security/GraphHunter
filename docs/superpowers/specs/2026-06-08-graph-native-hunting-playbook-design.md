# Graph-Native Hunting Playbook

**Fecha:** 2026-06-08
**Estado:** Diseño aprobado — pendiente plan
**Owner:** Lucas

## 1. Problema

El playbook de hunting semanal actual (4 prompts Phase 1–4 que el operador alimenta
a Claude Desktop con el MCP de GraphHunter) está escrito **KQL-first**. Un ciclo real
ejecutado el 2026-06-08 (caso Niubiz/Visanet) produjo un True Positive válido pero usó
GraphHunter como **ejecutor de KQL + almacén de notas/reportes**: cero grafo construido.
No hubo `sentinel_seed`, `node_enrich`, `node_expand`, `heavy_edges` ni `channel_behavior`.
El beaconing del Escenario E se calculó con `ConsistencyRatio` en KQL a mano — justo lo
que `channel_behavior` hace nativo.

Causa raíz: **los prompts mismos fuerzan KQL.** El output format de Phase 2 decía literal
*"The KQL query used and an explanation of the filters applied (Not DSL patterns)"* — le
prohíbe al LLM usar el grafo. Las descripciones de tools (ya reforzadas, commit `252626e`)
no pueden ganarle a una instrucción explícita en el prompt. El lever real es el playbook.

Consecuencia: se paga la complejidad de GraphHunter (ingesta, motor de grafo, matcher SIMD)
usando ~5% de su valor; el diferenciador (correlación cross-source, traversal multi-hop,
analítica temporal/volumen nativa, scoring, grafo persistente) queda dormido.

## 2. Objetivo

Reescribir el playbook como **documentación versionada en el repo** (`docs/hunting-playbook/`),
graph-native: el flujo por defecto es `sentinel_seed → node_enrich/node_expand → analítica de
grafo`, y `sentinel_query` (KQL) es escape hatch justificado. El output format pide **evidencia
de grafo** (subgrafos, paths, scores, salida de channel_behavior/heavy_edges), no la KQL usada.

Se preserva todo el rigor del playbook actual: hipótesis testeables, mapeo MITRE ATT&CK,
triage de falsos positivos, validación adversarial, blast radius, síntesis ejecutiva.

### No-objetivos (YAGNI)
- NO cambiar las MCP tools ni el motor (ya están; este es trabajo de prompts/docs).
- NO prohibir KQL del todo (Phase 1 audit y la Hardening List de Phase 4 lo necesitan
  legítimamente).
- NO automatizar la ejecución del playbook (sigue siendo prompts que el operador pega
  en Claude Desktop).

## 3. Decisiones tomadas (no re-debatir)

| Decisión | Valor |
|---|---|
| Alcance | 4 prompts Phase 1–4 **+** 5 templates HTML de reporte |
| Postura KQL | graph-first; `sentinel_query` escape hatch **con justificación obligatoria** en el reporte |
| Phase 1 | KQL-OK (recon pre-grafo) + nuevo entregable "Seeding Strategy" que puentea al grafo |
| Ubicación | `docs/hunting-playbook/` en el repo (versionado junto a las tools) |
| HTML source | el usuario provee los 5 HTML actuales; se adaptan preservando branding, cambiando qué evidencia muestran |

## 4. Arquitectura

```
docs/hunting-playbook/
  README.md                              # qué es, cómo usarlo, mapa de fases
  00-tooling-doctrine.md                 # bloque compartido: graph-first + cheat-sheet de tools
  01-phase1-telemetry-audit.md           # recon + Seeding Strategy
  02-phase2-hypothesis-execution.md      # graph-first hunt (el cambio mayor)
  03-phase3-validation-blast-radius.md   # validación + blast radius como traversal de grafo
  04-phase4-synthesis-reporting.md       # síntesis + Hardening List (KQL como entregable)
  templates/                             # HTML de reporte adaptados (pendiente upload)
    01-WeeklyHunting-Step1.html
    01-WeeklyHunting-Step2.html
    01-WeeklyHunting-Step3.html
    01-WeeklyHunting-Step4.html
    informe-threat-hunting.html
```

### 4.1 Tooling Doctrine (header compartido, `00-tooling-doctrine.md`)

Bloque corto que cada prompt Phase 2–4 incluye al inicio (copiado inline, no por referencia,
para que funcione pegado en Claude Desktop):

- **Principio:** El grafo correlacionado y persistente es el artefacto de la caza, no la query.
- **Flujo por defecto:** `sentinel_seed` (sembrar del IoC) → `node_enrich`/`node_expand`
  (construir vecindario) → analítica de grafo (test de hipótesis).
- **Escape hatch:** `sentinel_query` (KQL) solo cuando el grafo no puede expresar el test;
  el LLM debe **justificar por qué** en el reporte.
- **Cheat-sheet de selección:**
  | Necesito… | Tool |
  |---|---|
  | Arrancar desde un IoC | `sentinel_seed` |
  | Traer el slice de un nodo | `node_enrich` |
  | Vecindario / expandir | `node_expand` (live para hidratar) |
  | Beaconing / periodicidad | `graph_channel_behavior` |
  | Canales pesados / exfil | `graph_heavy_edges` |
  | Camino de ataque / pivot | `graph_path_nodes` |
  | Blast radius | `node_expand` ±N hops |
  | Anomalía / por qué es raro | `node_score_explanation` |
  | Subred / vecinos por rango | `graph_subnet_analysis` |
  | Patrón estructural | `hunt_run` |
  | Estado de conexión | `sentinel_status` |
  | KQL crudo (último recurso) | `sentinel_query` (+ justificar) |

### 4.2 Phase 1 — Telemetry Audit & Seeding Strategy

Mantiene: auditoría de tablas activas, visibility matrix (gaps de cobertura), de-confliction
contra detecciones SOC existentes (`catalog_get`). KQL permitido (es recon genuinamente
pre-grafo: "qué tablas existen" no es un problema de grafo).

**Nuevo entregable — Seeding Strategy:** por cada escenario propuesto, especificar:
- Los **IoCs/entidades semilla** concretas (IPs, UPNs, hosts) con su `entity_type`.
- El **plan de construcción del grafo**: qué tools y en qué orden poblarán y analizarán
  (ej. "seed IP 181.196.73.138 → node_expand 2-hop → channel_behavior sobre los canales SSH").
- La **ventana temporal** (lookback) para la siembra.

Esto convierte el cierre de Phase 1 de "queries a correr" en "cómo vamos a *construir* el grafo".

### 4.3 Phase 2 — Hypothesis Formulation & Graph Execution (cambio mayor)

Persona y rigor sin cambios (hipótesis granulares testeables, MITRE sub-technique, long-tail).
Lo que cambia es **el método de ejecución y el output format**.

**Método (graph-first):** por cada hipótesis,
1. `sentinel_seed` del IoC de la Seeding Strategy → grafo poblado.
2. `node_enrich`/`node_expand` → construir el vecindario relevante.
3. **Test con analítica de grafo** según la hipótesis: `channel_behavior` (beaconing),
   `heavy_edges` (volumen/exfil), `node_score_explanation` (anomalía), `graph_path_nodes`
   (paths), `graph_subnet_analysis`, `hunt_run` (patrón).
4. `sentinel_query` solo si ninguna tool de grafo expresa el test, **con justificación**.

**Output format (invertido):** el reporte Phase 2 pide, por hipótesis:
- **Tactical Hypothesis** (qué y por qué) + MITRE.
- **Graph Evidence:** entidades/relaciones agregadas (del HydrationOutcome), el subgrafo
  sembrado, paths encontrados, scores de anomalía, y la salida de channel_behavior/heavy_edges
  cuando aplique. (Reemplaza el viejo "the KQL query used (Not DSL patterns)".)
- **Pivot History:** secundarios via `node_expand`/`node_enrich`.
- **Escape-hatch log (si aplica):** la KQL usada **y la justificación** de por qué el grafo
  no alcanzaba.
- **Current Risk Status** + Reliability metric.

### 4.4 Phase 3 — Validation & Blast Radius (graph-native)

Persona QA adversarial sin cambios. Método graph-native:
- **Cross-examination:** baselines históricos via `node_enrich` (ventana ampliada),
  contexto de entidad via `node_expand`, findings previos via `tags`/`notes`/`catalog_get`
  (para "ignorar findings ya reportados").
- **Blast Radius como traversal:** `node_expand` ±N hops alrededor de la entidad +
  `graph_path_nodes` para coser la cadena de ataque (reemplaza las ventanas KQL ±60min a mano).
- **Verdict Adjudication:** TP / Environmental Anomaly / False Positive — sin cambios.
- Output: **Validation Matrix** (igual) + **Blast Radius** expresado como subgrafo/timeline
  derivado del grafo + Enrichment Data (IOCs nuevos) + Handoff Summary.

### 4.5 Phase 4 — Synthesis, Reporting & Remediation

Persona y estructura sin cambios. Matices:
- **Sentinel Hardening List SÍ produce KQL** — acá el KQL es el *entregable* (reglas de
  detección Scheduled Analytics que el SOC corre en Sentinel), no el método de caza. Se queda.
- Se agrega **evidencia derivada del grafo** al reporte: el subgrafo de la cadena de ataque,
  beacon scores, canales pesados — lo que el grafo reveló y KQL no habría mostrado igual.
- Executive Summary, MITRE heatmap, remediación corto/largo plazo, next-cycle: sin cambios.

### 4.6 HTML templates

Cuando el usuario provea los 5 HTML actuales, se adaptan **preservando branding/estructura**
y cambiando **qué evidencia renderizan**: subgrafos, paths, tablas de scores, MITRE heatmap,
salida de channel_behavior/heavy_edges — en vez de tablas de resultados KQL. Si algún template
no tiene lugar natural para evidencia de grafo, se agrega una sección.

## 5. Componentes

| Pieza | Archivo | Responsabilidad |
|---|---|---|
| Índice + guía de uso | `docs/hunting-playbook/README.md` | qué es, cómo se usa, orden de fases |
| Doctrina compartida | `00-tooling-doctrine.md` | principio graph-first + cheat-sheet |
| Prompt Phase 1 | `01-phase1-telemetry-audit.md` | recon + Seeding Strategy |
| Prompt Phase 2 | `02-phase2-hypothesis-execution.md` | hunt graph-first + output de evidencia de grafo |
| Prompt Phase 3 | `03-phase3-validation-blast-radius.md` | validación + blast radius como traversal |
| Prompt Phase 4 | `04-phase4-synthesis-reporting.md` | síntesis + Hardening List (KQL entregable) |
| HTML adaptados | `templates/*.html` | reportes con evidencia de grafo (pendiente upload) |

## 6. Criterios de aceptación

- Los 4 prompts incluyen el bloque Tooling Doctrine inline (pegables tal cual en Claude Desktop).
- Phase 1 produce la Seeding Strategy (IoCs + plan de construcción + ventana).
- Phase 2: el output format pide evidencia de grafo y el KQL solo aparece en el escape-hatch log
  con justificación. La frase "(Not DSL patterns)" NO aparece en ningún prompt.
- Phase 3: blast radius descrito como operación de `node_expand`/`graph_path_nodes`.
- Phase 4: la Hardening List conserva KQL (entregable) y el reporte incluye evidencia de grafo.
- Cada prompt referencia tools que existen en el catálogo MCP actual (43 tools) — sin inventar.
- HTML: adaptados al recibir los archivos; cada uno muestra evidencia de grafo donde antes
  mostraba tablas KQL, preservando branding.

## 7. Validación

- **Smoke "graph-first":** releer cada prompt y verificar que el primer paso de ejecución
  de la fase de caza es una tool de grafo (`sentinel_seed`/`node_*`/`graph_*`), no `sentinel_query`.
- **Grep negativo:** `grep -ri "not dsl\|KQL query used" docs/hunting-playbook/` → vacío en
  los prompts (salvo donde se documenta el escape-hatch o la Hardening List).
- **Cobertura de tools:** cada tool nombrada en los prompts existe en el catálogo MCP.
- **Dry-run conceptual:** re-narrar el caso Niubiz Escenario A bajo el nuevo Phase 2 y confirmar
  que el flujo sería seed(181.196.73.138) → expand → channel_behavior/heavy_edges, no KQL a mano.

## 8. Out of scope

- Cambios a MCP tools / motor (ya implementados en la iniciativa de enrichment).
- Automatizar la ejecución del playbook (sigue siendo manual via Claude Desktop).
- Nuevos templates HTML desde cero (se adaptan los existentes).
- Métricas de adopción / telemetría de qué tools usa el LLM en la práctica (follow-up posible).
