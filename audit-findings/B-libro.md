# B-libro — M9 sweep del libro unificado

**Date:** 2026-05-26
**Method:** 6 escaneos sobre `docs/libro/` para verificar release-readiness de
v1.0.0: (1) determinismo del build (sha256 de PDF en dos corridas), (2) `biber
--validate-datamodel`, (3) cross-refs y citas huérfanas en log de xelatex, (4)
`git grep TODO|FIXME|XXX|???` en `docs/libro/`, (5) ejecución de los tests de
integración `m1_cap0_*` y `m3_cap*_*`, (6) conteo de markers `@book-snippet`
en el repo.
**Worker:** unit-13
**Base commit:** 99fb150

## Summary

6 findings: 0 P0, 3 P1, 2 P2, 1 P3. El libro tiene tres problemas de
release-blocking que afectan reproducibilidad del PDF y experiencia de
contributor (Makefile top-level sin target `libro`, PDF no determinístico, y
build local imposible de completar por bug de minted+MiKTeX). Los 5 archivos
de tests de integración (no 9 como decía la memoria) pasan limpios. TODOs son
legítimos (placeholders en ejemplos).

## Findings

### Top-level Makefile no expone target para construir el libro

- **Severity:** P1
- **Axis:** build
- **Front:** libro
- **Evidence:** `grep -E '^libro:|^libro-pdf:|^docs-libro:' Makefile` → 0 hits.
  El Makefile en root solo expone `pre-merge`, `check`, `test`, `clippy`,
  `fmt-check`, `layering`, `smoke-bench`. Hay que `cd docs/libro && make all`
  o `make fast` para construir.
- **Risk:** Un contributor nuevo siguiendo el README top-level no encuentra
  cómo construir el libro; tampoco un script de release/CI puede asumir
  `make libro` desde root como punto de entrada estándar. Documentación
  inconsistente sobre el path canónico de build.
- **Fix action:** Añadir target en `Makefile` (root):

  ```makefile
  .PHONY: libro libro-fast
  libro:
      $(MAKE) -C docs/libro all
  libro-fast:
      $(MAKE) -C docs/libro fast
  ```

- **Cost:** XS
- **Gate:** pre-release
- **Owner suggested:** automatable

### PDF no determinístico — sha256 cambia entre builds idénticos

- **Severity:** P1
- **Axis:** build
- **Front:** libro
- **Evidence:** Dos corridas de `xelatex -shell-escape main.tex` sobre el
  mismo commit (sin cambios entre runs) producen PDFs con sha256 distintos:
  - Run 1: `536d2c49aafa8ff9db4cfe13507a6a7ae92189da4174abdae3c5b9795854e06e`
  - Run 2: `62004244e220d2222f5d42a480d8a13a43a6a680fdd9a63659e002ae16e26037`

  No hay configuración de reproducibilidad en `preamble.tex`,
  `docs/libro/Makefile`, ni env var `SOURCE_DATE_EPOCH` en el invocador.
  `git grep -E 'SOURCE_DATE_EPOCH|pdfcreationdate|pdfsuppressptexinfo'
  docs/libro` → 0 hits.
- **Risk:** Imposible verificar integridad del release artifact con
  checksum publicado; releases firmados no son reproducibles. Casos legales
  (publicación con ISBN) y de archivado requieren PDF determinístico.
- **Fix action:** En `docs/libro/Makefile`, exportar `SOURCE_DATE_EPOCH=$(git
  log -1 --format=%ct)` antes de los pases de xelatex, y añadir a
  `preamble.tex`:

  ```latex
  \pdfvariable suppressoptionalinfo 512\relax
  \pdfvariable info omitdate 1\relax
  ```

  (o equivalente con `\hypersetup{pdfcreationdate=...}`). Validar que dos
  builds consecutivos produzcan el mismo sha256.
- **Cost:** S
- **Gate:** pre-release
- **Owner suggested:** tú

### Build de xelatex se detiene en primer bloque `minted` (entorno local)

- **Severity:** P1
- **Axis:** build
- **Front:** libro
- **Evidence:** MiKTeX 26.2 en el host del auditor reporta
  `Package minted Error: minted v3+ executable is not installed or is not
  added to PATH; or MiKTeX is being used with -aux-directory or
  -output-directory without setting a TEXMF_OUTPUT_DIRECTORY environment
  variable.` aun con `TEXMF_OUTPUT_DIRECTORY=build` exportada. El error es
  reproducible:
  - `xelatex -shell-escape -output-directory=build main.tex` → falla en
    `parte0-primer-contacto/00-hola-graphhunter.tex:265` (`\end{minted}`).
  - `xelatex -shell-escape main.tex` (sin output-directory) → mismo error.
  - `TEXMF_OUTPUT_DIRECTORY=build xelatex …` → mismo error.

  PDF parcial generado: 17 páginas (debería ser ~500 según roadmap M0-M9).
  `latexminted` está en PATH y reporta `major issue: User/administrator
  updates are out-of-sync`. El bug afecta a MiKTeX en Windows y rompe el
  build incluso con `make fast`.
- **Risk:** Cualquier contributor en Windows con MiKTeX actualizado no
  parcialmente no puede construir el libro localmente, y por tanto no puede
  validar cambios antes de PR. El `docs/libro/Makefile` no tiene fallback ni
  detecta este modo de falla.
- **Fix action:** Documentar workaround en `docs/libro/README.md`
  (preferir TeX Live a MiKTeX en Windows, o sincronizar updates con
  `mpm --admin --update` antes del primer build). Alternativa más robusta:
  migrar de `minted` a `listings` (pure-LaTeX, sin dependencia python) para
  eliminar la superficie de fallo. Si se mantiene minted, añadir
  `requires_pygments_or_listings` check en el Makefile.
- **Cost:** M (workaround docs: XS; migración listings: M)
- **Gate:** pre-release
- **Owner suggested:** tú

### Referencias cruzadas no resueltas: `sec:metafora`, `sec:ingest`

- **Severity:** P2
- **Axis:** docs
- **Front:** libro
- **Evidence:** En log de single-pass build:
  - `LaTeX Warning: Reference 'sec:metafora' on page 2 undefined on input
    line 115.`
  - `LaTeX Warning: Reference 'sec:ingest' on page 3 undefined on input line
    214.`

  `git grep label\{sec:metafora|label\{sec:ingest docs/libro` confirma que
  ambos labels SÍ existen en
  `docs/libro/parte0-primer-contacto/00-hola-graphhunter.tex` (líneas 120 y
  402 respectivamente). Es probable que se resuelvan después de 2-3 pases
  multipass `xelatex → biber → xelatex → xelatex`. Pero el build completo no
  pudo verificarse por el bug minted descrito arriba.
- **Risk:** Si el bug minted bloquea la convergencia multi-pass, estas
  referencias quedarán como `??` en el PDF final, degradando la experiencia
  de lectura. Si convergen tras `make all`, este finding se cierra solo.
- **Fix action:** Confirmar con un build limpio en entorno funcional
  (TeX Live o MiKTeX sano) que estas refs se resuelven tras
  `make all` (4 pases). Si no, investigar por qué `sec:metafora` (línea 120,
  reference en línea 115) tiene problema de orden lexical.
- **Cost:** XS
- **Gate:** pre-release
- **Owner suggested:** tú

### Memory project_libro_unificado.md desactualizado sobre conteo de tests

- **Severity:** P2
- **Axis:** docs
- **Front:** libro
- **Evidence:** El plan del Unit 13 cita "9 integration tests protect
  libro↔code claims" basándose en
  `memory/project_libro_unificado.md`. El scan real:

  ```bash
  $ find . -name 'm1_cap0_*' -o -name 'm3_cap*_*' -not -path '*/target/*'
  ./core/graph-engine/tests/m1_cap0_e2e.rs
  ./core/graph-engine/tests/m3_cap13_dfs_baseline.rs
  ./core/graph-engine/tests/m3_cap15_nlf_pruning.rs
  ./core/graph-engine/tests/m3_cap20_yannakakis.rs
  ./core/graph-engine/tests/m3_cap21_planner.rs
  ```

  → 5 archivos (no 9). Suma de `#[test]` dentro de esos archivos = 19 tests
  individuales, todos verdes:
  - `m1_cap0_e2e`: 1 test (`cap0_credential_stuffing_finds_exactly_alicia`)
  - `m3_cap13_dfs_baseline`: 1
  - `m3_cap15_nlf_pruning`: 2
  - `m3_cap20_yannakakis`: 5
  - `m3_cap21_planner`: 10
- **Risk:** La memoria/spec citan un número incorrecto, lo que puede llevar
  a otros workers (Unit 14, 15, 16) a buscar tests inexistentes y reportar
  falsos negativos. No hay impacto en correctitud del libro porque los
  tests existentes pasan.
- **Fix action:** Actualizar
  `~/.claude/projects/.../memory/project_libro_unificado.md` para decir "5
  archivos de tests / 19 tests `#[test]` total". Considerar si faltan tests
  para los demás capítulos del libro (cap1-12, 14, 16-19, 22-50) — esto
  podría ser una **deuda separada** de cobertura de claims libro↔código,
  no un finding del sweep M9.
- **Cost:** XS (memory update). Cobertura adicional: L (out of scope M9).
- **Gate:** post-release
- **Owner suggested:** tú

### Hits de `XXX` en `docs/libro/` — todos placeholders legítimos

- **Severity:** P3
- **Axis:** content
- **Front:** libro
- **Evidence:** `git grep -nE 'TODO|FIXME|XXX|\?\?\?' docs/libro` → 3 hits:
  - `docs/libro/parte5-operacion/42-notas-tags-exportacion.tex:496:
    \code{jira-INC-XXXX}` (placeholder en ejemplo de tag de ticket)
  - `docs/libro/parte5-operacion/44-integraciones.tex:85:
    webhook = "https://hooks.slack.com/services/TXXXXXXXX/BXXXXXXXX/xxxx"`
    (placeholder en ejemplo de URL de Slack)
  - `docs/libro/refs.bib:636: % ESTADÍSTICA Y METODOLOGÍA EXPERIMENTAL
    (Cap 50)` (comentario de organización, NO un TODO real)

  Ningún hit es un TODO/FIXME/XXX real en narrativa pedagógica ni en
  comentario LaTeX. Cero hits de `???` literal.
- **Risk:** Ninguno. Los `XXXX` son patrones convencionales para indicar
  "valor del usuario" en ejemplos. No degradan la lectura.
- **Fix action:** Ninguna. Documento como evidencia de que el sweep M9 ya
  limpió TODOs reales (vista la cantidad de commits "M9 sweep" en el
  histórico).
- **Cost:** XS
- **Gate:** nice-to-have
- **Owner suggested:** tú

## Method log

### Comandos ejecutados y outputs

**1. Build determinístico (sha256 stability)**:

```bash
$ grep -E '^libro:|^libro-pdf:|^docs-libro:' Makefile
(no output — no libro target in top-level Makefile)

$ cat docs/libro/Makefile | grep -E '^all:|^fast:'
all: listings
fast: listings

$ which xelatex biber
/c/Program Files/MiKTeX/miktex/bin/x64/xelatex
/c/Program Files/MiKTeX/miktex/bin/x64/biber

$ xelatex --version | head -1
MiKTeX-XeTeX 4.18 (MiKTeX 26.2)

# Build 1
$ cd docs/libro && rm -rf build/ libro.pdf && mkdir -p build && \
    python ../../tools/extract-listings.py --repo-root ../.. --out listings/
Extracted 38 snippets

$ xelatex -shell-escape -interaction=nonstopmode -halt-on-error \
    -output-directory=build main.tex
# Exit 1 — minted error en .tex linea 265 de
# parte0-primer-contacto/00-hola-graphhunter.tex
# PDF parcial: 17 páginas
$ sha256sum docs/libro/build/main.pdf
536d2c49aafa8ff9db4cfe13507a6a7ae92189da4174abdae3c5b9795854e06e  build/main.pdf

# Build 2 (idéntico)
$ rm -rf build/ libro.pdf && mkdir -p build && \
    python ../../tools/extract-listings.py --repo-root ../.. --out listings/ &&
    xelatex -shell-escape -interaction=nonstopmode -halt-on-error \
    -output-directory=build main.tex
$ sha256sum build/main.pdf
62004244e220d2222f5d42a480d8a13a43a6a680fdd9a63659e002ae16e26037  build/main.pdf

# → SHA difiere ⇒ no reproducible
```

**2. biber validate-datamodel** — no aplicable porque `main.bcf` queda
malformado por el build incompleto:

```bash
$ biber --validate-datamodel --output-directory=build build/main
INFO - This is Biber 2.21
ERROR - build/main.bcf is malformed, last biblatex run probably failed.
INFO - ERRORS: 1
```

No registrado como finding separado: es consecuencia del finding "build se
detiene en minted".

**3. Cross-refs y citas huérfanas en build log**:

```bash
$ grep -iE 'undefined (reference|citation)|multiply.defined' \
    docs/libro/build/main.log
LaTeX Warning: Reference 'sec:ingest' on page 3 undefined on input line 214.

# y en log de build sin output-directory:
LaTeX Warning: Reference 'sec:metafora' on page 2 undefined on input line 115.
LaTeX Warning: Reference 'sec:ingest' on page 3 undefined on input line 214.
```

No `multiply defined` ni `undefined citation`. Solo 2 refs sin resolver, en
single-pass build → registradas como finding P2 con caveat de multi-pass.

**4. TODO/FIXME residuales en `docs/libro/`**:

```bash
$ git grep -nE 'TODO|FIXME|XXX|\?\?\?' docs/libro | wc -l
3

$ git grep -nE 'TODO|FIXME|XXX|\?\?\?' docs/libro
docs/libro/parte5-operacion/42-notas-tags-exportacion.tex:496:
  \code{jira-INC-XXXX}).
docs/libro/parte5-operacion/44-integraciones.tex:85:
  webhook   = "https://hooks.slack.com/services/TXXXXXXXX/BXXXXXXXX/xxxx"
docs/libro/refs.bib:636: % ESTADÍSTICA Y METODOLOGÍA EXPERIMENTAL (Cap 50)
```

Clasificados como P3 — todos legítimos.

**5. Integration tests del libro**:

```bash
$ find . -name 'm1_cap0_*' -o -name 'm3_cap*_*' -not -path '*/target/*'
./core/graph-engine/tests/m1_cap0_e2e.rs
./core/graph-engine/tests/m3_cap13_dfs_baseline.rs
./core/graph-engine/tests/m3_cap15_nlf_pruning.rs
./core/graph-engine/tests/m3_cap20_yannakakis.rs
./core/graph-engine/tests/m3_cap21_planner.rs

# 5 archivos, no 9. Memory stale → finding P2.

$ cd core/graph-engine && cargo test --test m1_cap0_e2e \
    --test m3_cap13_dfs_baseline --test m3_cap15_nlf_pruning \
    --test m3_cap20_yannakakis --test m3_cap21_planner
# 19 tests, 19 passed, 0 failed
```

Detalle por archivo:

- `m1_cap0_e2e`: 1 passed
  (`cap0_credential_stuffing_finds_exactly_alicia`)
- `m3_cap13_dfs_baseline`: 1 passed
- `m3_cap15_nlf_pruning`: 2 passed
- `m3_cap20_yannakakis`: 5 passed (incluye `cap20_yannakakis_parity_with_dfs_3hop`,
  parity test crítico)
- `m3_cap21_planner`: 10 passed (cubre planner dispatch para triangle, K4,
  K5, C6, chain, star)

Total: **19 tests passed, 0 failed**. Tests aceptan los claims del libro
para Cap 0 (m1) y Cap 13/15/20/21 (m3). Otros capítulos del libro (Cap
1-12, 14, 16-19, 22-50) no tienen tests con el naming convention
`mN_capX_*` — deuda separada de cobertura.

**6. `@book-snippet` markers**:

```bash
$ git grep -E '@book-snippet:[a-z]' \
    | grep -v 'CHANGELOG\|CONTRIBUTING\|book-snippet-end' \
    | wc -l
47  # incluye 4 hits en tools/test_extract_listings.py (test fixtures)

# Filtrado a archivos productivos (src/ y listings/):
$ git grep -cE '@book-snippet:[a-z]' core/ platform/ apps/ docs/libro/listings/
core/graph-engine/src/graph.rs:6
core/graph-engine/src/ingest/parser_task.rs:1
core/graph-engine/src/ingest/writer.rs:1
core/graph-engine/src/interner.rs:1
core/graph-engine/src/khop_reach.rs:2
core/graph-engine/src/lftj.rs:2
core/graph-engine/src/lftj_query.rs:2
core/graph-engine/src/lib.rs:1
core/graph-engine/src/nlf.rs:3
core/graph-engine/src/planner.rs:2
core/graph-engine/src/relation.rs:1
core/graph-engine/src/sentinel.rs:1
core/graph-engine/src/streaming.rs:5
core/graph-engine/src/yannakakis.rs:3
core/matcher-ffi/src/lib.rs:1
docs/libro/listings/mcp/hunt-run-tool.ts:1
platform/api/src/operations/hunt.rs:1
platform/dsl/src/hypothesis.rs:1
platform/dsl/src/lib.rs:2
platform/dsl/src/types.rs:2
platform/mcp/src/tools/hunt/run.ts:1

# Suma: 38 markers en archivos productivos.
# extract-listings.py output confirma: "Extracted 38 snippets".
# Coincide con memory project_libro_unificado.md ("~38").
```

No finding sobre conteo de snippets — el número es estable. La validación
detallada de "cada snippet referenciado en docs/libro/listings/ aparece en
texto del libro" queda fuera del scope de Unit 13 (asignada a Unit 12).

### Limitaciones de método

- **MiKTeX broken en host del auditor**: `User/administrator updates are
  out-of-sync` impide cualquier build completo del libro. Determinismo del
  PDF verificado sobre **build parcial de 17 páginas** (no sobre el PDF
  completo de ~500 páginas). El finding P1 sobre no-determinismo es
  conservador: si el PDF parcial difiere, es altamente probable que el
  completo también difiera, dado que la diferencia parece venir de
  `pdfcreationdate` metadata y `id` de objetos PDF.
- **biber sweep**: No pudo ejecutarse `biber --validate-datamodel` sobre un
  `.bcf` válido. Re-correr este sweep cuando se tenga un entorno TeX
  funcional.
- **Logs analizados**: `docs/libro/build/main.log` (build con
  `-output-directory=build`) y `/tmp/xelatex-3.log` (build sin
  `-output-directory`). Ambos confirman los mismos hallazgos.
