# GraphHunter: arquitectura (referencia estilo CLRS) — español

Fuente del PDF en `graphhunter-arquitectura.pdf`.

## Build

```bash
bash scripts/build-arch-pdf-es.sh
```

Requiere una distribución TeX funcionando (MiKTeX en Windows, TeX
Live en otros) con `latexmk` en PATH. Si no está `latexmk`, el
script cae a tres pasadas de `pdflatex` manuales.

Paquetes necesarios (todos presentes en una instalación estándar
de TeX Live / MiKTeX): `amsmath`, `amsthm`, `algorithm2e`,
`listings`, `xcolor`, `hyperref`, `bookmark`, `booktabs`, `tikz`,
`titlesec`, `geometry`, `mathtools`, `babel` con `spanish`.

Salida: `docs/architecture-es/graphhunter-arquitectura.pdf`.

## Layout

- `graphhunter-arquitectura.tex` — archivo principal; `\input`ea
  todos los capítulos.
- `preamble.tex` — imports de paquetes, entornos de teorema,
  estilo de listing Rust, macros propias (`\Ord`, `\filepath`,
  `\StrId`, etc.), localización a español de kw de `algorithm2e`
  (para/mientras/si/entonces/...).
- `chapters/ch01..ch30.tex` — un archivo por capítulo.
- `chapters/apendice-*.tex` — apéndices (resumen de complejidad,
  referencia de catálogo, benchmarks, índice de fuente).

## Estado

- Las Partes I–III (preliminares, estructuras de datos, algoritmos
  principales) están desarrolladas — pseudocódigo, derivaciones de
  complejidad, invariantes.
- Las Partes IV–VI (pipeline de ingesta, puntos de extensión, capa
  de transporte) son *stubs* — estructura + referencias de archivo
  + tipos clave — pendientes de expansión en revisiones
  posteriores.

## Versión inglesa

Hay una versión inglesa paralela en `docs/architecture/` con la
misma estructura. Las dos se mantienen en paralelo; si se actualiza
una, idealmente se actualiza la otra también.
