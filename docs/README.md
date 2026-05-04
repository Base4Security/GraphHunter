# Documentación de GraphHunter

Este directorio contiene los cuatro libros de documentación del proyecto, compilados desde LaTeX a PDF.

## Libros

| Libro | Carpeta | Propósito |
|-------|---------|-----------|
| Arquitectura | `arquitectura/` | Cómo está construido el sistema: capas (core/platform/apps), crates, patrones, ADRs. |
| Especificación | `especificacion/` | Superficies externas: HTTP API, MCP tools, DSL, C ABI, formatos de log, env vars. |
| Manual | `manual/` | Guía del operador/analista: instalación, ingesta, caza, exploración, integraciones. |
| Paper | `paper/` | Reporte interno de investigación: problema, contribuciones, evaluación, limitaciones. |

Todos están en **español** y usan LaTeX con `xelatex`.

## Requisitos

- TeX Live 2022 o superior (o MiKTeX en Windows) con XeLaTeX.
- `biber` para la bibliografía del paper.
- Fuentes del sistema: cualquier instalación estándar sirve (el preamble usa fontspec con fallbacks).

## Build

Desde la raíz del repo:

```bash
# Un libro específico
make -C docs arquitectura
make -C docs especificacion
make -C docs manual
make -C docs paper

# Todos
make -C docs all

# Limpiar artefactos intermedios (aux, log, toc, etc.)
make -C docs clean
```

Los PDF resultantes se llaman `arquitectura.pdf`, `especificacion.pdf`, `manual.pdf`, `paper.pdf` en cada carpeta respectiva.

## Build manual (sin Makefile)

```bash
cd docs/arquitectura
xelatex -shell-escape main.tex
xelatex -shell-escape main.tex   # segunda pasada para TOC / referencias cruzadas
```

Para el paper, correr `biber` entre pasadas:

```bash
cd docs/paper
xelatex -shell-escape main.tex
biber main
xelatex -shell-escape main.tex
xelatex -shell-escape main.tex
```

## Estructura por libro

Cada libro sigue el mismo patrón:

```
<libro>/
├── main.tex          # Documento raíz (clase book o report)
├── preamble.tex      # Paquetes, colores, comandos — un color distinto por libro
├── chapters/         # Capítulos numerados (01-*.tex, 02-*.tex, ...)
│   o sections/       # Para el paper
└── appendices/       # Apéndices (sólo arq, spec, manual)
```

## Archivo histórico

`_archive/` contiene la documentación previa (fases 0/1, manual LaTeX antiguo, traducciones EN/ES obsoletas, Sphinx RST, algoritmos en Markdown, reportes CSIRT). No se borra: sirve como referencia para quien quiera trazar la evolución del proyecto.

## CI

El workflow `.github/workflows/docs.yml` compila los 4 PDFs en cada PR que toca `docs/**` y los sube como artifacts. Ver `Actions` en GitHub.
