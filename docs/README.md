# Documentación de GraphHunter

La documentación viva está en **`docs/libro/`** — un solo libro
unificado en PDF (`docs/libro/libro.pdf`).

## Build rápido

```bash
make -C docs/libro fast       # ~15 s, sin biber/índice
make -C docs/libro all        # ~60 s, completo con bibliografía e índice
```

## Histórico

`docs/_archive/` contiene la documentación previa, incluido el
snapshot de los 5 libros LaTeX archivados en 2026-05 antes de la
consolidación. Ver `docs/_archive/2026-libros-pre-unificacion/README.md`
para el mapeo capítulo viejo → capítulo nuevo.

## Notas en Markdown

- `docs/perf/` — bitácora viva de benchmarks por fecha (no se archiva).
- `docs/superpowers/` — specs y planes de implementación.
