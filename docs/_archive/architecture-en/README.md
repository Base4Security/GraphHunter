# GraphHunter Architecture (CLRS-style reference)

Single-document source for the architecture PDF at
`graphhunter-architecture.pdf`.

## Build

```bash
bash scripts/build-arch-pdf.sh
```

Requires a working TeX distribution (MiKTeX on Windows, TeX Live
elsewhere) with `latexmk` on PATH. If `latexmk` isn't available, the
script falls back to three `pdflatex` passes manually.

Required packages (all present in a standard TeX Live / MiKTeX
install): `amsmath`, `amsthm`, `algorithm2e`, `listings`, `xcolor`,
`hyperref`, `bookmark`, `booktabs`, `tikz`, `titlesec`, `geometry`,
`mathtools`.

Output: `docs/architecture/graphhunter-architecture.pdf`.

## Layout

- `graphhunter-architecture.tex` — main file; `\input`s everything.
- `preamble.tex` — package imports, theorem environments, Rust
  listing style, custom macros (`\Ord`, `\filepath`, `\StrId`, etc.).
- `chapters/ch01..ch30.tex` — one file per chapter.
- `chapters/appendix-*.tex` — appendices (complexity summary,
  catalog reference, benchmarks, source index).

## Status

- Parts I–III (preliminaries, data structures, core algorithms) are
  fleshed out — pseudocode, complexity derivations, invariants.
- Parts IV–VI (ingestion pipeline, extension seams, transport layer)
  are stubs — structure + file references + key types — pending
  expansion in follow-up revisions.
