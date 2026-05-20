#!/usr/bin/env python3
"""
extract-listings.py — extrae snippets Rust del repo para incluir en el libro.

Busca marcadores `// @book-snippet:NAME` y `// @book-snippet-end` en archivos
.rs del repo. Cada bloque se escribe a `<out>/<NAME>.rs`.

Uso:
  python3 extract-listings.py --repo-root <path> --out <path>
  python3 extract-listings.py --repo-root <path> --out <path> --check

--check no escribe nada; verifica que todos los snippets referenciados en
docs/libro/**/*.tex existen en el código. Sale con código != 0 si falta uno.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Iterator

SNIPPET_START = re.compile(r"//\s*@book-snippet:([a-zA-Z0-9_/.-]+)\s*$")
SNIPPET_END = re.compile(r"//\s*@book-snippet-end\s*$")

# En .tex, buscamos referencias como \inputminted{rust}{listings/NAME.rs}
TEX_REF = re.compile(r"listings/([a-zA-Z0-9_/.-]+)\.rs")


def extract_snippets(rs_path: Path) -> Iterator[tuple[str, str]]:
    """Yields (name, body) para cada @book-snippet en el archivo dado."""
    try:
        with rs_path.open(encoding="utf-8") as f:
            lines = f.readlines()
    except (UnicodeDecodeError, PermissionError):
        return

    i = 0
    while i < len(lines):
        m = SNIPPET_START.search(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        body_start = i + 1
        j = body_start
        while j < len(lines) and not SNIPPET_END.search(lines[j]):
            j += 1
        if j >= len(lines):
            print(f"WARNING: snippet '{name}' en {rs_path} sin @book-snippet-end", file=sys.stderr)
            i = body_start
            continue
        body = "".join(lines[body_start:j])
        yield name, body
        i = j + 1


def find_all_snippets(repo_root: Path) -> dict[str, tuple[Path, str]]:
    """Devuelve dict name -> (path, body) de todos los snippets en el repo."""
    snippets: dict[str, tuple[Path, str]] = {}
    skip_dirs = {".git", "target", "node_modules", "build", "dist", "_archive"}
    for rs in repo_root.rglob("*.rs"):
        if any(part in skip_dirs for part in rs.parts):
            continue
        for name, body in extract_snippets(rs):
            if name in snippets:
                print(f"WARNING: snippet '{name}' duplicado en {rs} y {snippets[name][0]}", file=sys.stderr)
            snippets[name] = (rs, body)
    return snippets


def find_tex_refs(libro_root: Path) -> set[str]:
    """Devuelve set de nombres referenciados en docs/libro/**/*.tex."""
    refs: set[str] = set()
    for tex in libro_root.rglob("*.tex"):
        try:
            text = tex.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = tex.read_text(encoding="latin-1")
        for m in TEX_REF.finditer(text):
            refs.add(m.group(1))
    return refs


def write_listings(snippets: dict[str, tuple[Path, str]], out_dir: Path) -> int:
    """Escribe cada snippet a out_dir/<name>.rs. Devuelve número escritos."""
    out_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for name, (_, body) in snippets.items():
        target = out_dir / f"{name}.rs"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
        count += 1
    return count


def check_refs(snippets: dict[str, tuple[Path, str]], refs: set[str]) -> int:
    """Verifica que cada ref tenga un snippet. Devuelve número de faltantes."""
    missing = refs - snippets.keys()
    for name in sorted(missing):
        print(f"ERROR: snippet '{name}' referenciado en .tex pero no existe en .rs", file=sys.stderr)
    return len(missing)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True, help="raíz del repo")
    parser.add_argument("--out", type=Path, required=True, help="directorio destino para .rs extraídos")
    parser.add_argument("--check", action="store_true", help="no escribir; sólo verificar refs en .tex")
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    out_dir = args.out.resolve()
    libro_root = repo_root / "docs" / "libro"

    if not repo_root.exists():
        print(f"ERROR: --repo-root {repo_root} no existe", file=sys.stderr)
        return 2

    snippets = find_all_snippets(repo_root)

    if args.check:
        refs = find_tex_refs(libro_root)
        missing = check_refs(snippets, refs)
        if missing:
            print(f"\n{missing} snippet(s) referenciado(s) en .tex no existen en .rs", file=sys.stderr)
            return 1
        print(f"OK: {len(refs)} refs verificadas, {len(snippets)} snippets disponibles")
        return 0

    count = write_listings(snippets, out_dir)
    print(f"Extraídos {count} snippets a {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
