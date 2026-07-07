#!/usr/bin/env bash
# check-layering.sh — fail if core/* crates depend on platform/* crates
# outside the documented whitelist.
#
# Why: the shearing architecture (per docs/arquitectura/) requires core/
# to stay free of platform concerns. Path deps sneak in easily during
# refactors. This guard runs in CI and locally.
#
# Whitelist: docs/arquitectura/layering-exceptions.txt
#   Format (one per line, # comments ignored):
#       <core-crate-dir> -> <platform-crate-dir>
#
# Exit codes:
#   0  — no violations
#   1  — at least one un-whitelisted core -> platform edge
#   2  — configuration error (missing whitelist file, etc.)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WHITELIST="$ROOT/docs/arquitectura/layering-exceptions.txt"

if [[ ! -f "$WHITELIST" ]]; then
    echo "error: whitelist not found at $WHITELIST" >&2
    exit 2
fi

# Load whitelist into a normalized set (strip comments + blank lines +
# collapse whitespace to single space around the arrow).
allowed=$(grep -vE '^\s*(#|$)' "$WHITELIST" \
    | sed -E 's/\s*->\s*/ -> /; s/^\s+//; s/\s+$//')

violations=0

# Iterate over core/*/Cargo.toml and extract path-based platform deps.
shopt -s nullglob
for manifest in "$ROOT"/core/*/Cargo.toml; do
    crate_dir="$(dirname "$manifest")"
    crate_name="$(basename "$crate_dir")"
    # Match lines like:   path = "../../platform/sources"
    # Also accept: path = "../platform/..." (unlikely but cheap to cover)
    while IFS= read -r target; do
        # target like "../../platform/sources" -> "platform/sources"
        normalized="core/$crate_name -> $(echo "$target" \
            | sed -E 's|^(\.\./)+||')"
        if grep -qxF "$normalized" <<<"$allowed"; then
            echo "ok     $normalized"
        else
            echo "FAIL   $normalized" >&2
            echo "       (add an ADR and whitelist entry in $WHITELIST" >&2
            echo "        if the edge is intentional)" >&2
            violations=$((violations + 1))
        fi
        # Strip leading "# " comments before scanning so commented-out path deps
        # are ignored. Doing this as a sed pipeline inside the process
        # substitution keeps the dependency on POSIX tools only.
    done < <(sed -E 's/^\s*#.*$//' "$manifest" \
            | grep -oE 'path\s*=\s*"[^"]*platform/[^"]+"' \
            | sed -E 's/.*"([^"]+)".*/\1/')
done

if (( violations > 0 )); then
    echo "" >&2
    echo "$violations un-whitelisted core -> platform dependency/ies." >&2
    exit 1
fi

echo ""
echo "layering: clean."
