# VRL subset grammar (formal CFG)

- **Status**: stable (the grammar tracks `VrlSubsetValidator`; both must stay in sync)
- **Version**: v1.0
- **Date**: 2026-04-27
- **Source of truth**: `platform/constrained-decode/grammars/vrl_subset.lark`
- **Validator counterpart**: `platform/constrained-decode/src/vrl_subset.rs`
- **Compiler counterpart**: `platform/vrl/src/compiler.rs::field_config_to_vrl`
- **Citation target**: paper §LLM-as-compiler, ADR-005 follow-up.

## What this is

The Lark CFG that defines, statically, the entire surface of VRL
GraphHunter is willing to execute. It serves three call-sites:

1. **Constrained decoding** (feature `xgrammar`): the candle backend
   masks decoder logits against this grammar so the local LLM emits
   VRL that parses by construction. No retry loops, no malformed code
   reaching the runtime.
2. **Post-hoc validation** (always available): `VrlSubsetValidator`
   re-checks the source line-by-line. Used as the safety net when
   constrained decoding is off (mock backend) or when LLM output
   somehow slips through (model bug).
3. **Compiler self-check** (`grammar_roundtrip` test): every
   `field_config_to_vrl` output, over a proptest population of
   FieldConfigs, must parse against this grammar. If it doesn't,
   either the compiler emits something the LLM can't replicate, or
   the grammar has drifted — both are bugs.

## What's in the subset

### Top level

A program is a sequence of lines. Each line is one of:

- **Blank** or `#`-prefixed **comment**.
- **Statement**: an assignment or a `del(.field)` call.
- **Block**: `if exists(.field) {` … `}` enclosing statements.
- **Return**: a single `.` on its own line, signalling the program's
  output is the (possibly modified) event root.

### Assignments

Allowed left-hand sides — exhaustive list:

- `.` (root rebind)
- `.canonical`
- `.canonical.entities`
- `.canonical.metadata`
- `.canonical.timestamp`
- `.canonical.metadata.<ident>`
- `.canonical.metadata."<raw>"` (quoted form for keys with dots/spaces)

Allowed right-hand sides — exhaustive list:

| RHS form | Use |
|----------|-----|
| `{}`, `[]`, `null` | Scaffolding |
| `parse_json!(string!(.message))` | Root rebind to a parsed JSON message |
| `push(.canonical.entities, { … })` | Append an entity to the array |
| `parse_timestamp(<args>) ?? null` | Coerce a timestamp; null on failure |
| `<field-access>` | Plain copy from the source event |
| `to_string!(<field>)`, `string!(<field>)`, `downcase!(<field>)`, `upcase!(<field>)` | String coercions |
| `"<literal>"` | Quoted string (no backticks, no interpolation) |

### Field access

```
field_access ::= "." IDENT_PATH? | "." QUOTED | "." IDENT_PATH "." QUOTED
IDENT_PATH   ::= /[A-Za-z_][A-Za-z0-9_.]*/
QUOTED       ::= /"[^"]*"/
```

`.` alone refers to the event root. Quoted segments enable field names
that contain dots, spaces, or other non-identifier characters
(`."User-Agent"`).

### Conditional blocks

```
block ::= "if exists(" field_access ") {" NEWLINE inner_line+ "}" NEWLINE
```

Only `if exists(...)` is supported. No `else`, no nested ifs, no
boolean operators. The block body is a sequence of statements
(blank/comment/assignment/del). This shape is what makes the
deterministic compiler's output and the LLM-refined output
diff-friendly: same skeleton, possibly different field choices.

## What's *not* in the subset

The grammar deliberately rejects:

- **Loops**: `for`, `while`, `loop`.
- **Match**: `match … { … => … }`.
- **Boolean operators**: `&&`, `||`, `?:`.
- **Range / chain**: `..`.
- **Multiple statements per line**: `;`.
- **Arithmetic**: `+`, `-`, `*`, `/`.
- **Indexing**: `.x[0]`, `.x["key"]` (quoted dotted paths replace this).
- **Unrecognized function calls**: anything that isn't in the explicit
  RHS list above.
- **String interpolation / backticks**: `\`${...}\``.
- **Custom function definitions**: VRL doesn't really have them
  user-side; we explicitly forbid them anyway.

The rejection list is enforced both by the grammar (these tokens have
no production) and by `VrlSubsetValidator` as a defense in depth.

## Sync invariant

The grammar and the validator and the compiler form a triangle:

```
field_config_to_vrl ───► output ───► VrlSubsetValidator
        │                                  │
        ▼                                  ▼
vrl_subset.lark ◄─────── parses ◄──────────┘
```

Each edge is checked by a test:

- `compiler_roundtrip_grammar`: every compiler output parses against
  `vrl_subset.lark` (proptest, 100 cases).
- `compiler_roundtrip_validator`: every compiler output passes
  `VrlSubsetValidator` (existing test in `vrl_subset.rs`).
- `grammar_validator_agreement`: any string that parses against
  `vrl_subset.lark` is accepted by `VrlSubsetValidator`, modulo
  whitespace (proptest over a sampled grammar production).

If any of those edges fails, the offending component is the bug, not
the spec. The triangle is the contract.

## How to evolve the subset

Adding a new construct (say, a new string built-in) requires:

1. Update `field_config_to_vrl` to emit it.
2. Update `vrl_subset.lark` with the new production.
3. Update `vrl_subset.rs` validator with the matching pattern.
4. All three roundtrip tests stay green.

If any of those steps is skipped, the constrained decoder, the
validator, and the compiler will disagree, and the LLM-as-compiler
guarantee breaks. The CI gate enforces this.
