<!-- markdownlint-disable MD013 -->
# A4 — PII scan

**Date:** 2026-05-26
**Method:** git grep for public IPs (excluding RFC1918/doc-ranges), emails (excluding noreply trailer), base4sec.com username patterns, hardcoded secrets in non-LaTeX code
**Worker:** unit-11
**Base commit:** c85594d

## Summary

8 findings: 4 P0, 0 P1, 3 P2, 1 P3

## Findings

### Real company user emails in regression test fixtures

- **Severity:** P0
- **Axis:** security
- **Front:** core
- **Evidence:** `core/graph-engine/tests/path_dedup.rs:114,116,121,128,136,137` (entities `clitep...@base4sec.com`, `jvilch...@base4sec.com`)
- **Risk:** Two real internal user identifiers from the company's own SOC investigation domain (`base4sec.com`) are baked into a regression test that pins the exact string. Publishing this repo OSS would expose attribution data for the post-hunt Ator-case investigation — first-name + surname-initial + corporate domain is enough to identify the individuals on LinkedIn.
- **Fix action:** Replace the two literals with synthetic equivalents that preserve the 21-char-vs-20-char boundary the test guards (e.g. `cliteplo` → `userlongname` 12 chars + `@example.org`, with a comment explaining the off-by-one slicer regression). Mirror the rename in the chain-summary assertions on the same lines.
- **Cost:** XS
- **Gate:** pre-release
- **Owner suggested:** tú

### Real company user emails repeated in archived libro chapter (`docs/_archive/latex-manual-old/`)

- **Severity:** P0
- **Axis:** security
- **Front:** libro
- **Evidence:** `docs/_archive/latex-manual-old/appendices/G-piloto-referencia.tex:131-132`, `docs/_archive/latex-manual-old/chapters/20-mejoras-post-hunt.tex:474-475` (renders `clitep...@base4sec.com` and `litepl...@base4sec.com` to explain a truncation bug)
- **Risk:** Same identifiers as the test-fixture finding above, but in archived LaTeX that ships in the repo. Although the directory name is `_archive`, the files are tracked (`docs/_archive/2026-libros-pre-unificacion/` is the only carve-out in `.gitignore`; `latex-manual-old/` is NOT ignored) and would be visible from the OSS clone.
- **Fix action:** Either (a) move `docs/_archive/latex-manual-old/` to the gitignored pre-unificacion bundle, (b) delete it entirely (the content lives in `docs/libro/` now per M0 plan), or (c) sed-replace the literals with synthetic ones matching the test-fixture rename.
- **Cost:** S
- **Gate:** pre-release
- **Owner suggested:** tú

### 14 attacker-spray IPs in `core/graph-engine/tests/diff_hunts.rs` look like real public IPs

- **Severity:** P0
- **Axis:** security
- **Front:** core
- **Evidence:** `core/graph-engine/tests/diff_hunts.rs:30-44` (14 IPs in ranges 45.86.x.x, 91.217.x.x, 103.125.x.x, 103.163.x.x, 199.101.x.x, 216.24.x.x; e.g. `45.86.x.x`, `91.217.x.x`)
- **Risk:** The 14 IPs are not in RFC1918/RFC5737 documentation ranges. The test comment says "spraying scenario" — these match the shape of attacker IPs that would have been pulled from a real investigation (the active Ator fraud case is in memory). Even if these turn out to be VPN/hosting blocks chosen at random, shipping them as canonical "attacker IPs" pinned in an assertion creates legal risk: someone running `whois` on each one could be linked back to the project's threat-hunting context, defaming the IP owners.
- **Fix action:** Replace all 14 with TEST-NET ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or with another reserved doc-range. Since the test only cares about distinctness and count (3 baseline + 14 added = 17), the swap is mechanical.
- **Cost:** XS
- **Gate:** pre-release
- **Owner suggested:** tú

### Real-looking public IP in IIS parser test fixture

- **Severity:** P0
- **Axis:** security
- **Front:** core
- **Evidence:** `platform/parsers/src/iis_w3c.rs:180,201,217` (literal `186.182.x.x` in `SAMPLE_LOG` and asserted as `src.id`)
- **Risk:** `186.182.0.0/15` is allocated to a Latin-American ISP; not a documentation range. Same legal/attribution risk as the previous finding — a real client IP pinned to a "profile photo attack" log line is exactly the kind of forensic detail that should not survive into an OSS test corpus.
- **Fix action:** Replace with `198.51.100.89` (RFC5737 doc-range); update both the log line and the two `assert_eq!` calls.
- **Cost:** XS
- **Gate:** pre-release
- **Owner suggested:** tú

### Same attacker IP `45.86.x.x` also referenced in training script

- **Severity:** P2
- **Axis:** security
- **Front:** core
- **Evidence:** `scripts/train_gnn_v2.py:9` (`"node_id": "45.86.x.x"`)
- **Risk:** Reuses one of the 14 spray IPs (covered above) inside a Python training-data snippet. Low standalone exposure (it's a script fragment, not in a test that runs in CI), but inconsistency with the rename done in `diff_hunts.rs` would re-introduce the leak.
- **Fix action:** Apply the same rename as the spray-IP finding (use a TEST-NET address). Treat as part of the same PR.
- **Cost:** XS
- **Gate:** pre-release
- **Owner suggested:** tú

### Single Google-Cloud-range IP in libro narrative example

- **Severity:** P2
- **Axis:** content
- **Front:** libro
- **Evidence:** `docs/libro/parte1-fundamentos/01-threat-hunting.tex:389` (`\code{34.80.x.x}` as an illustrative node)
- **Risk:** `34.80.0.0/12` is assigned to Google Cloud (Taiwan region). The IP is used as a one-off teaching example ("la IP X es un nodo") and is not tied to attack context, but a documentation-range IP (`192.0.2.x`) would be cleaner and avoid implying the example points at a real GCP customer.
- **Fix action:** Replace with `192.0.2.10` in the chapter prose.
- **Cost:** XS
- **Gate:** post-release
- **Owner suggested:** colaborador

### Author Windows username `lsotomayor` hard-coded into debug command path

- **Severity:** P2
- **Axis:** content
- **Front:** tauri
- **Evidence:** `apps/tauri/src-tauri/src/commands/ingest_status.rs:262` (`"source_path": "C:\\Users\\lsoto...\\GraphHunter\\..."`)
- **Risk:** Cosmetic. The string is a stub payload for a debug Tauri command (`cmd_debug_emit_synthetic_llm_proposal`) and never opens that file. But it reveals the author's local user folder and reads as unpolished on first OSS impression.
- **Fix action:** Replace with a generic path like `C:\\Users\\Public\\Documents\\GraphHunter\\demo_data\\ambiguous_iis_for_llm.log` or use `~/GraphHunter/...`.
- **Cost:** XS
- **Gate:** post-release
- **Owner suggested:** tú

### Mock-token strings flagged by secret-grep are placeholders

- **Severity:** P3
- **Axis:** security
- **Front:** core
- **Evidence:** `platform/sources/src/token_storage.rs:193,214`, `platform/sources/src/defender_xdr.rs:423,450,605`, `platform/sources/src/log_analytics.rs:546,578,607,636`, `apps/tauri/src-tauri/src/commands/azure_streaming_smoke.rs:304` (literals like `rt_abc...`, `rt_xyz...`, `xdr-mock...`, `rt_smoke...`)
- **Risk:** None. These are intentional mock strings inside `#[cfg(test)]` blocks — they cannot authenticate against any real service. Listed for completeness so the next PII pass can pre-filter these locations and not re-flag them.
- **Fix action:** No action; document in audit cookbook that `rt_*` / `*-mock-*` patterns are pre-cleared.
- **Cost:** XS
- **Gate:** nice-to-have
- **Owner suggested:** automatable

## Method log

```bash
# 1. IPs (Perl regex needed for negative lookahead — git grep -E rejects it)
git grep -nP '\b((?!10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0|127\.|255\.255\.255\.255|198\.51\.100\.|203\.0\.113\.|192\.0\.2\.)[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b' > /tmp/audit-tmp-ips.txt
# Result: 240 lines, 45 unique IPs. After filtering well-known cloud (Google 8.8.x.x / 142.250.x.x, M365 13.107.x.x / 52.96.x.x, github.com 140.82.x.x, example.com 93.184.216.34, Reddit/Fastly 151.101.x.x, Tor exit nodes 185.220.101.x clearly used intentionally) and reserved/CGNAT/multicast ranges referenced inside `ip_utils.rs` classifier code, 15 IPs remained suspicious and were classified P0/P2.

# 2. Emails (exclude Co-Authored-By trailer)
git grep -nE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' | grep -v 'noreply@anthropic.com' > /tmp/audit-tmp-emails.txt
# Result: 106 lines, 30 unique addresses. Most are synthetic (`alice@*`, `bob@*`, `test@contoso.com`, Spanish `alicia@empresa.com`/`beatriz@empresa.com`, single-letter `a@x.com`/`b@x.com`). Real-looking: `clitep...@base4sec.com`, `jvilch...@base4sec.com`, `litepl...@base4sec.com` (= clitep... truncated by the bug the test guards), `idi@base4secur...` (SECURITY.md disclosure address — published intentionally, not a finding).

# 3. base4sec.com username pattern
git grep -nE '\b[a-z]+\.[a-z]+@base4sec\.com\b' > /tmp/audit-tmp-base4sec.txt
# Result: 0 lines. The base4sec emails found above use the `firstinitial+surname` shape (`cliteplo@`, `jvilcherrez@`), not the `first.last@` shape this pattern targets — so they were caught by the wider email grep, not here.

# 4. Hardcoded secrets in code
git grep -nE '(api_key|secret|password|token).*=.*[A-Za-z0-9]{10,}' -- '*.rs' '*.ts' '*.json' '*.toml' '*.js' '*.tsx' '*.jsx' '*.py' ':!docs/libro/*' > /tmp/audit-tmp-secrets.txt
# Result: 23 lines. After inspection: all are either (a) env-var lookups (`std::env::var(...)`), (b) parameter-passing in TS UI (`params.azure_client_secret = userInput.trim()`), or (c) mock tokens in `#[cfg(test)]` blocks (`StoredToken::new("rt_abc", ...)`, `StaticFetcher("xdr-mock-token")`). No real secret strings.

# 5. Sanity check for the author's own identifiers inside source (not git author metadata)
git grep -nE 'lsotomayor|lasotomayor20' -- ':!docs/_archive/*'
# Result: One hit in `apps/tauri/.../ingest_status.rs:262` (Windows path), plus many intentional `@lsotomayor` GitHub-handle attributions in `docs/libro/` chapters and CONTRIBUTING.md — those are normal authorship metadata, not findings.
```

All scratch files (`/tmp/audit-tmp-*.txt`, `/tmp/audit-unique-*.txt`) are outside the repo and not committed.
