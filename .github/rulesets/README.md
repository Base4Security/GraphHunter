# Rulesets

Configuración de protección de `main` versionada como código. GitHub no la lee
de acá: se aplica con la API y este archivo es la fuente de verdad. Si se cambia
en la UI, se actualiza también acá en el mismo PR.

## `main.json`

| Regla | Para qué |
|---|---|
| `deletion`, `non_fast_forward` | No se puede borrar `main` ni hacer push forzado |
| `pull_request` | Todo cambio entra por PR. Aprobaciones en 0 por RA-1 (un solo desarrollador); subir a 1 cuando haya un segundo |
| `required_status_checks` | Bloquean el merge: `Secret scanning`, `rust-ci-ok`, `frontend (apps/tauri)`, `mcp (platform/mcp)`, `python`. `integration_id` 15368 es GitHub Actions: un check con el mismo nombre de otra app no cuenta |
| `code_scanning` | Bloquea si CodeQL reporta alertas de seguridad altas o críticas |

`rust-ci-ok` es el único check de `rust-ci.yml` que se pide: los tests por crate
se saltean cuando el PR no toca Rust y el agregador siempre termina.

## Aplicar

Requiere admin del repo. Los checks tienen que existir en `main` antes de
activarlo: si no, todo PR que no traiga los workflows queda bloqueado.

```bash
# Crear
gh api --method POST repos/Base4Security/GraphHunter/rulesets --input .github/rulesets/main.json

# Actualizar (id con: gh api repos/Base4Security/GraphHunter/rulesets)
gh api --method PUT repos/Base4Security/GraphHunter/rulesets/<id> --input .github/rulesets/main.json
```
