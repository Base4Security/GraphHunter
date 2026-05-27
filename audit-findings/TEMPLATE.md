# <Method ID> — <Title>

**Date:** YYYY-MM-DD
**Method:** <description of what was scanned and how>
**Worker:** unit-<N>
**Base commit:** <git rev-parse --short HEAD>

## Summary

<1-2 sentence overview; include total findings count by tier, e.g. "3 findings: 0 P0, 2 P1, 1 P2">

## Findings

### <Finding title>

- **Severity:** P0 | P1 | P2 | P3
- **Axis:** legal | build | docs | content | security | community
- **Front:** libro | core | tauri | sidecar | infra
- **Evidence:** <path:line or exact command output>
- **Risk:** <one sentence — what breaks/leaks if unfixed>
- **Fix action:** <concrete action, not "investigate">
- **Cost:** XS (≤1h) | S (≤4h) | M (≤1d) | L (>1d)
- **Gate:** pre-release | post-release | nice-to-have
- **Owner suggested:** tú | colaborador | automatable

(Repeat one `###` section per finding.)

If 0 findings, replace the "## Findings" section with:

```
## Findings

None. Method ran cleanly on YYYY-MM-DD.
```

## Method log

<optional: paste relevant command outputs, error messages, paths inspected — anything that helps a reviewer reproduce>
