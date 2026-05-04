# ADR-005 — DSL Extensibility: grammar versioning + extension registry

- **Fecha**: 2026-04-23
- **Estado**: propuesto
- **Decisión**: extraer el DSL a crate `platform/dsl/`, introducir `DslExtension` trait para registrar entity types / relation types / predicados custom, versionar la gramática (`v1`, `v2-experimental`), y preservar compatibilidad de hipótesis escritas por usuarios existentes.

## Contexto

- DSL actual: `graph_hunter_core/src/dsl.rs` (767 LOC), parser hand-rolled, sintaxis:
  ```
  Entity -[Relation]-> Entity -[Relation]-> Entity ... {k=N}
  ```
- Entity types fijos: IP, Host, User, Process, File, Domain, Registry, URL, Service, `*`.
- Relation types fijos: Auth, Connect, Execute, Read, Write, DNS, Modify, Spawn, Delete, `*`.
- Predicados: inline en el parser, no pluggables.
- Clasificación de Fase 0: AMBIGUO (núcleo o plataforma).
- **Decisión del usuario**: plataforma. Clientes pueden pedir features/mejoras en la gramática.
- Clientes potenciales quieren: nuevos entity types (`Container`, `ServiceAccount`, `Cluster`), nuevos predicados (`in_subnet`, `matches_regex`, `is_weekend`), operadores temporales explícitos.

## Decisión

### D1 — Extraer a crate `platform/dsl/`

```
platform/dsl/
├─ src/
│   ├─ lib.rs                    (fachada pública)
│   ├─ grammar/
│   │   ├─ v1.rs                 (grammar estable — hoy)
│   │   └─ v2.rs                 (futura, feature-gated si aparece)
│   ├─ ast.rs                    (Hypothesis, Step, Predicate — tipos)
│   ├─ extension.rs              (trait DslExtension + registries)
│   ├─ parser.rs                 (combinators genéricos)
│   └─ format.rs                 (Hypothesis -> String)
├─ tests/
└─ Cargo.toml
```

Depende de: `core/graph-engine` (para `Hypothesis` runtime types).
Consumido por: `platform/api` (en `operations/dsl.rs`).

### D2 — Registries extensibles

```rust
pub struct EntityTypeRegistry {
    builtin: &'static [&'static str],  // IP, Host, User, ...
    extensions: HashMap<String, EntityTypeDef>,
}

pub struct RelationTypeRegistry { /* same shape */ }

pub struct PredicateRegistry {
    predicates: HashMap<String, Box<dyn PredicateEvaluator>>,
}

pub trait PredicateEvaluator: Send + Sync {
    fn evaluate(&self, ctx: &PredicateCtx) -> bool;
    fn signature(&self) -> &PredicateSignature;
}

pub trait DslExtension: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> u32;
    fn register_entity_types(&self, reg: &mut EntityTypeRegistry) {}
    fn register_relation_types(&self, reg: &mut RelationTypeRegistry) {}
    fn register_predicates(&self, reg: &mut PredicateRegistry) {}
}
```

### D3 — `DslParser` como constructor composable

```rust
pub struct DslParser {
    grammar: GrammarVersion,
    entity_types: EntityTypeRegistry,
    relation_types: RelationTypeRegistry,
    predicates: PredicateRegistry,
}

impl DslParser {
    pub fn v1() -> Self {
        Self::new_with_builtin(GrammarVersion::V1)
    }

    pub fn with_extension(mut self, ext: impl DslExtension + 'static) -> Self { ... }

    pub fn parse(&self, source: &str) -> Result<Hypothesis, DslError>;

    pub fn format(&self, h: &Hypothesis) -> String;
}
```

- `DslParser::v1()` es drop-in replacement del parser actual.
- Tests de Fase 0 (`tests/dsl_predicates.rs`, `tests/dsl_bindings.rs`) siguen pasando.

### D4 — Grammar versioning

- **v1**: grammar actual. Congelada una vez Fase 4 cierra. Breaking changes requieren v2.
- **v2-experimental**: feature flag opcional. Candidatos (clientes pueden pedir):
  - Operadores temporales explícitos: `within 5m`, `after 2m`.
  - Grupos: `(A -[x]-> B) or (A -[y]-> C)`.
  - Cuantificadores: `-[*]{2,4}->` (2-4 hops).
  - Predicados inline: `User[name matches 'admin.*']`.
- El DslParser escoge grammar en construcción: `DslParser::v2()` o `DslParser::v1()`.
- Hipótesis escritas con v1 válidas en v2 (v2 ⊇ v1). Tests de migración obligatorios.

### D5 — Proceso para agregar features pedidas por clientes

1. Cliente abre issue con uso concreto.
2. Revisión: ¿es extension (predicado/entity type custom en su deployment) o core (modificación de grammar)?
3. **Si extension**: el cliente implementa `DslExtension` en su codebase, registra en su propio embeddeing. No merge al repo principal.
4. **Si core**: PR que toca grammar → requiere ADR de cambio, incremento de versión (v1 → v2 si breaking) o extension de v2 (si aditivo y ya estamos en v2).
5. Tests de roundtrip agregados: `parse(format(h)) == h` para las nuevas construcciones.

### D6 — Tests

- Property-based (Fase 3): `parse(format(h)) == h` sobre hipótesis arbitrarias válidas.
- Roundtrip contra corpus de hipótesis reales (`docs/examples/hypotheses/`).
- Test de backward compat: todas las hipótesis del corpus v1 parsean en v2 cuando se introduzca.

## Consecuencias positivas

- Clientes agregan entity types/predicados sin forkear.
- Versioning explícito → evolvable sin romper queries existentes.
- Trait `DslExtension` documenta claramente el contrato de extensión.
- Separación `platform/dsl` ↔ `core/graph-engine` → claridad de capa.

## Consecuencias negativas / costos

- Parser actual es hand-rolled. Refactorizar a combinators genéricos con registries es ~2-3 días.
- Runtime hace lookup en registries por cada parse → overhead mínimo pero presente (pre-compile cache en `DslParser` amortiza).
- Documentar el cookbook de extensión (Fase 4 deliverable) añade work.

## Alternativas consideradas

- **Macros proc-macro de extensión en tiempo de compilación**: más performante pero bloquea extensiones dinámicas. Rechazado.
- **DSL basado en pest/nom/lalrpop**: tentador; cambia masivamente el parser. Pospuesto a v2 si/cuando se haga.
- **Dejar el DSL en núcleo, hardcoded**: rechazado por decisión del usuario.

## Referencias

- SHEARING_MAP §CONFIRMAR (ambiguidad DSL)
- CURRENT_STATE §5 (extension points)
- Decisión explícita del usuario sobre plataforma + clientes.
