# Extending the hypothesis DSL

GraphHunter's hypothesis DSL — the arrow-chain language users type to
describe attack patterns — is designed to be extended **without
forking**. Downstream crates (or an in-house deployment of GraphHunter)
add new entity types, relation types, and predicates by implementing
one trait and registering it on the parser.

This cookbook walks through the extension surface end to end, with a
worked example of a Kubernetes-flavoured extension that adds
`Container`, `Cluster`, and a `Mount` relation.

Contract of reference: [ADR-005](../architecture/phase1/ADR/005-dsl-extensibility.md).

## When to reach for this

You want to extend the DSL if:

- Your deployment has entities the stock grammar doesn't name
  (`Container`, `ServiceAccount`, `Cluster`, `Lambda`, `Queue`).
- You need relation types beyond the built-ins
  (`Mount`, `Assume`, `Invoke`, `Publish`).
- You want predicates the stock grammar doesn't express
  (`ip in_subnet "10.0.0.0/8"`, `host matches_regex "web-\\d+"`).

You do **not** need to extend the DSL if your addition is a variant of
an existing type (e.g. a new process category) — those belong in
predicates over `Process`, not in a new entity type.

## The three registries

A `DslParser` carries three independent registries:

| Registry | What it holds | User-written token |
|---|---|---|
| `EntityTypeRegistry` | Names of user-defined entity types | `Container`, `Cluster`, … |
| `RelationTypeRegistry` | Names of user-defined relation types | `Mount`, `Assume`, … |
| `PredicateRegistry` | Custom predicate evaluators | `in_subnet`, `matches_regex`, … |

Built-in names (`IP`, `Host`, `User`, `Process`, `File`, `Domain`,
`Registry`, `URL`, `Service`, `Auth`, `Connect`, `Execute`, `Read`,
`Write`, `DNS`, `Modify`, `Spawn`, `Delete`) are always available —
extensions add to the set but cannot shadow them.

## The `DslExtension` trait

An extension is any type that implements:

```rust
pub trait DslExtension: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> u32;
    fn register_entity_types(&self, reg: &mut EntityTypeRegistry) {}
    fn register_relation_types(&self, reg: &mut RelationTypeRegistry) {}
    fn register_predicates(&self, reg: &mut PredicateRegistry) {}
}
```

All three register hooks default to no-ops — implement only the ones
you need.

## Worked example: a Kubernetes extension

### Step 1 — declare the extension

```rust
use graph_hunter_dsl::extension::{
    DslExtension, EntityTypeDef, EntityTypeRegistry,
    RelationTypeDef, RelationTypeRegistry,
    PredicateCtx, PredicateEvaluator, PredicateRegistry,
    PredicateSignature,
};

pub struct K8sExtension;

impl DslExtension for K8sExtension {
    fn name(&self) -> &str {
        "k8s"
    }

    fn version(&self) -> u32 {
        1
    }

    fn register_entity_types(&self, reg: &mut EntityTypeRegistry) {
        reg.register(EntityTypeDef {
            name: "Container".into(),
            description: "A container workload (Docker, containerd, podman).".into(),
        });
        reg.register(EntityTypeDef {
            name: "Cluster".into(),
            description: "A Kubernetes or orchestrator cluster.".into(),
        });
        reg.register(EntityTypeDef {
            name: "ServiceAccount".into(),
            description: "A K8s ServiceAccount principal.".into(),
        });
    }

    fn register_relation_types(&self, reg: &mut RelationTypeRegistry) {
        reg.register(RelationTypeDef {
            name: "Mount".into(),
            description: "Container mounts a volume or configmap.".into(),
        });
        reg.register(RelationTypeDef {
            name: "Schedule".into(),
            description: "Pod scheduled on a node.".into(),
        });
    }

    fn register_predicates(&self, reg: &mut PredicateRegistry) {
        reg.register(
            "in_subnet",
            Box::new(InSubnetEvaluator::default()),
        );
    }
}
```

### Step 2 — implement a custom predicate evaluator

```rust
#[derive(Default)]
struct InSubnetEvaluator {
    sig: PredicateSignature,
}

impl InSubnetEvaluator {
    fn new() -> Self {
        Self {
            sig: PredicateSignature {
                name: "in_subnet".into(),
                description: "IP within a CIDR range.".into(),
            },
        }
    }
}

impl PredicateEvaluator for InSubnetEvaluator {
    fn evaluate(&self, ctx: &PredicateCtx<'_>) -> bool {
        // ctx.key is the predicate key the user wrote;
        // ctx.value is the value to test against.
        // Real implementations parse ctx.value as a CIDR
        // and check membership. Keep this Send + Sync —
        // the registry is shared across matcher threads.
        ctx.value.starts_with("10.")
    }

    fn signature(&self) -> &PredicateSignature {
        &self.sig
    }}
```

### Step 3 — install into a parser

```rust
use graph_hunter_dsl::DslParser;

let parser = DslParser::v1().with_extension(K8sExtension);

let result = parser.parse(
    "Container -[Mount]-> File",
    Some("container-mount-hunt"),
)?;

assert_eq!(result.hypothesis.steps.len(), 1);
```

`with_extension` is chainable — stack multiple extensions:

```rust
let parser = DslParser::v1()
    .with_extension(K8sExtension)
    .with_extension(AwsExtension)
    .with_extension(CustomPredicates);
```

### Step 4 — introspect what's registered

Tests and tooling can query the parser:

```rust
assert!(parser.entity_types().contains("Container"));
assert!(parser.relation_types().contains("Mount"));
assert!(parser.predicates().contains("in_subnet"));

for name in parser.entity_types().extension_names() {
    println!("extension entity: {name}");
}
```

## Rules and invariants

### Built-ins always win

If your extension tries to register `IP` or `Auth`, the call is a
silent no-op — built-ins can't be shadowed. This keeps the stable
grammar unambiguous across deployments.

### Extensions don't reject unknown names

At F4.3, registries are **informational**: parsing an unknown type
(e.g. `Widget -[Frob]-> Thing` with no extension installed) still
succeeds — the names become `EntityType::Other("Widget")` /
`RelationType::Other("Frob")`. This preserves backwards compatibility
with pre-F4 DSL scripts.

A future phase may add a `strict: true` mode where the parser rejects
names not in any registry. Until then, registries are how tooling
discovers what's *intentionally* available vs. what's a typo.

### Evaluators must be `Send + Sync`

Predicate evaluators ride in a shared registry consulted from the
matcher's rayon worker threads. Don't hold non-`Sync` state inside an
evaluator. If you need mutable state, wrap it in `Arc<Mutex<_>>` or
`Arc<RwLock<_>>` and accept the contention cost.

### Version your extension

`version()` is informational at F4.3 — bump it when the extension's
registered surface changes in a way a consumer's tests might observe.
A later phase may key compatibility checks off it.

## When extensions aren't enough

Extensions add **data** to the registries; they don't change the
grammar. Additions that need new syntax — temporal operators, grouping,
quantifiers, inline predicates — are grammar-level changes that go
through the v1 → v2 versioning path documented in ADR-005 §D4, not
through an extension.

Flow for grammar-level requests:

1. Open an issue describing the concrete use case.
2. Triage: does an extension cover it? If yes, you're done here.
3. If no: a grammar PR adds the construct to a `v2-experimental`
   module behind a feature flag, with backward-compat tests proving
   every v1 hypothesis still parses cleanly under v2.

## Reference

- Trait + registry definitions: [`platform/dsl/src/extension.rs`](../../platform/dsl/src/extension.rs)
- Stateful parser + installation: [`platform/dsl/src/lib.rs`](../../platform/dsl/src/lib.rs)
- ADR: [`docs/architecture/phase1/ADR/005-dsl-extensibility.md`](../architecture/phase1/ADR/005-dsl-extensibility.md)
