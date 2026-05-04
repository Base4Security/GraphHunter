//! F4.2 — DSL extensibility surface (ADR-005 §D2).
//!
//! Lets a downstream crate register new entity types, relation types,
//! and predicate evaluators without forking the DSL. The trait and its
//! three registries are defined here; `DslParser` wiring comes in F4.3.
//!
//! Built-in entity/relation names stay hard-coded — the registries only
//! hold *extension* additions. Lookup is `builtin ∪ extensions`, with
//! extensions unable to shadow built-ins (a register call that collides
//! with a built-in is silently ignored to keep the grammar stable; a
//! collision with another extension overwrites the earlier one, matching
//! `HashMap::insert` semantics).
//!
//! The evaluator API (`PredicateEvaluator` + `PredicateCtx`) is
//! intentionally minimal at this phase: it carries just the predicate's
//! key/value pair so a custom predicate can decide true/false. When F4.3
//! wires the registry into the parser and the match-time path, this API
//! may grow richer context (the current event, the binding environment)
//! without breaking the trait object signature.

use std::collections::HashMap;

/// Built-in entity type names that live in [`crate::types::EntityType`]
/// as distinct variants. The built-in set is frozen at grammar v1 —
/// adding a new built-in is a breaking grammar change (v2). Extensions
/// only add names that resolve to `EntityType::Other(_)`.
pub const BUILTIN_ENTITY_TYPES: &[&str] = &[
    "IP", "Host", "User", "Process", "File", "Domain", "Registry", "URL", "Service",
];

/// Built-in relation type names. Frozen at grammar v1. See
/// [`BUILTIN_ENTITY_TYPES`] for extension policy.
pub const BUILTIN_RELATION_TYPES: &[&str] = &[
    "Auth", "Connect", "Execute", "Read", "Write", "DNS", "Modify", "Spawn", "Delete",
];

/// Metadata describing a user-defined entity type registered via a
/// [`DslExtension`]. `name` is the token users type in the DSL
/// (e.g. `Container`, `ServiceAccount`); `description` is shown in
/// error messages and cookbook docs.
#[derive(Debug, Clone)]
pub struct EntityTypeDef {
    pub name: String,
    pub description: String,
}

/// Metadata describing a user-defined relation type.
#[derive(Debug, Clone)]
pub struct RelationTypeDef {
    pub name: String,
    pub description: String,
}

/// Signature of a custom predicate — carries the name the user writes
/// in the DSL and a human description for docs/error output.
#[derive(Debug, Clone)]
pub struct PredicateSignature {
    pub name: String,
    pub description: String,
}

/// Context handed to a [`PredicateEvaluator`] at match time. Minimal at
/// F4.2 — the key/value pair of the predicate under evaluation. When
/// F4.3+ wires this into the matcher it will grow a reference to the
/// event being matched and to the binding environment, but additions
/// go on the struct without changing the trait signature.
#[derive(Debug)]
pub struct PredicateCtx<'a> {
    pub key: &'a str,
    pub value: &'a str,
}

/// Trait implemented by a custom predicate. Object-safe — the registry
/// stores trait objects. Evaluators must be `Send + Sync` because the
/// registry is shared by the parser and the match-time path, which runs
/// across rayon worker threads.
pub trait PredicateEvaluator: Send + Sync {
    fn evaluate(&self, ctx: &PredicateCtx<'_>) -> bool;
    fn signature(&self) -> &PredicateSignature;
}

/// Entity type names valid in the DSL. Built-ins are constant;
/// extensions append user-defined names that resolve to
/// `EntityType::Other(_)` when parsed.
#[derive(Default)]
pub struct EntityTypeRegistry {
    extensions: HashMap<String, EntityTypeDef>,
}

impl EntityTypeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an extension entity type. Silently ignored if `name`
    /// collides with a built-in (built-ins win to keep grammar stable).
    /// Collisions between extensions overwrite.
    pub fn register(&mut self, def: EntityTypeDef) {
        if BUILTIN_ENTITY_TYPES.contains(&def.name.as_str()) {
            return;
        }
        self.extensions.insert(def.name.clone(), def);
    }

    pub fn contains(&self, name: &str) -> bool {
        BUILTIN_ENTITY_TYPES.contains(&name) || self.extensions.contains_key(name)
    }

    pub fn is_builtin(name: &str) -> bool {
        BUILTIN_ENTITY_TYPES.contains(&name)
    }

    pub fn extension_names(&self) -> impl Iterator<Item = &str> {
        self.extensions.keys().map(String::as_str)
    }
}

/// Relation type names valid in the DSL. Mirrors [`EntityTypeRegistry`].
#[derive(Default)]
pub struct RelationTypeRegistry {
    extensions: HashMap<String, RelationTypeDef>,
}

impl RelationTypeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, def: RelationTypeDef) {
        if BUILTIN_RELATION_TYPES.contains(&def.name.as_str()) {
            return;
        }
        self.extensions.insert(def.name.clone(), def);
    }

    pub fn contains(&self, name: &str) -> bool {
        BUILTIN_RELATION_TYPES.contains(&name) || self.extensions.contains_key(name)
    }

    pub fn is_builtin(name: &str) -> bool {
        BUILTIN_RELATION_TYPES.contains(&name)
    }

    pub fn extension_names(&self) -> impl Iterator<Item = &str> {
        self.extensions.keys().map(String::as_str)
    }
}

/// Registry of custom predicate evaluators. Keyed by the predicate name
/// users write in the DSL (e.g. `in_subnet`, `matches_regex`).
#[derive(Default)]
pub struct PredicateRegistry {
    evaluators: HashMap<String, Box<dyn PredicateEvaluator>>,
}

impl PredicateRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, name: impl Into<String>, eval: Box<dyn PredicateEvaluator>) {
        self.evaluators.insert(name.into(), eval);
    }

    pub fn get(&self, name: &str) -> Option<&dyn PredicateEvaluator> {
        self.evaluators.get(name).map(|b| b.as_ref())
    }

    pub fn contains(&self, name: &str) -> bool {
        self.evaluators.contains_key(name)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.evaluators.keys().map(String::as_str)
    }
}

/// A bundle of additions a downstream crate installs into a
/// [`crate::DslParser`] (wiring lands in F4.3). An extension typically
/// implements one or more of the three register hooks; defaults are
/// no-ops so implementors override only what they add.
pub trait DslExtension: Send + Sync {
    /// Stable identifier for the extension — shown in error messages and
    /// any "registered extensions" introspection. Must be unique per
    /// parser instance.
    fn name(&self) -> &str;

    /// Extension schema version. Bump when the extension's registered
    /// surface changes in a breaking way. Informational at F4.2.
    fn version(&self) -> u32;

    fn register_entity_types(&self, _reg: &mut EntityTypeRegistry) {}
    fn register_relation_types(&self, _reg: &mut RelationTypeRegistry) {}
    fn register_predicates(&self, _reg: &mut PredicateRegistry) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ContainerExt;

    impl DslExtension for ContainerExt {
        fn name(&self) -> &str {
            "container-ext"
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
        }
        fn register_relation_types(&self, reg: &mut RelationTypeRegistry) {
            reg.register(RelationTypeDef {
                name: "Mount".into(),
                description: "A container mounts a volume or config.".into(),
            });
        }
    }

    struct InSubnetEval(PredicateSignature);

    impl PredicateEvaluator for InSubnetEval {
        fn evaluate(&self, ctx: &PredicateCtx<'_>) -> bool {
            // Toy semantics: true iff the value starts with "10." —
            // enough to prove the wiring carries the ctx through.
            ctx.key == "ip" && ctx.value.starts_with("10.")
        }
        fn signature(&self) -> &PredicateSignature {
            &self.0
        }
    }

    fn install<E: DslExtension>(
        ext: &E,
    ) -> (EntityTypeRegistry, RelationTypeRegistry, PredicateRegistry) {
        let (mut e, mut r, mut p) = (
            EntityTypeRegistry::new(),
            RelationTypeRegistry::new(),
            PredicateRegistry::new(),
        );
        ext.register_entity_types(&mut e);
        ext.register_relation_types(&mut r);
        ext.register_predicates(&mut p);
        (e, r, p)
    }

    #[test]
    fn entity_registry_accepts_extension_name() {
        let (e, _, _) = install(&ContainerExt);
        assert!(e.contains("Container"));
        assert!(e.contains("Cluster"));
        assert!(e.contains("IP"), "builtins still resolve");
        assert!(!e.contains("Nonexistent"));
    }

    #[test]
    fn relation_registry_accepts_extension_name() {
        let (_, r, _) = install(&ContainerExt);
        assert!(r.contains("Mount"));
        assert!(r.contains("Auth"), "builtins still resolve");
    }

    #[test]
    fn extension_cannot_shadow_builtin_entity() {
        let mut e = EntityTypeRegistry::new();
        e.register(EntityTypeDef {
            name: "IP".into(),
            description: "malicious shadow".into(),
        });
        // Still resolves — but via builtin, not the extension entry.
        assert!(e.contains("IP"));
        assert_eq!(e.extension_names().count(), 0);
    }

    #[test]
    fn extension_cannot_shadow_builtin_relation() {
        let mut r = RelationTypeRegistry::new();
        r.register(RelationTypeDef {
            name: "Auth".into(),
            description: "malicious shadow".into(),
        });
        assert!(r.contains("Auth"));
        assert_eq!(r.extension_names().count(), 0);
    }

    #[test]
    fn predicate_registry_roundtrip() {
        let mut p = PredicateRegistry::new();
        p.register(
            "in_subnet",
            Box::new(InSubnetEval(PredicateSignature {
                name: "in_subnet".into(),
                description: "IP membership in a /8 subnet (toy).".into(),
            })),
        );
        assert!(p.contains("in_subnet"));
        let ev = p.get("in_subnet").unwrap();
        assert_eq!(ev.signature().name, "in_subnet");
        assert!(ev.evaluate(&PredicateCtx {
            key: "ip",
            value: "10.0.0.1"
        }));
        assert!(!ev.evaluate(&PredicateCtx {
            key: "ip",
            value: "192.168.0.1"
        }));
        assert!(!ev.evaluate(&PredicateCtx {
            key: "host",
            value: "10.0.0.1"
        }));
    }

    #[test]
    fn extension_metadata_roundtrip() {
        let ext = ContainerExt;
        assert_eq!(ext.name(), "container-ext");
        assert_eq!(ext.version(), 1);
    }

    #[test]
    fn empty_registries_contain_only_builtins() {
        let e = EntityTypeRegistry::new();
        for b in BUILTIN_ENTITY_TYPES {
            assert!(e.contains(b), "missing builtin {b}");
        }
        assert_eq!(e.extension_names().count(), 0);

        let r = RelationTypeRegistry::new();
        for b in BUILTIN_RELATION_TYPES {
            assert!(r.contains(b), "missing builtin {b}");
        }
    }
}
