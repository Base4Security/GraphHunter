/// Stateful DSL parser holding the three extension registries
/// (entity types, relation types, predicates). Construct with
/// [`DslParser::v1`] for the stable grammar, then chain
/// [`DslParser::with_extension`] to install custom types/predicates.
/// Parsing is `&self` — a single `DslParser` is reusable across calls
/// and cheap to clone via [`std::sync::Arc`] when shared across threads.
///
/// This is F4.3 structural wiring: the registries ride along with the
/// parser but unknown `Other(_)` entity/relation names still parse
/// successfully, preserving the pre-F4 grammar. A later phase may add
/// a strict mode that rejects unknown names.
pub struct DslParser {
    entity_types: EntityTypeRegistry,
    relation_types: RelationTypeRegistry,
    predicates: PredicateRegistry,
}
