use crate::entity::Entity;
use crate::relation::Relation;

/// A triple produced by parsing a single log event:
/// (source entity, relation, destination entity).
pub type ParsedTriple = (Entity, Relation, Entity);

/// Trait for log format parsers.
///
/// Implementors convert raw log text into a vector of graph triples.
/// Each event may produce one or more triples (e.g., a process creation
/// event yields a User->Execute->Process triple AND a Process->Execute->Process
/// parent-child triple).
///
/// Parsers are expected to be stateless — all context comes from the input data.
pub trait LogParser: Send + Sync {
    /// Parses raw log data and returns extracted triples.
    ///
    /// Malformed or unrecognized events are silently skipped (logged in metadata)
    /// to allow best-effort ingestion of real-world, often messy, log sources.
    fn parse(&self, data: &str) -> Vec<ParsedTriple>;
}
