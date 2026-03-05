use std::fmt;

/// Domain errors for the GraphHunter engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    /// Attempted to add a relation referencing a non-existent entity.
    EntityNotFound(String),
    /// The hypothesis failed validation before search.
    InvalidHypothesis(String),
    /// A duplicate entity ID was inserted.
    DuplicateEntity(String),
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GraphError::EntityNotFound(id) => write!(f, "Entity not found: {id}"),
            GraphError::InvalidHypothesis(msg) => write!(f, "Invalid hypothesis: {msg}"),
            GraphError::DuplicateEntity(id) => write!(f, "Duplicate entity ID: {id}"),
        }
    }
}

impl std::error::Error for GraphError {}
