//! Public trait surface. Concrete validators live in sibling modules.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ValidationError {}

pub type ValidationResult<T = ()> = Result<T, ValidationError>;

/// Single-method trait so callers don't have to think about which
/// validator they got. The xgrammar-backed sampler that lands later
/// will implement this same trait, so the call sites in
/// `parser_generator` stay stable.
pub trait GrammarValidator: Send + Sync {
    fn validate(&self, source: &str) -> ValidationResult<()>;
}
