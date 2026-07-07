use std::fmt;

/// Errors originating from the spill-to-disk edge store.
#[derive(Debug)]
pub enum SpillError {
    /// Failed to create the temporary directory for spill files.
    TempDir(std::io::Error),
    /// Failed to create, open, write, or flush a spill/merged file.
    Io(std::io::Error),
    /// Failed to memory-map a spill or merged file.
    Mmap(std::io::Error),
    /// Refused to spill because available disk space is below the guard
    /// threshold. `free_bytes` is what was observed; `required_bytes` is
    /// the minimum we insist on keeping free.
    DiskFull {
        free_bytes: u64,
        required_bytes: u64,
    },
}

impl fmt::Display for SpillError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpillError::TempDir(e) => write!(f, "Failed to create temp dir for spill store: {e}"),
            SpillError::Io(e) => write!(f, "Spill store I/O error: {e}"),
            SpillError::Mmap(e) => write!(f, "Spill store mmap error: {e}"),
            SpillError::DiskFull {
                free_bytes,
                required_bytes,
            } => write!(
                f,
                "Refusing to spill: only {} MB free, need at least {} MB to continue safely",
                free_bytes / (1024 * 1024),
                required_bytes / (1024 * 1024),
            ),
        }
    }
}

impl std::error::Error for SpillError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SpillError::TempDir(e) | SpillError::Io(e) | SpillError::Mmap(e) => Some(e),
            SpillError::DiskFull { .. } => None,
        }
    }
}

/// Domain errors for the GraphHunter engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    /// Attempted to add a relation referencing a non-existent entity.
    EntityNotFound(String),
    /// The hypothesis failed validation before search.
    InvalidHypothesis(String),
    /// A duplicate entity ID was inserted.
    DuplicateEntity(String),
    /// An error occurred in the spill-to-disk edge store.
    Spill(String),
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GraphError::EntityNotFound(id) => write!(f, "Entity not found: {id}"),
            GraphError::InvalidHypothesis(msg) => write!(f, "Invalid hypothesis: {msg}"),
            GraphError::DuplicateEntity(id) => write!(f, "Duplicate entity ID: {id}"),
            GraphError::Spill(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for GraphError {}

impl From<SpillError> for GraphError {
    fn from(e: SpillError) -> Self {
        GraphError::Spill(e.to_string())
    }
}
