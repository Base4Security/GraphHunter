use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Represents the type of entity observed in the network/host telemetry.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum EntityType {
    IP,
    Host,
    User,
    Process,
    File,
    Domain,
    Registry,
    URL,
    Service,
    /// Wildcard: matches any entity type in DFS search.
    Any,
    /// User-defined type name (e.g. from "Rename type" custom field).
    Other(String),
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EntityType::IP => write!(f, "IP"),
            EntityType::Host => write!(f, "Host"),
            EntityType::User => write!(f, "User"),
            EntityType::Process => write!(f, "Process"),
            EntityType::File => write!(f, "File"),
            EntityType::Domain => write!(f, "Domain"),
            EntityType::Registry => write!(f, "Registry"),
            EntityType::URL => write!(f, "URL"),
            EntityType::Service => write!(f, "Service"),
            EntityType::Any => write!(f, "*"),
            EntityType::Other(s) => write!(f, "{}", s),
        }
    }
}

impl FromStr for EntityType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "IP" => Ok(EntityType::IP),
            "Host" => Ok(EntityType::Host),
            "User" => Ok(EntityType::User),
            "Process" => Ok(EntityType::Process),
            "File" => Ok(EntityType::File),
            "Domain" => Ok(EntityType::Domain),
            "Registry" => Ok(EntityType::Registry),
            "URL" => Ok(EntityType::URL),
            "Service" => Ok(EntityType::Service),
            "*" => Ok(EntityType::Any),
            other if !other.is_empty() => Ok(EntityType::Other(other.to_string())),
            _ => Err("Empty entity type".to_string()),
        }
    }
}

/// Represents the type of relationship between two entities.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RelationType {
    Auth,
    Connect,
    Execute,
    Read,
    Write,
    DNS,
    Modify,
    Spawn,
    Delete,
    /// Wildcard: matches any relation type in DFS search.
    Any,
}

impl fmt::Display for RelationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelationType::Auth => write!(f, "Auth"),
            RelationType::Connect => write!(f, "Connect"),
            RelationType::Execute => write!(f, "Execute"),
            RelationType::Read => write!(f, "Read"),
            RelationType::Write => write!(f, "Write"),
            RelationType::DNS => write!(f, "DNS"),
            RelationType::Modify => write!(f, "Modify"),
            RelationType::Spawn => write!(f, "Spawn"),
            RelationType::Delete => write!(f, "Delete"),
            RelationType::Any => write!(f, "*"),
        }
    }
}

impl FromStr for RelationType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Auth" => Ok(RelationType::Auth),
            "Connect" => Ok(RelationType::Connect),
            "Execute" => Ok(RelationType::Execute),
            "Read" => Ok(RelationType::Read),
            "Write" => Ok(RelationType::Write),
            "DNS" => Ok(RelationType::DNS),
            "Modify" => Ok(RelationType::Modify),
            "Spawn" => Ok(RelationType::Spawn),
            "Delete" => Ok(RelationType::Delete),
            "*" => Ok(RelationType::Any),
            other => Err(format!("Unknown relation type: '{}'", other)),
        }
    }
}

/// Helper: checks if two entity types match, treating `Any` as a wildcard.
pub fn entity_type_matches(pattern: &EntityType, actual: &EntityType) -> bool {
    *pattern == EntityType::Any || *pattern == *actual
}

/// Helper: checks if two relation types match, treating `Any` as a wildcard.
pub fn relation_type_matches(pattern: &RelationType, actual: &RelationType) -> bool {
    *pattern == RelationType::Any || *pattern == *actual
}

/// Controls how duplicate metadata keys are handled during entity upsert.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub enum MergePolicy {
    /// First value wins — existing keys are preserved (current default).
    #[default]
    FirstWriteWins,
    /// Last value wins — new values overwrite existing keys.
    LastWriteWins,
    /// Values are concatenated with ", " separator.
    Append,
}
