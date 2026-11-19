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
