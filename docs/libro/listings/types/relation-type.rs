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
    /// User-defined rel type (e.g. "Consent", "Assign", "Forward") used
    /// by cloud-identity and post-compromise patterns. Tag 254 in FFI;
    /// the actual name travels through the meta_store side-table at
    /// insert time. DFS compares on Display strings so matching is
    /// correct even across FFI round-trips.
    Other(String),
}
