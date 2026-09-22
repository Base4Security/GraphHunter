/// Parses a DSL string into a Hypothesis.
///
/// Syntax: `EntityType -[RelationType]-> EntityType -[RelationType]-> EntityType ...`
///
/// Entity types: IP, Host, User, Process, File, Domain, Registry, URL, Service, *
/// Relation types: Auth, Connect, Execute, Read, Write, DNS, Modify, Spawn, Delete, *
pub fn parse_dsl(input: &str, name: Option<&str>) -> Result<DslParseResult, DslError> {
    DslParser::v1().parse(input, name)
}
