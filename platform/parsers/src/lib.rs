//! Concrete `LogParser` implementations lifted out of `graph_hunter_core`.
//!
//! The trait itself (`LogParser`, `ParsedTriple`, `ParseStats`) stays in
//! `graph_hunter_core::parser` so the core ingest pipeline keeps
//! consuming it without needing an outbound dependency on this crate.
//! Callers who previously imported `graph_hunter_core::CognitoParser`
//! now import `graph_hunter_parsers::CognitoParser` (and similar for
//! the other two impls that migrated).
//!
//! Only three of the seven impls moved in F2.10: **cognito**,
//! **forti_analyzer**, and **iis_w3c**. The other four stay in core for
//! now:
//!
//! - `generic` and `csv_parser` are reachable from `field_preview.rs`,
//!   `preview.rs`, and the mapping library through `GenericParser`'s
//!   static canonical-mapping helpers — moving them would drag those
//!   callers along and create a core→parsers edge.
//! - `sysmon` and `sentinel` are used by the ~400 unit tests inlined in
//!   `graph_hunter_core/src/lib.rs`. Pulling them via a `[dev-dependencies]`
//!   cycle fails because `parsers` impls `core::LogParser`, so the
//!   core-under-test and core-linked-by-parsers are different crate
//!   instances and the trait bound doesn't hold. Unwinding that belongs
//!   in a dedicated later pass (hoisting the tests to
//!   `graph_hunter_core/tests/*.rs` integration tests, which bypass the
//!   two-copy problem).

pub mod cognito;
pub mod forti_analyzer;
pub mod fortigate;
pub mod iis_w3c;

pub use cognito::{CognitoParser, looks_like_cognito};
pub use forti_analyzer::{
    ChartHandler, CompromisedHostHandler, FortiAnalyzerXmlParser, GenericFortiHandler,
    HandlerRegistry, ReportContext, Row, TopApplicationBySeverityHandler,
    TopApplicationCategoryHandler, TopThreatHandler, TopUserByTrafficHandler,
    TopWebsiteByTrafficHandler,
};
pub use fortigate::{FortiGateParser, looks_like_fortigate};
pub use iis_w3c::{IisW3cParser, extract_fields_header, looks_like_iis_w3c};
