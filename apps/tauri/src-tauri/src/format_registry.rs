//! Thin shim: the format registry moved to
//! `graph_hunter_api::format_registry`. Re-exported here so existing
//! `crate::format_registry::*` imports keep compiling.

pub use graph_hunter_api::format_registry::{
    find_descriptor, make_parser_for_format, preview_for_format, resolve_format, FormatDescriptor,
};
