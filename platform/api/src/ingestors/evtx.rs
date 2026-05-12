//! Windows EVTX ingestor (Sysmon, Security, Application, …).
//!
//! Wraps the pre-existing free function
//! [`crate::evtx::evtx_ingest_streaming`] behind the
//! [`StreamingIngestor`] trait. Zero behavior change vs. the
//! pre-refactor `if`-branch in `load_data_streaming` — same parser
//! selection (`ConfigurableParser` when a [`FieldConfig`] is supplied,
//! [`GenericParser`] otherwise), same batch size, same emitter path.

use std::path::Path;

use graph_hunter_core::{ConfigurableParser, GenericParser, LogParser};

use super::{IngestContext, StreamingIngestor};
use crate::evtx::{evtx_ingest_streaming, file_looks_like_evtx, path_is_evtx};

/// Stateless ingestor — the per-call EVTX parser is built fresh inside
/// [`StreamingIngestor::ingest`] from the optional `FieldConfig`.
pub struct EvtxIngestor;

impl EvtxIngestor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for EvtxIngestor {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingIngestor for EvtxIngestor {
    fn name(&self) -> &'static str {
        "evtx"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["evtx"]
    }

    /// EVTX files start with `"ElfFile\0"` (8 bytes). Confidence
    /// scoring:
    /// - Magic match (extension or not): `255` — the EVTX magic is
    ///   unambiguous.
    /// - Extension match only (`.evtx` but no/short magic): `150` — a
    ///   common case is a truncated download; let it through with low
    ///   confidence and surface the real error in `ingest`.
    fn sniff(&self, path: &Path, magic: &[u8]) -> Option<u8> {
        if magic.starts_with(b"ElfFile\0") {
            return Some(255);
        }
        let ext_match = path
            .extension()
            .map(|e| e.eq_ignore_ascii_case("evtx"))
            .unwrap_or(false);
        // Fall back to the file-open helpers for safety: matches the
        // pre-refactor behavior for the `auto` dispatch where the
        // file might be opened from a path with mixed-case extension.
        let path_str = path.to_string_lossy();
        if ext_match && (path_is_evtx(&path_str) || file_looks_like_evtx(&path_str)) {
            return Some(150);
        }
        None
    }

    fn ingest(&self, ctx: IngestContext<'_>) -> Result<(usize, usize), String> {
        let parser: Box<dyn LogParser + Send> = match ctx.config {
            Some(cfg) => Box::new(ConfigurableParser::new(cfg.clone())),
            None => Box::new(GenericParser),
        };
        evtx_ingest_streaming(
            ctx.path,
            parser.as_ref(),
            ctx.session,
            ctx.dataset_id,
            ctx.emitter,
            ctx.job_id,
        )
    }
}
