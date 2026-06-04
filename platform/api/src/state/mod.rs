//! Session registry and per-session state.
//!
//! Everything needed to model the analyst's workspace lives here:
//! - [`Session`] + [`SessionStore`]: the in-memory session and registry.
//! - [`SessionHandle`]: opaque id handed to clients.
//! - [`Note`], [`EntityTag`], [`DatasetInfo`], [`SessionFile`]: payload
//!   types shared with transports.
//! - [`persistence`]: disk layout helpers.

pub mod agentic;
pub mod persistence;
pub mod session;
pub mod session_binary;
pub mod session_types;

pub use persistence::{
    ensure_session_dir, session_data_dir, session_file_path, validate_session_id,
};
pub use session::{Session, SessionHandle, SessionStore};
pub use session_types::{DatasetInfo, EntityTag, LiveTailStats, Note, SessionFile, SessionPhase};
