//! Heavy-logs #3 — binary session-file format with streaming I/O.
//!
//! The legacy JSON session format is correct but expensive: the JSON
//! save serializes entities and relations one-by-one (memory-safe
//! after `bb3c32c`), but the *load* path uses
//! `serde_json::from_reader::<SessionFile>` which materializes the
//! entire document into a `Vec<Entity>` + `Vec<Relation>` before
//! handing them to the graph builder. For a 28 GB EVTX session
//! (~100M entities, ~200M relations) those two vectors alone allocate
//! ~10 GB transient at load time on top of the graph's own footprint.
//!
//! This module defines a binary format (magic `b"GHS1"`) where the
//! header is JSON-encoded (schema-tolerant) and entity/relation records
//! are bincode-encoded with explicit lengths, so both save and load are
//! streaming: peak memory during persistence is bounded by the
//! writer/reader buffers (a few MB), independent of session size.
//!
//! Backward compatibility. The save path always writes the new
//! binary format. The load path peeks the first 4 bytes of the file:
//!   * `b"GHS1"`  → binary loader (this module).
//!   * anything else (legacy JSON) → existing JSON loader.
//! Existing on-disk JSON sessions stay loadable; the next save
//! migrates them to binary transparently. No user configuration.
//!
//! On-disk layout (all integers little-endian):
//!
//! ```text
//! [magic       u32 = 0x31534847 ("GHS1")]
//! [version     u32 = FORMAT_VERSION]     (2 = JSON header)
//! [hdr_len     u32]
//! [hdr_bytes   serde_json(SessionHeader)]   ← schema-tolerant (v2)
//! [n_entities  u64]
//! repeated n_entities times:
//!   [rec_len   u32]
//!   [rec_bytes bincode(Entity)]
//! [n_relations u64]
//! repeated n_relations times:
//!   [rec_len   u32]
//!   [rec_bytes bincode(Relation)]
//! ```
//!
//! Version history:
//!   v1 — header was bincode(SessionHeader); breaks on any struct change.
//!   v2 — header is serde_json(SessionHeader); tolerates field add/remove.
//!
//! Each record is length-prefixed so a corrupted/truncated middle
//! record is detectable rather than mis-aligning the whole stream.

use std::io::{Read, Write};

use graph_hunter_core::Entity;
use graph_hunter_core::Relation;
use serde::{Deserialize, Serialize};

use crate::state::session_types::{DatasetInfo, EntityTag, Note};

/// Magic bytes identifying a binary session file. ASCII "GHS1".
pub const MAGIC: [u8; 4] = *b"GHS1";

/// Current binary format version.
///   1 = bincode header (legacy; breaks on struct change)
///   2 = JSON header (schema-tolerant; field add/remove safe)
pub const FORMAT_VERSION: u32 = 2;

/// Layout version of the binary BODY (entity/relation bincode arrays).
/// Bump when Entity / Relation / CompactRelation (or anything they
/// serialize) changes in a way that breaks bincode round-trip.
pub const BODY_FORMAT_VERSION: u32 = 1;

/// Oldest body version this build can still deserialize. Raise this when
/// a body change drops backward compatibility with older saved sessions.
pub const MIN_SUPPORTED_BODY_VERSION: u32 = 1;

fn default_body_format_version() -> u32 {
    // Files written before body versioning have no field; their body is
    // the original (v1) layout.
    1
}

/// Serializable header — everything *except* the streaming entity /
/// relation arrays. Small, lives entirely in memory at save and
/// load time.
///
/// `#[serde(default)]` on collection fields ensures that a header
/// written by a future version that omits a field (e.g. a new optional
/// collection that wasn't present) still deserializes cleanly.
#[derive(Serialize, Deserialize)]
pub struct SessionHeader {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    #[serde(default)]
    pub path_node_ids: Vec<String>,
    #[serde(default)]
    pub notes: Vec<Note>,
    #[serde(default)]
    pub datasets: Vec<DatasetInfo>,
    #[serde(default)]
    pub tags: Vec<EntityTag>,
    /// Layout version of the entity/relation body that follows the header.
    /// Absent in pre-versioning files → defaults to 1.
    #[serde(default = "default_body_format_version")]
    pub body_format_version: u32,
}

/// Read the magic bytes and return whether this looks like a
/// binary session file. Does not advance the reader past the magic
/// — callers that proceed with the binary path call `read_header`
/// next which expects the magic still in front.
pub fn is_binary_session(prefix: &[u8]) -> bool {
    prefix.len() >= 4 && prefix[..4] == MAGIC
}

/// Errors specific to the binary format. Wrapped into the API's
/// own `ApiError::Io` variant by callers.
#[derive(Debug)]
pub enum BinaryError {
    Io(std::io::Error),
    Bincode(bincode::Error),
    Json(serde_json::Error),
    BadMagic,
    UnsupportedVersion(u32),
    Truncated(&'static str),
    IncompatibleBody { found: u32, min: u32, max: u32 },
}

impl std::fmt::Display for BinaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Bincode(e) => write!(f, "bincode: {e}"),
            Self::Json(e) => write!(f, "json: {e}"),
            Self::BadMagic => write!(f, "bad session magic (file is not a GHS1 binary session)"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported binary session version: {v}"),
            Self::Truncated(stage) => write!(f, "truncated session file at stage: {stage}"),
            Self::IncompatibleBody { found, min, max } => {
                if found > max {
                    write!(
                        f,
                        "session was saved by a newer GraphHunter build (body format v{found}; \
                         this build supports up to v{max}) — update GraphHunter to open it"
                    )
                } else {
                    write!(
                        f,
                        "session was saved with an incompatible older data format \
                         (body v{found}; minimum supported v{min}) — it cannot be loaded"
                    )
                }
            }
        }
    }
}

impl From<std::io::Error> for BinaryError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<bincode::Error> for BinaryError {
    fn from(e: bincode::Error) -> Self {
        Self::Bincode(e)
    }
}

impl From<serde_json::Error> for BinaryError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

fn write_u32<W: Write>(w: &mut W, v: u32) -> Result<(), BinaryError> {
    w.write_all(&v.to_le_bytes())?;
    Ok(())
}

fn write_u64<W: Write>(w: &mut W, v: u64) -> Result<(), BinaryError> {
    w.write_all(&v.to_le_bytes())?;
    Ok(())
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32, BinaryError> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64<R: Read>(r: &mut R) -> Result<u64, BinaryError> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Returns Ok if a body declaring `version` can be read by this build,
/// else an `IncompatibleBody` error carrying the actionable bounds.
pub fn check_body_compatible(version: u32) -> Result<(), BinaryError> {
    if version > BODY_FORMAT_VERSION || version < MIN_SUPPORTED_BODY_VERSION {
        return Err(BinaryError::IncompatibleBody {
            found: version,
            min: MIN_SUPPORTED_BODY_VERSION,
            max: BODY_FORMAT_VERSION,
        });
    }
    Ok(())
}

/// Write the magic, version, and JSON-serialized header. Caller
/// follows up with `write_entities` and `write_relations`.
///
/// The header is written as JSON (format version 2) so that future
/// struct changes (field additions, removals) do not corrupt existing
/// session files. Entity/relation records remain bincode for efficiency.
pub fn write_header<W: Write>(w: &mut W, header: &SessionHeader) -> Result<(), BinaryError> {
    w.write_all(&MAGIC)?;
    write_u32(w, FORMAT_VERSION)?; // 2 = JSON header
    let hdr_bytes = serde_json::to_vec(header)?;
    write_u32(w, u32::try_from(hdr_bytes.len()).expect("header < 4 GiB"))?;
    w.write_all(&hdr_bytes)?;
    Ok(())
}

/// Stream-write a count followed by `count` length-prefixed
/// bincode records. The caller drives the iterator so we never
/// materialize the full record set in memory.
pub fn write_entities<'a, W, I>(w: &mut W, count: u64, iter: I) -> Result<(), BinaryError>
where
    W: Write,
    I: IntoIterator<Item = &'a Entity>,
{
    write_u64(w, count)?;
    for entity in iter {
        let bytes = bincode::serialize(entity)?;
        write_u32(w, u32::try_from(bytes.len()).expect("entity < 4 GiB"))?;
        w.write_all(&bytes)?;
    }
    Ok(())
}

pub fn write_relations<W, I>(w: &mut W, count: u64, iter: I) -> Result<(), BinaryError>
where
    W: Write,
    I: IntoIterator<Item = Relation>,
{
    write_u64(w, count)?;
    for rel in iter {
        let bytes = bincode::serialize(&rel)?;
        write_u32(w, u32::try_from(bytes.len()).expect("relation < 4 GiB"))?;
        w.write_all(&bytes)?;
    }
    Ok(())
}

/// Read the magic + version + header. Returns the parsed header;
/// `r` is left positioned at the start of the entity-count u64.
///
/// Version dispatch:
///   2 — header is JSON; tolerant to field additions and removals.
///   1 — legacy bincode header (best-effort; fails if the struct drifted
///        since the file was written — those sessions are not recoverable
///        via this path, by design).
pub fn read_header<R: Read>(r: &mut R) -> Result<SessionHeader, BinaryError> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(BinaryError::BadMagic);
    }
    let version = read_u32(r)?;
    let hdr_len = read_u32(r)? as usize;
    let mut hdr_bytes = vec![0u8; hdr_len];
    r.read_exact(&mut hdr_bytes)?;
    match version {
        2 => Ok(serde_json::from_slice(&hdr_bytes)?),
        // Legacy bincode header (best-effort; fails if the struct drifted
        // since the file was written — those sessions are not recoverable
        // via this path, by design).
        1 => Ok(bincode::deserialize(&hdr_bytes)?),
        v => Err(BinaryError::UnsupportedVersion(v)),
    }
}

/// Reads the entity count and returns an iterator-like struct that
/// lazy-decodes one entity per call. Stops yielding when `count`
/// records have been read.
pub struct EntityReader<'a, R: Read> {
    r: &'a mut R,
    remaining: u64,
}

impl<'a, R: Read> EntityReader<'a, R> {
    pub fn new(r: &'a mut R) -> Result<Self, BinaryError> {
        let count = read_u64(r)?;
        Ok(Self { r, remaining: count })
    }

    pub fn count(&self) -> u64 {
        self.remaining
    }

    /// Read the next entity, or `Ok(None)` when the stream is
    /// exhausted. Errors propagate.
    pub fn next(&mut self) -> Result<Option<Entity>, BinaryError> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let len = read_u32(self.r)? as usize;
        let mut bytes = vec![0u8; len];
        self.r
            .read_exact(&mut bytes)
            .map_err(|_| BinaryError::Truncated("entity record"))?;
        let entity: Entity = bincode::deserialize(&bytes)?;
        self.remaining -= 1;
        Ok(Some(entity))
    }
}

pub struct RelationReader<'a, R: Read> {
    r: &'a mut R,
    remaining: u64,
}

impl<'a, R: Read> RelationReader<'a, R> {
    pub fn new(r: &'a mut R) -> Result<Self, BinaryError> {
        let count = read_u64(r)?;
        Ok(Self { r, remaining: count })
    }

    pub fn count(&self) -> u64 {
        self.remaining
    }

    pub fn next(&mut self) -> Result<Option<Relation>, BinaryError> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let len = read_u32(self.r)? as usize;
        let mut bytes = vec![0u8; len];
        self.r
            .read_exact(&mut bytes)
            .map_err(|_| BinaryError::Truncated("relation record"))?;
        let rel: Relation = bincode::deserialize(&bytes)?;
        self.remaining -= 1;
        Ok(Some(rel))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph_hunter_core::types::{EntityType, RelationType};
    use std::io::Cursor;

    #[test]
    fn header_roundtrip() {
        let header = SessionHeader {
            id: "test-session".into(),
            name: "test".into(),
            created_at: 12345,
            path_node_ids: vec!["a".into(), "b".into()],
            notes: vec![],
            datasets: vec![],
            tags: vec![],
            body_format_version: 1,
        };
        let mut buf = Vec::new();
        write_header(&mut buf, &header).unwrap();
        assert!(is_binary_session(&buf));
        let mut cur = Cursor::new(&buf);
        let parsed = read_header(&mut cur).unwrap();
        assert_eq!(parsed.id, header.id);
        assert_eq!(parsed.name, header.name);
        assert_eq!(parsed.created_at, header.created_at);
        assert_eq!(parsed.path_node_ids, header.path_node_ids);
    }

    #[test]
    fn entity_relation_roundtrip() {
        let header = SessionHeader {
            id: "s".into(),
            name: "s".into(),
            created_at: 0,
            path_node_ids: vec![],
            notes: vec![],
            datasets: vec![],
            tags: vec![],
            body_format_version: 1,
        };
        let entities = vec![
            Entity::new("a", EntityType::User),
            Entity::new("b", EntityType::Host),
        ];
        let relations = vec![Relation::new("a", "b", RelationType::Auth, 100)];

        let mut buf = Vec::new();
        write_header(&mut buf, &header).unwrap();
        write_entities(&mut buf, entities.len() as u64, &entities).unwrap();
        write_relations(&mut buf, relations.len() as u64, relations.iter().cloned()).unwrap();

        let mut cur = Cursor::new(&buf);
        let _parsed_hdr = read_header(&mut cur).unwrap();
        let mut er = EntityReader::new(&mut cur).unwrap();
        assert_eq!(er.count(), 2);
        let e0 = er.next().unwrap().unwrap();
        let e1 = er.next().unwrap().unwrap();
        assert!(er.next().unwrap().is_none());
        assert_eq!(e0.id, "a");
        assert_eq!(e1.id, "b");
        let mut rr = RelationReader::new(&mut cur).unwrap();
        assert_eq!(rr.count(), 1);
        let r0 = rr.next().unwrap().unwrap();
        assert!(rr.next().unwrap().is_none());
        assert_eq!(r0.source_id, "a");
        assert_eq!(r0.dest_id, "b");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = b"XXXX".to_vec();
        buf.extend_from_slice(&[0; 4]);
        let mut cur = Cursor::new(&buf);
        match read_header(&mut cur) {
            Err(BinaryError::BadMagic) => {}
            other => panic!("expected BadMagic, got {:?}", other.err()),
        }
    }

    #[test]
    fn check_body_compatible_accepts_current_rejects_out_of_range() {
        assert!(check_body_compatible(BODY_FORMAT_VERSION).is_ok());
        let too_new = check_body_compatible(BODY_FORMAT_VERSION + 1).unwrap_err();
        assert!(matches!(too_new, BinaryError::IncompatibleBody { .. }));
        assert!(too_new.to_string().contains("newer"));
        let too_old = check_body_compatible(0).unwrap_err();
        assert!(matches!(too_old, BinaryError::IncompatibleBody { .. }));
        assert!(too_old.to_string().contains("older") || too_old.to_string().contains("incompatible"));
    }

    #[test]
    fn header_without_body_version_defaults_to_one() {
        let json = br#"{"id":"s","name":"n","created_at":0,"path_node_ids":[],"notes":[],"datasets":[],"tags":[]}"#;
        let h: SessionHeader = serde_json::from_slice(json).unwrap();
        assert_eq!(h.body_format_version, 1);
    }

    #[test]
    fn json_header_tolerates_schema_drift() {
        // Simulate a header written by a DIFFERENT struct version:
        // (a) it has an EXTRA unknown field, and (b) it omits `tags`.
        // A schema-tolerant reader must still recover id/name/created_at.
        let future_json = br#"{"id":"sess-x","name":"niubiz","created_at":1780667944,"path_node_ids":[],"notes":[],"datasets":[],"future_field":{"whatever":true}}"#;
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&2u32.to_le_bytes());                 // version 2 = JSON header
        buf.extend_from_slice(&(future_json.len() as u32).to_le_bytes());
        buf.extend_from_slice(future_json);
        // (no entity/relation bytes needed — read_header stops after the header)

        let mut cur = Cursor::new(&buf);
        let h = read_header(&mut cur).expect("v2 JSON header must parse despite drift");
        assert_eq!(h.id, "sess-x");
        assert_eq!(h.name, "niubiz");
        assert_eq!(h.created_at, 1780667944);
        assert!(h.tags.is_empty(), "missing tags must default to empty");
    }
}
