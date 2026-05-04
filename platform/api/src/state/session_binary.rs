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
//! This module defines a binary format (magic `b"GHS1"`) where every
//! record is bincode-encoded and lengths are explicit, so both save
//! and load are streaming: peak memory during persistence is bounded
//! by the writer/reader buffers (a few MB), independent of session
//! size.
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
//! [version     u32 = FORMAT_VERSION]
//! [hdr_len     u32]
//! [hdr_bytes   bincode(SessionHeader)]
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
//! Each record is length-prefixed so a corrupted/truncated middle
//! record is detectable rather than mis-aligning the whole stream.

use std::io::{Read, Write};

use graph_hunter_core::Entity;
use graph_hunter_core::Relation;
use serde::{Deserialize, Serialize};

use crate::state::session_types::{DatasetInfo, EntityTag, Note};

/// Magic bytes identifying a binary session file. ASCII "GHS1".
pub const MAGIC: [u8; 4] = *b"GHS1";

/// Current binary format version. Bump on any breaking change to
/// the layout below; keep readers on older versions for backward
/// compat when feasible.
pub const FORMAT_VERSION: u32 = 1;

/// Serializable header — everything *except* the streaming entity /
/// relation arrays. Small, lives entirely in memory at save and
/// load time.
#[derive(Serialize, Deserialize)]
pub struct SessionHeader {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub path_node_ids: Vec<String>,
    pub notes: Vec<Note>,
    pub datasets: Vec<DatasetInfo>,
    pub tags: Vec<EntityTag>,
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
    BadMagic,
    UnsupportedVersion(u32),
    Truncated(&'static str),
}

impl std::fmt::Display for BinaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Bincode(e) => write!(f, "bincode: {e}"),
            Self::BadMagic => write!(f, "bad session magic (file is not a GHS1 binary session)"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported binary session version: {v}"),
            Self::Truncated(stage) => write!(f, "truncated session file at stage: {stage}"),
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

/// Write the magic, version, and serialized header. Caller follows
/// up with `write_entities` and `write_relations`.
pub fn write_header<W: Write>(w: &mut W, header: &SessionHeader) -> Result<(), BinaryError> {
    w.write_all(&MAGIC)?;
    write_u32(w, FORMAT_VERSION)?;
    let hdr_bytes = bincode::serialize(header)?;
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
pub fn read_header<R: Read>(r: &mut R) -> Result<SessionHeader, BinaryError> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(BinaryError::BadMagic);
    }
    let version = read_u32(r)?;
    if version != FORMAT_VERSION {
        return Err(BinaryError::UnsupportedVersion(version));
    }
    let hdr_len = read_u32(r)? as usize;
    let mut hdr_bytes = vec![0u8; hdr_len];
    r.read_exact(&mut hdr_bytes)?;
    let header: SessionHeader = bincode::deserialize(&hdr_bytes)?;
    Ok(header)
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
}
