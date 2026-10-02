//! Offline probe of the streaming ingest path against real files.
//!
//! Mirrors what `operations::ingestion` does — peek, resolve the format,
//! ask the registry for the stream mode, cut records with
//! [`RecordScanner`], re-inject the header into every batch, parse — but
//! without a session or a graph. It exists to answer, on the real corpus
//! rather than on a fixture, the two questions the unit tests cannot:
//! does the file reach the right parser, and does that parser actually
//! produce edges from it.
//!
//! Usage:
//!   cargo run --example probe_ingest --manifest-path platform/api/Cargo.toml -- <file> [max_mb]

use std::collections::BTreeMap;
use std::io::Read;

use graph_hunter_api::format_registry::{
    format_is_headed, make_parser_for_format, resolve_format, stream_mode_for,
};
use graph_hunter_api::record_scan::RecordScanner;

/// Lines per batch. The production path uses a larger value; a smaller
/// one here deliberately exercises MORE batch boundaries per megabyte,
/// which is where header re-injection and mid-record cuts go wrong.
const BATCH_LINES: usize = 5_000;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: probe_ingest <file> [max_mb]");
        std::process::exit(2);
    }
    let path = &args[0];
    let max_bytes = args
        .get(1)
        .and_then(|s| s.parse::<usize>().ok())
        .map(|mb| mb * 1024 * 1024)
        .unwrap_or(usize::MAX);

    let mut file = std::fs::File::open(path).expect("open");
    let total = file.metadata().map(|m| m.len()).unwrap_or(0);

    let mut buf = Vec::new();
    if max_bytes == usize::MAX {
        file.read_to_end(&mut buf).expect("read");
    } else {
        buf.resize(max_bytes, 0);
        let n = read_fully(&mut file, &mut buf);
        buf.truncate(n);
    }
    // Trim a trailing partial record so the tail is not reported as a
    // parse failure that only the byte cap caused.
    if let Some(last_nl) = buf.iter().rposition(|b| *b == b'\n') {
        buf.truncate(last_nl + 1);
    }

    let text = String::from_utf8_lossy(&buf);
    let peek: String = text.chars().take(8192).collect();
    let resolved = resolve_format(&peek, "auto");
    let mode = stream_mode_for(&resolved, peek.trim_start());
    let headed = format_is_headed(&resolved);

    println!("file        : {path}");
    println!("size        : {:.1} MB (probing {:.1} MB)", mb(total), mb(buf.len() as u64));
    println!("format      : {resolved}");
    println!("stream mode : {mode:?}  (streamable: {})", mode.is_streamable());
    println!("headed      : {headed}");

    if !mode.is_streamable() && total > 512 * 1024 * 1024 {
        println!("VERDICT     : would be REJECTED by the whole-file size guard");
        return;
    }

    let parser = match make_parser_for_format(&resolved) {
        Ok(p) => p,
        Err(e) => {
            println!("parser      : ERROR {e}");
            return;
        }
    };

    let raw = buf.as_slice();
    let header = if headed {
        let mut hs = RecordScanner::new(mode);
        hs.next_record_end(raw, 0)
            .map(|end| String::from_utf8_lossy(&raw[..end]).trim_end().to_string())
    } else {
        None
    };

    let mut scanner = RecordScanner::new(mode);
    let mut batch_start = 0usize;
    let mut lines_in_batch = 0usize;
    let mut records = 0usize;
    let mut batches = 0usize;
    let mut triples = 0usize;
    let mut rel_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut src_types: BTreeMap<String, usize> = BTreeMap::new();
    let mut at = 0usize;

    let mut flush = |chunk: &str, triples: &mut usize, batches: &mut usize| {
        if chunk.trim().is_empty() {
            return;
        }
        *batches += 1;
        let parsed = parser.parse(chunk);
        *triples += parsed.len();
        for (s, r, _) in parsed {
            *rel_counts.entry(r.rel_type.to_string()).or_default() += 1;
            *src_types.entry(s.entity_type.to_string()).or_default() += 1;
        }
    };

    while let Some(pos) = scanner.next_record_end(raw, at) {
        at = pos + 1;
        records += 1;
        lines_in_batch += 1;
        if lines_in_batch >= BATCH_LINES {
            let body = String::from_utf8_lossy(&raw[batch_start..pos + 1]);
            let chunk = match (&header, batch_start > 0) {
                (Some(h), true) => format!("{h}\n{body}"),
                _ => body.into_owned(),
            };
            flush(&chunk, &mut triples, &mut batches);
            batch_start = pos + 1;
            lines_in_batch = 0;
        }
    }
    if batch_start < raw.len() {
        let body = String::from_utf8_lossy(&raw[batch_start..]);
        let chunk = match (&header, batch_start > 0) {
            (Some(h), true) => format!("{h}\n{body}"),
            _ => body.into_owned(),
        };
        flush(&chunk, &mut triples, &mut batches);
    }

    println!("records     : {records}  in {batches} batches");
    println!("triples     : {triples}");
    if records > 0 {
        println!("triples/rec : {:.2}", triples as f64 / records as f64);
    }
    println!("relations   : {rel_counts:?}");
    println!("src types   : {src_types:?}");
    println!(
        "VERDICT     : {}",
        if triples > 0 {
            "OK — file streams and yields edges"
        } else {
            "EMPTY — streams but produced no edges (silent-failure shape)"
        }
    );
}

fn read_fully(f: &mut std::fs::File, buf: &mut [u8]) -> usize {
    let mut filled = 0;
    while filled < buf.len() {
        match f.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => break,
        }
    }
    filled
}

fn mb(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}
