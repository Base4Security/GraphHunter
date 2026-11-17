//! Record-boundary scanning for the streaming ingest path.
//!
//! # Why this exists
//!
//! The streaming branch of `operations::ingestion` splits a memory-mapped
//! file into line batches and parses each batch independently. Deciding
//! *where a record ends* used to be a single `memchr(b'\n')` — correct
//! only for formats where a newline can never appear inside a value.
//!
//! That assumption was encoded as a hard-coded allowlist of format names
//! (`is_line_based`). Two things went wrong with it:
//!
//! 1. **It silently excluded `csv`.** Any CSV over the whole-file limit
//!    was rejected with "this format isn't line-delimited so it can't be
//!    streamed" — while the same message recommended converting to CSV.
//!    The allowlist had simply not kept up with the registry.
//! 2. **A plain newline split is wrong for quoted formats.** FortiWeb WAF
//!    logs embed raw newlines inside `msg="..."` whenever the attack
//!    payload is multi-line (an Elasticsearch RCE body, say). Splitting
//!    those on every newline shreds precisely the records that matter most.
//!
//! So streamability becomes a declared property of each format
//! ([`StreamMode`], set in `format_registry`) and the scan honours it.
//!
//! # The three modes
//!
//! * [`StreamMode::WholeFile`] — the parser needs the entire input in one
//!   call (JSON arrays, XML reports). These keep the size guard.
//! * [`StreamMode::Lines`] — every newline ends a record (NDJSON, IIS W3C,
//!   HAProxy, FortiGate KV).
//! * [`StreamMode::Quoted`] — a newline ends a record only when it falls
//!   outside a double-quoted run (CSV, FortiWeb).
//!
//! `Quoted` is strictly more permissive than `Lines`, never less: with no
//! quotes in the data the two agree byte for byte. It is not the default
//! only because tracking quote state costs a wider memchr needle over
//! multi-GB inputs.

/// How a format's records may be split for streaming.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamMode {
    /// Not splittable: parse the whole file in one call.
    WholeFile,
    /// Every newline terminates a record.
    Lines,
    /// A newline terminates a record only outside a double-quoted value.
    Quoted,
}

impl StreamMode {
    /// True when the format can be fed to the ingest path in batches,
    /// i.e. it is not subject to the whole-file size guard.
    pub fn is_streamable(self) -> bool {
        !matches!(self, StreamMode::WholeFile)
    }
}

/// Forward scanner over a mapped buffer that yields record-terminating
/// newline offsets.
///
/// Quote state is carried *across* calls, which is what makes the scan
/// usable on a memory-mapped file processed in batches: a quoted value
/// that spans a batch boundary keeps its state instead of resetting and
/// re-synchronising mid-record.
///
/// Escape handling covers both conventions that occur in the corpora this
/// was written against:
///
/// * backslash escapes — FortiWeb writes an inner quote as a backslash
///   followed by the quote character, inside `msg="..."`;
/// * doubled quotes — RFC 4180 CSV repeats the quote character.
///
/// A lone trailing backslash cannot escape past the end of the buffer, so
/// the state machine never reads out of bounds.
/// Longest run, in bytes, that a single quoted value is allowed to hold
/// before the scanner concludes its quote state has desynchronised and
/// resynchronises at the next newline.
///
/// Some producers emit *unescaped* quotes inside a quoted value. FortiWeb
/// does it whenever the captured attack payload contains JSON:
///
/// ```text
/// match_location="Parameter({"size":1, "script_fields": { … }})"
/// ```
///
/// The inner `{"` opens a quote that nothing closes in the intended
/// place, so a strict state machine — any strict state machine, this is a
/// property of the data, not of the algorithm — stays "inside a value"
/// and swallows every following record.
///
/// Without a bound the damage runs to end of file and the batch grows
/// until it exhausts memory, which is the failure the whole-file size
/// guard was put there to prevent. With it, a desync costs one oversized
/// record and the scan recovers.
///
/// Set far above any legitimate record: the widest well-formed record
/// measured in this corpus (an Auth0 CSV row) is ~24 KB.
const QUOTED_RESYNC_BYTES: usize = 256 * 1024;

pub struct RecordScanner {
    mode: StreamMode,
    in_quotes: bool,
    /// Absolute offset of the quote that opened the current value, used
    /// to measure the run against [`QUOTED_RESYNC_BYTES`].
    quote_start: Option<usize>,
    resyncs: usize,
}

impl RecordScanner {
    pub fn new(mode: StreamMode) -> Self {
        Self {
            mode,
            in_quotes: false,
            quote_start: None,
            resyncs: 0,
        }
    }

    /// How many times the scanner had to force a boundary because a
    /// quoted value ran past [`QUOTED_RESYNC_BYTES`].
    ///
    /// Non-zero means the input's quoting is unreliable. Callers surface
    /// it rather than letting a desync stay invisible — an unnoticed one
    /// merges records, and for a header-mapped format that shows up as
    /// missing rows rather than as an error.
    pub fn resyncs(&self) -> usize {
        self.resyncs
    }

    /// True when the scanner is currently inside an unterminated quoted
    /// value. Used by the ingest loop to decide whether a trailing
    /// remainder is a real record or a truncated one.
    pub fn in_quotes(&self) -> bool {
        self.in_quotes
    }

    /// Index of the next record-terminating newline at or after `from`, or
    /// `None` when the buffer ends without one.
    ///
    /// In [`StreamMode::Lines`] this is exactly `memchr`. In
    /// [`StreamMode::Quoted`] newlines inside a quoted value are skipped.
    /// [`StreamMode::WholeFile`] never yields a boundary — callers must
    /// not stream it, and returning `None` makes a misuse inert rather
    /// than silently splitting an unsplittable format.
    pub fn next_record_end(&mut self, raw: &[u8], from: usize) -> Option<usize> {
        match self.mode {
            StreamMode::WholeFile => None,
            StreamMode::Lines => memchr::memchr(b'\n', &raw[from..]).map(|p| from + p),
            StreamMode::Quoted => self.scan_quoted(raw, from),
        }
    }

    fn scan_quoted(&mut self, raw: &[u8], from: usize) -> Option<usize> {
        let mut i = from;
        while i < raw.len() {
            // Only three bytes can change state or end a record, so let
            // memchr3 do the striding instead of stepping byte by byte —
            // this runs over every byte of a multi-GB file.
            let rel = memchr::memchr3(b'\n', b'"', b'\\', &raw[i..])?;
            let pos = i + rel;
            match raw[pos] {
                b'\n' => {
                    if !self.in_quotes {
                        return Some(pos);
                    }
                    // Bounded resync: a "value" this long is a desync,
                    // not a record. Cut here and drop back out of quote
                    // state so the rest of the file scans normally.
                    if self
                        .quote_start
                        .is_some_and(|qs| pos.saturating_sub(qs) > QUOTED_RESYNC_BYTES)
                    {
                        self.in_quotes = false;
                        self.quote_start = None;
                        self.resyncs += 1;
                        return Some(pos);
                    }
                    i = pos + 1;
                }
                b'"' => {
                    if self.in_quotes && raw.get(pos + 1) == Some(&b'"') {
                        // RFC 4180 doubled quote: an escaped literal quote,
                        // not the end of the value. Skip both.
                        i = pos + 2;
                    } else {
                        self.in_quotes = !self.in_quotes;
                        self.quote_start = self.in_quotes.then_some(pos);
                        i = pos + 1;
                    }
                }
                _ => {
                    // Backslash. Inside a quoted value it escapes the next
                    // byte (including a quote or a newline); outside one it
                    // is an ordinary character — a Windows path in an
                    // unquoted column must not start swallowing bytes.
                    if self.in_quotes {
                        i = pos + 2;
                    } else {
                        i = pos + 1;
                    }
                }
            }
        }
        None
    }
}

/// Split `input` into at most `max_chunks` sub-slices, cutting **only** at
/// record boundaries for `mode`.
///
/// This replaces a `str::lines()` chunking that fed the rayon fan-out in the
/// ingest loop. `lines()` is the same wrong assumption [`RecordScanner`]
/// exists to fix, one level down: for a quoted format it can cut in the
/// middle of a multi-line value, handing each worker half a record. The
/// boundary scan here is the same one used for batching, so a record is
/// indivisible at both levels.
///
/// Returns a single chunk when `input` holds fewer than two records — there
/// is nothing to parallelise and an empty slice would cost a wasted task.
pub fn split_records(input: &str, mode: StreamMode, max_chunks: usize) -> Vec<&str> {
    let max_chunks = max_chunks.max(1);
    if max_chunks == 1 || input.is_empty() {
        return vec![input];
    }
    let raw = input.as_bytes();
    let mut scanner = RecordScanner::new(mode);
    let mut boundaries = Vec::new();
    let mut at = 0;
    while let Some(p) = scanner.next_record_end(raw, at) {
        boundaries.push(p);
        at = p + 1;
    }
    if boundaries.len() < 2 {
        return vec![input];
    }
    let per_chunk = boundaries.len().div_ceil(max_chunks).max(1);
    let mut out = Vec::new();
    let mut start = 0;
    for window in boundaries.chunks(per_chunk) {
        // `end` is the byte just past this window's last record
        // terminator, so every chunk is a whole number of records.
        let end = window[window.len() - 1] + 1;
        if end > start {
            out.push(&input[start..end]);
            start = end;
        }
    }
    // Trailing bytes after the final terminator (a last record with no
    // newline) belong to the last chunk rather than being dropped.
    if start < input.len() {
        if let Some(last) = out.pop() {
            out.push(&input[start - last.len()..]);
        } else {
            out.push(&input[start..]);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ends(mode: StreamMode, input: &str) -> Vec<usize> {
        let mut s = RecordScanner::new(mode);
        let raw = input.as_bytes();
        let mut out = Vec::new();
        let mut at = 0;
        while let Some(p) = s.next_record_end(raw, at) {
            out.push(p);
            at = p + 1;
        }
        out
    }

    #[test]
    fn lines_mode_matches_plain_memchr() {
        assert_eq!(ends(StreamMode::Lines, "a\nb\nc\n"), vec![1, 3, 5]);
    }

    /// With no quotes in the data, `Quoted` must agree with `Lines` byte
    /// for byte — the guarantee that lets a format opt into quote-aware
    /// scanning without changing how its clean rows are batched.
    #[test]
    fn quoted_mode_agrees_with_lines_when_no_quotes() {
        let sample = "date=1 a=b\ndate=2 a=c\ndate=3 a=d\n";
        assert_eq!(
            ends(StreamMode::Quoted, sample),
            ends(StreamMode::Lines, sample)
        );
    }

    /// The FortiWeb case that motivated this module: a multi-line attack
    /// payload inside a quoted value is ONE record, not four.
    #[test]
    fn quoted_newlines_do_not_end_a_record() {
        let sample = "src=1.2.3.4,msg=\"line one\nline two\nline three\"\nsrc=5.6.7.8,msg=\"ok\"\n";
        let boundaries = ends(StreamMode::Quoted, sample);
        assert_eq!(
            boundaries.len(),
            2,
            "expected 2 records, got {} — embedded newlines leaked",
            boundaries.len()
        );
        for b in &boundaries {
            assert_eq!(sample.as_bytes()[*b], b'\n');
        }
    }

    /// FortiWeb escapes inner quotes with a backslash. The closing quote
    /// of the value must be the unescaped one, otherwise the scanner
    /// leaves quote mode early and starts splitting inside the payload.
    #[test]
    fn backslash_escaped_quote_does_not_close_the_value() {
        let sample = "msg=\"exec(\\\"cat /etc/passwd\\\")\nstill inside\"\nnext=1\n";
        assert_eq!(ends(StreamMode::Quoted, sample).len(), 2);
    }

    /// RFC 4180 CSV escapes an inner quote by doubling it.
    #[test]
    fn doubled_quote_does_not_close_the_value() {
        let sample = "\"he said \"\"hi\"\"\nstill inside\",b\n\"x\",y\n";
        assert_eq!(ends(StreamMode::Quoted, sample).len(), 2);
    }

    /// A backslash OUTSIDE a quoted value is just a character. Windows
    /// paths in unquoted columns are common; treating the backslash as an
    /// escape there would swallow the following byte and could hide a
    /// record-terminating newline.
    #[test]
    fn backslash_outside_quotes_is_literal() {
        let sample = "C:\\Users\\x\nC:\\Users\\y\n";
        assert_eq!(ends(StreamMode::Quoted, sample).len(), 2);
    }

    /// Quote state must survive across calls so a value spanning a batch
    /// boundary is not re-synchronised mid-record.
    #[test]
    fn quote_state_carries_across_calls() {
        let raw = b"a=\"one\ntwo\"\nb=1\n";
        let mut s = RecordScanner::new(StreamMode::Quoted);
        let first = s.next_record_end(raw, 0).unwrap();
        assert_eq!(first, 11, "first boundary must skip the quoted newline");
        assert!(!s.in_quotes());
        assert_eq!(s.next_record_end(raw, first + 1), Some(15));
    }

    /// An unterminated quote at EOF must report no boundary and leave the
    /// scanner in-quotes, so the caller can tell a truncated tail from a
    /// complete record.
    #[test]
    fn unterminated_quote_reports_no_boundary() {
        let raw = b"a=\"dangling\nmore";
        let mut s = RecordScanner::new(StreamMode::Quoted);
        assert_eq!(s.next_record_end(raw, 0), None);
        assert!(s.in_quotes());
    }

    #[test]
    fn whole_file_never_yields_a_boundary() {
        let mut s = RecordScanner::new(StreamMode::WholeFile);
        assert_eq!(s.next_record_end(b"a\nb\n", 0), None);
        assert!(!StreamMode::WholeFile.is_streamable());
        assert!(StreamMode::Lines.is_streamable());
        assert!(StreamMode::Quoted.is_streamable());
    }

    /// A trailing backslash as the final byte must not read past the end.
    #[test]
    fn trailing_backslash_does_not_overrun() {
        let mut s = RecordScanner::new(StreamMode::Quoted);
        assert_eq!(s.next_record_end(b"a=\"x\\", 0), None);
    }

    // ── split_records ───────────────────────────────────────────────

    /// Losing bytes at a chunk seam is a silent under-ingest, so the
    /// concatenation of the chunks must reproduce the input exactly.
    #[test]
    fn split_records_is_lossless() {
        for mode in [StreamMode::Lines, StreamMode::Quoted] {
            for n in 1..8 {
                let input = "a=1\nb=2\nc=3\nd=4\ne=5\nf=6\ng=7\n";
                let chunks = split_records(input, mode, n);
                assert_eq!(chunks.concat(), input, "mode {:?}, n={}", mode, n);
            }
        }
    }

    /// The tail after the last newline is a record too — dropping it
    /// silently loses the final row of every file without a trailing
    /// newline.
    #[test]
    fn split_records_keeps_unterminated_tail() {
        let input = "a=1\nb=2\nc=3";
        let chunks = split_records(input, StreamMode::Lines, 2);
        assert_eq!(chunks.concat(), input);
        assert!(chunks.last().unwrap().ends_with("c=3"));
    }

    /// The reason this function exists: a multi-line quoted value must
    /// never be cut across two workers.
    #[test]
    fn split_records_never_cuts_a_multiline_record() {
        let input = "src=1,msg=\"one\ntwo\nthree\"\nsrc=2,msg=\"x\"\nsrc=3,msg=\"y\"\n";
        for n in 1..6 {
            let chunks = split_records(input, StreamMode::Quoted, n);
            assert_eq!(chunks.concat(), input);
            for c in &chunks {
                // A chunk that splits a quoted value leaves an odd number
                // of unescaped quotes behind.
                let quotes = c.bytes().filter(|b| *b == b'"').count();
                assert_eq!(quotes % 2, 0, "chunk cut inside a quoted value: {:?}", c);
            }
        }
    }

    // ── Desync resynchronisation ────────────────────────────────────

    /// A producer that emits unescaped quotes inside a quoted value (real
    /// FortiWeb behaviour) leaves the scanner stuck "inside" a value. The
    /// bound must cut it loose instead of letting one bad record swallow
    /// the rest of the file and grow the batch without limit.
    #[test]
    fn runaway_quote_resynchronises_at_the_bound() {
        let mut input = String::from("a=\"opened and never closed\n");
        // Far more than QUOTED_RESYNC_BYTES of "inside the value" lines.
        for i in 0..40_000 {
            input.push_str(&format!("filler line {i}\n"));
        }
        input.push_str("b=1\n");
        let raw = input.as_bytes();

        let mut s = RecordScanner::new(StreamMode::Quoted);
        let mut at = 0;
        let mut boundaries = 0;
        while let Some(p) = s.next_record_end(raw, at) {
            boundaries += 1;
            at = p + 1;
        }
        assert!(s.resyncs() >= 1, "scanner never resynchronised");
        assert!(
            boundaries > 1,
            "a single runaway quote swallowed the whole input"
        );
    }

    /// The bound must not fire on legitimate multi-line values, or every
    /// captured attack payload would be cut in half.
    #[test]
    fn bound_does_not_fire_on_a_normal_multiline_value() {
        let sample = "src=1,msg=\"line one\nline two\nline three\"\nsrc=2,msg=\"ok\"\n";
        let mut s = RecordScanner::new(StreamMode::Quoted);
        let mut at = 0;
        let mut n = 0;
        while let Some(p) = s.next_record_end(sample.as_bytes(), at) {
            n += 1;
            at = p + 1;
        }
        assert_eq!(n, 2);
        assert_eq!(s.resyncs(), 0, "bound fired on a well-formed record");
    }

    /// A clean file must never report a resync — that counter is the
    /// signal callers use to warn that quoting is unreliable.
    #[test]
    fn well_formed_input_reports_no_resyncs() {
        let mut s = RecordScanner::new(StreamMode::Quoted);
        let raw = b"\"a\",\"b\"\n\"c\",\"d\"\n";
        let mut at = 0;
        while let Some(p) = s.next_record_end(raw, at) {
            at = p + 1;
        }
        assert_eq!(s.resyncs(), 0);
    }

    #[test]
    fn split_records_single_record_is_one_chunk() {
        assert_eq!(split_records("only one\n", StreamMode::Lines, 8).len(), 1);
        assert_eq!(split_records("", StreamMode::Lines, 8), vec![""]);
    }
}
