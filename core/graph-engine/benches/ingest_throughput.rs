//! F8 — ingest throughput benchmark.
//!
//! Measures rows/sec the pipeline sustains for three increasingly
//! realistic Sysmon-like NDJSON batches. The `SysmonJsonParser.parse()`
//! path is the hot loop behind the one-shot ingest route exposed via
//! `GraphHunterApi::load_data`; regressions here are felt immediately
//! by analysts dragging a 28 GB EVTX export into the app.
//!
//! Run: `cargo bench --bench ingest_throughput`

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use graph_hunter_core::{LogParser, SysmonJsonParser};

/// Synthesize `n_events` Sysmon-style EventID-1 rows as NDJSON. No
/// file I/O — the benchmark reads from an in-memory string so we're
/// measuring parse cost, not disk throughput.
///
/// All-EventID-1 fixture: every line is a Process Create. Exercises
/// the typed fast path exclusively.
fn synth_sysmon_ndjson(n_events: usize) -> String {
    let mut out = String::with_capacity(n_events * 200);
    for i in 0..n_events {
        // Rotate user / host / binary so the parser can't short-circuit
        // via interning-identity-eq on repeated inputs.
        let user = format!("user{}", i % 50);
        let host = format!("host{}", i % 25);
        let ts_sec = 1_700_000_000 + (i as i64);
        out.push_str(&format!(
            "{{\"EventID\":1,\"UtcTime\":\"2023-11-14 22:13:{:02}.000\",\
              \"Image\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\",\
              \"User\":\"{user}\",\"Computer\":\"{host}\",\
              \"ProcessId\":{pid},\"ParentImage\":\"C:\\\\Windows\\\\explorer.exe\"}}\n",
            ts_sec % 60,
            pid = 1000 + (i % 4096),
        ));
    }
    out
}

/// Mixed-EventID fixture mimicking a real Sysmon stream — original
/// 4-ID distribution (1, 3, 7, 11) covering ~80% of typical events.
fn synth_sysmon_ndjson_mixed(n_events: usize) -> String {
    let mut out = String::with_capacity(n_events * 220);
    for i in 0..n_events {
        let host = format!("host{}", i % 25);
        let ts_sec = 1_700_000_000 + (i as i64);
        let ts_str = format!("2023-11-14 22:13:{:02}.000", ts_sec % 60);
        // Distribution rotates by 20-event cycle: 8 ID=1, 5 ID=3,
        // 4 ID=7, 3 ID=11.
        let bucket = i % 20;
        if bucket < 8 {
            let user = format!("user{}", i % 50);
            out.push_str(&format!(
                "{{\"EventID\":1,\"UtcTime\":\"{ts_str}\",\
                  \"Image\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\",\
                  \"User\":\"{user}\",\"Computer\":\"{host}\",\
                  \"ProcessId\":{pid},\"ParentImage\":\"C:\\\\Windows\\\\explorer.exe\"}}\n",
                pid = 1000 + (i % 4096),
            ));
        } else if bucket < 13 {
            let dst_octet = (i * 7) % 254 + 1;
            out.push_str(&format!(
                "{{\"EventID\":3,\"UtcTime\":\"{ts_str}\",\
                  \"Computer\":\"{host}\",\"Image\":\"C:\\\\Windows\\\\System32\\\\svchost.exe\",\
                  \"DestinationIp\":\"10.0.{}.{dst_octet}\",\
                  \"DestinationPort\":\"443\",\"Protocol\":\"tcp\"}}\n",
                (i / 254) % 256,
            ));
        } else if bucket < 17 {
            let lib_idx = i % 30;
            out.push_str(&format!(
                "{{\"EventID\":7,\"UtcTime\":\"{ts_str}\",\
                  \"Image\":\"C:\\\\Windows\\\\System32\\\\powershell.exe\",\
                  \"ImageLoaded\":\"C:\\\\Windows\\\\System32\\\\lib{lib_idx}.dll\",\
                  \"Signed\":\"true\",\"Hashes\":\"SHA256={i:032x}\"}}\n",
            ));
        } else {
            let path_idx = i % 100;
            out.push_str(&format!(
                "{{\"EventID\":11,\"UtcTime\":\"{ts_str}\",\
                  \"Image\":\"C:\\\\Windows\\\\System32\\\\notepad.exe\",\
                  \"TargetFilename\":\"C:\\\\Users\\\\u\\\\file{path_idx}.txt\"}}\n",
            ));
        }
    }
    out
}

/// Long-tail mix: includes EventIDs 5 (Process Terminated), 8
/// (CreateRemoteThread), 12/13 (Registry), 15 (File Stream Hash),
/// 23 (File Delete) on top of 1/3/7/11. Validates the typed
/// fast path covers ~all common Sysmon emissions; the remaining
/// EventIDs (PowerShell 4104, Windows Security 46xx/51xx) still
/// fall through to the legacy Value path but their volume is low.
fn synth_sysmon_ndjson_long_tail(n_events: usize) -> String {
    let mut out = String::with_capacity(n_events * 220);
    for i in 0..n_events {
        let host = format!("host{}", i % 25);
        let ts_sec = 1_700_000_000 + (i as i64);
        let ts_str = format!("2023-11-14 22:13:{:02}.000", ts_sec % 60);
        // 30-bucket cycle: 8 ID=1, 5 ID=3, 3 ID=7, 3 ID=11,
        // 2 ID=5, 2 ID=8, 3 ID=12, 2 ID=15, 2 ID=23.
        let bucket = i % 30;
        if bucket < 8 {
            let user = format!("user{}", i % 50);
            out.push_str(&format!(
                "{{\"EventID\":1,\"UtcTime\":\"{ts_str}\",\
                  \"Image\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\",\
                  \"User\":\"{user}\",\"Computer\":\"{host}\",\
                  \"ProcessId\":{pid},\"ParentImage\":\"C:\\\\Windows\\\\explorer.exe\"}}\n",
                pid = 1000 + (i % 4096),
            ));
        } else if bucket < 13 {
            let dst_octet = (i * 7) % 254 + 1;
            out.push_str(&format!(
                "{{\"EventID\":3,\"UtcTime\":\"{ts_str}\",\
                  \"Computer\":\"{host}\",\"Image\":\"C:\\\\Windows\\\\System32\\\\svchost.exe\",\
                  \"DestinationIp\":\"10.0.{}.{dst_octet}\",\
                  \"DestinationPort\":\"443\",\"Protocol\":\"tcp\"}}\n",
                (i / 254) % 256,
            ));
        } else if bucket < 16 {
            let lib_idx = i % 30;
            out.push_str(&format!(
                "{{\"EventID\":7,\"UtcTime\":\"{ts_str}\",\
                  \"Image\":\"C:\\\\Windows\\\\System32\\\\powershell.exe\",\
                  \"ImageLoaded\":\"C:\\\\Windows\\\\System32\\\\lib{lib_idx}.dll\",\
                  \"Signed\":\"true\",\"Hashes\":\"SHA256={i:032x}\"}}\n",
            ));
        } else if bucket < 19 {
            let path_idx = i % 100;
            out.push_str(&format!(
                "{{\"EventID\":11,\"UtcTime\":\"{ts_str}\",\
                  \"Image\":\"C:\\\\Windows\\\\System32\\\\notepad.exe\",\
                  \"TargetFilename\":\"C:\\\\Users\\\\u\\\\file{path_idx}.txt\"}}\n",
            ));
        } else if bucket < 21 {
            out.push_str(&format!(
                "{{\"EventID\":5,\"UtcTime\":\"{ts_str}\",\
                  \"Image\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\",\
                  \"Computer\":\"{host}\",\"ProcessId\":{pid}}}\n",
                pid = 1000 + (i % 4096),
            ));
        } else if bucket < 23 {
            out.push_str(&format!(
                "{{\"EventID\":8,\"UtcTime\":\"{ts_str}\",\
                  \"SourceImage\":\"C:\\\\Windows\\\\System32\\\\svchost.exe\",\
                  \"TargetImage\":\"C:\\\\Windows\\\\System32\\\\lsass.exe\",\
                  \"StartAddress\":\"0x7FF{i:08x}\",\"NewThreadId\":\"{i}\"}}\n",
            ));
        } else if bucket < 26 {
            let key_idx = i % 200;
            out.push_str(&format!(
                "{{\"EventID\":12,\"UtcTime\":\"{ts_str}\",\
                  \"Image\":\"C:\\\\Windows\\\\System32\\\\reg.exe\",\
                  \"TargetObject\":\"HKLM\\\\Software\\\\App\\\\key{key_idx}\",\
                  \"EventType\":\"CreateKey\"}}\n",
            ));
        } else if bucket < 28 {
            let path_idx = i % 100;
            out.push_str(&format!(
                "{{\"EventID\":15,\"UtcTime\":\"{ts_str}\",\
                  \"Image\":\"C:\\\\Windows\\\\System32\\\\notepad.exe\",\
                  \"TargetFilename\":\"C:\\\\Users\\\\u\\\\stream{path_idx}.txt:ads\",\
                  \"Hash\":\"SHA1={i:040x}\"}}\n",
            ));
        } else {
            let path_idx = i % 100;
            out.push_str(&format!(
                "{{\"EventID\":23,\"UtcTime\":\"{ts_str}\",\
                  \"Image\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\",\
                  \"TargetFilename\":\"C:\\\\Users\\\\u\\\\del{path_idx}.txt\"}}\n",
            ));
        }
    }
    out
}

fn bench_ingest(c: &mut Criterion) {
    let mut group = c.benchmark_group("ingest-sysmon-ndjson");
    for n in &[1_000usize, 10_000, 50_000] {
        let payload = synth_sysmon_ndjson(*n);
        group.throughput(Throughput::Elements(*n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
            b.iter(|| {
                let parser = SysmonJsonParser;
                let triples = parser.parse(black_box(&payload));
                black_box(triples)
            });
        });
    }
    group.finish();

    let mut group = c.benchmark_group("ingest-sysmon-ndjson-mixed");
    for n in &[1_000usize, 10_000, 50_000] {
        let payload = synth_sysmon_ndjson_mixed(*n);
        group.throughput(Throughput::Elements(*n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
            b.iter(|| {
                let parser = SysmonJsonParser;
                let triples = parser.parse(black_box(&payload));
                black_box(triples)
            });
        });
    }
    group.finish();

    let mut group = c.benchmark_group("ingest-sysmon-ndjson-long-tail");
    for n in &[1_000usize, 10_000, 50_000] {
        let payload = synth_sysmon_ndjson_long_tail(*n);
        group.throughput(Throughput::Elements(*n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
            b.iter(|| {
                let parser = SysmonJsonParser;
                let triples = parser.parse(black_box(&payload));
                black_box(triples)
            });
        });
    }
    group.finish();

    // Parse-only benchmark: measures simd-json + serde reflection
    // throughput WITHOUT building Entity / Relation / HashMap
    // intermediates. Anchors the upper bound — any production
    // ingest path will be bounded above by this number, since
    // the only thing it skips is the post-parse triple
    // construction. Sequential to isolate parse cost from rayon
    // worker scheduling effects.
    let mut group = c.benchmark_group("ingest-sysmon-parse-only");
    for n in &[1_000usize, 10_000, 50_000] {
        let payload = synth_sysmon_ndjson(*n);
        group.throughput(Throughput::Elements(*n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
            b.iter(|| {
                let mut scratch = Vec::<u8>::with_capacity(2048);
                let mut count: usize = 0;
                for line in black_box(&payload).lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    if SysmonJsonParser::parse_only_sysmon(line, &mut scratch) {
                        count += 1;
                    }
                }
                black_box(count)
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_ingest);
criterion_main!(benches);
