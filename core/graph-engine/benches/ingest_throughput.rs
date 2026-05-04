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

/// Mixed-EventID fixture mimicking a real Sysmon stream:
/// ~40% Process Create (1), ~25% Network Connection (3), ~20% Image
/// Load (7), ~15% File Create (11). Exercises all four typed
/// parsers; numbers reflect what a production EDR sees.
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
}

criterion_group!(benches, bench_ingest);
criterion_main!(benches);
