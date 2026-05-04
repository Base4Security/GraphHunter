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
}

criterion_group!(benches, bench_ingest);
criterion_main!(benches);
