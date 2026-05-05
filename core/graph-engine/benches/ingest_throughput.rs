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

/// Windows Security + PowerShell mixed fixture. Exercises the typed
/// parsers shipped in PR #20 (4624/4625, 4688, 4689, 4663, 5145, 5156,
/// 4104) which had no dedicated bench group until now. Bucket ratios
/// approximate a busy member-server profile: heavy logon + process +
/// firewall, light powershell + share access.
fn synth_winsec_ndjson(n_events: usize) -> String {
    let mut out = String::with_capacity(n_events * 260);
    for i in 0..n_events {
        let host = format!("host{}", i % 25);
        let ts_sec = 1_700_000_000 + (i as i64);
        let ts_str = format!("2023-11-14 22:13:{:02}.000", ts_sec % 60);
        let bucket = i % 100;
        if bucket < 25 {
            // 4624 logon success
            let lt = [2u8, 3, 4, 5, 7, 10][i % 6];
            out.push_str(&format!(
                "{{\"EventID\":4624,\"UtcTime\":\"{ts_str}\",\
                  \"TargetUserName\":\"user{u}\",\"TargetDomainName\":\"CORP\",\
                  \"LogonType\":{lt},\"IpAddress\":\"10.1.{a}.{b}\",\"Computer\":\"{host}\"}}\n",
                u = i % 200,
                a = (i / 254) % 256,
                b = (i * 7) % 254 + 1,
            ));
        } else if bucket < 30 {
            // 4625 logon failure (string LogonType variant)
            out.push_str(&format!(
                "{{\"EventID\":4625,\"UtcTime\":\"{ts_str}\",\
                  \"TargetUserName\":\"user{u}\",\"TargetDomainName\":\"CORP\",\
                  \"LogonType\":\"3\",\"IpAddress\":\"10.2.{a}.{b}\",\"Computer\":\"{host}\"}}\n",
                u = i % 50,
                a = (i / 254) % 256,
                b = (i * 11) % 254 + 1,
            ));
        } else if bucket < 55 {
            // 4688 security process create
            out.push_str(&format!(
                "{{\"EventID\":4688,\"UtcTime\":\"{ts_str}\",\
                  \"NewProcessName\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\",\
                  \"SubjectUserName\":\"user{u}\",\"SubjectDomainName\":\"CORP\",\
                  \"ParentProcessName\":\"C:\\\\Windows\\\\explorer.exe\",\
                  \"CommandLine\":\"cmd.exe /c whoami\",\"Computer\":\"{host}\"}}\n",
                u = i % 100,
            ));
        } else if bucket < 70 {
            // 4689 security process terminated
            out.push_str(&format!(
                "{{\"EventID\":4689,\"UtcTime\":\"{ts_str}\",\
                  \"ProcessName\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\",\
                  \"SubjectUserName\":\"user{u}\",\"SubjectDomainName\":\"CORP\",\
                  \"Computer\":\"{host}\"}}\n",
                u = i % 100,
            ));
        } else if bucket < 80 {
            // 4663 object access
            let obj_idx = i % 200;
            out.push_str(&format!(
                "{{\"EventID\":4663,\"UtcTime\":\"{ts_str}\",\
                  \"ProcessName\":\"C:\\\\Windows\\\\System32\\\\notepad.exe\",\
                  \"ObjectName\":\"C:\\\\Users\\\\u\\\\file{obj_idx}.txt\",\
                  \"ObjectType\":\"File\",\"SubjectUserName\":\"user{u}\",\"Computer\":\"{host}\"}}\n",
                u = i % 100,
            ));
        } else if bucket < 85 {
            // 5145 network share
            let rel = i % 50;
            out.push_str(&format!(
                "{{\"EventID\":5145,\"UtcTime\":\"{ts_str}\",\
                  \"ShareName\":\"\\\\\\\\*\\\\IPC$\",\"RelativeTargetName\":\"share{rel}\",\
                  \"SubjectUserName\":\"user{u}\",\"IpAddress\":\"10.3.{a}.{b}\",\"Computer\":\"{host}\"}}\n",
                u = i % 50,
                a = (i / 254) % 256,
                b = (i * 13) % 254 + 1,
            ));
        } else if bucket < 95 {
            // 5156 WFP connection
            out.push_str(&format!(
                "{{\"EventID\":5156,\"UtcTime\":\"{ts_str}\",\
                  \"Application\":\"\\\\device\\\\harddiskvolume2\\\\windows\\\\system32\\\\svchost.exe\",\
                  \"DestAddress\":\"10.4.{a}.{b}\",\"DestPort\":\"443\",\
                  \"SourceAddress\":\"10.0.{a}.{c}\",\"Computer\":\"{host}\"}}\n",
                a = (i / 254) % 256,
                b = (i * 17) % 254 + 1,
                c = (i * 19) % 254 + 1,
            ));
        } else {
            // 4104 PowerShell script block
            out.push_str(&format!(
                "{{\"EventID\":4104,\"UtcTime\":\"{ts_str}\",\
                  \"ScriptBlockText\":\"Get-Process | Where-Object {{$_.CPU -gt {i}}}\",\
                  \"ScriptBlockId\":\"{i:032x}\",\"Computer\":\"{host}\"}}\n",
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
    let mut group = c.benchmark_group("ingest-winsec-ndjson");
    for n in &[1_000usize, 10_000, 50_000] {
        let payload = synth_winsec_ndjson(*n);
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

    // Raw-event vs legacy comparison on the all-EventID-1 fixture
    // (process_create — the only EventID with a raw-path
    // implementation today). Group covers parse-only and the full
    // parse+insert end-to-end so the writer-side savings are visible.
    {
        let mut group = c.benchmark_group("ingest-eid1-raw-vs-legacy-parse");
        for n in &[1_000usize, 10_000, 50_000] {
            let payload = synth_sysmon_ndjson(*n);
            group.throughput(Throughput::Elements(*n as u64));
            group.bench_with_input(BenchmarkId::new("legacy", n), n, |b, _| {
                b.iter(|| {
                    let parser = SysmonJsonParser;
                    let triples = parser.parse(black_box(&payload));
                    black_box(triples)
                });
            });
            group.bench_with_input(BenchmarkId::new("raw", n), n, |b, _| {
                b.iter(|| {
                    let parser = SysmonJsonParser;
                    let events = parser.parse_raw(black_box(&payload));
                    black_box(events)
                });
            });
        }
        group.finish();
    }

    {
        // WinSec + PowerShell raw-vs-legacy parse comparison. All
        // 8 IDs (4624, 4625, 4688, 4689, 4663, 5145, 5156, 4104) on
        // the raw path. Mirror of the ingest-winsec-ndjson group.
        let mut group = c.benchmark_group("ingest-winsec-raw-vs-legacy-parse");
        for n in &[1_000usize, 10_000, 50_000] {
            let payload = synth_winsec_ndjson(*n);
            group.throughput(Throughput::Elements(*n as u64));
            group.bench_with_input(BenchmarkId::new("legacy", n), n, |b, _| {
                b.iter(|| {
                    let parser = SysmonJsonParser;
                    let triples = parser.parse(black_box(&payload));
                    black_box(triples)
                });
            });
            group.bench_with_input(BenchmarkId::new("raw", n), n, |b, _| {
                b.iter(|| {
                    let parser = SysmonJsonParser;
                    let events = parser.parse_raw(black_box(&payload));
                    black_box(events)
                });
            });
        }
        group.finish();
    }

    {
        // parse_raw_with_stats native typed-fast-path vs the
        // parse_with_stats + lift legacy path. Confirms the trait
        // method captures the parser-side wins on the
        // line-streaming JSONL ingest path.
        let mut group = c.benchmark_group("ingest-eid1-raw-with-stats-vs-legacy");
        for n in &[1_000usize, 10_000, 50_000] {
            let payload = synth_sysmon_ndjson(*n);
            group.throughput(Throughput::Elements(*n as u64));
            group.bench_with_input(BenchmarkId::new("legacy-with-stats", n), n, |b, _| {
                b.iter(|| {
                    let parser = SysmonJsonParser;
                    let (triples, stats) = parser.parse_with_stats(black_box(&payload));
                    black_box((triples, stats))
                });
            });
            group.bench_with_input(BenchmarkId::new("raw-with-stats", n), n, |b, _| {
                b.iter(|| {
                    let parser = SysmonJsonParser;
                    let (events, stats) = parser.parse_raw_with_stats(black_box(&payload));
                    black_box((events, stats))
                });
            });
        }
        group.finish();
    }

    {
        // Long-tail raw-vs-legacy parse comparison. 9 EventIDs (1, 3,
        // 5, 7, 8, 11, 12, 15, 23) all migrated to *_raw — the
        // entire group should show consistent improvement.
        let mut group = c.benchmark_group("ingest-long-tail-raw-vs-legacy-parse");
        for n in &[1_000usize, 10_000, 50_000] {
            let payload = synth_sysmon_ndjson_long_tail(*n);
            group.throughput(Throughput::Elements(*n as u64));
            group.bench_with_input(BenchmarkId::new("legacy", n), n, |b, _| {
                b.iter(|| {
                    let parser = SysmonJsonParser;
                    let triples = parser.parse(black_box(&payload));
                    black_box(triples)
                });
            });
            group.bench_with_input(BenchmarkId::new("raw", n), n, |b, _| {
                b.iter(|| {
                    let parser = SysmonJsonParser;
                    let events = parser.parse_raw(black_box(&payload));
                    black_box(events)
                });
            });
        }
        group.finish();
    }

    {
        use graph_hunter_core::GraphHunter;
        let mut group = c.benchmark_group("ingest-eid1-raw-vs-legacy-end-to-end");
        for n in &[1_000usize, 10_000, 50_000] {
            let payload = synth_sysmon_ndjson(*n);
            group.throughput(Throughput::Elements(*n as u64));
            group.bench_with_input(BenchmarkId::new("legacy", n), n, |b, _| {
                b.iter(|| {
                    let parser = SysmonJsonParser;
                    let triples = parser.parse(black_box(&payload));
                    let mut g = GraphHunter::new();
                    let _ = g.insert_triples(triples, None);
                    black_box(g)
                });
            });
            group.bench_with_input(BenchmarkId::new("raw", n), n, |b, _| {
                b.iter(|| {
                    let parser = SysmonJsonParser;
                    let events = parser.parse_raw(black_box(&payload));
                    let mut g = GraphHunter::new();
                    let _ = g.insert_raw_events(events, None);
                    black_box(g)
                });
            });
        }
        group.finish();
    }
}

criterion_group!(benches, bench_ingest);
criterion_main!(benches);
