//! Integration smoke test: run `pcap_preview_sample` against a real
//! PCAP file on the operator's machine. Gated behind an env var so CI
//! and other developers don't blow up when the file isn't present.
//!
//! Run with:
//!   $env:GH_PCAP_FIXTURE = 'C:\Users\lsotomayor\Downloads\evo_telecarga_externa.pcap'
//!   cargo test --test pcap_preview_real_file -- --nocapture

use graph_hunter_api::pcap_preview::pcap_preview_sample;

#[test]
fn preview_real_world_pcap() {
    let path = match std::env::var("GH_PCAP_FIXTURE") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("skipping: GH_PCAP_FIXTURE not set");
            return;
        }
    };
    if !std::path::Path::new(&path).exists() {
        eprintln!("skipping: fixture missing at {path}");
        return;
    }

    let result = pcap_preview_sample(&path).expect("preview should succeed");
    eprintln!("\n──────── PCAP preview ────────");
    eprintln!("format:           {}", result.format);
    eprintln!("file_size:        {} bytes", result.file_size);
    eprintln!("packets_sampled:  {}", result.packets_sampled);
    eprintln!("packet_estimate:  {}", result.packet_count_estimate);
    if let Some(ts) = &result.time_span {
        eprintln!(
            "time_span:        {} → {} ({}s)",
            ts.first_unix_secs, ts.last_unix_secs, ts.duration_secs
        );
    } else {
        eprintln!("time_span:        none");
    }
    eprintln!("\nprotocol mix:");
    for p in &result.protocol_mix {
        eprintln!("  {:<8} {:>6} pkt  {:>10} bytes", p.protocol, p.packets, p.bytes);
    }
    eprintln!("\ntop source IPs:");
    for ip in &result.top_src_ips {
        eprintln!("  {:<40} {:>6} pkt  {:>10} bytes", ip.ip, ip.packets, ip.bytes);
    }
    eprintln!("\ntop destination IPs:");
    for ip in &result.top_dst_ips {
        eprintln!("  {:<40} {:>6} pkt  {:>10} bytes", ip.ip, ip.packets, ip.bytes);
    }
    eprintln!("\ntop destination ports:");
    for p in &result.top_dst_ports {
        eprintln!(
            "  {:<5} {:<6} {:<16} {:>6} pkt",
            p.port,
            p.protocol,
            p.service.as_deref().unwrap_or(""),
            p.packets,
        );
    }
    if !result.warnings.is_empty() {
        eprintln!("\nwarnings:");
        for w in &result.warnings {
            eprintln!("  ⚠ {w}");
        }
    }
    eprintln!("──────────────────────────────\n");

    assert!(result.packets_sampled > 0, "expected ≥1 packet from real file");
    assert!(
        !result.protocol_mix.is_empty(),
        "expected some protocol breakdown"
    );
}
