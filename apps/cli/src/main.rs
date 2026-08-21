#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod commands;
mod protocol;
use graph_hunter_siem as siem;

use std::io::{self, BufRead, Write};

use commands::CommandHandler;
use protocol::{Request, Response};

/// Reproducible performance harness (WS1.5). `graph_hunter_cli bench`
/// runs the fixed synthetic suite and emits a table — the "run → figure"
/// artifact a paper's evaluation section is checked against, rather than
/// numbers pasted from a one-off run.
///
/// Flags: `--runs N` (default 30, the plan's ≥30 for stable percentiles),
/// `--seed S` (default 42), `--plant N` (default 0 — plant N matching
/// attack paths so the search emits and the latency covers path
/// materialisation, not just rejection), `--format csv|json` (default
/// csv), `--out FILE` (default stdout). Build with `--release` — debug
/// latencies are not representative, and the harness says so on stderr.
fn run_bench(args: &[String]) -> ! {
    use graph_hunter_core::benchmark::{perf_rows_to_csv, run_perf_suite_planted};

    let mut runs: usize = 30;
    let mut seed: u64 = 42;
    let mut plant: usize = 0;
    let mut format = String::from("csv");
    let mut out_path: Option<String> = None;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--runs" => runs = it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| bail("--runs needs a positive integer")),
            "--seed" => seed = it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| bail("--seed needs an integer")),
            "--plant" => plant = it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| bail("--plant needs a non-negative integer")),
            "--format" => format = it.next().cloned().unwrap_or_else(|| bail("--format needs csv|json")),
            "--out" => out_path = Some(it.next().cloned().unwrap_or_else(|| bail("--out needs a path"))),
            "-h" | "--help" => bail("usage: graph_hunter_cli bench [--runs N] [--seed S] [--plant N] [--format csv|json] [--out FILE]"),
            other => bail(&format!("unknown bench flag: {other}")),
        }
    }

    if cfg!(debug_assertions) {
        eprintln!(
            "warning: debug build — latencies are not representative. \
             Rebuild with `cargo build --release -p graph_hunter_cli`."
        );
    }

    let rows = run_perf_suite_planted(seed, runs, plant);
    let rendered = match format.as_str() {
        "csv" => perf_rows_to_csv(&rows),
        "json" => serde_json::to_string_pretty(&rows).expect("perf rows serialize"),
        other => bail(&format!("unknown --format '{other}': use csv or json")),
    };

    match out_path {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, &rendered) {
                bail(&format!("could not write {path}: {e}"));
            }
            eprintln!("wrote {} rows to {path}", rows.len());
        }
        None => {
            print!("{rendered}");
            let _ = io::stdout().flush();
        }
    }
    std::process::exit(0);
}

/// Prints a bench-mode error to stderr and exits non-zero. Never returns.
fn bail(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(2);
}

fn main() {
    // `bench` subcommand: a one-shot performance run, distinct from the
    // long-running stdin/stdout daemon below. Dispatched on argv before
    // the daemon so the two modes never interleave.
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("bench") {
        run_bench(&argv[2..]);
    }

    // M-track perf flags: default-on so the CLI binary picks up the
    // structural K_4 LFTJ dispatch automatically when invoked from
    // the Go gateway. Same conservative dispatcher contract as the
    // Tauri app — any non-K_4 hypothesis falls back to the legacy
    // DFS. Override with `GRAPHHUNTER_LFTJ_PLANNER=0` /
    // `GRAPHHUNTER_K4_LFTJ=0`.
    for (key, default) in [
        ("GRAPHHUNTER_LFTJ_PLANNER", "1"),
        ("GRAPHHUNTER_K4_LFTJ", "1"),
        ("GRAPHHUNTER_YANNAKAKIS", "1"),
        // GRAPHHUNTER_LLM_INGEST is no longer default-on — Phase G
        // demoted the silent dispatcher to an explicit click on the
        // desktop UI. CLI ingest stays heuristic-only.
    ] {
        if std::env::var(key).is_err() {
            // SAFETY: still single-threaded at startup; the matcher
            // reads these flags lazily on first hunt.
            unsafe { std::env::set_var(key, default) };
        }
    }

    // Emit ready signal so the Go gateway knows we're alive.
    let ready = serde_json::to_string(&Response::ready()).unwrap();
    {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        let _ = writeln!(handle, "{}", ready);
        let _ = handle.flush();
    }

    let mut handler = CommandHandler::new();
    let stdin = io::stdin();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break, // stdin closed
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let req: Request = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let err = Response::error("", format!("invalid JSON: {}", e));
                let out = serde_json::to_string(&err).unwrap();
                let stdout = io::stdout();
                let mut handle = stdout.lock();
                let _ = writeln!(handle, "{}", out);
                let _ = handle.flush();
                continue;
            }
        };

        handler.dispatch(&req.id, &req.cmd, &req.params);
    }
}
