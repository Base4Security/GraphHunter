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
///
/// `--ablation` runs the pruning ablation over logs instead: the two demo
/// scenarios in `--data-dir` (default `demo_data`) and, with `--mordor
/// FILE`, the OTRF corpus described in `demo_data/DOWNLOAD_REAL_DATA.md`.
/// `--naive-max-relations N` (default 1000) bounds the graphs the naive DFS
/// runs on; above it the baseline does not finish and is reported empty.
fn run_bench(args: &[String]) -> ! {
    use graph_hunter_core::benchmark::{
        perf_rows_to_csv, run_perf_scaling, run_perf_suite_planted,
    };

    let mut runs: usize = 30;
    let mut seed: u64 = 42;
    let mut plant: usize = 0;
    let mut sweep = false;
    let mut ablation = false;
    let mut data_dir = String::from("demo_data");
    let mut mordor: Option<String> = None;
    let mut naive_max_relations: usize = 1_000;
    let mut lengths: Vec<usize> = vec![2, 3, 4, 5];
    let mut format = String::from("csv");
    let mut out_path: Option<String> = None;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--runs" => {
                runs = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| bail("--runs needs a positive integer"))
            }
            "--seed" => {
                seed = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| bail("--seed needs an integer"))
            }
            "--plant" => {
                plant = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| bail("--plant needs a non-negative integer"))
            }
            // Scaling sweep (D3.1): ER at fixed avg degree across growing n,
            // to find where DFS latency breaks. Overrides the fixed suite.
            "--sweep" => sweep = true,
            "--ablation" => ablation = true,
            "--data-dir" => {
                data_dir = it
                    .next()
                    .cloned()
                    .unwrap_or_else(|| bail("--data-dir needs a path"))
            }
            "--mordor" => {
                mordor = Some(
                    it.next()
                        .cloned()
                        .unwrap_or_else(|| bail("--mordor needs a path")),
                )
            }
            "--naive-max-relations" => {
                naive_max_relations = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| bail("--naive-max-relations needs an integer"))
            }
            "--lengths" => {
                lengths = it
                    .next()
                    .and_then(|v| v.split(',').map(|s| s.trim().parse().ok()).collect())
                    .filter(|l: &Vec<usize>| !l.is_empty() && l.iter().all(|&n| n > 0))
                    .unwrap_or_else(|| bail("--lengths needs positive integers, e.g. 2,3,4,5"))
            }
            "--format" => {
                format = it
                    .next()
                    .cloned()
                    .unwrap_or_else(|| bail("--format needs csv|json"))
            }
            "--out" => {
                out_path = Some(
                    it.next()
                        .cloned()
                        .unwrap_or_else(|| bail("--out needs a path")),
                )
            }
            "-h" | "--help" => bail(
                "usage: graph_hunter_cli bench [--runs N] [--seed S] [--plant N] [--sweep] [--format csv|json] [--out FILE]\n       graph_hunter_cli bench --ablation [--data-dir DIR] [--mordor FILE] [--naive-max-relations N] [--lengths 2,3,4,5] [--runs N] [--format csv|json] [--out FILE]",
            ),
            other => bail(&format!("unknown bench flag: {other}")),
        }
    }

    if cfg!(debug_assertions) {
        eprintln!(
            "warning: debug build — latencies are not representative. \
             Rebuild with `cargo build --release -p graph_hunter_cli`."
        );
    }

    let (rendered, n_rows) = if ablation {
        let rows = run_ablation_suite(
            &data_dir,
            mordor.as_deref(),
            &lengths,
            runs,
            naive_max_relations,
        );
        let rendered = match format.as_str() {
            "csv" => graph_hunter_core::benchmark::ablation_rows_to_csv(&rows),
            "json" => serde_json::to_string_pretty(&rows).expect("ablation rows serialize"),
            other => bail(&format!("unknown --format '{other}': use csv or json")),
        };
        (rendered, rows.len())
    } else {
        let rows = if sweep {
            // Fixed avg degree 10, L=3, growing n. The knee in latency-vs-|E|
            // is the answer to "where does the DFS break".
            let sizes = [1_000usize, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000];
            run_perf_scaling(seed, runs, &sizes, 10.0, 3, plant)
        } else {
            run_perf_suite_planted(seed, runs, plant)
        };
        let rendered = match format.as_str() {
            "csv" => perf_rows_to_csv(&rows),
            "json" => serde_json::to_string_pretty(&rows).expect("perf rows serialize"),
            other => bail(&format!("unknown --format '{other}': use csv or json")),
        };
        (rendered, rows.len())
    };

    match out_path {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, &rendered) {
                bail(&format!("could not write {path}: {e}"));
            }
            eprintln!("wrote {n_rows} rows to {path}");
        }
        None => {
            print!("{rendered}");
            let _ = io::stdout().flush();
        }
    }
    std::process::exit(0);
}

/// Loads each ablation dataset with the parser its format needs and runs
/// the hypothesis family that has matches in it: a process chain for the
/// Sysmon logs, lateral movement for Sentinel. A demo file that is missing
/// is an error; the OTRF corpus is optional because it is not in the repo.
fn run_ablation_suite(
    data_dir: &str,
    mordor: Option<&str>,
    lengths: &[usize],
    runs: usize,
    naive_max_relations: usize,
) -> Vec<graph_hunter_core::benchmark::AblationRow> {
    use graph_hunter_core::benchmark::{
        build_lateral_movement_hypothesis, build_spawn_chain_hypothesis, run_ablation,
    };
    use graph_hunter_core::{
        GenericParser, GraphHunter, LogParser, SentinelJsonParser, SysmonJsonParser,
    };

    fn load(path: &str, parser: &impl LogParser) -> GraphHunter {
        let data = std::fs::read_to_string(path)
            .unwrap_or_else(|e| bail(&format!("could not read {path}: {e}")));
        let mut g = GraphHunter::new();
        g.ingest_logs(&data, parser, None)
            .unwrap_or_else(|e| bail(&format!("could not ingest {path}: {e}")));
        g
    }

    let mut rows = Vec::new();
    let mut apt = load(
        &format!("{data_dir}/apt_attack_simulation.json"),
        &SysmonJsonParser,
    );
    rows.extend(run_ablation(
        "APT",
        &mut apt,
        build_spawn_chain_hypothesis,
        lengths,
        runs,
        naive_max_relations,
    ));
    let mut sentinel = load(
        &format!("{data_dir}/sentinel_attack_simulation.json"),
        &SentinelJsonParser,
    );
    rows.extend(run_ablation(
        "Sentinel",
        &mut sentinel,
        build_lateral_movement_hypothesis,
        lengths,
        runs,
        naive_max_relations,
    ));
    if let Some(path) = mordor {
        let mut g = load(path, &GenericParser);
        rows.extend(run_ablation(
            "Mordor",
            &mut g,
            build_spawn_chain_hypothesis,
            lengths,
            runs,
            naive_max_relations,
        ));
    }
    rows
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
