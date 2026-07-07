#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod commands;
mod protocol;
use graph_hunter_siem as siem;

use std::io::{self, BufRead, Write};

use commands::CommandHandler;
use protocol::{Request, Response};

fn main() {
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
