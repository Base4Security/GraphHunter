//! `graph-hunter-server` — the Graph Hunter HTTP API without the desktop
//! app. Same router, same stores, same session directory: a session
//! saved here opens in the app and the other way round.

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::sync::Arc;

use graph_hunter_api::{GraphHunterApi, NoopEmitter};
use graph_hunter_server::{ServerState, bootstrap, http};

const USAGE: &str = "\
usage: graph-hunter-server [--port N] [--host ADDR] [--ingest-root DIR[,DIR...]]
                           [--exit-with-stdin]

  --port N           Port to listen on (default: GRAPHHUNTER_API_PORT or 37891).
  --host ADDR        Address to bind (default: GRAPHHUNTER_API_HOST or 127.0.0.1).
  --ingest-root DIR  Directories clients may ingest log files from. Same as
                     GRAPHHUNTER_INGEST_ROOT; without it file ingest answers 403.
  --exit-with-stdin  Exit when stdin reaches end of file. For a parent that
                     spawns this server and holds the write end of the pipe:
                     the server then never outlives it, however it dies.

Auth: set GRAPHHUNTER_API_TOKEN to choose the bearer token. If it is unset a
random one is generated and printed once on stderr.";

fn bail(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(2);
}

fn main() {
    // Flags only override the environment, so they are applied before
    // anything reads it — and before any thread exists (see
    // `bootstrap::default_perf_flags`).
    let mut exit_with_stdin = false;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        if arg == "--exit-with-stdin" {
            exit_with_stdin = true;
            continue;
        }
        let (key, what) = match arg.as_str() {
            "--port" => ("GRAPHHUNTER_API_PORT", "--port needs a number"),
            "--host" => ("GRAPHHUNTER_API_HOST", "--host needs an address"),
            "--ingest-root" => (
                graph_hunter_api::paths::INGEST_ROOT_ENV,
                "--ingest-root needs a directory",
            ),
            "-h" | "--help" => bail(USAGE),
            other => bail(&format!("unknown flag: {other}\n\n{USAGE}")),
        };
        let value = it.next().unwrap_or_else(|| bail(what));
        // SAFETY: still single-threaded; the runtime starts below.
        unsafe { std::env::set_var(key, value) };
    }

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    bootstrap::load_dotenv();
    // SAFETY: still single-threaded.
    unsafe { bootstrap::default_perf_flags() };

    let (api_token, generated) = bootstrap::resolve_token();
    if generated {
        // The only way the operator can learn a generated token. A token
        // supplied through the environment is never echoed.
        eprintln!("GRAPHHUNTER_API_TOKEN={api_token}");
    }

    let api = Arc::new(GraphHunterApi::new(Arc::new(NoopEmitter)));
    api.bootstrap_geoip(None);
    bootstrap::init_stores(&api);

    let state = Arc::new(ServerState {
        api_token,
        journal: bootstrap::open_journal(),
        emitter: api.emitter_arc(),
    });
    let port = bootstrap::resolve_port();

    if exit_with_stdin {
        // A parent that is killed cannot ask us to stop, but the OS closes
        // its end of the pipe. Without this, a crashed MCP client leaves a
        // server holding a multi-gigabyte graph with nobody to talk to.
        std::thread::spawn(|| {
            let mut sink = [0u8; 256];
            let mut stdin = std::io::stdin().lock();
            while matches!(std::io::Read::read(&mut stdin, &mut sink), Ok(n) if n > 0) {}
            tracing::info!("stdin closed, shutting down");
            std::process::exit(0);
        });
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| bail(&format!("failed to start the async runtime: {e}")));
    let served = runtime.block_on(async {
        tokio::select! {
            r = http::run_async(state, api, port) => r,
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("interrupt received, shutting down");
                Ok(())
            }
        }
    });
    if let Err(e) = served {
        bail(&format!("graph-hunter-server: {e}"));
    }
}
