mod commands;
mod protocol;
mod siem;

use std::io::{self, BufRead, Write};

use commands::CommandHandler;
use protocol::{Request, Response};

fn main() {
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
