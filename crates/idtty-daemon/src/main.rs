//! IDtty IPC daemon.
//!
//! Background Unix socket (or Named Pipes on Windows) server that holds
//! an unlocked vault in memory and responds to Protobuf gateway requests
//! from CLI, Tauri webview, and browser extension clients.

mod handler;

use anyhow::Result;
use std::path::Path;
use tokio::net::UnixListener;
use tokio::signal;

const DEFAULT_SOCKET_PATH: &str = "/tmp/idtty.sock";

fn main() -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async { run(None).await })
}

async fn run(socket_path: Option<&str>) -> Result<()> {
    let path = socket_path.unwrap_or(DEFAULT_SOCKET_PATH);

    // Clean stale socket
    if Path::new(path).exists() {
        std::fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;

    // Enforce 0600 permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    eprintln!("idtty-daemon listening on {path} (0600)");

    // Graceful shutdown on SIGINT / SIGTERM
    tokio::select! {
        _ = accept_loop(&listener) => {},
        _ = signal::ctrl_c() => {
            eprintln!("Shutting down...");
        }
    }

    // Cleanup socket on exit
    let _ = std::fs::remove_file(path);
    Ok(())
}

async fn accept_loop(listener: &UnixListener) -> Result<()> {
    loop {
        let (stream, _addr) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handler::handle_connection(stream).await {
                eprintln!("Connection error: {e}");
            }
        });
    }
}
