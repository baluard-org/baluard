//! IDtty IPC daemon.
//!
//! Background Unix socket (or Named Pipes on Windows) server that holds
//! an unlocked vault in memory and responds to Protobuf gateway requests
//! from CLI, Tauri webview, and browser extension clients.

mod handler;

use anyhow::Result;
use std::path::Path;
use tokio::net::UnixListener;

#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};

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

    // Set restrictive umask BEFORE bind so socket is born with 0600.
    // This eliminates the TOCTOU race between bind() and chmod().
    #[cfg(unix)]
    {
        let prev = unsafe { libc::umask(0o177) };
        // umask persists for the process; restore is not needed since
        // we want all subsequent file creates restricted too.
        let _ = prev;
    }

    let listener = UnixListener::bind(path)?;

    eprintln!("idtty-daemon listening on {path} (0600)");

    // Graceful shutdown on SIGINT or SIGTERM
    #[cfg(unix)]
    let shutdown = async {
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigterm = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = sigint.recv() => eprintln!("Received SIGINT, shutting down..."),
            _ = sigterm.recv() => eprintln!("Received SIGTERM, shutting down..."),
        }
        Result::<(), anyhow::Error>::Ok(())
    };

    #[cfg(not(unix))]
    let shutdown = async {
        tokio::signal::ctrl_c().await?;
        eprintln!("Shutting down...");
        Result::<(), anyhow::Error>::Ok(())
    };

    tokio::select! {
        result = accept_loop(&listener) => result?,
        result = shutdown => result?,
    }

    // Cleanup socket on exit
    let _ = std::fs::remove_file(path);
    // TODO: zeroize vault in memory before drop once vault state is held here
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
