//! IDtty IPC daemon.
//!
//! Background Unix socket (or Named Pipes on Windows) server that holds
//! an unlocked vault in memory and responds to Protobuf gateway requests
//! from CLI, Tauri webview, and browser extension clients.

mod handler;
mod state;
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/idtty.auth.rs"));
    include!(concat!(env!("OUT_DIR"), "/idtty.vault.rs"));
    include!(concat!(env!("OUT_DIR"), "/idtty.space.rs"));
}

use state::{SharedVaultState, VaultState};

use std::sync::Arc;
use anyhow::Result;
use std::path::PathBuf;
use tokio::net::UnixListener;

#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};

const DEFAULT_SOCKET_PATH: &str = "/tmp/idtty.sock";
const DEFAULT_VAULT_PATH: &str = ".";

fn main() -> anyhow::Result<()> {
    let matches = clap::Command::new("idtty-daemon")
        .arg(
            clap::Arg::new("vault-path")
                .long("vault-path")
                .short('v')
                .default_value(".")
                .help("Path to the vault directory"),
        )
        .arg(
            clap::Arg::new("socket")
                .long("socket")
                .short('s')
                .default_value(DEFAULT_SOCKET_PATH)
                .help("Unix socket path"),
        )
        .get_matches();

    let vault = matches.get_one::<String>("vault-path").unwrap();
    let sock = matches.get_one::<String>("socket").unwrap();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async { run(Some(sock), Some(vault)).await })
}

async fn run(socket_path: Option<&str>, vault_path: Option<&str>) -> Result<()> {
    let sock = socket_path.unwrap_or(DEFAULT_SOCKET_PATH);
    let vault = vault_path.unwrap_or(DEFAULT_VAULT_PATH);

    let vault_state: SharedVaultState = Arc::new(
        VaultState::new(PathBuf::from(vault))
    );

    // Clean stale socket
    if std::path::Path::new(sock).exists() {
        std::fs::remove_file(sock)?;
    }

    // Set restrictive umask BEFORE bind so socket is born with 0600.
    #[cfg(unix)]
    {
        let _prev = unsafe { libc::umask(0o177) };
    }

    let listener = UnixListener::bind(sock)?;

    eprintln!("idtty-daemon listening on {sock} (0600)");
    eprintln!("Vault path: {vault}");

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
        result = accept_loop(&listener, vault_state.clone()) => result?,
        result = shutdown => result?,
    }

    // Lock vault before exit (zeroizes keys)
    let _ = vault_state.lock().await;
    let _ = std::fs::remove_file(sock);
    Ok(())
}

async fn accept_loop(listener: &UnixListener, vault_state: SharedVaultState) -> Result<()> {
    loop {
        let (stream, _addr) = listener.accept().await?;
        let state = vault_state.clone();
        tokio::spawn(async move {
            if let Err(e) = handler::handle_connection(stream, state).await {
                eprintln!("Connection error: {e}");
            }
        });
    }
}
