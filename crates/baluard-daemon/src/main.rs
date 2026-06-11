//! Baluard IPC daemon.
//!
//! Background Unix socket (or Named Pipes on Windows) server that holds
//! an unlocked vault in memory and responds to Protobuf gateway requests
//! from CLI, Tauri webview, and browser extension clients.

mod crypto;
mod handler;
mod rate_limit;
pub mod socket_path;
mod state;
pub mod proto {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/baluard.auth.rs"));
    include!(concat!(env!("OUT_DIR"), "/baluard.vault.rs"));
    include!(concat!(env!("OUT_DIR"), "/baluard.space.rs"));
}

use state::{SharedVaultState, VaultState};

use anyhow::Result;
use baluard_core::vault::registry::VaultSource;
use clap::parser::ValueSource;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UnixListener;

#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};

const DEFAULT_VAULT_PATH: &str = ".";

/// Initialize debug logging. When BALUARD_DEBUG=1:
/// - Daemon logs to stderr (captured by Tauri sidecar) AND to `baluard_core::paths::debug_log_path()`
/// - Level: Debug for baluard crates, Warn for dependencies
///
/// When BALUARD_DEBUG is unset: only errors to stderr.
fn init_debug_logging() {
    use env_logger::Builder;
    use log::LevelFilter;
    use std::io::Write;

    let debug = std::env::var("BALUARD_DEBUG").unwrap_or_default() == "1";

    if debug {
        // Determine log file path (same dir as socket)
        let log_path = dirs::debug_log_path();
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            Ok(file) => {
                let file = Box::new(file) as Box<dyn Write + Send>;
                // Multi-target: write to both stderr and file
                let target = env_logger::Target::Pipe(Box::new(std::io::LineWriter::new(
                    std::io::BufWriter::new(MultiWriter {
                        a: std::io::stderr(),
                        b: file,
                    }),
                )));
                Builder::new()
                    .target(target)
                    .filter_level(LevelFilter::Warn)
                    .filter(Some("baluard_core"), LevelFilter::Debug)
                    .filter(Some("baluard_daemon"), LevelFilter::Debug)
                    .format_timestamp_secs()
                    .init();
                log::info!("=== baluard-daemon debug session started ===");
                log::info!("Log file: {}", log_path.display());
            }
            Err(e) => {
                eprintln!("Could not open debug log {}: {e}", log_path.display());
                // Fallback to stderr-only
                Builder::new()
                    .filter_level(LevelFilter::Warn)
                    .filter(Some("baluard_core"), LevelFilter::Debug)
                    .filter(Some("baluard_daemon"), LevelFilter::Debug)
                    .format_timestamp_secs()
                    .init();
            }
        }
    } else {
        // Production: only errors
        Builder::new().filter_level(LevelFilter::Error).init();
    }
}

/// Writer that fans out to two sinks.
struct MultiWriter<A: std::io::Write, B: std::io::Write> {
    a: A,
    b: B,
}

impl<A: std::io::Write, B: std::io::Write> std::io::Write for MultiWriter<A, B> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Write to both, return the first successful result
        let ra = self.a.write(buf);
        let _ = self.b.write(buf);
        ra
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.a.flush()?;
        self.b.flush()?;
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    init_debug_logging();

    let matches =
        clap::Command::new("baluard-daemon")
            .arg(
                clap::Arg::new("vault-path")
                    .long("vault-path")
                    .short('v')
                    .default_value(DEFAULT_VAULT_PATH)
                    .help("Path to the vault directory. Ignored if --vault-slug is set."),
            )
            .arg(clap::Arg::new("vault-slug").long("vault-slug").help(
                "Target vault by slug. Looks up path in the registry. Overrides --vault-path.",
            ))
            .arg(
                clap::Arg::new("socket")
                    .long("socket")
                    .short('s')
                    .help("Unix socket path (default: platform-specific)"),
            )
            .get_matches();

    // Resolve which vault to serve. Priority: --vault-slug, --vault-path, registry active_vault, default.
    let explicit_slug = matches.get_one::<String>("vault-slug").map(|s| s.as_str());
    let explicit_path = match matches.value_source("vault-path") {
        Some(ValueSource::CommandLine) => {
            let p = matches.get_one::<String>("vault-path").unwrap();
            Some(PathBuf::from(p))
        }
        // EnvVariable / DefaultValue both mean "user did not pass --vault-path on the CLI".
        // Note: if an env-var override for vault path is ever added, this arm will
        // silently ignore it. Intentional for now — there is no such env var.
        _ => None,
    };

    // Registry load policy: when the user gives us an explicit vault location
    // (slug or path), a missing/unreadable registry is non-fatal — they know
    // where their vault is. When no flag is given, the registry is the source
    // of truth; a corrupt-but-present registry is a hard error so we never
    // silently start on the wrong (fallback) vault.
    let registry_path = baluard_core::vault::registry::VaultRegistry::path();
    let registry = if explicit_slug.is_some() || explicit_path.is_some() {
        baluard_core::vault::registry::VaultRegistry::load_locked().unwrap_or_else(|e| {
            log::warn!("Failed to load vault registry (using explicit vault flag): {e}");
            baluard_core::vault::registry::VaultRegistry::default()
        })
    } else if !registry_path.exists() {
        // Fresh install or pre-registry-era vault. No file = no problem.
        baluard_core::vault::registry::VaultRegistry::default()
    } else {
        match baluard_core::vault::registry::VaultRegistry::load_locked() {
            Ok(reg) => reg,
            Err(e) => {
                eprintln!(
                    "error: registry exists at {} but failed to load: {e}.\n\
                     Refusing to start — would otherwise serve the wrong vault. \
                     Inspect or remove the registry and retry.",
                    registry_path.display()
                );
                std::process::exit(1);
            }
        }
    };

    let fallback = PathBuf::from(DEFAULT_VAULT_PATH);
    let resolved = match baluard_core::vault::registry::resolve_active_vault(
        explicit_slug,
        explicit_path.as_deref(),
        &registry,
        &fallback,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    match &resolved.source {
        VaultSource::ExplicitSlug | VaultSource::ExplicitPath | VaultSource::RegistryActive => {
            log::info!("{resolved}")
        }
        VaultSource::StaleActive(_) | VaultSource::Fallback => log::warn!("{resolved}"),
    }

    let vault = resolved.path.to_string_lossy().into_owned();
    let sock = matches
        .get_one::<String>("socket")
        .cloned()
        .unwrap_or_else(|| {
            socket_path::default_socket_path()
                .to_string_lossy()
                .into_owned()
        });

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async { run(&sock, &vault).await })
}

async fn run(socket_path: &str, vault_path: &str) -> Result<()> {
    let vault_state: SharedVaultState = Arc::new(VaultState::new(PathBuf::from(vault_path)));

    // Spawn auto-lock background timer
    VaultState::spawn_auto_lock_checker(vault_state.clone());

    // Ensure socket parent directory exists.
    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Clean stale socket
    if std::path::Path::new(socket_path).exists() {
        std::fs::remove_file(socket_path)?;
    }

    // Set restrictive umask BEFORE bind so socket is born with 0600,
    // then restore original umask so subsequent mkdir calls keep the execute bit.
    let listener = {
        #[cfg(unix)]
        {
            let prev = unsafe { libc::umask(0o177) }; // lgtm[cpp/overflow]
            let l = UnixListener::bind(socket_path)?;
            unsafe {
                libc::umask(prev);
            }
            l
        }
        #[cfg(not(unix))]
        {
            UnixListener::bind(socket_path)?
        }
    };

    log::info!("baluard-daemon listening on {socket_path} (0600)");
    log::info!("Vault path: {vault_path}");

    // Graceful shutdown on SIGINT or SIGTERM
    #[cfg(unix)]
    let shutdown = async {
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigterm = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = sigint.recv() => log::warn!("Received SIGINT, shutting down..."),
            _ = sigterm.recv() => log::warn!("Received SIGTERM, shutting down..."),
        }
        Result::<(), anyhow::Error>::Ok(())
    };

    #[cfg(not(unix))]
    let shutdown = async {
        tokio::signal::ctrl_c().await?;
        log::warn!("Shutting down...");
        Result::<(), anyhow::Error>::Ok(())
    };

    tokio::select! {
        result = accept_loop(&listener, vault_state.clone()) => result?,
        result = shutdown => result?,
    }

    // Lock vault before exit (zeroizes keys)
    let _ = vault_state.lock().await;
    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

async fn accept_loop(listener: &UnixListener, vault_state: SharedVaultState) -> Result<()> {
    loop {
        let (stream, _addr) = listener.accept().await?;
        let state = vault_state.clone();
        tokio::spawn(async move {
            if let Err(e) = handler::handle_connection(stream, state).await {
                log::error!("Connection error: {e}");
            }
        });
    }
}

/// Resolve debug log path via baluard_core::paths.
/// Respects BALUARD_LOG_DIR env override.
mod dirs {
    pub fn debug_log_path() -> std::path::PathBuf {
        baluard_core::paths::debug_log_path()
    }
}
