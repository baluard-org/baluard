//! Baluard IPC daemon.
//!
//! Background Unix socket (or Named Pipes on Windows) server that holds
//! every opened vault in memory and responds to Protobuf gateway requests
//! from CLI, Tauri webview, and browser extension clients.
//!
//! This is the thin binary wrapper. All logic lives in the library crate
//! (`baluard_daemon`) so it is unit/integration-testable.

use baluard_daemon::host::{SharedVaultHost, VaultHost};
use baluard_daemon::state::VaultState;

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
    // Load `.env` from cwd (and parents) into process env. `dotenvy` returns
    // `Err` if no `.env` is present — the expected case in CI / production
    // installs. Real env vars take precedence over the file. The `.env`
    // file is gitignored; `.env.example` documents the variables.
    let _ = dotenvy::dotenv();

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
            baluard_daemon::socket_path::default_socket_path()
                .to_string_lossy()
                .into_owned()
        });

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async { run(&sock, &vault, &resolved.slug).await })
}

async fn run(socket_path: &str, vault_path: &str, active_slug: &Option<String>) -> Result<()> {
    // Best-effort wipe of the legacy global `quick-unlock` keychain entry
    // written by pre-QU daemon versions (one shared secret for ALL vaults).
    // Per-vault scoping is now keyed by vault_id; this prevents an old
    // per-app secret from lingering in the keychain. Non-fatal.
    if let Err(e) = baluard_core::biometric::disable_legacy_global() {
        eprintln!("warning: failed to wipe legacy biometric secret: {e}");
    }

    let host: SharedVaultHost = VaultHost::shared();

    // Lazy-load the resolved active vault into the host map (opened but
    // locked). The map starts with at most one entry; the rest fill as the
    // user switches/unlocks. We do NOT unlock here — the user still has to
    // present the master password. Opening here (rather than lazily on the
    // first request) keeps the no-slug `vault.open` path honest: a
    // registered-and-present vault returns locked info instead of failing.
    if let Some(slug) = active_slug {
        // Read the path from the registry (the slug was resolved from the
        // registry or --vault-slug, so it must be present).
        let reg = baluard_core::vault::registry::VaultRegistry::load_locked().unwrap_or_default();
        if let Some(entry) = reg.get(slug) {
            let state = Arc::new(VaultState::new(entry.path.clone()));
            host.insert(slug.clone(), state.clone()).await;
            if state.open().await.is_ok() {
                // Opened (locked). Make it the active focus.
                let _ = host.switch(slug).await;
            } else {
                // Path vanished or unreadable (e.g. stale active_vault).
                // Evict so the no-slug `vault.open` fallback can pick a
                // vault whose path still exists. Non-fatal: the registry
                // may still hold other usable vaults.
                log::warn!("Active vault '{slug}' could not be opened; evicted from host");
                host.close(slug).await;
            }
        }
    }

    // Spawn the single multi-vault auto-lock checker. Iterates the host map
    // every 30s and applies each vault's own vault_timeout policy.
    host.spawn_auto_lock_checker();

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
    let _ = vault_path; // kept for log line; host is source of truth

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
        result = accept_loop(&listener, host.clone()) => result?,
        result = shutdown => result?,
    }

    // Phase 6: lock every open vault before exit (zeroizes all key material).
    let locked = host.lock_all().await;
    if locked > 0 {
        log::info!("Locked {locked} vault(s) on shutdown.");
    }
    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

async fn accept_loop(listener: &UnixListener, host: SharedVaultHost) -> Result<()> {
    loop {
        let (stream, _addr) = listener.accept().await?;
        let host = host.clone();
        tokio::spawn(async move {
            if let Err(e) = baluard_daemon::handler::handle_connection(stream, host).await {
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
