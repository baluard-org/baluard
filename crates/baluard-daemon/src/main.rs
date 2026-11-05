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
#[cfg(unix)]
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

        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // The debug log carries slugs, device ids and repo paths:
            // never world-readable.
            opts.mode(0o600);
        }
        match opts.open(&log_path) {
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
    // HID-enumerate child mode (hwkey::fido): must run before any daemon
    // state exists; a parent spawns us to keep IOKit crashes out of the
    // daemon process.
    #[cfg(feature = "fido2")]
    if std::env::args_os().any(|a| a == baluard_core::hwkey::fido::ENUMERATE_FLAG) {
        baluard_core::hwkey::fido::run_enumerate_child();
    }

    // Load `.env` from cwd (and parents) into process env. `dotenvy` returns
    // `Err` if no `.env` is present — the expected case in CI / production
    // installs. Real env vars take precedence over the file. The `.env`
    // file is gitignored; `.env.example` documents the variables.
    let _ = dotenvy::dotenv();

    init_debug_logging();

    // Hardware-backed key seal (progressive enhancement): install the
    // platform keystore when this build carries one. Devices without a
    // backend compile or probe stay on seal v1 with zero behavior change
    // (docs/adr/0097-hardware-backed-keys.md §0).
    if let Some(store) = baluard_core::hwkey::platform_store() {
        baluard_core::hwkey::install(store);
    }
    #[cfg(feature = "fido2")]
    baluard_core::hwkey::install(baluard_core::hwkey::fido::store());

    // Self-register the browser-bridge manifests: macOS has no installer
    // step to drop them, and on Windows the installer registry keys point
    // at a manifest file only the daemon can write with correct path
    // escaping (crates/baluard-core/src/nmh_register.rs). Best effort: a
    // denied write must not block the daemon.
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    match baluard_core::nmh_register::register_for_current_exec() {
        Ok(n) if n > 0 => log::debug!("registered {n} native messaging host manifests"),
        Ok(_) => {}
        Err(e) => log::warn!("native messaging host registration failed: {e}"),
    }

    // Test-fixture kill switch: when the spawning parent goes away
    // (SIGKILLed test runner, OOM kill, crash), no Drop guard can run,
    // so the daemon would sit orphaned forever — 1816 of them once
    // filled this machine's RAM. Polling getppid beats PR_SET_PDEATHSIG
    // for portability (macOS has no pdeathsig); a missed poll only adds
    // a 2s grace. Production never sets this env var. Unix-only by
    // design: Windows test runs keep the (weaker) Drop-guard layer
    // only.
    #[cfg(unix)]
    if std::env::var("BALUARD_DAEMON_DIE_WITH_PARENT").as_deref() == Ok("1") {
        std::thread::spawn(|| {
            let ppid = unsafe { libc::getppid() };
            // Already orphaned before we captured the parent (parent
            // died inside the spawn race): init re-parented us, exit
            // now (review F3). A subreaper adoption in that same race
            // is accepted residual risk — the Drop guards cover it in
            // every normal test flow.
            if ppid == 1 {
                std::process::exit(0);
            }
            loop {
                std::thread::sleep(std::time::Duration::from_secs(2));
                if unsafe { libc::getppid() } != ppid {
                    std::process::exit(0);
                }
            }
        });
    }

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
    let result = rt.block_on(async { run(&sock, &vault, &resolved.slug).await });
    // A stuck spawn_blocking task (e.g. the FIDO probe wedging in HID when no
    // device is attached) would otherwise make the implicit Runtime drop wait
    // forever and leave a daemon that ignores SIGTERM.
    rt.shutdown_timeout(std::time::Duration::from_secs(2));
    result
}

async fn run(socket_path: &str, vault_path: &str, active_slug: &Option<String>) -> Result<()> {
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

    // Ensure socket parent directory exists (named pipes have none).
    #[cfg(unix)]
    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Clean stale socket — but never steal a live daemon's socket: probe
    // with a connect first (a connectable path means another daemon owns
    // it and startup must fail loudly instead of silently taking over).
    // Named pipes have no filesystem residue, so this is unix-only.
    #[cfg(unix)]
    if std::path::Path::new(socket_path).exists() {
        if baluard_core::ipc::IpcStream::connect(std::path::Path::new(socket_path)).is_ok() {
            anyhow::bail!("another daemon is already listening on this socket");
        }
        std::fs::remove_file(socket_path)?;
    }

    // Set restrictive umask BEFORE bind so socket is born with 0600,
    // then restore original umask so subsequent mkdir calls keep the execute bit.
    #[cfg(unix)]
    let listener = {
        let prev = unsafe { libc::umask(0o177) }; // lgtm[cpp/overflow]
        let l = UnixListener::bind(socket_path)?;
        unsafe {
            libc::umask(prev);
        }
        l
    };

    // first_pipe_instance makes startup fail loudly when another daemon
    // already owns the pipe name (the unix stale-socket probe equivalent).
    // The explicit user DACL replaces the default one, whose Everyone
    // read ACE would let any local account hold instances open.
    #[cfg(windows)]
    let listener = {
        use anyhow::Context as _;
        use tokio::net::windows::named_pipe::ServerOptions;

        let pipe_name: &str = socket_path;
        let mut attrs = baluard_core::ipc::user_dacl_security_attributes()
            .context("failed to build the pipe security descriptor")?;
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(true)
                .create_with_security_attributes_raw(
                    pipe_name,
                    attrs.as_ptr() as *mut std::ffi::c_void,
                )
                .context("failed to create the daemon named pipe (another daemon may own it)")
        }?
    };

    log::info!("baluard-daemon listening on {socket_path}");
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

    #[cfg(unix)]
    tokio::select! {
        result = accept_task(&listener, host.clone()) => result?,
        result = shutdown => result?,
    }
    #[cfg(windows)]
    tokio::select! {
        result = accept_task(listener, socket_path, host.clone()) => result?,
        result = shutdown => result?,
    }

    // Phase 6: lock every open vault before exit (zeroizes all key material).
    let locked = host.lock_all().await;
    if locked > 0 {
        log::info!("Locked {locked} vault(s) on shutdown.");
    }
    #[cfg(unix)]
    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

/// Accept a client. Unix: the blocking socket listener. Windows: keep one
/// named-pipe instance listening at all times — each instance serves one
/// connection, so the replacement instance is created before spawning the
/// handler for the current client.
#[cfg(unix)]
async fn accept_task(listener: &UnixListener, host: SharedVaultHost) -> Result<()> {
    accept_loop(listener, host).await
}

#[cfg(windows)]
async fn accept_task(
    mut server: tokio::net::windows::named_pipe::NamedPipeServer,
    pipe_name: &'_ str,
    host: SharedVaultHost,
) -> Result<()> {
    loop {
        // A transient connect error must not kill the daemon and lock out
        // every vault: log, back off, and start from a fresh instance — a
        // client that vanished leaves the old one permanently unusable.
        if let Err(e) = server.connect().await {
            log::warn!("[daemon] pipe connect failed: {e}");
            server = spawn_next_pipe_instance(pipe_name).await;
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            continue;
        }
        let client = server;
        server = spawn_next_pipe_instance(pipe_name).await;
        let host = host.clone();
        tokio::spawn(async move {
            if let Err(e) = baluard_daemon::handler::handle_connection(
                baluard_daemon::handler::IpcStream::Pipe(client),
                host,
            )
            .await
            {
                log::error!("Connection error: {e}");
            }
        });
    }
}

/// Keep exactly one listening instance alive. create() is sync; a
/// persistent failure retries rather than killing a daemon that may hold
/// unlocked vaults.
#[cfg(windows)]
async fn spawn_next_pipe_instance(
    pipe_name: &str,
) -> tokio::net::windows::named_pipe::NamedPipeServer {
    use tokio::net::windows::named_pipe::ServerOptions;

    loop {
        match ServerOptions::new().create(pipe_name) {
            Ok(server) => return server,
            Err(e) => {
                log::warn!("[daemon] pipe instance create failed: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
    }
}

#[cfg(unix)]
async fn accept_loop(listener: &UnixListener, host: SharedVaultHost) -> Result<()> {
    loop {
        // A transient accept error (EMFILE, ECONNABORTED) must not kill
        // the daemon and lock out every vault: log, back off, continue.
        let stream = match listener.accept().await {
            Ok((stream, _addr)) => stream,
            Err(e) => {
                log::warn!("[daemon] accept failed: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                continue;
            }
        };
        let host = host.clone();
        tokio::spawn(async move {
            if let Err(e) = baluard_daemon::handler::handle_connection(
                baluard_daemon::handler::IpcStream::Unix(stream),
                host,
            )
            .await
            {
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
