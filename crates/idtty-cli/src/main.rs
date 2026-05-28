//! IDtty CLI: command-line interface for the git-native password manager.

mod client;
mod commands;

use clap::{Parser, Subcommand};

/// How to connect to the vault.
#[derive(Clone, Copy, Debug)]
pub enum ConnectMode {
    /// Route through idtty-daemon over Unix socket.
    Daemon,
    /// Call idtty-core directly (no daemon).
    Direct,
}

#[derive(Parser)]
#[command(name = "idtty", version, about = "Git-native password manager")]
struct Cli {
    /// Vault path (defaults to current directory).
    #[arg(long, global = true, default_value = ".")]
    vault_path: String,

    /// Use idtty-core directly instead of the daemon.
    #[arg(long, global = true)]
    direct: bool,

    /// Daemon socket path (default: /tmp/idtty.sock).
    #[arg(long, global = true)]
    socket: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new vault with master password.
    Init {
        /// KDF profile: mobile-low, desktop-std, desktop-high.
        #[arg(long, default_value = "desktop-std")]
        profile: String,
    },

    /// Unlock vault in the daemon (verifies master password).
    Unlock,

    /// Lock vault in the daemon (zeroizes keys).
    Lock,

    /// Sync vault with remote.
    Sync {
        #[command(subcommand)]
        action: SyncAction,
    },

    /// Add a new cipher.
    Add {
        /// Cipher name.
        #[arg(long)]
        name: String,
        /// Username.
        #[arg(long)]
        username: Option<String>,
        /// Password (omitted = prompt).
        #[arg(long)]
        password: Option<String>,
        /// URI.
        #[arg(long)]
        uri: Option<String>,
        /// Notes.
        #[arg(long)]
        notes: Option<String>,
    },

    /// Get a cipher by ID or name.
    Get {
        /// Cipher ID or name prefix.
        id: String,
        /// Decrypt and show cipher content (requires master password).
        #[arg(long)]
        decrypt: bool,
        /// Output format for decrypted content.
        #[arg(long, default_value = "quiet")]
        output: String,
    },

    /// List all ciphers.
    List,

    /// Delete a cipher by ID.
    Delete {
        /// Cipher ID.
        id: String,
    },

    /// Manage enrolled devices.
    Devices {
        #[command(subcommand)]
        action: DeviceCommands,
    },

    /// Ping the daemon to check connectivity.
    Ping,
}

#[derive(Subcommand)]
enum DeviceCommands {
    /// List enrolled devices.
    List,
}

#[derive(Subcommand)]
enum SyncAction {
    /// Initialize git repo for sync.
    Init,
    /// Set remote URL.
    Remote {
        /// Remote URL (HTTPS or SSH).
        url: String,
    },
    /// Push local changes to remote.
    Push,
    /// Pull remote changes.
    Pull,
    /// Show sync status.
    Status,
    /// Show commit log.
    Log {
        /// Number of commits to show.
        #[arg(long, default_value = "10")]
        limit: usize,
    },
}

fn main() {
    let cli = Cli::parse();

    let mode = if cli.direct {
        ConnectMode::Direct
    } else {
        ConnectMode::Daemon
    };

    let result = match cli.command {
        // Init always direct (creates vault on disk)
        Commands::Init { profile } => commands::handle_init(&cli.vault_path, &profile),

        // Vault lifecycle
        Commands::Unlock => commands::handle_unlock(mode, &cli.vault_path, cli.socket.as_deref()),
        Commands::Lock => commands::handle_lock(mode, cli.socket.as_deref()),

        // Sync: daemon-first with direct fallback
        Commands::Sync { action } => match action {
            SyncAction::Init => commands::handle_sync_init(mode, &cli.vault_path, cli.socket.as_deref()),
            SyncAction::Remote { url } => commands::handle_sync_remote(mode, &cli.vault_path, cli.socket.as_deref(), &url),
            SyncAction::Push => commands::handle_sync_push(mode, &cli.vault_path, cli.socket.as_deref()),
            SyncAction::Pull => commands::handle_sync_pull(mode, &cli.vault_path, cli.socket.as_deref()),
            SyncAction::Status => commands::handle_sync_status(mode, &cli.vault_path, cli.socket.as_deref()),
            SyncAction::Log { limit } => commands::handle_sync_log(mode, &cli.vault_path, cli.socket.as_deref(), limit),
        },

        // Cipher CRUD: daemon-first with direct fallback
        Commands::Add { name, username, password, uri, notes } => {
            commands::handle_add(mode, &cli.vault_path, cli.socket.as_deref(), name, username, password, uri, notes)
        }
        Commands::Get { id, decrypt, output } => {
            commands::handle_get(mode, &cli.vault_path, cli.socket.as_deref(), &id, decrypt, &output)
        }
        Commands::List => commands::handle_list(mode, &cli.vault_path, cli.socket.as_deref()),
        Commands::Delete { id } => commands::handle_delete(mode, &cli.vault_path, cli.socket.as_deref(), &id),

        // Devices: direct for now (daemon doesn't route devices yet)
        Commands::Devices { action } => match action {
            DeviceCommands::List => commands::handle_devices(&cli.vault_path),
        },

        Commands::Ping => {
            match client::request_to("ping", "", cli.socket.as_deref()) {
                Ok(resp) => {
                    if resp.success {
                        println!("{}", resp.payload);
                        println!("Daemon is reachable.");
                    } else {
                        eprintln!("Daemon error: {}", resp.error_message);
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Cannot reach daemon: {e}");
                    eprintln!("Start it with: cargo run -p idtty-daemon");
                    std::process::exit(1);
                }
            }
            Ok(())
        },
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
