//! IDtty CLI: command-line interface for the git-native password manager.

mod client;
mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "idtty", version, about = "Git-native password manager")]
struct Cli {
    /// Vault path (defaults to current directory).
    #[arg(long, global = true, default_value = ".")]
    vault_path: String,

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

    /// Unlock vault (verify master password, test decryption).
    Unlock,

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

    let result = match cli.command {
        Commands::Init { profile } => commands::handle_init(&cli.vault_path, &profile),
        Commands::Unlock => commands::handle_unlock(&cli.vault_path),
        Commands::Sync { action } => match action {
            SyncAction::Init => commands::handle_sync_init(&cli.vault_path),
            SyncAction::Remote { url } => commands::handle_sync_remote(&cli.vault_path, &url),
            SyncAction::Push => commands::handle_sync_push(&cli.vault_path),
            SyncAction::Pull => commands::handle_sync_pull(&cli.vault_path),
            SyncAction::Status => commands::handle_sync_status(&cli.vault_path),
            SyncAction::Log { limit } => commands::handle_sync_log(&cli.vault_path, limit),
        },
        Commands::Add { name, username, password, uri, notes } => {
            commands::handle_add(&cli.vault_path, name, username, password, uri, notes)
        }
        Commands::Get { id, decrypt, output } => commands::handle_get(&cli.vault_path, &id, decrypt, &output),
        Commands::List => commands::handle_list(&cli.vault_path),
        Commands::Delete { id } => commands::handle_delete(&cli.vault_path, &id),
        Commands::Devices { action } => match action {
            DeviceCommands::List => commands::handle_devices(&cli.vault_path),
        },
        Commands::Ping => {
            match client::request("ping", "") {
                Ok(resp) => {
                    if resp.success {
                        println!("{}
Daemon is reachable.", resp.payload);
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
