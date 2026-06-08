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

    /// Daemon socket path (default: platform-specific, see `idtty_core::paths::socket_path`).
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
        /// Folder ID to assign to.
        #[arg(long)]
        folder: Option<String>,
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
    List {
        /// Show archived entries instead of active ones.
        #[arg(long)]
        archived: bool,
    },

    /// Delete a cipher by ID.
    Delete {
        /// Cipher ID.
        id: String,
    },

    /// Archive a cipher (hide from main list).
    Archive {
        /// Cipher ID.
        id: String,
    },

    /// Unarchive a cipher (restore to main list).
    Unarchive {
        /// Cipher ID.
        id: String,
    },

    /// Edit an existing cipher.
    Edit {
        /// Cipher ID.
        id: String,
        /// New name.
        #[arg(long)]
        name: Option<String>,
        /// New favorite status.
        #[arg(long)]
        favorite: Option<bool>,
        /// New folder ID.
        #[arg(long)]
        folder: Option<String>,
    },

    /// Manage enrolled devices.
    Devices {
        #[command(subcommand)]
        action: DeviceCommands,
    },

    /// Get or set vault settings.
    Settings {
        #[command(subcommand)]
        action: SettingsAction,
    },

    /// Manage folders.
    Folders {
        #[command(subcommand)]
        action: FolderAction,
    },

    /// Manage tags.
    Tags {
        #[command(subcommand)]
        action: TagAction,
    },

    /// Import entries from external format.
    Import {
        /// Format: bw-json, bw-csv, chrome-csv, firefox-csv, lastpass-csv, 1password-1pux, 1password-csv, keepass-xml.
        format: String,
        /// Path to import file.
        path: String,
    },

    /// Export vault entries.
    Export {
        /// Format: bw-json, bw-csv.
        format: String,
        /// Output file path.
        path: String,
    },

    /// Show password health report (weak, reused, old passwords).
    Health,

    /// Upload a file attachment to a cipher.
    AttachUpload {
        /// Cipher ID.
        cipher_id: String,
        /// Path to file to attach.
        file: String,
    },

    /// Download an attachment from a cipher.
    AttachDownload {
        /// Cipher ID.
        cipher_id: String,
        /// Attachment ID.
        attachment_id: String,
        /// Output file path.
        output: String,
    },

    /// Delete an attachment from a cipher.
    AttachDelete {
        /// Cipher ID.
        cipher_id: String,
        /// Attachment ID.
        attachment_id: String,
    },

    /// List attachments on a cipher.
    AttachList {
        /// Cipher ID.
        cipher_id: String,
    },

    /// Ping the daemon to check connectivity.
    Ping,
}

#[derive(Subcommand)]
enum DeviceCommands {
    /// List enrolled devices.
    List,
    /// Show rotation status.
    RotationStatus,
    /// Abort a stalled rotation (requires --direct).
    RotationAbort,
    /// Show current device enrollment details.
    Info,
    /// Revoke a device by UUID.
    Revoke {
        /// Device UUID to revoke.
        device_id: String,
    },
}

#[derive(Subcommand)]
enum SettingsAction {
    /// Show current settings.
    Get,
    /// Set a setting (key=value).
    Set {
        /// Setting key and value (e.g., default_uri_match=host).
        kv: String,
    },
}

#[derive(Subcommand)]
enum FolderAction {
    /// Create a new folder.
    Create {
        /// Folder name.
        name: String,
    },
    /// List all folders.
    List,
    /// Rename a folder.
    Rename {
        /// Folder ID.
        id: String,
        /// New folder name.
        name: String,
    },
    /// Delete a folder (unassigns all entries).
    Delete {
        /// Folder ID.
        id: String,
    },
}

#[derive(Subcommand)]
enum TagAction {
    /// Create a new tag.
    Create {
        /// Tag name.
        name: String,
    },
    /// List all tags.
    List,
    /// Rename a tag across all entries.
    Rename {
        /// Current tag name.
        old: String,
        /// New tag name.
        new: String,
    },
    /// Delete a tag from all entries.
    Delete {
        /// Tag name.
        name: String,
    },
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
            SyncAction::Init => {
                commands::handle_sync_init(mode, &cli.vault_path, cli.socket.as_deref())
            }
            SyncAction::Remote { url } => {
                commands::handle_sync_remote(mode, &cli.vault_path, cli.socket.as_deref(), &url)
            }
            SyncAction::Push => {
                commands::handle_sync_push(mode, &cli.vault_path, cli.socket.as_deref())
            }
            SyncAction::Pull => {
                commands::handle_sync_pull(mode, &cli.vault_path, cli.socket.as_deref())
            }
            SyncAction::Status => {
                commands::handle_sync_status(mode, &cli.vault_path, cli.socket.as_deref())
            }
            SyncAction::Log { limit } => {
                commands::handle_sync_log(mode, &cli.vault_path, cli.socket.as_deref(), limit)
            }
        },

        // Cipher CRUD: daemon-first with direct fallback
        Commands::Add {
            name,
            username,
            password,
            uri,
            notes,
            folder,
        } => commands::handle_add(
            mode,
            &cli.vault_path,
            cli.socket.as_deref(),
            name,
            username,
            password,
            uri,
            notes,
            folder.as_deref(),
        ),
        Commands::Get {
            id,
            decrypt,
            output,
        } => commands::handle_get(
            mode,
            &cli.vault_path,
            cli.socket.as_deref(),
            &id,
            decrypt,
            &output,
        ),
        Commands::List { archived } => {
            commands::handle_list(mode, &cli.vault_path, cli.socket.as_deref(), archived)
        }
        Commands::Delete { id } => {
            commands::handle_delete(mode, &cli.vault_path, cli.socket.as_deref(), &id)
        }

        Commands::Archive { id } => {
            commands::handle_archive(mode, &cli.vault_path, cli.socket.as_deref(), &id)
        }

        Commands::Unarchive { id } => {
            commands::handle_unarchive(mode, &cli.vault_path, cli.socket.as_deref(), &id)
        }

        Commands::Edit {
            id,
            name,
            favorite,
            folder,
        } => commands::handle_edit(
            mode,
            &cli.vault_path,
            cli.socket.as_deref(),
            &id,
            name,
            favorite,
            folder,
        ),

        // Devices
        Commands::Devices { action } => match action {
            DeviceCommands::List => {
                commands::handle_devices(mode, &cli.vault_path, cli.socket.as_deref())
            }
            DeviceCommands::RotationStatus => {
                commands::handle_rotation_status(mode, &cli.vault_path, cli.socket.as_deref())
            }
            DeviceCommands::RotationAbort => {
                commands::handle_rotation_abort(mode, &cli.vault_path, cli.socket.as_deref())
            }
            DeviceCommands::Info => {
                commands::handle_device_info(mode, &cli.vault_path, cli.socket.as_deref())
            }
            DeviceCommands::Revoke { device_id } => commands::handle_device_revoke(
                mode,
                &cli.vault_path,
                cli.socket.as_deref(),
                &device_id,
            ),
        },

        // Settings
        Commands::Settings { action } => match action {
            SettingsAction::Get => commands::handle_settings_get(mode, cli.socket.as_deref()),
            SettingsAction::Set { kv } => {
                commands::handle_settings_set(mode, cli.socket.as_deref(), &kv)
            }
        },

        Commands::Folders { action } => match action {
            FolderAction::Create { name } => {
                commands::handle_folder_create(mode, cli.socket.as_deref(), &name)
            }
            FolderAction::List => commands::handle_folder_list(mode, cli.socket.as_deref()),
            FolderAction::Rename { id, name } => {
                commands::handle_folder_rename(mode, cli.socket.as_deref(), &id, &name)
            }
            FolderAction::Delete { id } => {
                commands::handle_folder_delete(mode, cli.socket.as_deref(), &id)
            }
        },

        Commands::Tags { action } => match action {
            TagAction::Create { name } => {
                commands::handle_tag_create(mode, cli.socket.as_deref(), &name)
            }
            TagAction::List => commands::handle_tag_list(mode, cli.socket.as_deref()),
            TagAction::Rename { old, new } => {
                commands::handle_tag_rename(mode, cli.socket.as_deref(), &old, &new)
            }
            TagAction::Delete { name } => {
                commands::handle_tag_delete(mode, cli.socket.as_deref(), &name)
            }
        },

        Commands::Import { format, path } => {
            commands::handle_import(cli.socket.as_deref(), &format, &path)
        }

        Commands::Export { format, path } => {
            commands::handle_export(cli.socket.as_deref(), &format, &path)
        }

        Commands::Health => commands::handle_health(cli.socket.as_deref()),

        Commands::AttachUpload { cipher_id, file } => {
            commands::handle_attach_upload(cli.socket.as_deref(), &cipher_id, &file)
        }

        Commands::AttachDownload {
            cipher_id,
            attachment_id,
            output,
        } => commands::handle_attach_download(
            cli.socket.as_deref(),
            &cipher_id,
            &attachment_id,
            &output,
        ),

        Commands::AttachDelete {
            cipher_id,
            attachment_id,
        } => commands::handle_attach_delete(cli.socket.as_deref(), &cipher_id, &attachment_id),

        Commands::AttachList { cipher_id } => {
            commands::handle_attach_list(cli.socket.as_deref(), &cipher_id)
        }

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
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
