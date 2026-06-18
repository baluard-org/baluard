//! Baluard CLI: command-line interface for the git-native password manager.

mod client;
mod commands;

use baluard_core::types::{CipherInput, CipherKind, LoginData};
use clap::{Parser, Subcommand};

/// How to connect to the vault.
#[derive(Clone, Copy, Debug)]
pub enum ConnectMode {
    /// Route through baluard-daemon over Unix socket.
    Daemon,
    /// Call baluard-core directly (no daemon).
    Direct,
}

#[derive(Parser)]
#[command(name = "baluard", version, about = "Git-native password manager")]
struct Cli {
    /// Vault path (defaults to current directory).
    #[arg(long, global = true, default_value = ".")]
    vault_path: String,

    /// Target a specific vault by slug (uses --direct mode if not active vault).
    #[arg(long, global = true)]
    vault: Option<String>,

    /// Use baluard-core directly instead of the daemon.
    #[arg(long, global = true)]
    direct: bool,

    /// Daemon socket path (default: platform-specific, see `baluard_core::paths::socket_path`).
    #[arg(long, global = true)]
    socket: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // Pre-existing: Commands has unit + struct variants of widely different sizes
enum Commands {
    /// Create a new vault with master password.
    Init {
        /// KDF profile: mobile-low, desktop-std, desktop-high.
        #[arg(long, default_value = "desktop-std")]
        profile: String,
        /// Display name (shown in sidebar).
        #[arg(long)]
        name: Option<String>,
        /// Vault slug (machine-friendly ID, e.g. "baluard-personal"). Defaults to auto-generated from name.
        #[arg(long)]
        slug: Option<String>,
        /// Theme: light, dark, system.
        #[arg(long)]
        theme: Option<String>,
        /// Language: en, es.
        #[arg(long)]
        lang: Option<String>,
        /// Auto-lock timeout in minutes.
        #[arg(long)]
        auto_lock: Option<u32>,
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
        #[command(subcommand)]
        cipher: CipherAddCommand,
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
        /// Replace tags (comma-separated). Use "" to clear all.
        #[arg(long, value_delimiter = ',')]
        tags: Option<Vec<String>>,
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

    /// Manage passkeys (FIDO2/WebAuthn credentials).
    Passkey {
        #[command(subcommand)]
        action: PasskeyAction,
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

    /// Manage vaults (list, switch).
    Vaults {
        #[command(subcommand)]
        action: VaultAction,
    },
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
    /// Enroll this device into an existing vault using the recovery phrase.
    /// Non-destructive: existing devices remain in the registry.
    /// Requires the vault's `enrollment_policy` to be `Personal`.
    EnrollWithPhrase {
        /// The 24-word BIP-39 recovery phrase for the existing vault.
        /// Will prompt if not provided.
        #[arg(long)]
        phrase: Option<String>,
    },
    /// Revoke a device by UUID.
    Revoke {
        /// Device UUID to revoke.
        device_id: String,
    },
}

#[derive(Subcommand)]
enum VaultAction {
    /// List all registered vaults with their in-daemon state.
    List,
    /// Switch the active vault (instant if already unlocked;
    /// prompts for the master password if locked).
    Switch {
        /// Vault slug.
        slug: String,
    },
    /// Close a vault: remove it from the daemon's in-memory map.
    /// Keys zeroize once any in-flight request drains. The vault stays
    /// registered; reopen with `baluard vaults switch <slug>`.
    Close {
        /// Vault slug.
        slug: String,
    },
    /// Set the default vault for next launch (persists `active_vault` in
    /// the registry). Distinct from `switch`, which is the live focus change.
    SetDefault {
        /// Vault slug.
        slug: String,
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
enum PasskeyAction {
    /// List passkeys, optionally filtered by RP ID.
    List {
        /// Filter by relying party ID (e.g. "github.com").
        #[arg(long)]
        rp_id: Option<String>,
    },
    /// Delete a passkey credential.
    Delete {
        /// Login cipher ID.
        id: String,
        /// Credential ID (base64url) of the passkey to remove.
        #[arg(long)]
        credential_id: String,
    },
    /// Rename a passkey credential.
    Rename {
        /// Login cipher ID.
        id: String,
        /// Credential ID (base64url) of the passkey to rename.
        #[arg(long)]
        credential_id: String,
        /// New name for the passkey.
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

// ── Cipher Add Subcommands ─────────────────────────────────────────────────

#[derive(Subcommand)]
enum CipherAddCommand {
    /// Add a login entry (username, password, URI).
    Login {
        #[arg(long)]
        name: String,
        /// Username.
        #[arg(long)]
        username: Option<String>,
        /// Password (omitted = interactive prompt).
        #[arg(long)]
        password: Option<String>,
        /// URI.
        #[arg(long)]
        uri: Option<String>,
        /// TOTP URI (otpauth://...).
        #[arg(long)]
        totp_uri: Option<String>,
        /// Notes.
        #[arg(long)]
        notes: Option<String>,
        /// Folder ID.
        #[arg(long)]
        folder: Option<String>,
        /// Tags (comma-separated).
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        /// Mark as favorite.
        #[arg(long, default_value_t = false)]
        favorite: bool,
    },

    /// Add a payment card.
    Card {
        #[arg(long)]
        name: String,
        /// Cardholder name.
        #[arg(long)]
        cardholder_name: Option<String>,
        /// Card brand (Visa, Mastercard, etc).
        #[arg(long)]
        brand: Option<String>,
        /// Card number.
        #[arg(long)]
        number: Option<String>,
        /// Expiration month.
        #[arg(long)]
        exp_month: Option<String>,
        /// Expiration year.
        #[arg(long)]
        exp_year: Option<String>,
        /// CVV/CVC.
        #[arg(long)]
        code: Option<String>,
        /// Notes.
        #[arg(long)]
        notes: Option<String>,
        /// Folder ID.
        #[arg(long)]
        folder: Option<String>,
        /// Tags (comma-separated).
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        /// Mark as favorite.
        #[arg(long, default_value_t = false)]
        favorite: bool,
    },

    /// Add a secure note.
    #[command(visible_alias = "note")]
    SecureNote {
        #[arg(long)]
        name: String,
        /// Note content.
        #[arg(long)]
        notes: Option<String>,
        /// Folder ID.
        #[arg(long)]
        folder: Option<String>,
        /// Tags (comma-separated).
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        /// Mark as favorite.
        #[arg(long, default_value_t = false)]
        favorite: bool,
    },

    /// Add an identity record.
    Identity {
        #[arg(long)]
        name: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        first_name: Option<String>,
        #[arg(long)]
        middle_name: Option<String>,
        #[arg(long)]
        last_name: Option<String>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        company: Option<String>,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        phone: Option<String>,
        #[arg(long)]
        address1: Option<String>,
        #[arg(long)]
        address2: Option<String>,
        #[arg(long)]
        address3: Option<String>,
        #[arg(long)]
        city: Option<String>,
        #[arg(long)]
        state: Option<String>,
        #[arg(long)]
        postal_code: Option<String>,
        #[arg(long)]
        country: Option<String>,
        /// Notes.
        #[arg(long)]
        notes: Option<String>,
        /// Folder ID.
        #[arg(long)]
        folder: Option<String>,
        /// Tags (comma-separated).
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        /// Mark as favorite.
        #[arg(long, default_value_t = false)]
        favorite: bool,
    },

    /// Add an SSH key.
    #[command(visible_alias = "ssh")]
    SshKey {
        #[arg(long)]
        name: String,
        /// Public key (OpenSSH format).
        #[arg(long)]
        public_key: Option<String>,
        /// Private key (PEM format).
        #[arg(long)]
        private_key: Option<String>,
        /// Key fingerprint.
        #[arg(long)]
        fingerprint: Option<String>,
        /// Notes.
        #[arg(long)]
        notes: Option<String>,
        /// Folder ID.
        #[arg(long)]
        folder: Option<String>,
        /// Tags (comma-separated).
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        /// Mark as favorite.
        #[arg(long, default_value_t = false)]
        favorite: bool,
    },

    /// Add a bank account.
    #[command(visible_alias = "bank")]
    BankAccount {
        #[arg(long)]
        name: String,
        #[arg(long)]
        bank_name: Option<String>,
        #[arg(long)]
        name_on_account: Option<String>,
        #[arg(long)]
        account_type: Option<String>,
        #[arg(long)]
        account_number: Option<String>,
        #[arg(long)]
        routing_number: Option<String>,
        #[arg(long)]
        branch_number: Option<String>,
        #[arg(long)]
        swift_code: Option<String>,
        #[arg(long)]
        iban: Option<String>,
        /// Notes.
        #[arg(long)]
        notes: Option<String>,
        /// Folder ID.
        #[arg(long)]
        folder: Option<String>,
        /// Tags (comma-separated).
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        /// Mark as favorite.
        #[arg(long, default_value_t = false)]
        favorite: bool,
    },

    /// Add a driver's license.
    #[command(visible_alias = "license")]
    DriversLicense {
        #[arg(long)]
        name: String,
        #[arg(long)]
        first_name: Option<String>,
        #[arg(long)]
        middle_name: Option<String>,
        #[arg(long)]
        last_name: Option<String>,
        #[arg(long)]
        date_of_birth: Option<String>,
        #[arg(long)]
        license_number: Option<String>,
        #[arg(long)]
        issuing_country: Option<String>,
        #[arg(long)]
        issuing_state: Option<String>,
        #[arg(long)]
        issue_date: Option<String>,
        #[arg(long)]
        expiration_date: Option<String>,
        /// Notes.
        #[arg(long)]
        notes: Option<String>,
        /// Folder ID.
        #[arg(long)]
        folder: Option<String>,
        /// Tags (comma-separated).
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        /// Mark as favorite.
        #[arg(long, default_value_t = false)]
        favorite: bool,
    },

    /// Add a passport.
    Passport {
        #[arg(long)]
        name: String,
        #[arg(long)]
        surname: Option<String>,
        #[arg(long)]
        given_name: Option<String>,
        #[arg(long)]
        date_of_birth: Option<String>,
        #[arg(long)]
        sex: Option<String>,
        #[arg(long)]
        birth_place: Option<String>,
        #[arg(long)]
        nationality: Option<String>,
        #[arg(long)]
        passport_number: Option<String>,
        #[arg(long)]
        issuing_country: Option<String>,
        #[arg(long)]
        issue_date: Option<String>,
        #[arg(long)]
        expiration_date: Option<String>,
        /// Notes.
        #[arg(long)]
        notes: Option<String>,
        /// Folder ID.
        #[arg(long)]
        folder: Option<String>,
        /// Tags (comma-separated).
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        /// Mark as favorite.
        #[arg(long, default_value_t = false)]
        favorite: bool,
    },

    /// Add a cipher from a CipherInput JSON file (use - for stdin).
    Json {
        /// Path to JSON file, or - for stdin.
        path: String,
    },
}

/// Parse a folder ID string into a UUID, returning a descriptive error on failure.
fn parse_folder_id(
    folder: Option<&String>,
) -> Result<Option<uuid::Uuid>, Box<dyn std::error::Error>> {
    folder
        .map(|f| {
            uuid::Uuid::parse_str(f).map_err(|e| format!("Invalid folder UUID '{f}': {e}").into())
        })
        .transpose()
}

/// Build a CipherInput from a CipherAddCommand subcommand.
fn build_cipher_input(cipher: CipherAddCommand) -> Result<CipherInput, Box<dyn std::error::Error>> {
    match cipher {
        CipherAddCommand::Json { path } => {
            let json_str = if path == "-" {
                use std::io::Read;
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf
            } else {
                std::fs::read_to_string(&path)?
            };
            serde_json::from_str(&json_str)
                .map_err(|e| format!("Invalid CipherInput JSON: {e}").into())
        }
        CipherAddCommand::Login {
            name,
            username,
            password,
            uri,
            totp_uri,
            notes,
            folder,
            tags,
            favorite,
        } => {
            let cipher_password = match password {
                Some(p) => {
                    eprintln!("warning: --password exposes secret in process list.");
                    Some(p)
                }
                None => {
                    let pw = commands::prompt_password("Password: ")?;
                    if pw.is_empty() { None } else { Some(pw) }
                }
            };
            Ok(CipherInput {
                name,
                folder_id: parse_folder_id(folder.as_ref())?,
                kind: CipherKind::Login(LoginData {
                    username,
                    password: cipher_password,
                    uris: uri
                        .map(|u| vec![baluard_core::types::LoginUri::new(u)])
                        .unwrap_or_default(),
                    totp_uri,
                    autofill_on_page_load: false,
                    password_revision_date: None,
                    fido2_credentials: None,
                }),
                favorite,
                notes,
                custom_fields: vec![],
                created_at: None,
                password_history: vec![],
                attachments: vec![],
                archived: false,
                reprompt: false,
                tags,
            })
        }
        CipherAddCommand::Card {
            name,
            cardholder_name,
            brand,
            number,
            exp_month,
            exp_year,
            code,
            notes,
            folder,
            tags,
            favorite,
        } => Ok(CipherInput {
            name,
            folder_id: parse_folder_id(folder.as_ref())?,
            kind: CipherKind::Card(baluard_core::types::CardData {
                cardholder_name,
                brand,
                number,
                exp_month,
                exp_year,
                code,
            }),
            favorite,
            notes,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            reprompt: false,
            tags,
        }),
        CipherAddCommand::SecureNote {
            name,
            notes,
            folder,
            tags,
            favorite,
        } => Ok(CipherInput {
            name,
            folder_id: parse_folder_id(folder.as_ref())?,
            kind: CipherKind::SecureNote,
            favorite,
            notes,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            reprompt: false,
            tags,
        }),
        CipherAddCommand::Identity {
            name,
            title,
            first_name,
            middle_name,
            last_name,
            username,
            company,
            email,
            phone,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            notes,
            folder,
            tags,
            favorite,
        } => Ok(CipherInput {
            name,
            folder_id: parse_folder_id(folder.as_ref())?,
            kind: CipherKind::Identity(baluard_core::types::IdentityData {
                title,
                first_name,
                middle_name,
                last_name,
                username,
                company,
                email,
                phone,
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                ..Default::default()
            }),
            favorite,
            notes,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            reprompt: false,
            tags,
        }),
        CipherAddCommand::SshKey {
            name,
            public_key,
            private_key,
            fingerprint,
            notes,
            folder,
            tags,
            favorite,
        } => Ok(CipherInput {
            name,
            folder_id: parse_folder_id(folder.as_ref())?,
            kind: CipherKind::SshKey(baluard_core::types::SshKeyData {
                public_key,
                private_key,
                key_fingerprint: fingerprint,
            }),
            favorite,
            notes,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            reprompt: false,
            tags,
        }),
        CipherAddCommand::BankAccount {
            name,
            bank_name,
            name_on_account,
            account_type,
            account_number,
            routing_number,
            branch_number,
            swift_code,
            iban,
            notes,
            folder,
            tags,
            favorite,
        } => Ok(CipherInput {
            name,
            folder_id: parse_folder_id(folder.as_ref())?,
            kind: CipherKind::BankAccount(baluard_core::types::BankAccountData {
                bank_name,
                name_on_account,
                account_type,
                account_number,
                routing_number,
                branch_number,
                swift_code,
                iban,
                ..Default::default()
            }),
            favorite,
            notes,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            reprompt: false,
            tags,
        }),
        CipherAddCommand::DriversLicense {
            name,
            first_name,
            middle_name,
            last_name,
            date_of_birth,
            license_number,
            issuing_country,
            issuing_state,
            issue_date,
            expiration_date,
            notes,
            folder,
            tags,
            favorite,
        } => Ok(CipherInput {
            name,
            folder_id: parse_folder_id(folder.as_ref())?,
            kind: CipherKind::DriversLicense(baluard_core::types::DriversLicenseData {
                first_name,
                middle_name,
                last_name,
                date_of_birth,
                license_number,
                issuing_country,
                issuing_state,
                issue_date,
                expiration_date,
                ..Default::default()
            }),
            favorite,
            notes,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            reprompt: false,
            tags,
        }),
        CipherAddCommand::Passport {
            name,
            surname,
            given_name,
            date_of_birth,
            sex,
            birth_place,
            nationality,
            passport_number,
            issuing_country,
            issue_date,
            expiration_date,
            notes,
            folder,
            tags,
            favorite,
        } => Ok(CipherInput {
            name,
            folder_id: parse_folder_id(folder.as_ref())?,
            kind: CipherKind::Passport(baluard_core::types::PassportData {
                surname,
                given_name,
                date_of_birth,
                sex,
                birth_place,
                nationality,
                passport_number,
                issuing_country,
                issue_date,
                expiration_date,
                ..Default::default()
            }),
            favorite,
            notes,
            custom_fields: vec![],
            created_at: None,
            password_history: vec![],
            attachments: vec![],
            archived: false,
            reprompt: false,
            tags,
        }),
    }
}

fn main() {
    let cli = Cli::parse();

    // Resolve --vault flag.
    //
    // Phase 6 / M2: under the keep-unlocked / switch-pointer model the daemon
    // holds every opened vault in a map. `--vault <slug>` now routes each
    // request to that vault via the proto `slug` field WITHOUT mutating the
    // global active pointer or the registry — so read-only commands like
    // `baluard --vault work list` are side-effect-free and don't race a
    // concurrently-running desktop. If the daemon is unreachable we fall
    // back to direct mode (preserves single-shot scripting).
    let vault_path = if let Some(ref vault_slug) = cli.vault {
        match baluard_core::vault::registry::VaultRegistry::load() {
            Ok(reg) => match reg.get(vault_slug) {
                Some(entry) => entry.path.to_string_lossy().into_owned(),
                None => {
                    eprintln!("error: vault '{vault_slug}' not found in registry");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("error: failed to load registry: {e}");
                std::process::exit(1);
            }
        }
    } else {
        cli.vault_path.clone()
    };

    // If --vault <slug> was given, install the per-request slug override so
    // every daemon call targets that vault without a global switch. Then pick
    // the connect mode: --direct wins if explicitly asked or if the daemon is
    // unreachable. Otherwise stay in daemon mode and let per-request slug
    // routing do the targeting.
    let forced_direct = if cli.direct {
        true
    } else if let Some(ref vault_slug) = cli.vault {
        // Install the override (idempotent — single process).
        client::set_vault_slug_override(vault_slug);
        // Daemon reachability check: a ping tells us the daemon is up. If the
        // vault isn't open in the map the daemon will reject the per-request
        // slug with a clear error; the user can `baluard unlock --vault <slug>`
        // first. We do NOT fall back to --direct on "slug not open" because
        // that would silently re-KDF on every invocation.
        client::request_to("ping", "", cli.socket.as_deref()).is_err()
    } else {
        false
    };
    let mode = if forced_direct {
        ConnectMode::Direct
    } else {
        ConnectMode::Daemon
    };

    let result = match cli.command {
        // Init always direct (creates vault on disk)
        Commands::Init {
            profile,
            name,
            slug,
            theme,
            lang,
            auto_lock,
        } => commands::handle_init(
            &cli.vault_path,
            &profile,
            name,
            slug,
            theme,
            lang,
            auto_lock,
        ),

        // Vault lifecycle
        Commands::Unlock => commands::handle_unlock(mode, &vault_path, cli.socket.as_deref()),
        Commands::Lock => commands::handle_lock(mode, cli.socket.as_deref()),

        // Sync: daemon-first with direct fallback
        Commands::Sync { action } => match action {
            SyncAction::Init => {
                commands::handle_sync_init(mode, &vault_path, cli.socket.as_deref())
            }
            SyncAction::Remote { url } => {
                commands::handle_sync_remote(mode, &vault_path, cli.socket.as_deref(), &url)
            }
            SyncAction::Push => {
                commands::handle_sync_push(mode, &vault_path, cli.socket.as_deref())
            }
            SyncAction::Pull => {
                commands::handle_sync_pull(mode, &vault_path, cli.socket.as_deref())
            }
            SyncAction::Status => {
                commands::handle_sync_status(mode, &vault_path, cli.socket.as_deref())
            }
            SyncAction::Log { limit } => {
                commands::handle_sync_log(mode, &vault_path, cli.socket.as_deref(), limit)
            }
        },

        // Cipher CRUD: daemon-first with direct fallback
        Commands::Add { cipher } => match build_cipher_input(cipher) {
            Ok(input) => commands::handle_add(mode, &vault_path, cli.socket.as_deref(), input),
            Err(e) => Err(e),
        },
        Commands::Get {
            id,
            decrypt,
            output,
        } => commands::handle_get(
            mode,
            &vault_path,
            cli.socket.as_deref(),
            &id,
            decrypt,
            &output,
        ),
        Commands::List { archived } => {
            commands::handle_list(mode, &vault_path, cli.socket.as_deref(), archived)
        }
        Commands::Delete { id } => {
            commands::handle_delete(mode, &vault_path, cli.socket.as_deref(), &id)
        }

        Commands::Archive { id } => {
            commands::handle_archive(mode, &vault_path, cli.socket.as_deref(), &id)
        }

        Commands::Unarchive { id } => {
            commands::handle_unarchive(mode, &vault_path, cli.socket.as_deref(), &id)
        }

        Commands::Edit {
            id,
            name,
            favorite,
            folder,
            tags,
        } => commands::handle_edit(
            mode,
            &vault_path,
            cli.socket.as_deref(),
            &id,
            name,
            favorite,
            folder,
            tags,
        ),

        // Devices
        Commands::Devices { action } => match action {
            DeviceCommands::List => {
                commands::handle_devices(mode, &vault_path, cli.socket.as_deref())
            }
            DeviceCommands::RotationStatus => {
                commands::handle_rotation_status(mode, &vault_path, cli.socket.as_deref())
            }
            DeviceCommands::RotationAbort => {
                commands::handle_rotation_abort(mode, &vault_path, cli.socket.as_deref())
            }
            DeviceCommands::Info => {
                commands::handle_device_info(mode, &vault_path, cli.socket.as_deref())
            }
            DeviceCommands::EnrollWithPhrase { phrase } => {
                commands::handle_enroll_with_phrase(mode, &vault_path, phrase.as_deref())
            }
            DeviceCommands::Revoke { device_id } => {
                commands::handle_device_revoke(mode, &vault_path, cli.socket.as_deref(), &device_id)
            }
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
                commands::handle_folder_create(mode, &vault_path, cli.socket.as_deref(), &name)
            }
            FolderAction::List => {
                commands::handle_folder_list(mode, &vault_path, cli.socket.as_deref())
            }
            FolderAction::Rename { id, name } => {
                commands::handle_folder_rename(mode, &vault_path, cli.socket.as_deref(), &id, &name)
            }
            FolderAction::Delete { id } => {
                commands::handle_folder_delete(mode, &vault_path, cli.socket.as_deref(), &id)
            }
        },

        Commands::Tags { action } => match action {
            TagAction::Create { name } => {
                commands::handle_tag_create(mode, &vault_path, cli.socket.as_deref(), &name)
            }
            TagAction::List => commands::handle_tag_list(mode, &vault_path, cli.socket.as_deref()),
            TagAction::Rename { old, new } => {
                commands::handle_tag_rename(mode, &vault_path, cli.socket.as_deref(), &old, &new)
            }
            TagAction::Delete { name } => {
                commands::handle_tag_delete(mode, &vault_path, cli.socket.as_deref(), &name)
            }
        },

        Commands::Passkey { action } => match action {
            PasskeyAction::List { rp_id } => commands::handle_passkey_list(
                &mode,
                &vault_path,
                cli.socket.as_deref(),
                rp_id.as_deref(),
            ),
            PasskeyAction::Delete { id, credential_id } => commands::handle_passkey_delete(
                &mode,
                &vault_path,
                cli.socket.as_deref(),
                &id,
                &credential_id,
            ),
            PasskeyAction::Rename {
                id,
                credential_id,
                name,
            } => commands::handle_passkey_rename(
                &mode,
                &vault_path,
                cli.socket.as_deref(),
                &id,
                &credential_id,
                &name,
            ),
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
                    eprintln!("Start it with: cargo run -p baluard-daemon");
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        Commands::Vaults { ref action } => commands::handle_vaults(action, &cli),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
