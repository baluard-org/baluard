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
        /// Create the vault as a FAMILY vault (plan-family-spaces):
        /// purpose, Shared collection, Guardians group, team shape.
        #[arg(long)]
        family: bool,
        /// Machine-readable output for scripts and test harnesses.
        #[arg(long)]
        json: bool,
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

    /// Manage the trash.
    Trash {
        #[command(subcommand)]
        action: TrashAction,
    },

    /// Search entries by name or username.
    Search {
        /// Text to match (case-insensitive substring).
        query: String,
        /// Search every unlocked merge-eligible vault, not just the active one.
        #[arg(long)]
        all: bool,
        /// Search one explicit vault by slug (an organization Space included).
        #[arg(long, value_name = "SLUG")]
        vault: Option<String>,
    },

    /// Generate a password or passphrase. Printed once, never stored
    /// unless a vault is open (best-effort history, like the apps).
    Generate {
        /// password | passphrase
        #[arg(default_value = "password")]
        kind: String,
        /// Password length.
        #[arg(long)]
        length: Option<usize>,
        /// Passphrase word count.
        #[arg(long)]
        words: Option<usize>,
        /// Exclude uppercase letters.
        #[arg(long)]
        no_upper: bool,
        /// Exclude digits.
        #[arg(long)]
        no_numbers: bool,
        /// Exclude symbols.
        #[arg(long)]
        no_symbols: bool,
        /// Passphrase separator.
        #[arg(long, default_value = "-")]
        sep: String,
    },

    /// Show the live TOTP code for an entry (id or name substring).
    Totp {
        /// Entry id, or a case-insensitive name substring.
        target: String,
    },

    /// Generate an SSH keypair daemon-side. The private key is printed
    /// once; store it with --store or keep it out of the vault.
    SshKeygen {
        /// ed25519 | ecdsa256
        #[arg(long, default_value = "ed25519")]
        key_type: String,
        #[arg(long, default_value = "")]
        comment: String,
        /// Also store as a new SSH-key entry with this name.
        #[arg(long)]
        store: Option<String>,
    },

    /// Git provider accounts: connect, status, repositories.
    Provider {
        #[command(subcommand)]
        action: ProviderAction,
    },

    /// Rotate this vault's root key. Other enrolled devices adopt the
    /// rekey on their next unlock; the recovery phrase rotates too.
    RotateRoot,

    /// Space collections: list, create, assign entries, manage grants.
    Collections {
        #[command(subcommand)]
        action: CollectionAction,
    },

    /// Space members and their pending asks (joins, access requests).
    Members {
        #[command(subcommand)]
        action: MemberAction,
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
        /// Format: baluard-encrypted, baluard, bw-json, bw-csv, chrome-csv, firefox-csv, lastpass-csv, 1password-1pux, 1password-csv, keepass-xml.
        format: String,
        /// Path to import file.
        path: String,
    },

    /// Export vault entries.
    Export {
        /// Format: baluard (full backup, default), baluard-encrypted (with --encrypted), bw-json, bw-csv.
        #[arg(short, long, default_value = "baluard")]
        format: String,
        /// Output file path.
        path: String,
        /// Encrypt the backup with a passphrase (.bldbak, restorable into any Baluard vault).
        #[arg(long)]
        encrypted: bool,
        /// Generate a 6-word backup passphrase and print it once (with --encrypted).
        #[arg(long)]
        generate: bool,
        /// Overwrite an existing file without asking (scripting/E2E only).
        #[arg(long)]
        force: bool,
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

    /// Manage vaults (list, switch, prune stale).
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
        /// Skip the typed 'enroll' confirmation (scripting/E2E only).
        #[arg(long)]
        yes: bool,
    },
    /// Revoke a device by UUID.
    Revoke {
        /// Device UUID to revoke.
        device_id: String,
    },
}

#[derive(Subcommand)]
enum VaultAction {
    /// Register an already-existing vault directory (e.g. moved from
    /// another machine or restored from a backup) so it appears in the
    /// app again. Non-destructive: no key material is touched. If this
    /// device was never enrolled into the vault, run
    /// `baluard enroll-with-phrase` afterwards.
    Add {
        /// Path to the vault directory (must contain a .baluard marker).
        path: String,
        /// Override the registry slug (default: the vault's marker slug).
        #[arg(long)]
        slug: Option<String>,
    },
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
    /// Remove registry entries whose vault directory no longer exists on
    /// disk (e.g. deleted or never-restored `/tmp` test vaults). The vault
    /// files are not touched; only stale registry pointers are dropped.
    /// If the active vault is pruned, the first remaining slug (alphabetical)
    /// is promoted so the daemon still auto-selects on next launch.
    Prune {
        /// Show what would be removed without changing the registry.
        #[arg(long)]
        dry_run: bool,
    },
    /// Detach a vault from Baluard: drop the registry entry so the vault
    /// no longer appears in the app. Without `--delete-from-disk` the
    /// vault directory is left on disk and can be re-attached via
    /// `baluard open <path>`. Works pre-unlock (the vault does not need to
    /// be unlocked or even open in the daemon).
    Detach {
        /// Vault slug.
        slug: String,
        /// Also remove the vault directory from disk. Requires typing the
        /// slug a second time as confirmation. Permanent — no recovery.
        #[arg(long)]
        delete_from_disk: bool,
    },
    /// Copy selected entries from one unlocked vault into another
    /// (family-spaces founding flow: bring items from a personal vault
    /// into a new family vault). Both vaults must be unlocked in the
    /// daemon. The target assigns fresh ids and re-encrypts under its
    /// own keys; filing follows the target's defaults. Attachments are
    /// not copied and are reported.
    CopyItems {
        /// Vault slug to copy FROM.
        source: String,
        /// Vault slug to copy INTO.
        target: String,
        /// Cipher UUID to copy (repeat for several).
        #[arg(long = "cipher")]
        ciphers: Vec<String>,
        /// Copy every entry in the source vault.
        #[arg(long)]
        all: bool,
    },
    /// Re-point a registered vault's sync origin to a new URL without
    /// announcing (S3-8 power-user escape hatch; the admin migrate in
    /// the app is the normal path and every device follows it
    /// automatically). Keyless: no unlock, no key material touched.
    Repoint {
        /// Vault slug.
        slug: String,
        /// New sync address (https://, ssh://, or git@).
        url: String,
    },
    RecoverKit {
        /// Vault slug (the fresh clone of the Space).
        slug: String,
        /// Device name for the recovered device (prompted when omitted).
        device_name: Option<String>,
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
    /// Show space policy knobs (sharing settings).
    SpaceGet,
    /// Set a space policy knob (key=value).
    SpaceSet {
        /// Knob key and value (e.g., guest_enabled=true).
        kv: String,
    },
}

#[derive(Subcommand)]
enum TrashAction {
    /// List entries in the trash.
    List,
    /// Restore a trashed entry.
    Restore {
        /// Cipher ID.
        id: String,
    },
    /// Permanently delete trash older than N days (0 = everything).
    Purge {
        /// Age threshold in days.
        #[arg(long, default_value_t = 30)]
        days: u32,
    },
}

#[derive(Subcommand)]
enum ProviderAction {
    /// Connect an account. Device flow where the provider supports it,
    /// otherwise connect with a personal access token (--pat).
    Connect {
        /// github | gitlab | codeberg
        provider: String,
        /// Connect with a personal access token instead of a flow.
        #[arg(long)]
        pat: bool,
        /// Override the instance URL (self-hosted).
        #[arg(long)]
        instance: Option<String>,
        /// Override the OAuth client id.
        #[arg(long)]
        client_id: Option<String>,
    },
    /// Show every provider's connection state.
    List,
    /// Validate one account's stored token against the provider.
    Status { provider: String },
    /// Disconnect and revoke the stored token.
    Disconnect { provider: String },
    /// List the account's repositories.
    Repos { provider: String },
    /// List repositories that carry a Baluard marker.
    VaultRepos { provider: String },
    /// Create a private repository (name normalized, baluard- prefixed).
    CreateRepo { provider: String, name: String },
}

#[derive(Subcommand)]
enum CollectionAction {
    /// List collections with their grants.
    List,
    /// Create a collection.
    Create { name: String },
    /// Assign an entry to a collection; omit --to to unassign.
    Assign {
        /// Entry id, or a case-insensitive name substring.
        cipher: String,
        /// Collection id or exact name.
        #[arg(long)]
        to: Option<String>,
    },
    /// Grant a member or group access to a collection.
    Grant {
        /// Collection id or exact name.
        collection: String,
        /// member | group
        #[arg(long)]
        kind: String,
        #[arg(long)]
        target_id: String,
        /// read | write | manage
        #[arg(long, default_value = "read")]
        access: String,
        /// Expiry as unix seconds.
        #[arg(long)]
        expires_at: Option<u64>,
    },
    /// Revoke a member or group's access to a collection.
    Revoke {
        /// Collection id or exact name.
        collection: String,
        /// member | group
        #[arg(long)]
        kind: String,
        #[arg(long)]
        target_id: String,
    },
}

#[derive(Subcommand)]
enum MemberAction {
    /// List members with roles and trust.
    List,
    /// Mint a member invite. The returned code travels to the joiner
    /// out-of-band; pass --username so the joiner's clone seat can be
    /// granted on the connected provider.
    Invite {
        /// editor or viewer (admin requires a verified contact card on
        /// the joiner's side; the owner seat cannot be invited).
        #[arg(long, default_value = "editor")]
        role: String,
        /// Joiner's provider username (grant clone access).
        #[arg(long)]
        username: Option<String>,
    },
    /// Stage a joiner's out-of-band intro reply into the join queue.
    Stage {
        /// The intro code the joiner sent you.
        code: String,
    },
    /// Change a member's role (admin or owner). Keywraps follow the
    /// role: demotion strips the member's Root-Key keywraps, promotion
    /// mints them (admin rank needs a verified contact on the member).
    SetRole {
        /// Member id from `baluard members list`.
        member_id: String,
        /// admin, editor, or viewer.
        role: String,
    },
    /// List pending asks: join confirmations and access requests.
    Requests,
    /// Confirm a pending join (the member becomes a space member).
    ApproveJoin {
        /// Join request id from `baluard members requests`.
        req_id: String,
    },
    /// Drop a pending join.
    DenyJoin {
        /// Join request id from `baluard members requests`.
        req_id: String,
    },
    /// Approve a collection access ask. Ids come from
    /// `baluard members requests`.
    Approve {
        request_id: String,
        requester_member_id: String,
    },
    /// Deny a collection access ask.
    Deny {
        request_id: String,
        requester_member_id: String,
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
    /// Commit pending local changes (no network). The signer is this
    /// device's key; peers verify the commit on their next pull.
    Commit,
    /// Pull remote changes.
    Pull,
    /// Revoke a bad commit via an append-only signed manifest (works
    /// under branch protection; never rewrites history).
    Revoke {
        /// Commit hash to revoke.
        commit: String,
        /// Why this commit is being revoked.
        #[arg(short, long)]
        reason: String,
    },
    /// Show sync status.
    Status,
    /// Show commit log.
    Log {
        /// Number of commits to show.
        #[arg(long, default_value = "10")]
        limit: usize,
    },
    /// Clone a remote vault from a provider (daemon only).
    Clone {
        /// Provider: github, gitlab, or codeberg.
        provider: String,
        /// Repository full name (e.g. user/vault).
        repo: String,
        /// Override the local slug (default: repo name).
        #[arg(long)]
        slug: Option<String>,
    },
    /// Clone a vault from a plain git URL (daemon only). Auth comes from
    /// your own git setup (ssh-agent for ssh://, a connected provider
    /// token or BALUARD_GIT_TOKEN for https) — Baluard stores nothing.
    CloneUrl {
        /// Git clone URL (https://, ssh://, or git@host:path).
        url: String,
        /// Override the local slug (default: last URL path segment).
        #[arg(long)]
        slug: Option<String>,
        /// Hint the provider whose stored token should authenticate an
        /// https clone (github, gitlab, or codeberg).
        #[arg(long)]
        provider: Option<String>,
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
                    commands::warn_argv_secret("--password");
                    Some(p)
                }
                None => {
                    let pw = commands::prompt_password("Password: ")?;
                    if pw.is_empty() { None } else { Some(pw) }
                }
            };
            if totp_uri.is_some() {
                commands::warn_argv_secret("--totp-uri");
            }
            Ok(CipherInput {
                name,
                folder_id: parse_folder_id(folder.as_ref())?,
                collection_id: None,
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
                    favicon: None,
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
        } => {
            if number.is_some() {
                commands::warn_argv_secret("--number");
            }
            if code.is_some() {
                commands::warn_argv_secret("--code");
            }
            Ok(CipherInput {
                name,
                folder_id: parse_folder_id(folder.as_ref())?,
                collection_id: None,
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
            })
        }
        CipherAddCommand::SecureNote {
            name,
            notes,
            folder,
            tags,
            favorite,
        } => Ok(CipherInput {
            name,
            folder_id: parse_folder_id(folder.as_ref())?,
            collection_id: None,
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
            collection_id: None,
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
        } => {
            if private_key.is_some() {
                commands::warn_argv_secret("--private-key");
            }
            Ok(CipherInput {
                name,
                folder_id: parse_folder_id(folder.as_ref())?,
                collection_id: None,
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
            })
        }
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
        } => {
            if account_number.is_some() {
                commands::warn_argv_secret("--account-number");
            }
            if routing_number.is_some() {
                commands::warn_argv_secret("--routing-number");
            }
            if branch_number.is_some() {
                commands::warn_argv_secret("--branch-number");
            }
            if swift_code.is_some() {
                commands::warn_argv_secret("--swift-code");
            }
            if iban.is_some() {
                commands::warn_argv_secret("--iban");
            }
            Ok(CipherInput {
                name,
                folder_id: parse_folder_id(folder.as_ref())?,
                collection_id: None,
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
            })
        }
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
            collection_id: None,
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
            collection_id: None,
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
    // Load `.env` from cwd (and parents) into process env at startup.
    // `dotenvy` returns `Err` if no `.env` is present — the expected case
    // in CI / production installs. Real env vars take precedence over the
    // file. The `.env` file is gitignored; `.env.example` documents the
    // recognised variables.
    let _ = dotenvy::dotenv();

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
            family,
            json,
        } => commands::handle_init(
            &cli.vault_path,
            &profile,
            name,
            slug,
            theme,
            lang,
            auto_lock,
            family,
            json,
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
            SyncAction::Commit => commands::handle_sync_commit(&vault_path),
            SyncAction::Pull => {
                commands::handle_sync_pull(mode, &vault_path, cli.socket.as_deref())
            }
            SyncAction::Revoke { commit, reason } => commands::handle_sync_revoke(
                mode,
                &vault_path,
                cli.socket.as_deref(),
                &commit,
                &reason,
            ),
            SyncAction::Status => {
                commands::handle_sync_status(mode, &vault_path, cli.socket.as_deref())
            }
            SyncAction::Log { limit } => {
                commands::handle_sync_log(mode, &vault_path, cli.socket.as_deref(), limit)
            }
            SyncAction::Clone {
                provider,
                repo,
                slug,
            } => commands::handle_sync_clone(
                mode,
                &vault_path,
                cli.socket.as_deref(),
                &provider,
                &repo,
                slug.as_deref(),
            ),
            SyncAction::CloneUrl {
                url,
                slug,
                provider,
            } => commands::handle_sync_clone_url(
                mode,
                cli.socket.as_deref(),
                &url,
                slug.as_deref(),
                provider.as_deref(),
            ),
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
            DeviceCommands::EnrollWithPhrase { phrase, yes } => {
                commands::handle_enroll_with_phrase(
                    mode,
                    &vault_path,
                    phrase.as_deref(),
                    yes,
                    cli.socket.as_deref(),
                )
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
            SettingsAction::SpaceGet => {
                commands::handle_space_settings_get(mode, cli.socket.as_deref())
            }
            SettingsAction::SpaceSet { kv } => {
                commands::handle_space_settings_set(mode, cli.socket.as_deref(), &kv)
            }
        },

        Commands::Search { query, all, vault } => {
            commands::handle_search(mode, cli.socket.as_deref(), &query, all, vault.as_deref())
        }

        Commands::Generate {
            kind,
            length,
            words,
            no_upper,
            no_numbers,
            no_symbols,
            sep,
        } => commands::handle_generate(
            mode,
            cli.socket.as_deref(),
            &kind,
            length,
            words,
            no_upper,
            no_numbers,
            no_symbols,
            &sep,
        ),

        Commands::Totp { target } => commands::handle_totp(mode, cli.socket.as_deref(), &target),

        Commands::SshKeygen {
            key_type,
            comment,
            store,
        } => commands::handle_ssh_keygen(
            mode,
            cli.socket.as_deref(),
            &key_type,
            &comment,
            store.as_deref(),
        ),

        Commands::Provider { action } => {
            commands::handle_provider(mode, cli.socket.as_deref(), &action)
        }

        Commands::RotateRoot => commands::handle_rotate_root(mode, cli.socket.as_deref()),

        Commands::Collections { action } => {
            commands::handle_collections(mode, cli.socket.as_deref(), &action)
        }

        Commands::Members { action } => {
            commands::handle_members(mode, cli.socket.as_deref(), &action)
        }

        Commands::Trash { action } => match action {
            TrashAction::List => {
                commands::handle_trash_list(mode, &vault_path, cli.socket.as_deref())
            }
            TrashAction::Restore { id } => {
                commands::handle_trash_restore(mode, &vault_path, cli.socket.as_deref(), &id)
            }
            TrashAction::Purge { days } => {
                commands::handle_trash_purge(mode, &vault_path, cli.socket.as_deref(), days)
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

        Commands::Export {
            format,
            path,
            encrypted,
            generate,
            force,
        } => commands::handle_export(
            cli.socket.as_deref(),
            &format,
            &path,
            encrypted,
            generate,
            force,
        ),

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
