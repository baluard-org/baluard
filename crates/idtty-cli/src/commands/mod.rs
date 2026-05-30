//! CLI command implementations.
//!
//! Each vault command supports two modes:
//! - Daemon: routes through idtty-daemon via Unix socket (default)
//! - Direct: calls idtty-core directly (fallback, --direct flag)

use crate::ConnectMode;
use crate::client;

use std::path::Path;

use idtty_core::types::{CipherInput, KdfProfile};
use idtty_core::vault::handle::{CipherRead, VaultHandle};
use zeroize::Zeroize;

// ── Init (always direct) ──

pub fn handle_init(vault_path: &str, profile_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let profile = parse_profile(profile_str)?;

    let password = zeroize::Zeroizing::new(prompt_password("Master password: ")?);
    let confirm = zeroize::Zeroizing::new(prompt_password("Confirm password: ")?);

    if *password != *confirm {
        eprintln!("error: passwords do not match");
        std::process::exit(1);
    }

    if password.len() < 8 {
        eprintln!("warning: password is shorter than recommended (8+ characters)");
    }

    println!("Creating vault...");
    let (_handle, secrets) = idtty_core::vault::creation::VaultCreator::new(vault_path, &password, "this-device")
        .kdf_profile(profile)
        .execute()?;

    println!();
    println!("Vault created successfully.");
    println!("  Vault ID: {}", secrets.vault_id);
    println!("  Epoch:    1");
    println!("  Device:   {}", secrets.device_id);
    println!();
    println!("=== RECOVERY PHRASE (write this down!) ===");
    println!("{}", secrets.recovery_phrase.phrase());
    println!("=== END RECOVERY PHRASE ===");
    println!();
    println!(
        "Trust fingerprint: {}",
        hex::encode(secrets.trust_fingerprint)
    );

    println!("Vault files written to: {}", vault_path);
    Ok(())
}

// ── Unlock ──

pub fn handle_unlock(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => unlock_daemon(socket),
        ConnectMode::Direct => unlock_direct(vault_path),
    }
}

fn unlock_daemon(socket: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    // Open vault in daemon
    let resp = client::request_to("vault.open", "", socket)?;
    if !resp.success {
        return Err(resp.error_message.into());
    }

    // Prompt and unlock
    let mut password = prompt_password("Master password: ")?;
    let resp = client::request_to("vault.unlock", &password, socket)?;
    password.zeroize();
    if !resp.success {
        return Err(resp.error_message.into());
    }

    // Parse info from response
    let info: serde_json::Value = serde_json::from_str(&resp.payload)?;
    println!("Vault unlocked (daemon).");
    println!("  Vault ID:  {}", info["vault_id"]);
    println!("  Ciphers:   {}", info["cipher_count"]);
    Ok(())
}

fn unlock_direct(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(vault_path);
    let mut handle = VaultHandle::open(path)?;

    if handle.is_unlocked() {
        println!("Vault is already unlocked.");
        return Ok(());
    }

    let mut password = prompt_password("Master password: ")?;
    handle.unlock(&password)?;
    password.zeroize();

    println!("Vault unlocked (direct).");
    println!("  Vault ID:  {}", handle.vault_id);
    println!("  Device:    {}", handle.device_id);
    println!("  Ciphers:   {}", handle.list_cipher_ids()?.len());
    println!();
    println!("(Direct mode: vault locks on process exit. Use daemon mode for persistence.)");
    Ok(())
}

// ── Lock ──

pub fn handle_lock(
    mode: ConnectMode,
    socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            let resp = client::request_to("vault.lock", "", socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            client::clear_session_token(socket);
            println!("Vault locked. Keys zeroized.");
            Ok(())
        }
        ConnectMode::Direct => {
            return Err(
                "lock requires daemon mode (no vault held in memory in direct mode)".into(),
            );
        }
    }
}

// ── Add cipher ──

pub fn handle_add(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    name: String,
    username: Option<String>,
    password: Option<String>,
    uri: Option<String>,
    notes: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cipher_password = match password {
        Some(p) => {
            eprintln!(
                "warning: --password exposes secret in process list. Use interactive prompt instead."
            );
            zeroize::Zeroizing::new(p)
        }
        None => zeroize::Zeroizing::new(prompt_password("Password: ")?),
    };

    let input = CipherInput {
        name,
        folder_id: None,
        username,
        password: Some((*cipher_password).clone()),
        uris: uri.map(|u| vec![u]).unwrap_or_default(),
        notes,
        totp_uri: None,
        custom_fields: vec![],
    };

    match mode {
        ConnectMode::Daemon => {
            ensure_unlocked_daemon(socket)?;
            let payload = serde_json::to_string(&input)?;
            let resp = client::request_to("vault.add", &payload, socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("Cipher added: {}", resp.payload);
            Ok(())
        }
        ConnectMode::Direct => {
            let mp = zeroize::Zeroizing::new(prompt_password("Master password: ")?);
            let path = Path::new(vault_path);
            let mut handle = VaultHandle::open(path)?;
            handle.unlock(&mp)?;
            let cipher_id = handle.add_cipher(&input)?;
            println!("Cipher added: {cipher_id}");
            Ok(())
        }
    }
}

// ── Get cipher ──

pub fn handle_get(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    id_or_name: &str,
    decrypt: bool,
    output: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let cipher_id = match uuid::Uuid::parse_str(id_or_name) {
        Ok(id) => id,
        Err(_) => {
            eprintln!("error: searching by name not yet implemented, use cipher UUID");
            std::process::exit(1);
        }
    };

    match mode {
        ConnectMode::Daemon => {
            // Only unlock if decryption is needed (metadata reads work on locked vaults)
            if decrypt {
                ensure_unlocked_daemon(socket)?;
            }
            let payload =
                serde_json::json!({"id": cipher_id.to_string(), "decrypt": decrypt}).to_string();
            let resp = client::request_to("vault.get", &payload, socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }

            let c: serde_json::Value = serde_json::from_str(&resp.payload)?;
            match output {
                "json" => println!("{c}"),
                "text" => {
                    println!("Cipher: {}", c["id"]);
                    println!("  Name:      {}", c["name"]);
                    if !c["username"].is_null() {
                        println!("  Username:  {}", c["username"]);
                    }
                    if !c["password"].is_null() {
                        println!("  Password:  {}", c["password"]);
                    }
                    if let Some(uris) = c["uris"].as_array() {
                        for u in uris {
                            println!("  URI:       {u}");
                        }
                    }
                    if !c["notes"].is_null() {
                        println!("  Notes:     {}", c["notes"]);
                    }
                    if !c["totp"].is_null() {
                        println!("  TOTP:      {}", c["totp"]);
                    }
                    println!("  Tier:      {}", c["tier"]);
                    println!("  Epoch:     {}", c["epoch"]);
                    println!("  Seq:       {}", c["seq"]);
                }
                _ => {
                    println!("Cipher: {}", c["id"]);
                    println!("  Name:      {}", c["name"]);
                    if !c["username"].is_null() {
                        println!("  Username:  {}", c["username"]);
                    }
                    println!("  Password:  ***");
                    if let Some(uris) = c["uris"].as_array() {
                        for u in uris {
                            println!("  URI:       {u}");
                        }
                    }
                    if !c["notes"].is_null() {
                        println!("  Notes:     ***");
                    }
                    if !c["totp"].is_null() {
                        println!("  TOTP:      ***");
                    }
                    println!("  Use --output=text to reveal secrets");
                }
            }
            Ok(())
        }
        ConnectMode::Direct => {
            let path = Path::new(vault_path);
            let mut handle = VaultHandle::open(path)?;

            if decrypt {
                let mp = zeroize::Zeroizing::new(prompt_password("Master password: ")?);
                handle.unlock(&mp)?;
            }

            match handle.get_cipher(cipher_id)? {
                CipherRead::Decrypted(c) => match output {
                    "json" => {
                        let json = serde_json::json!({
                            "id": c.id.to_string(),
                            "name": c.name,
                            "username": c.username,
                            "password": c.password,
                            "uris": c.uris,
                            "notes": c.notes,
                            "totp": c.totp_uri,
                            "tier": format!("{:?}", c.tier),
                            "epoch": c.key_epoch,
                            "seq": c.update_seq,
                        });
                        println!("{json}");
                    }
                    "text" => {
                        println!("Cipher: {}", c.id);
                        println!("  Name:      {}", c.name);
                        if let Some(ref u) = c.username {
                            println!("  Username:  {u}");
                        }
                        if let Some(ref p) = c.password {
                            println!("  Password:  {p}");
                        }
                        for u in &c.uris {
                            println!("  URI:       {u}");
                        }
                        if let Some(ref n) = c.notes {
                            println!("  Notes:     {n}");
                        }
                        if let Some(ref t) = c.totp_uri {
                            println!("  TOTP:      {t}");
                        }
                        println!("  Tier:      {:?}", c.tier);
                        println!("  Epoch:     {}", c.key_epoch);
                        println!("  Seq:       {}", c.update_seq);
                    }
                    _ => {
                        println!("Cipher: {}", c.id);
                        println!("  Name:      {}", c.name);
                        if let Some(ref u) = c.username {
                            println!("  Username:  {u}");
                        }
                        println!("  Password:  ***");
                        for u in &c.uris {
                            println!("  URI:       {u}");
                        }
                        if c.notes.is_some() {
                            println!("  Notes:     ***");
                        }
                        if c.totp_uri.is_some() {
                            println!("  TOTP:      ***");
                        }
                        println!("  Use --output=text to reveal secrets");
                    }
                },
                CipherRead::Locked(info) => {
                    println!("Cipher: {}", info.id);
                    println!("  Epoch:          {}", info.key_epoch);
                    println!("  Seq:            {}", info.update_seq);
                    println!("  Tier:           {:?}", info.tier);
                    println!("  Ciphertext:     {} bytes", info.ciphertext_len);
                    if !decrypt {
                        println!();
                        println!("(Use --decrypt to view cipher content)");
                    }
                }
            }
            Ok(())
        }
    }
}

// ── List ciphers ──

pub fn handle_list(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            let resp = client::request_to("vault.list", "", socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            let data: serde_json::Value = serde_json::from_str(&resp.payload)?;
            let ids = data["cipher_ids"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if ids.is_empty() {
                println!("No ciphers found.");
            } else {
                for id in &ids {
                    println!("{id}");
                }
                println!();
                println!("{} cipher(s)", ids.len());
            }
            Ok(())
        }
        ConnectMode::Direct => list_direct(vault_path),
    }
}

fn list_direct(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(vault_path);
    let handle = VaultHandle::open(path)?;
    let ids = handle.list_cipher_ids()?;

    if ids.is_empty() {
        println!("No ciphers found.");
        return Ok(());
    }

    for id in &ids {
        println!("{id}");
    }
    println!();
    println!("{} cipher(s)", ids.len());
    Ok(())
}

// ── Delete cipher ──

pub fn handle_delete(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let cipher_id = uuid::Uuid::parse_str(id).map_err(|_| "invalid UUID")?;

    match mode {
        ConnectMode::Daemon => {
            let resp = client::request_to("vault.delete", &cipher_id.to_string(), socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("Cipher deleted: {cipher_id}");
            Ok(())
        }
        ConnectMode::Direct => {
            let path = Path::new(vault_path);
            let handle = VaultHandle::open(path)?;
            handle.delete_cipher(cipher_id)?;
            println!("Cipher deleted: {cipher_id}");
            Ok(())
        }
    }
}

// ── Devices (direct only, not yet routed through daemon) ──

pub fn handle_devices(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            // Open vault in daemon first if needed
            let open_resp = client::request_to("vault.open", "", socket)?;
            if !open_resp.success {
                return Err(open_resp.error_message.into());
            }
            let resp = client::request_to("vault.devices", "", socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            let data: serde_json::Value = serde_json::from_str(&resp.payload)?;
            let devices = data["devices"].as_array().cloned().unwrap_or_default();
            println!("Enrolled devices:");
            for d in &devices {
                println!("  {} ({})", d["name"], d["device_id"]);
                println!("    Encryption key: {}", d["encryption_key"]);
                println!("    Signing key:    {}", d["signing_key"]);
                println!("    Enrolled at:    {}", d["enrolled_at"]);
            }
            println!();
            println!("Total: {} device(s)", data["total"]);
            Ok(())
        }
        ConnectMode::Direct => {
            let path = Path::new(vault_path);
            let handle = VaultHandle::open(path)?;
            println!("Enrolled devices:");
            for entry in handle.registry.devices.values() {
                println!("  {} ({})", entry.name, entry.device_id);
                println!(
                    "    Encryption key: {}...{}",
                    &entry.encryption_public_key[..8],
                    &entry.encryption_public_key[56..]
                );
                println!(
                    "    Signing key:    {}...{}",
                    &entry.signing_public_key[..8],
                    &entry.signing_public_key[56..]
                );
                println!("    Enrolled at:    {}", entry.enrolled_at);
            }
            println!();
            println!("Total: {} device(s)", handle.registry.count());
            Ok(())
        }
    }
}

// ── Sync (daemon-first with direct fallback) ──

pub fn handle_sync_init(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            let resp = client::request_to("sync.init", "", socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("{}", resp.payload);
            Ok(())
        }
        ConnectMode::Direct => sync_init_direct(vault_path),
    }
}

pub fn handle_sync_remote(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            let resp = client::request_to("sync.remote", url, socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("{}", resp.payload);
            Ok(())
        }
        ConnectMode::Direct => sync_remote_direct(vault_path, url),
    }
}

pub fn handle_sync_push(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            let resp = client::request_to("sync.push", "", socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("{}", resp.payload);
            Ok(())
        }
        ConnectMode::Direct => sync_push_direct(vault_path),
    }
}

pub fn handle_sync_pull(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            let resp = client::request_to("sync.pull", "", socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("{}", resp.payload);
            Ok(())
        }
        ConnectMode::Direct => sync_pull_direct(vault_path),
    }
}

pub fn handle_sync_status(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            let resp = client::request_to("sync.status", "", socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("{}", resp.payload);
            Ok(())
        }
        ConnectMode::Direct => sync_status_direct(vault_path),
    }
}

pub fn handle_sync_log(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    limit: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            let resp = client::request_to("sync.log", &limit.to_string(), socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("{}", resp.payload);
            Ok(())
        }
        ConnectMode::Direct => sync_log_direct(vault_path, limit),
    }
}

// ── Sync direct implementations ──

#[cfg(feature = "git-sync")]
fn sync_init_direct(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(vault_path);
    let engine = idtty_core::sync::engine::SyncEngine::new(path, &device_name(vault_path));
    let repo = engine.init_repo()?;
    println!("Git repo initialized at {}", path.display());
    let log = engine.log(&repo, 1)?;
    if let Some(c) = log.first() {
        println!("Initial commit: {}", &c.id[..7]);
    }
    Ok(())
}

#[cfg(feature = "git-sync")]
fn sync_remote_direct(vault_path: &str, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(vault_path);
    let engine = idtty_core::sync::engine::SyncEngine::new(path, &device_name(vault_path));
    let repo = engine.open_repo()?;
    engine.add_remote(&repo, "origin", url)?;
    println!("Remote 'origin' set to: {url}");
    Ok(())
}

#[cfg(feature = "git-sync")]
fn sync_push_direct(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(vault_path);
    let engine = idtty_core::sync::engine::SyncEngine::new(path, &device_name(vault_path));
    let repo = engine.open_repo()?;
    let status = engine.status(&repo)?;
    if status.is_dirty() {
        engine.commit_all(&repo, "")?;
        println!("Committed pending changes.");
    }
    engine.push(&repo, "origin")?;
    println!("Pushed to origin.");
    Ok(())
}

#[cfg(feature = "git-sync")]
fn sync_pull_direct(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(vault_path);
    let engine = idtty_core::sync::engine::SyncEngine::new(path, &device_name(vault_path));
    engine.recover_state()?;
    let repo = engine.open_repo()?;
    let result = engine.pull(&repo, "origin")?;
    match result {
        idtty_core::sync::engine::PullResult::AlreadyUpToDate => println!("Already up to date."),
        idtty_core::sync::engine::PullResult::FastForward => println!("Fast-forwarded to latest."),
        idtty_core::sync::engine::PullResult::Merged => println!("Merged remote changes."),
        idtty_core::sync::engine::PullResult::Conflict { files, .. } => {
            let file_list = files.join(", ");
            return Err(format!("merge conflict in {file_list}. Resolution required.").into());
        }
    }
    Ok(())
}

#[cfg(feature = "git-sync")]
fn sync_status_direct(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(vault_path);
    let engine = idtty_core::sync::engine::SyncEngine::new(path, &device_name(vault_path));
    let repo = engine.open_repo()?;
    let status = engine.status(&repo)?;
    if status.is_dirty() {
        println!(
            "Working tree: dirty ({} staged, {} unstaged)",
            status.staged, status.unstaged
        );
    } else {
        println!("Working tree: clean");
    }
    let log = engine.log(&repo, 5)?;
    if !log.is_empty() {
        println!("\nRecent commits:");
        for c in &log {
            let ts = chrono::DateTime::from_timestamp(c.time, 0)
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_default();
            println!(
                "  {} {} <{}>",
                &c.id[..7.min(c.id.len())],
                c.message.trim(),
                ts
            );
        }
    }
    Ok(())
}

#[cfg(feature = "git-sync")]
fn sync_log_direct(vault_path: &str, limit: usize) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(vault_path);
    let engine = idtty_core::sync::engine::SyncEngine::new(path, &device_name(vault_path));
    let repo = engine.open_repo()?;
    let log = engine.log(&repo, limit)?;
    if log.is_empty() {
        println!("No commits.");
        return Ok(());
    }
    for c in &log {
        let ts = chrono::DateTime::from_timestamp(c.time, 0)
            .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_default();
        println!("{} {} {}", &c.id[..7.min(c.id.len())], ts, c.message.trim());
    }
    println!("\n{} commit(s)", log.len());
    Ok(())
}

// Fallbacks when git-sync feature is disabled
#[cfg(not(feature = "git-sync"))]
fn sync_init_direct(_: &str) -> Result<(), Box<dyn std::error::Error>> {
    Err("git-sync feature not enabled".into())
}
#[cfg(not(feature = "git-sync"))]
fn sync_remote_direct(_: &str, _u: &str) -> Result<(), Box<dyn std::error::Error>> {
    Err("git-sync feature not enabled".into())
}
#[cfg(not(feature = "git-sync"))]
fn sync_push_direct(_: &str) -> Result<(), Box<dyn std::error::Error>> {
    Err("git-sync feature not enabled".into())
}
#[cfg(not(feature = "git-sync"))]
fn sync_pull_direct(_: &str) -> Result<(), Box<dyn std::error::Error>> {
    Err("git-sync feature not enabled".into())
}
#[cfg(not(feature = "git-sync"))]
fn sync_status_direct(_: &str) -> Result<(), Box<dyn std::error::Error>> {
    Err("git-sync feature not enabled".into())
}
#[cfg(not(feature = "git-sync"))]
fn sync_log_direct(_: &str, _n: usize) -> Result<(), Box<dyn std::error::Error>> {
    Err("git-sync feature not enabled".into())
}

// ── Helpers ──

/// Ensure vault is opened and unlocked in the daemon.
/// Prompts for master password if needed. Zeroizes password after use.
fn ensure_unlocked_daemon(socket: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    // Check current state
    let info_resp = client::request_to("vault.info", "", socket)?;
    if info_resp.success {
        let info: serde_json::Value = serde_json::from_str(&info_resp.payload)?;
        if info["unlocked"].as_bool().unwrap_or(false) {
            return Ok(()); // Already unlocked
        }
        // Vault is open but locked — skip redundant vault.open
    } else {
        // Vault not opened yet
        let open_resp = client::request_to("vault.open", "", socket)?;
        if !open_resp.success {
            return Err(format!("Failed to open vault: {}", open_resp.error_message).into());
        }
    }

    let mut password = prompt_password("Master password: ")?;
    let unlock_resp = client::request_to("vault.unlock", &password, socket)?;
    password.zeroize();
    if !unlock_resp.success {
        return Err(format!("Unlock failed: {}", unlock_resp.error_message).into());
    }
    Ok(())
}

fn parse_profile(s: &str) -> Result<KdfProfile, Box<dyn std::error::Error>> {
    match s {
        "mobile-low" => Ok(KdfProfile::MobileLow),
        "desktop-std" => Ok(KdfProfile::DesktopStd),
        "desktop-high" => Ok(KdfProfile::DesktopHigh),
        _ => {
            Err(format!("unknown profile: {s}. Use: mobile-low, desktop-std, desktop-high").into())
        }
    }
}

fn device_name(vault_path: &str) -> String {
    let path = Path::new(vault_path);
    let reg_path = path.join("meta/devices.json");
    if reg_path.exists() {
        if let Ok(data) = std::fs::read_to_string(&reg_path) {
            let reg: std::result::Result<idtty_core::devices::DeviceRegistry, _> =
                serde_json::from_str(&data);
            if let Ok(reg) = reg {
                if let Some(entry) = reg.devices.values().next() {
                    return entry.name.clone();
                }
            }
        }
    }
    "idtty-device".into()
}

fn prompt_password(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    match rpassword::prompt_password(prompt) {
        Ok(pw) => Ok(pw),
        Err(_) => {
            use std::io::{BufRead, Write};
            eprint!("{prompt}");
            std::io::stderr().flush()?;
            let mut buf = String::new();
            std::io::stdin().lock().read_line(&mut buf)?;
            Ok(buf.trim().to_string())
        }
    }
}
