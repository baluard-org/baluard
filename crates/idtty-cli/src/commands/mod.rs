//! CLI command implementations.
//!
//! Each vault command supports two modes:
//! - Daemon: routes through idtty-daemon via Unix socket (default)
//! - Direct: calls idtty-core directly (fallback, --direct flag)

use crate::ConnectMode;
use crate::client;

use std::path::Path;

use idtty_core::types::{CipherInput, CipherKind, KdfProfile, LoginData};
use idtty_core::vault::handle::{CipherRead, VaultHandle};
use zeroize::Zeroize;
use base64::Engine;

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
    folder_id: Option<&str>,
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

    let folder_uuid = folder_id
        .map(|id| uuid::Uuid::parse_str(id))
        .transpose()
        .map_err(|e| Box::<dyn std::error::Error>::from(format!("Invalid folder UUID: {e}")))?;

    let input = CipherInput {
        name,
        folder_id: folder_uuid,
        kind: CipherKind::Login(LoginData {
            username,
            password: Some((*cipher_password).clone()),
            uris: uri.map(|u| vec![idtty_core::types::LoginUri::new(u)]).unwrap_or_default(),
            totp_uri: None,
            autofill_on_page_load: false,
            password_revision_date: None,
        }),
        favorite: false,
        notes,
        custom_fields: vec![],
        created_at: None,
        password_history: vec![],
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
                            println!("  URI:       {}", u["uri"]);
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
                            println!("  URI:       {}", u["uri"]);
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
                        let mut json_obj = serde_json::json!({
                            "id": c.id.to_string(),
                            "name": c.name,
                            "type": serde_json::to_value(c.kind.cipher_type()).unwrap_or(serde_json::Value::Null),
                            "notes": c.notes,
                            "tier": format!("{:?}", c.tier),
                            "epoch": c.key_epoch,
                            "seq": c.update_seq,
                        });
                        match &c.kind {
                            idtty_core::types::CipherKind::Login(data) => {
                                json_obj["username"] = serde_json::json!(data.username);
                                json_obj["password"] = serde_json::json!(data.password);
                                json_obj["uris"] = serde_json::json!(data.uris);
                                json_obj["totp"] = serde_json::json!(data.totp_uri);
                            }
                            idtty_core::types::CipherKind::Card(data) => {
                                json_obj["cardholder_name"] = serde_json::json!(data.cardholder_name);
                                json_obj["brand"] = serde_json::json!(data.brand);
                                json_obj["number"] = serde_json::json!(data.number);
                            }
                            idtty_core::types::CipherKind::Identity(data) => {
                                json_obj["first_name"] = serde_json::json!(data.first_name);
                                json_obj["last_name"] = serde_json::json!(data.last_name);
                                json_obj["email"] = serde_json::json!(data.email);
                            }
                            _ => {}
                        }
                        println!("{json_obj}");
                    }
                    "text" => {
                        println!("Cipher: {}", c.id);
                        println!("  Name:      {}", c.name);
                        println!("  Type:      {:?}", c.kind.cipher_type());
                        match &c.kind {
                            idtty_core::types::CipherKind::Login(data) => {
                                if let Some(ref u) = data.username {
                                    println!("  Username:  {u}");
                                }
                                if let Some(ref p) = data.password {
                                    println!("  Password:  {p}");
                                }
                                for u in &data.uris {
                                    println!("  URI:       {}", u.uri);
                                }
                                if let Some(ref t) = data.totp_uri {
                                    println!("  TOTP:      {t}");
                                }
                            }
                            idtty_core::types::CipherKind::Card(data) => {
                                if let Some(ref v) = data.cardholder_name {
                                    println!("  Cardholder: {v}");
                                }
                                if let Some(ref v) = data.brand {
                                    println!("  Brand:     {v}");
                                }
                                if let Some(ref v) = data.number {
                                    println!("  Number:    {v}");
                                }
                            }
                            idtty_core::types::CipherKind::Identity(data) => {
                                if let Some(ref v) = data.first_name {
                                    println!("  First:     {v}");
                                }
                                if let Some(ref v) = data.last_name {
                                    println!("  Last:      {v}");
                                }
                                if let Some(ref v) = data.email {
                                    println!("  Email:     {v}");
                                }
                            }
                            idtty_core::types::CipherKind::SshKey(data) => {
                                if let Some(ref v) = data.public_key {
                                    println!("  Public:    {v}");
                                }
                                if let Some(ref v) = data.key_fingerprint {
                                    println!("  Fingerprint: {v}");
                                }
                            }
                            idtty_core::types::CipherKind::SecureNote => {}
                        }
                        if let Some(ref n) = c.notes {
                            println!("  Notes:     {n}");
                        }
                        println!("  Tier:      {:?}", c.tier);
                        println!("  Epoch:     {}", c.key_epoch);
                        println!("  Seq:       {}", c.update_seq);
                    }
                    _ => {
                        println!("Cipher: {}", c.id);
                        println!("  Name:      {}", c.name);
                        println!("  Type:      {:?}", c.kind.cipher_type());
                        match &c.kind {
                            idtty_core::types::CipherKind::Login(data) => {
                                if let Some(ref u) = data.username {
                                    println!("  Username:  {u}");
                                }
                                println!("  Password:  ***");
                                for u in &data.uris {
                                    println!("  URI:       {}", u.uri);
                                }
                            }
                            _ => {}
                        }
                        if c.notes.is_some() {
                            println!("  Notes:     ***");
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
            let ciphers = data["ciphers"].as_array();
            if ciphers.map_or(true, |a| a.is_empty()) {
                println!("No ciphers found.");
            } else if let Some(ciphers) = ciphers {
                // Fetch folders for name resolution
                let folder_map: std::collections::HashMap<String, String> =
                    if let Ok(fresp) = client::request_to("folder.list", "", socket) {
                        if let Ok(fdata) = serde_json::from_str::<serde_json::Value>(&fresp.payload) {
                            fdata.as_array()
                                .unwrap_or(&vec![])
                                .iter()
                                .filter_map(|f| {
                                    let id = f["id"].as_str()?.to_string();
                                    let name = f["name"].as_str()?.to_string();
                                    Some((id, name))
                                })
                                .collect()
                        } else { std::collections::HashMap::new() }
                    } else { std::collections::HashMap::new() };

                for c in ciphers {
                    let id = c["id"].as_str().unwrap_or("?");
                    let name = c["name"].as_str().unwrap_or("?");
                    let ctype = c["type"].as_str().unwrap_or("login");
                    let fav = if c["favorite"].as_bool().unwrap_or(false) { "*" } else { " " };
                    let username = c["username"].as_str().unwrap_or("");
                    let folder = c["folder_id"].as_str()
                        .and_then(|fid| folder_map.get(fid))
                        .map(|n| n.as_str())
                        .unwrap_or("");
                    if folder.is_empty() {
                        println!("{fav} {id}  [{ctype:>10}]  {name}  {username}");
                    } else {
                        println!("{fav} {id}  [{ctype:>10}]  {name}  {username}  [{folder}]");
                    }
                }
                println!();
                println!("{} cipher(s)", ciphers.len());
            }
            Ok(())
        }
        ConnectMode::Direct => list_direct(vault_path),
    }
}

fn list_direct(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(vault_path);
    let handle = VaultHandle::open(path)?;

    // Try CipherMeta listing (requires unlock)
    if handle.is_unlocked() {
        let metas = handle.list_cipher_meta()?;
        if metas.is_empty() {
            println!("No ciphers found.");
            return Ok(());
        }
        for m in &metas {
            let fav = if m.favorite { "*" } else { " " };
            let ctype = format!("{:?}", m.cipher_type).to_lowercase();
            let username = m.username.as_deref().unwrap_or("");
            println!("{fav} {}  [{ctype:>10}]  {}  {username}", m.id, m.name);
        }
        println!();
        println!("{} cipher(s)", metas.len());
    } else {
        // Locked: fall back to IDs only
        let ids = handle.list_cipher_ids()?;
        if ids.is_empty() {
            println!("No ciphers found.");
            return Ok(());
        }
        for id in &ids {
            println!("{id}");
        }
        println!();
        println!("{} cipher(s) (locked, unlock for details)", ids.len());
    }
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

// ── Edit cipher ──

pub fn handle_edit(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    id: &str,
    name: Option<String>,
    favorite: Option<bool>,
    folder: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if name.is_none() && favorite.is_none() && folder.is_none() {
        eprintln!("Nothing to edit. Use --name, --favorite, or --folder.");
        return Ok(());
    }

    let mut payload = serde_json::json!({"id": id});
    if let Some(ref n) = name {
        payload["name"] = serde_json::Value::String(n.clone());
    }
    if let Some(f) = favorite {
        payload["favorite"] = serde_json::Value::Bool(f);
    }
    if let Some(ref fid) = folder {
        payload["folder_id"] = serde_json::Value::String(fid.clone());
    }

    match mode {
        ConnectMode::Daemon => {
            let resp = client::request_to("vault.update", &payload.to_string(), socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("Cipher updated.");
            Ok(())
        }
        ConnectMode::Direct => {
            let mp = zeroize::Zeroizing::new(prompt_password("Master password: ")?);
            let path = Path::new(vault_path);
            let mut handle = VaultHandle::open(path)?;
            handle.unlock(&mp)?;

            let cipher_id = uuid::Uuid::parse_str(id).map_err(|_| "invalid UUID")?;
            let existing = handle.get_cipher(cipher_id)?;
            let existing_cipher = match existing {
                CipherRead::Decrypted(c) => c,
                CipherRead::Locked(_) => return Err("Cipher not found or vault locked".into()),
            };

            let input = idtty_core::types::CipherInput {
                name: name.clone().unwrap_or_else(|| existing_cipher.name.clone()),
                folder_id: folder
                    .as_ref()
                    .map(|f| f.parse::<uuid::Uuid>().ok())
                    .flatten()
                    .or(existing_cipher.folder_id),
                kind: existing_cipher.kind.clone(),
                favorite: favorite.unwrap_or(existing_cipher.favorite),
                notes: existing_cipher.notes.clone(),
                custom_fields: existing_cipher.custom_fields.clone(),
                created_at: Some(existing_cipher.created_at),
                password_history: existing_cipher.password_history.clone(),
            };

            handle.update_cipher(cipher_id, &input)?;
            println!("Cipher updated.");
            Ok(())
        }
    }
}

// ── Settings ──

pub fn handle_settings_get(
    mode: ConnectMode,
    socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            let resp = client::request_to("settings.get", "", socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("{}", resp.payload);
            Ok(())
        }
        ConnectMode::Direct => {
            eprintln!("Settings requires daemon mode. Use --socket or start the daemon.");
            std::process::exit(1);
        }
    }
}

pub fn handle_settings_set(
    mode: ConnectMode,
    socket: Option<&str>,
    kv: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (key, value) = kv
        .split_once('=')
        .ok_or("Usage: idtty settings set key=value")?;

    let payload = match key {
        "auto_lock_minutes" => serde_json::json!({"auto_lock_minutes": value.parse::<u32>().map_err(|e: std::num::ParseIntError| format!("Invalid number: {e}"))?}),
        "theme" => serde_json::json!({"theme": value}),
        "default_uri_match" => {
            let strategy = idtty_core::types::UriMatchStrategy::from_str_strict(value)
                .map_err(|e| format!("Invalid URI match strategy: {e}"))?;
            serde_json::json!({"default_uri_match": serde_json::to_value(strategy)?})
        }
        _ => return Err(format!("Unknown setting: {key}. Available: auto_lock_minutes, theme, default_uri_match").into()),
    };

    match mode {
        ConnectMode::Daemon => {
            let resp = client::request_to("settings.set", &payload.to_string(), socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("Setting updated.");
            Ok(())
        }
        ConnectMode::Direct => {
            eprintln!("Settings requires daemon mode. Use --socket or start the daemon.");
            std::process::exit(1);
        }
    }
}

// ── Folder CRUD ──

pub fn handle_folder_create(
    mode: ConnectMode,
    socket: Option<&str>,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            ensure_unlocked_daemon(socket)?;
            let resp = client::request_to("folder.create", name, socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("Folder created: {}", resp.payload);
            Ok(())
        }
        ConnectMode::Direct => {
            eprintln!("Folder management requires daemon mode.");
            std::process::exit(1);
        }
    }
}

pub fn handle_folder_list(
    mode: ConnectMode,
    socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            let resp = client::request_to("folder.list", "", socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            let folders: Vec<serde_json::Value> = serde_json::from_str(&resp.payload)?;
            if folders.is_empty() {
                println!("No folders.");
                return Ok(());
            }
            println!("{:<36} {}", "ID", "NAME");
            for f in &folders {
                let id = f["id"].as_str().unwrap_or("?");
                let name = f["name"].as_str().unwrap_or("?");
                println!("{id} {name}");
            }
            Ok(())
        }
        ConnectMode::Direct => {
            eprintln!("Folder management requires daemon mode.");
            std::process::exit(1);
        }
    }
}

pub fn handle_folder_rename(
    mode: ConnectMode,
    socket: Option<&str>,
    id: &str,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            ensure_unlocked_daemon(socket)?;
            let payload = serde_json::json!({"id": id, "name": name}).to_string();
            let resp = client::request_to("folder.rename", &payload, socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("Folder renamed.");
            Ok(())
        }
        ConnectMode::Direct => {
            eprintln!("Folder management requires daemon mode.");
            std::process::exit(1);
        }
    }
}

pub fn handle_folder_delete(
    mode: ConnectMode,
    socket: Option<&str>,
    id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            ensure_unlocked_daemon(socket)?;
            let resp = client::request_to("folder.delete", id, socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("Folder deleted. Entries moved to unassigned.");
            Ok(())
        }
        ConnectMode::Direct => {
            eprintln!("Folder management requires daemon mode.");
            std::process::exit(1);
        }
    }
}

// ── Import ──

pub fn handle_import(
    socket: Option<&str>,
    format: &str,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let import_format = idtty_core::import::ImportFormat::from_str(format)
        .ok_or_else(|| -> Box<dyn std::error::Error> {
            format!("Unknown format: {format}. Supported: {:?}", idtty_core::import::ImportFormat::all_names()).into()
        })?;

    ensure_unlocked_daemon(socket)?;

    // Pre-read file size check (prevent OOM on large files)
    const MAX_IMPORT_SIZE: u64 = 50 * 1024 * 1024; // 50MB
    let file_meta = std::fs::metadata(path)
        .map_err(|e| format!("Failed to stat {path}: {e}"))?;
    if file_meta.len() > MAX_IMPORT_SIZE {
        return Err(format!("Import file too large: {} bytes (max {} bytes)", file_meta.len(), MAX_IMPORT_SIZE).into());
    }

    // For 1PUX, read as binary and base64-encode
    let payload = match import_format {
        idtty_core::import::ImportFormat::OnePassword1pux => {
            let bytes = std::fs::read(path)
                .map_err(|e| format!("Failed to read {path}: {e}"))?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            serde_json::json!({"format": format, "data": b64}).to_string()
        }
        _ => {
            let file_data = std::fs::read_to_string(path)
                .map_err(|e| format!("Failed to read {path}: {e}"))?;
            serde_json::json!({"format": format, "data": file_data}).to_string()
        }
    };

    println!("Importing from {path} (format: {format})...");
    let resp = client::request_to("vault.import", &payload, socket)?;

    if !resp.success {
        return Err(resp.error_message.into());
    }

    let result: serde_json::Value = serde_json::from_str(&resp.payload)?;
    println!("Import complete:");
    println!("  Imported: {}", result["imported"].as_u64().unwrap_or(0));
    println!("  Skipped:  {}", result["skipped"].as_u64().unwrap_or(0));
    if let Some(folders) = result["folders_created"].as_u64() {
        if folders > 0 {
            println!("  Folders created: {folders}");
        }
    }
    if let Some(errors) = result["errors"].as_array() {
        if !errors.is_empty() {
            eprintln!("Errors:");
            for err in errors {
                eprintln!("  - {}", err.as_str().unwrap_or("unknown"));
            }
        }
    }
    Ok(())
}

// ── Export ──

pub fn handle_export(
    socket: Option<&str>,
    format: &str,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_unlocked_daemon(socket)?;

    // Warn about plaintext secrets
    eprintln!("WARNING: Export file will contain UNENCRYPTED secrets (passwords, cards, SSH keys).");
    eprintln!("         Delete the file after use. Do not upload to cloud storage.");

    // Confirm overwrite if file exists
    if std::path::Path::new(path).exists() {
        println!("File '{path}' already exists. Overwrite? [y/N] ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            println!("Export cancelled.");
            return Ok(());
        }
    }

    println!("Exporting vault as {format}...");
    let resp = client::request_to("vault.export", format, socket)?;

    if !resp.success {
        return Err(resp.error_message.into());
    }

    std::fs::write(path, &resp.payload)
        .map_err(|e| format!("Failed to write {path}: {e}"))?;

    // Set file permissions to 0600 on Unix (owner-only read/write)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    println!("Export complete: {path}");
    Ok(())
}
