//! CLI command implementations.

use std::path::Path;

use idtty_core::types::{CipherInput, KdfProfile};
use idtty_core::vault::handle::{CipherRead, VaultHandle};
use idtty_core::vault::creation;

pub fn handle_init(vault_path: &str, profile_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let profile = parse_profile(profile_str)?;

    let password = prompt_password("Master password: ")?;
    let confirm = prompt_password("Confirm password: ")?;

    if password != confirm {
        eprintln!("error: passwords do not match");
        std::process::exit(1);
    }

    if password.len() < 8 {
        eprintln!("warning: password is shorter than recommended (8+ characters)");
    }

    println!("Creating vault...");
    let result = creation::create_vault_ceremony(&password, profile)?;

    println!();
    println!("Vault created successfully.");
    println!("  Vault ID: {}", result.vault_id);
    println!("  Epoch:    {}", result.epoch_info.epoch);
    println!("  Device:   {}", result.device_id);
    println!();
    println!("=== RECOVERY PHRASE (write this down!) ===");
    println!("{}", result.recovery_phrase.phrase());
    println!("=== END RECOVERY PHRASE ===");
    println!();
    println!("Trust fingerprint: {}", hex::encode(result.trust_fingerprint));

    let path = Path::new(vault_path);
    std::fs::create_dir_all(path.join("ciphers"))?;
    std::fs::create_dir_all(path.join("meta"))?;
    std::fs::create_dir_all(path.join("meta/keywrap"))?;
    std::fs::create_dir_all(path.join("meta/sequences"))?;

    // Device registry
    let mut registry = idtty_core::devices::DeviceRegistry::new();
    let pub_enc = x25519_dalek::PublicKey::from(&result.device_x25519_secret);
    let verifying = result.device_ed25519_signing.verifying_key();
    registry.enroll(
        "this-device".into(),
        pub_enc.to_bytes(),
        verifying.to_bytes(),
    )?;
    std::fs::write(path.join("meta/devices.json"), serde_json::to_string_pretty(&registry)?)?;

    // KDF params
    std::fs::write(path.join("meta/kdf-params.json"), serde_json::to_string_pretty(&result.kdf_params)?)?;

    // Keywrap
    let (eph_pub, ct, tag) = &result.wrapped_root_key;
    let keywrap_data = serde_json::json!({
        "device_id": result.device_id.to_string(),
        "ephemeral_public": hex::encode(eph_pub),
        "encrypted_key": hex::encode(ct),
        "tag": hex::encode(tag),
    });
    std::fs::write(
        path.join(format!("meta/keywrap/{}.json", result.device_id)),
        serde_json::to_string_pretty(&keywrap_data)?,
    )?;

    // CLI mode: device private key (NOT for production!)
    let privkey_data = serde_json::json!({
        "x25519_private": hex::encode(result.device_x25519_secret.to_bytes()),
    });
    std::fs::write(path.join("meta/device-privkey.json"), serde_json::to_string_pretty(&privkey_data)?)?;

    // Vault .gitignore: exclude secrets that must never be pushed
    std::fs::write(
        path.join(".gitignore"),
        "# Secrets - never push these\nmeta/device-privkey.json\n",
    )?;

    // KEK canary (for password verification on unlock)
    std::fs::write(path.join("meta/kek-canary.enc"), &result.kek_canary)?;

    // Root Key canary (for RK verification on unlock)
    std::fs::write(path.join("meta/rk-canary.enc"), &result.rk_canary)?;

    println!("Vault files written to: {}", path.display());
    Ok(())
}

pub fn handle_unlock(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(vault_path);
    let mut handle = VaultHandle::open(path)?;

    if handle.is_unlocked() {
        println!("Vault is already unlocked.");
        return Ok(());
    }

    let password = prompt_password("Master password: ")?;
    handle.unlock(&password)?;

    println!("Vault unlocked.");
    println!("  Vault ID:  {}", handle.vault_id);
    println!("  Device:    {}", handle.device_id);
    println!("  Ciphers:   {}", handle.list_cipher_ids()?.len());

    // In a real app, the handle would persist in memory.
    // For CLI, each command is a separate process, so we just
    // demonstrate the unlock works. A session file approach
    // would be needed for persistent unlock across commands.
    println!();
    println!("(CLI mode: vault locks on exit. Use individual commands with --password flag for now.)");
    Ok(())
}

pub fn handle_add(
    vault_path: &str,
    name: String,
    username: Option<String>,
    password: Option<String>,
    uri: Option<String>,
    notes: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let password = match password {
        Some(p) => {
            eprintln!("warning: --password exposes secret in process list. Use interactive prompt instead.");
            p
        }
        None => prompt_password("Password: ")?,
    };

    let mp = prompt_password("Master password: ")?;
    let path = Path::new(vault_path);
    let mut handle = VaultHandle::open(path)?;
    handle.unlock(&mp)?;

    let input = CipherInput {
        name,
        folder_id: None,
        username,
        password: Some(password),
        uris: uri.map(|u| vec![u]).unwrap_or_default(),
        notes,
        totp_uri: None,
        custom_fields: vec![],
    };

    let cipher_id = handle.add_cipher(&input)?;
    println!("Cipher added: {cipher_id}");
    Ok(())
}

pub fn handle_get(vault_path: &str, id_or_name: &str, decrypt: bool, output: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cipher_id = match uuid::Uuid::parse_str(id_or_name) {
        Ok(id) => id,
        Err(_) => {
            eprintln!("error: searching by name not yet implemented, use cipher UUID");
            std::process::exit(1);
        }
    };

    let path = Path::new(vault_path);
    let mut handle = VaultHandle::open(path)?;

    if decrypt {
        let mp = prompt_password("Master password: ")?;
        handle.unlock(&mp)?;
    }

    match handle.get_cipher(cipher_id)? {
        CipherRead::Decrypted(c) => {
            match output {
                "json" => {
                    // JSON output: use serde to prevent injection
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
                    // Text output: human-readable, includes secrets
                    println!("Cipher: {}", c.id);
                    println!("  Name:      {}", c.name);
                    if let Some(ref u) = c.username { println!("  Username:  {u}"); }
                    if let Some(ref p) = c.password { println!("  Password:  {p}"); }
                    for u in &c.uris { println!("  URI:       {u}"); }
                    if let Some(ref n) = c.notes { println!("  Notes:     {n}"); }
                    if let Some(ref t) = c.totp_uri { println!("  TOTP:      {t}"); }
                    println!("  Tier:      {:?}", c.tier);
                    println!("  Epoch:     {}", c.key_epoch);
                    println!("  Seq:       {}", c.update_seq);
                }
                _ => {
                    // Quiet (default): show metadata only, secrets hidden
                    println!("Cipher: {}", c.id);
                    println!("  Name:      {}", c.name);
                    if let Some(ref u) = c.username { println!("  Username:  {u}"); }
                    println!("  Password:  ***");
                    for u in &c.uris { println!("  URI:       {u}"); }
                    if c.notes.is_some() { println!("  Notes:     ***"); }
                    if c.totp_uri.is_some() { println!("  TOTP:      ***"); }
                    println!("  Use --output=text to reveal secrets");
                }
            }
        }
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

pub fn handle_list(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
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

pub fn handle_delete(vault_path: &str, id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cipher_id = uuid::Uuid::parse_str(id).map_err(|_| "invalid UUID")?;
    let path = Path::new(vault_path);
    let handle = VaultHandle::open(path)?;
    handle.delete_cipher(cipher_id)?;
    println!("Cipher deleted: {cipher_id}");
    Ok(())
}

pub fn handle_sync_init(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "git-sync")]
    {
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
    #[cfg(not(feature = "git-sync"))]
    {
        eprintln!("error: git-sync feature not enabled");
        std::process::exit(1);
    }
}

pub fn handle_sync_remote(vault_path: &str, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "git-sync")]
    {
        let path = Path::new(vault_path);
        let engine = idtty_core::sync::engine::SyncEngine::new(path, &device_name(vault_path));
        let repo = engine.open_repo()?;
        engine.add_remote(&repo, "origin", url)?;
        println!("Remote 'origin' set to: {url}");
        Ok(())
    }
    #[cfg(not(feature = "git-sync"))]
    {
        let _ = url;
        eprintln!("error: git-sync feature not enabled");
        std::process::exit(1);
    }
}

pub fn handle_sync_push(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "git-sync")]
    {
        let path = Path::new(vault_path);
        let engine = idtty_core::sync::engine::SyncEngine::new(path, &device_name(vault_path));
        let repo = engine.open_repo()?;

        // Commit any pending changes first
        let status = engine.status(&repo)?;
        if status.is_dirty() {
            engine.commit_all(&repo, "")?;
            println!("Committed pending changes.");
        }

        engine.push(&repo, "origin")?;
        println!("Pushed to origin.");
        Ok(())
    }
    #[cfg(not(feature = "git-sync"))]
    {
        eprintln!("error: git-sync feature not enabled");
        std::process::exit(1);
    }
}

pub fn handle_sync_pull(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "git-sync")]
    {
        let path = Path::new(vault_path);
        let engine = idtty_core::sync::engine::SyncEngine::new(path, &device_name(vault_path));
        let repo = engine.open_repo()?;

        let result = engine.pull(&repo, "origin")?;
        match result {
            idtty_core::sync::engine::PullResult::AlreadyUpToDate => println!("Already up to date."),
            idtty_core::sync::engine::PullResult::FastForward => println!("Fast-forwarded to latest."),
            idtty_core::sync::engine::PullResult::Merged => println!("Merged remote changes."),
            idtty_core::sync::engine::PullResult::Conflict => {
                eprintln!("error: merge conflict detected. Manual resolution required.");
                std::process::exit(1);
            }
        }
        Ok(())
    }
    #[cfg(not(feature = "git-sync"))]
    {
        eprintln!("error: git-sync feature not enabled");
        std::process::exit(1);
    }
}

pub fn handle_sync_status(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "git-sync")]
    {
        let path = Path::new(vault_path);
        let engine = idtty_core::sync::engine::SyncEngine::new(path, &device_name(vault_path));
        let repo = engine.open_repo()?;

        let status = engine.status(&repo)?;
        if status.is_dirty() {
            println!("Working tree: dirty ({} staged, {} unstaged)", status.staged, status.unstaged);
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
                println!("  {} {} <{}>", &c.id[..7.min(c.id.len())], c.message.trim(), ts);
            }
        }
        Ok(())
    }
    #[cfg(not(feature = "git-sync"))]
    {
        eprintln!("error: git-sync feature not enabled");
        std::process::exit(1);
    }
}

pub fn handle_sync_log(vault_path: &str, limit: usize) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "git-sync")]
    {
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
    #[cfg(not(feature = "git-sync"))]
    {
        let _ = limit;
        eprintln!("error: git-sync feature not enabled");
        std::process::exit(1);
    }
}

pub fn handle_devices(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(vault_path);
    let handle = VaultHandle::open(path)?;

    println!("Enrolled devices:");
    for entry in handle.registry.devices.values() {
        println!("  {} ({})", entry.name, entry.device_id);
        println!("    Encryption key: {}...{}", &entry.encryption_public_key[..8], &entry.encryption_public_key[56..]);
        println!("    Signing key:    {}...{}", &entry.signing_public_key[..8], &entry.signing_public_key[56..]);
        println!("    Enrolled at:    {}", entry.enrolled_at);
    }
    println!();
    println!("Total: {} device(s)", handle.registry.count());
    Ok(())
}

// ── Helpers ──

fn parse_profile(s: &str) -> Result<KdfProfile, Box<dyn std::error::Error>> {
    match s {
        "mobile-low" => Ok(KdfProfile::MobileLow),
        "desktop-std" => Ok(KdfProfile::DesktopStd),
        "desktop-high" => Ok(KdfProfile::DesktopHigh),
        _ => Err(format!("unknown profile: {s}. Use: mobile-low, desktop-std, desktop-high").into()),
    }
}

fn device_name(vault_path: &str) -> String {
    let path = Path::new(vault_path);
    let reg_path = path.join("meta/devices.json");
    if reg_path.exists() {
        if let Ok(data) = std::fs::read_to_string(&reg_path) {
            let reg: std::result::Result<idtty_core::devices::DeviceRegistry, _> = serde_json::from_str(&data);
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
    // Use rpassword when TTY available, fall back to stdin for scripts
    match rpassword::prompt_password(prompt) {
        Ok(pw) => Ok(pw),
        Err(_) => {
            // No TTY: read from stdin (for scripts/pipes)
            use std::io::{BufRead, Write};
            eprint!("{prompt}");
            std::io::stderr().flush()?;
            let mut buf = String::new();
            std::io::stdin().lock().read_line(&mut buf)?;
            Ok(buf.trim().to_string())
        }
    }
}
