//! CLI command implementations.
//!
//! Each vault command supports two modes:
//! - Daemon: routes through baluard-daemon via Unix socket (default)
//! - Direct: calls baluard-core directly (fallback, --direct flag)

use crate::Cli;
use crate::ConnectMode;
use crate::VaultAction;
use crate::client;

use std::path::Path;

use baluard_core::types::{CipherInput, KdfProfile};
use baluard_core::vault::handle::{CipherRead, VaultHandle};
use base64::Engine;
use zeroize::Zeroize;

// ── Direct-mode helpers ──

/// Open and unlock a vault in direct mode. Returns the unlocked VaultHandle.
/// Supports BALUARD_PASSWORD env-var for scripting (avoids TTY prompt).
fn unlock_vault_direct(vault_path: &str) -> Result<VaultHandle, Box<dyn std::error::Error>> {
    let path = Path::new(vault_path);
    let mut handle = VaultHandle::open(path)?;
    let password = match std::env::var("BALUARD_PASSWORD") {
        Ok(pw) => pw,
        Err(_) => prompt_password("Master password: ")?,
    };
    let mp = zeroize::Zeroizing::new(password);
    handle.unlock(&mp)?;
    Ok(handle)
}

// ── Init (always direct) ──

/// Detect OS locale from environment variables.
/// Priority: $LANGUAGE > $LC_ALL > $LC_MESSAGES > $LANG.
/// Parses "es_CL.UTF-8" -> "es". Falls back to "en".
fn detect_locale() -> String {
    let candidates = [
        std::env::var("LANGUAGE").ok(),
        std::env::var("LC_ALL").ok(),
        std::env::var("LC_MESSAGES").ok(),
        std::env::var("LANG").ok(),
    ];
    for candidate in candidates.into_iter().flatten() {
        // $LANGUAGE may be colon-separated (GNU gettext priority)
        for entry in candidate.split(':') {
            let code = entry
                .split('.')
                .next()
                .unwrap_or("")
                .split('_')
                .next()
                .unwrap_or("");
            match code {
                "en" | "es" => return code.to_string(),
                _ => continue,
            }
        }
    }
    "en".to_string()
}

/// Check if stdin is a TTY (interactive terminal).
fn is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

/// Parse theme string to ThemeMode.
fn parse_theme(s: &str) -> Result<baluard_core::types::ThemeMode, String> {
    match s {
        "light" => Ok(baluard_core::types::ThemeMode::Light),
        "dark" => Ok(baluard_core::types::ThemeMode::Dark),
        "system" => Ok(baluard_core::types::ThemeMode::System),
        _ => Err(format!("unknown theme: '{s}' (valid: light, dark, system)")),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn handle_init(
    vault_path: &str,
    profile_str: &str,
    flag_name: Option<String>,
    flag_slug: Option<String>,
    flag_theme: Option<String>,
    flag_lang: Option<String>,
    flag_auto_lock: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let profile = parse_profile(profile_str)?;

    // Resolve password: env var > TTY prompt > error
    let password = match std::env::var("BALUARD_PASSWORD") {
        Ok(pw) => {
            if pw.len() < 8 {
                eprintln!("error: password must be at least 8 characters");
                std::process::exit(1);
            }
            zeroize::Zeroizing::new(pw)
        }
        Err(_) if !is_tty() => {
            eprintln!("error: no password available. Set BALUARD_PASSWORD or run interactively.");
            std::process::exit(1);
        }
        Err(_) => {
            let pw = zeroize::Zeroizing::new(prompt_password("Master password: ")?);
            let confirm = zeroize::Zeroizing::new(prompt_password("Confirm password: ")?);
            if *pw != *confirm {
                eprintln!("error: passwords do not match");
                std::process::exit(1);
            }
            if pw.len() < 8 {
                eprintln!("error: password must be at least 8 characters");
                std::process::exit(1);
            }
            pw
        }
    };

    // Resolve wizard fields: flags > interactive prompts > defaults
    let display_name = match flag_name {
        Some(n) => Some(n),
        None if is_tty() => {
            let input = prompt_password_optional("Display name (optional, Enter to skip): ");
            if input.is_empty() { None } else { Some(input) }
        }
        None => None,
    };

    // Resolve slug: flag > auto-generate from display name > prompt
    let slug = match flag_slug {
        Some(s) => {
            // Enforced prefix: "personal" becomes "baluard-personal".
            let normalized = baluard_core::vault::slug::normalize_slug(&s);
            if let Err(e) = baluard_core::vault::slug::validate_slug(&normalized) {
                eprintln!("error: invalid slug '{s}': {e}");
                std::process::exit(1);
            }
            if normalized != s {
                eprintln!("Slug normalized to: {normalized}");
            }
            Some(normalized)
        }
        None => {
            let name_for_slug = display_name.as_deref().unwrap_or("Personal");
            let suggested = baluard_core::vault::slug::suggest_slug(name_for_slug);
            if is_tty() {
                let input = prompt_password_optional(&format!("Vault slug [{suggested}]: "));
                if input.is_empty() {
                    Some(suggested)
                } else {
                    let cleaned = baluard_core::vault::slug::normalize_slug(&input);
                    match baluard_core::vault::slug::validate_slug(&cleaned) {
                        Ok(()) => Some(cleaned),
                        Err(e) => {
                            eprintln!("error: invalid slug: {e}");
                            std::process::exit(1);
                        }
                    }
                }
            } else {
                Some(suggested)
            }
        }
    };

    let theme = match flag_theme.as_deref() {
        Some(t) => Some(parse_theme(t)?),
        None if is_tty() => {
            let input = prompt_password_optional("Theme [light/dark/system, default: system]: ");
            match input.trim() {
                "" | "system" => Some(baluard_core::types::ThemeMode::System),
                "light" => Some(baluard_core::types::ThemeMode::Light),
                "dark" => Some(baluard_core::types::ThemeMode::Dark),
                other => {
                    eprintln!("warning: unknown theme '{other}', using system");
                    Some(baluard_core::types::ThemeMode::System)
                }
            }
        }
        None => Some(baluard_core::types::ThemeMode::System),
    };

    let lang = match flag_lang {
        Some(l) => Some(l),
        None => Some(detect_locale()),
    };

    let vault_timeout: Option<baluard_core::vault::manifest::VaultTimeout> = match flag_auto_lock {
        Some(0) => None, // no "never" option yet; fall back to creator default
        Some(m) => Some(baluard_core::vault::manifest::VaultTimeout::Minutes(m)),
        None if is_tty() => {
            let input = prompt_password_optional("Auto-lock minutes [default: 15]: ");
            match input.trim() {
                "" | "0" => None, // use creator default (15m)
                n => n
                    .parse::<u32>()
                    .ok()
                    .map(baluard_core::vault::manifest::VaultTimeout::Minutes)
                    .or_else(|| {
                        eprintln!("warning: invalid number, using default 15m");
                        None
                    }),
            }
        }
        None => None, // use creator default (15m)
    };

    println!("Creating vault...");

    // Pre-flight: check slug collision before writing any files
    let reg = baluard_core::vault::registry::VaultRegistry::load_locked().unwrap_or_default();
    if let Some(ref s) = slug {
        if reg.exists(s) {
            eprintln!("error: vault '{s}' already exists in registry");
            std::process::exit(1);
        }
    }

    // Determine vault path: if slug is set and user gave ".", use vaults_dir
    let resolved_path = if vault_path == "." {
        if let Some(ref s) = slug {
            let p = baluard_core::paths::vaults_dir().join(s);
            if p.exists() {
                eprintln!("error: vault directory already exists: {}", p.display());
                std::process::exit(1);
            }
            println!("Vault path: {}", p.display());
            p
        } else {
            std::path::PathBuf::from(vault_path)
        }
    } else {
        std::path::PathBuf::from(vault_path)
    };

    let (_handle, secrets) =
        baluard_core::vault::creation::VaultCreator::new(&resolved_path, &password, "this-device")
            .kdf_profile(profile)
            .profile(display_name.clone(), None)
            .slug(slug.clone())
            .preferences(theme, lang.clone(), vault_timeout)
            .execute()?;

    // Register vault in registry (fatal on failure)
    if let Some(ref s) = slug {
        let mut reg = reg; // reuse pre-flight registry (still valid)
        reg.add(baluard_core::vault::registry::VaultEntry {
            slug: s.clone(),
            display_name: display_name.clone().unwrap_or_else(|| s.clone()),
            path: resolved_path.clone(),
            provider: None,
            remote_url: None,
            last_synced: None,
            last_opened: None,
            vault_id: secrets.vault_id,
        })?;
        reg.set_active(s)?;
        reg.save_locked()?;
    }

    println!();
    println!("Vault created successfully.");
    println!("  Vault ID: {}", secrets.vault_id);
    println!("  Epoch:    1");
    println!("  Device:   {}", secrets.device_id);
    println!();
    // Print the 24-word phrase numbered and grouped into 3 rows of 8.
    // Numbering makes the mandatory re-entry verification step trivial to
    // confirm against during testing (and real use).
    println!("=== RECOVERY PHRASE (write this down!) ===");
    let phrase = secrets.recovery_phrase.phrase();
    let words: Vec<&str> = phrase.split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        if i % 8 != 0 {
            print!(" ");
        }
        print!("{:>2}. {:<8}", i + 1, word);
        if i % 8 == 7 || i == words.len() - 1 {
            println!();
        }
    }
    println!("=== END RECOVERY PHRASE ===");
    println!();
    println!(
        "Trust fingerprint: {}",
        hex::encode(secrets.trust_fingerprint)
    );

    // MANDATORY VERIFICATION: user must re-enter 4 random words to prove
    // they actually wrote the phrase down. This is not security theater —
    // the recovery phrase is the only root authority for total device loss.
    println!();
    println!("┌──────────────────────────────────────────────────────────────┐");
    println!("│  WHY THIS MATTERS                                              │");
    println!("├──────────────────────────────────────────────────────────────┤");
    println!("│  This 24-word phrase is the ONLY way to recover your vault    │");
    println!("│  if every device fails. There is no server, no email reset,   │");
    println!("│  no phone number to call.                                     │");
    println!("│                                                                │");
    println!("│  Examples of when you would need it:                           │");
    println!("│   • You buy a new laptop and your old one is already gone      │");
    println!("│   • Your phone is lost and your laptop died last month          │");
    println!("│   • A fire, flood, or theft takes every device at once          │");
    println!("│   • You return to Baluard after years away                      │");
    println!("└──────────────────────────────────────────────────────────────┘");
    println!();
    println!("Write the phrase on paper. Store it somewhere SAFE (safe,     ");
    println!("safety deposit box, fireproof bag). Screenshots and password  ");
    println!("managers are NOT safe enough — they can fail too.              ");
    println!();

    // Scripting mode (BALUARD_PASSWORD set, e.g. `just seed-demo`) cannot
    // interactively verify words, and verification only slows automated runs.
    // The phrase is already printed above; just continue.
    let scripting = std::env::var("BALUARD_PASSWORD").is_ok();
    if scripting {
        println!();
        println!("✓ Recovery phrase shown above (verification skipped in scripting mode).");
    } else if !verify_recovery_phrase_interactive(&secrets.recovery_phrase.phrase()) {
        // PR-6 fix: roll back the newly-created vault. Previously we left
        // it on disk and told the user to re-run `baluard init`, which
        // would fail with "vault already exists." Now we delete the
        // whole directory so the user can retry cleanly.
        eprintln!();
        eprintln!("Verification failed. Rolling back the new vault at:");
        eprintln!("  {}", resolved_path.display());
        if let Err(e) = std::fs::remove_dir_all(&resolved_path) {
            eprintln!("warning: failed to remove vault directory: {e}");
            eprintln!("Delete it manually before re-running `baluard init`.");
        }
        // Also remove the registry entry if we added one
        if let Some(ref s) = slug {
            if let Ok(mut reg) = baluard_core::vault::registry::VaultRegistry::load() {
                let _ = reg.remove(s);
                let _ = reg.save();
            }
        }
        return Err("Recovery phrase verification failed. Vault rolled back. \
             Re-run `baluard init` and complete the verification step."
            .into());
    } else {
        println!("✓ Recovery phrase verified. Continuing setup.");
    }

    println!("Vault files written to: {}", resolved_path.display());
    Ok(())
}

/// Read a line from stdin (echoes normally, for non-secret fields).
/// Returns empty string on EOF or empty input.
fn prompt_password_optional(prompt: &str) -> String {
    eprint!("{prompt}");
    let mut buf = String::new();
    let _ = std::io::stdin().read_line(&mut buf);
    buf.trim().to_string()
}

/// Interactive recovery phrase verification.
/// Asks the user to re-enter 4 random words from the phrase. Returns true
/// only if all 4 match. Same algorithm as the desktop UI
/// (deterministic position selection from phrase hash).
fn verify_recovery_phrase_interactive(phrase: &str) -> bool {
    // Pick 4 stable positions (1-indexed) from the phrase via FNV-1a hash
    let bytes = phrase.as_bytes();
    let mut hash: u32 = 0x811c9dc5;
    for &b in bytes {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    let mut positions: Vec<usize> = Vec::new();
    let mut h = hash;
    while positions.len() < 4 {
        let pos = (h as usize % 24) + 1;
        if !positions.contains(&pos) {
            positions.push(pos);
        }
        h = h.wrapping_mul(0x01000193).wrapping_add(0x9e3779b9);
    }
    positions.sort();

    let words: Vec<&str> = phrase.split_whitespace().collect();
    if words.len() != 24 {
        eprintln!("internal error: recovery phrase is not 24 words");
        return false;
    }

    println!("PROVE YOU WROTE IT DOWN");
    println!("Enter the following 4 words from your recovery phrase:");
    println!();
    for (i, &pos) in positions.iter().enumerate() {
        loop {
            eprint!("  Word #{}: ", pos);
            use std::io::Write;
            std::io::stderr().flush().ok();
            let mut input = String::new();
            if std::io::stdin().read_line(&mut input).is_err() {
                return false;
            }
            let got = input.trim().to_lowercase();
            let expected = words[pos - 1].to_lowercase();
            if got == expected {
                eprintln!("  ✓");
                break;
            } else if got.is_empty() {
                eprintln!("  (skipped — try again)");
                continue;
            } else {
                eprintln!("  ✗ does not match. Check your written copy and try again.");
                // Give the user a way to abort if they're stuck
                eprint!("  (type 'quit' to abort, or press Enter to retry): ");
                std::io::stderr().flush().ok();
                let mut retry = String::new();
                if std::io::stdin().read_line(&mut retry).is_err() {
                    return false;
                }
                if retry.trim().eq_ignore_ascii_case("quit") {
                    return false;
                }
                // Continue the loop to retry
            }
        }
        // i unused, positions is ordered
        let _ = i;
    }
    true
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

    // Resolve password: env var > TTY prompt. Mirrors handle_init + unlock_vault_direct
    // so scripting (`BALUARD_PASSWORD=... baluard unlock`) and tests can skip the prompt.
    let mut password = match std::env::var("BALUARD_PASSWORD") {
        Ok(pw) => zeroize::Zeroizing::new(pw),
        Err(_) => zeroize::Zeroizing::new(prompt_password("Master password: ")?),
    };
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
            Err("lock requires daemon mode (no vault held in memory in direct mode)".into())
        }
    }
}

// ── Add cipher ──

pub fn handle_add(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    input: CipherInput,
) -> Result<(), Box<dyn std::error::Error>> {
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
            let mut handle = unlock_vault_direct(vault_path)?;
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
                    if let Some(fido2_list) = c["fido2_credentials"].as_array() {
                        if !fido2_list.is_empty() {
                            println!("  Passkeys:");
                            for pk in fido2_list {
                                let pk_name = pk["name"]
                                    .as_str()
                                    .or(pk["rp_name"].as_str())
                                    .unwrap_or(pk["rp_id"].as_str().unwrap_or("?"));
                                println!("    - {} ({})", pk_name, pk["rp_id"]);
                                if let Some(u) = pk["user_name"].as_str() {
                                    println!("      User:     {u}");
                                }
                                println!("      Counter:  {}", pk["counter"]);
                                if pk["private_key_missing"].as_bool() == Some(true) {
                                    println!(
                                        "      WARNING:  Imported (no private key, re-register needed)"
                                    );
                                }
                            }
                        }
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
            let handle = unlock_vault_direct(vault_path)?;

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
                            baluard_core::types::CipherKind::Login(data) => {
                                json_obj["username"] = serde_json::json!(data.username);
                                json_obj["password"] = serde_json::json!(data.password);
                                json_obj["uris"] = serde_json::json!(data.uris);
                                json_obj["totp"] = serde_json::json!(data.totp_uri);
                            }
                            baluard_core::types::CipherKind::Card(data) => {
                                json_obj["cardholder_name"] =
                                    serde_json::json!(data.cardholder_name);
                                json_obj["brand"] = serde_json::json!(data.brand);
                                json_obj["number"] = serde_json::json!(data.number);
                            }
                            baluard_core::types::CipherKind::Identity(data) => {
                                json_obj["first_name"] = serde_json::json!(data.first_name);
                                json_obj["last_name"] = serde_json::json!(data.last_name);
                                json_obj["email"] = serde_json::json!(data.email);
                            }
                            baluard_core::types::CipherKind::BankAccount(data) => {
                                json_obj["bank_name"] = serde_json::json!(data.bank_name);
                                json_obj["account_number"] = serde_json::json!(data.account_number);
                            }
                            baluard_core::types::CipherKind::DriversLicense(data) => {
                                json_obj["license_number"] = serde_json::json!(data.license_number);
                            }
                            baluard_core::types::CipherKind::Passport(data) => {
                                json_obj["passport_number"] =
                                    serde_json::json!(data.passport_number);
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
                            baluard_core::types::CipherKind::Login(data) => {
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
                                if let Some(ref fido2_list) = data.fido2_credentials {
                                    if !fido2_list.is_empty() {
                                        println!("  Passkeys:");
                                        for pk in fido2_list {
                                            let pk_name = pk
                                                .name
                                                .as_deref()
                                                .or(pk.rp_name.as_deref())
                                                .unwrap_or(&pk.rp_id);
                                            println!("    - {} ({})", pk_name, pk.rp_id);
                                            if let Some(ref u) = pk.user_name {
                                                println!("      User:     {u}");
                                            }
                                            println!("      Counter:  {}", pk.counter);
                                            if pk.private_key_missing {
                                                println!(
                                                    "      WARNING:  Imported (no private key, re-register needed)"
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            baluard_core::types::CipherKind::Card(data) => {
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
                            baluard_core::types::CipherKind::Identity(data) => {
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
                            baluard_core::types::CipherKind::SshKey(data) => {
                                if let Some(ref v) = data.public_key {
                                    println!("  Public:    {v}");
                                }
                                if let Some(ref v) = data.key_fingerprint {
                                    println!("  Fingerprint: {v}");
                                }
                            }
                            baluard_core::types::CipherKind::BankAccount(data) => {
                                if let Some(ref v) = data.bank_name {
                                    println!("  Bank Name: {v}");
                                }
                                if let Some(ref v) = data.account_number {
                                    println!("  Account:   {v}");
                                }
                            }
                            baluard_core::types::CipherKind::DriversLicense(data) => {
                                if let Some(ref v) = data.license_number {
                                    println!("  License:   {v}");
                                }
                            }
                            baluard_core::types::CipherKind::Passport(data) => {
                                if let Some(ref v) = data.passport_number {
                                    println!("  Passport:  {v}");
                                }
                            }
                            baluard_core::types::CipherKind::SecureNote => {}
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
                        if let baluard_core::types::CipherKind::Login(data) = &c.kind {
                            if let Some(ref u) = data.username {
                                println!("  Username:  {u}");
                            }
                            println!("  Password:  ***");
                            for u in &data.uris {
                                println!("  URI:       {}", u.uri);
                            }
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
    archived: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            let action = if archived {
                "vault.list_archived"
            } else {
                "vault.list"
            };
            let resp = client::request_to(action, "", socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            let data: serde_json::Value = serde_json::from_str(&resp.payload)?;
            let ciphers = data["ciphers"].as_array();
            if ciphers.as_ref().is_none_or(|a| a.is_empty()) {
                println!("No ciphers found.");
            } else if let Some(ciphers) = ciphers {
                // Fetch folders for name resolution
                let folder_map: std::collections::HashMap<String, String> = if let Ok(fresp) =
                    client::request_to("folder.list", "", socket)
                {
                    if let Ok(fdata) = serde_json::from_str::<serde_json::Value>(&fresp.payload) {
                        fdata
                            .as_array()
                            .unwrap_or(&vec![])
                            .iter()
                            .filter_map(|f| {
                                let id = f["id"].as_str()?.to_string();
                                let name = f["name"].as_str()?.to_string();
                                Some((id, name))
                            })
                            .collect()
                    } else {
                        std::collections::HashMap::new()
                    }
                } else {
                    std::collections::HashMap::new()
                };

                for c in ciphers {
                    let id = c["id"].as_str().unwrap_or("?");
                    let name = c["name"].as_str().unwrap_or("?");
                    let ctype = c["type"].as_str().unwrap_or("login");
                    let fav = if c["favorite"].as_bool().unwrap_or(false) {
                        "*"
                    } else {
                        " "
                    };
                    let username = c["username"].as_str().unwrap_or("");
                    let folder = c["folder_id"]
                        .as_str()
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
        ConnectMode::Direct => list_direct(vault_path, archived),
    }
}

fn list_direct(vault_path: &str, archived: bool) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(vault_path);
    // Auto-unlock when BALUARD_PASSWORD is set, so scripting/tests get full
    // cipher metadata (name, type, username) without an explicit `unlock`
    // step. Matches the env-var bypass used by `add`/`edit` via
    // `unlock_vault_direct`. If the env var is unset we fall back to the
    // locked-ID listing below.
    let handle = if std::env::var("BALUARD_PASSWORD").is_ok() {
        unlock_vault_direct(vault_path)?
    } else {
        VaultHandle::open(path)?
    };

    // Try CipherMeta listing (requires unlock)
    if handle.is_unlocked() {
        let metas = if archived {
            handle.list_archived_meta()?
        } else {
            handle.list_cipher_meta()?
        };
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
            // Auto-unlock when BALUARD_PASSWORD is set so scripting/tests can
            // chain `add` → `delete` without an explicit `unlock` step.
            let handle = unlock_vault_direct(vault_path)?;
            handle.delete_cipher(cipher_id)?;
            println!("Cipher deleted: {cipher_id}");
            Ok(())
        }
    }
}

// ── Archive / Unarchive ──

pub fn handle_archive(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            ensure_unlocked_daemon(socket)?;
            let resp = client::request_to("vault.archive", id, socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("Cipher archived: {id}");
            Ok(())
        }
        ConnectMode::Direct => {
            // Auto-unlock when BALUARD_PASSWORD is set so scripting/tests can
            // chain `add` → `archive` without an explicit `unlock` step.
            let mut handle = unlock_vault_direct(vault_path)?;
            let cipher_id = uuid::Uuid::parse_str(id).map_err(|_| "invalid UUID")?;
            handle.archive_cipher(cipher_id)?;
            println!("Cipher archived: {id}");
            Ok(())
        }
    }
}

pub fn handle_unarchive(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            ensure_unlocked_daemon(socket)?;
            let resp = client::request_to("vault.unarchive", id, socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("Cipher unarchived: {id}");
            Ok(())
        }
        ConnectMode::Direct => {
            // Auto-unlock when BALUARD_PASSWORD is set (see handle_archive).
            let mut handle = unlock_vault_direct(vault_path)?;
            let cipher_id = uuid::Uuid::parse_str(id).map_err(|_| "invalid UUID")?;
            handle.unarchive_cipher(cipher_id)?;
            println!("Cipher unarchived: {id}");
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

pub fn handle_rotation_abort(
    mode: ConnectMode,
    vault_path: &str,
    _socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => Err(
            "rotation-abort requires --direct mode. Use: baluard --direct devices rotation-abort"
                .into(),
        ),
        ConnectMode::Direct => {
            let path = Path::new(vault_path);
            let mut handle = VaultHandle::open(path)?;
            let dm = &mut handle.device_manager;

            let state = dm.epoch_state();
            if state != baluard_core::keys::epoch::EpochState::Rotating {
                println!("No rotation in progress. Current state: {:?}", state);
                return Ok(());
            }

            let elapsed = dm.rotation_stalled_secs(3600).unwrap_or(0);
            if elapsed == 0 {
                println!("Rotation has been in ROTATING state for less than 1 hour. Not aborting.");
                println!("Use --force or wait for the timeout to elapse.");
                return Ok(());
            }
            println!(
                "Rotation has been in ROTATING state for {}s (threshold: 3600s)",
                elapsed
            );

            // Safety: abort only if no cipher files at new epoch
            let pending_epoch = dm.pending_transaction().map(|tx| tx.new_epoch).unwrap_or(0);
            if pending_epoch > 0 {
                let entries_dir = path.join("entries");
                if entries_dir.exists() {
                    // Check if any cipher files reference the new epoch
                    // (simplified: just warn, since actual re-encryption uses staged .tmp writes)
                    println!(
                        "Warning: pending epoch is {}. Ensure no ciphers were re-encrypted.",
                        pending_epoch
                    );
                }
            }

            dm.abort_stalled_rotation()?;
            println!("Rotation aborted. Epoch reset to ACTIVE.");
            Ok(())
        }
    }
}

pub fn handle_rotation_status(
    mode: ConnectMode,
    vault_path: &str,
    _socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => Err(
            "rotation-status requires --direct mode. Use: baluard --direct devices rotation-status"
                .into(),
        ),
        ConnectMode::Direct => {
            let path = Path::new(vault_path);
            let handle = VaultHandle::open(path)?;
            let dm = &handle.device_manager;

            println!("Epoch: {}", dm.current_epoch());
            println!("State: {:?}", dm.epoch_state());
            println!(
                "Writes: {}",
                if dm.writes_allowed() {
                    "allowed"
                } else {
                    "BLOCKED"
                }
            );

            if dm.epoch_state() == baluard_core::keys::epoch::EpochState::Rotating {
                if let Some(elapsed) = dm.rotation_stalled_secs(3600) {
                    println!("Rotation elapsed: {}s", elapsed);
                }
                if let Some(tx) = dm.pending_transaction() {
                    println!("Pending new epoch: {}", tx.new_epoch);
                    println!("Initiator: {}", tx.initiating_device_id);
                }
            }

            Ok(())
        }
    }
}

pub fn handle_device_info(
    mode: ConnectMode,
    vault_path: &str,
    _socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            Err("device info requires --direct mode. Use: baluard --direct devices info".into())
        }
        ConnectMode::Direct => {
            let path = Path::new(vault_path);
            let handle = VaultHandle::open(path)?;
            let dm = &handle.device_manager;

            println!("Current device: {}", handle.device_id);
            println!("Epoch: {}", dm.current_epoch());
            println!("State: {:?}", dm.epoch_state());

            if let Some(entry) = handle.registry.devices.get(&handle.device_id) {
                println!("Name: {}", entry.name);
                println!("Enrolled at: {}", entry.enrolled_at);
                println!(
                    "Enrolled by: {}",
                    entry
                        .enrolled_by
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "(founding device)".into())
                );
                println!("Last seen epoch: {}", entry.last_seen_epoch);
            }

            // Show fleet activity
            let activity = baluard_core::device_manager::DeviceActivityIndex::read(path);
            if let Some(act) = activity.devices.get(&handle.device_id.to_string()) {
                println!("Last push: {}", act.last_push);
                println!(
                    "Last commit: {}",
                    &act.last_commit[..7.min(act.last_commit.len())]
                );
            }

            Ok(())
        }
    }
}

pub fn handle_device_revoke(
    mode: ConnectMode,
    vault_path: &str,
    _socket: Option<&str>,
    device_id_str: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let device_id: uuid::Uuid = device_id_str.parse().map_err(|_| "Invalid UUID")?;

    match mode {
        ConnectMode::Daemon => Err(
            "device revoke requires --direct mode. Use: baluard --direct devices revoke <UUID>"
                .into(),
        ),
        ConnectMode::Direct => {
            let path = Path::new(vault_path);
            let mut handle = VaultHandle::open(path)?;

            if device_id == handle.device_id {
                return Err(
                    "Cannot revoke the current device. Use force-evict from another device.".into(),
                );
            }

            if !handle.registry.devices.contains_key(&device_id) {
                return Err(format!("Device {} not found in registry", device_id).into());
            }

            let target_name = handle
                .registry
                .devices
                .get(&device_id)
                .map(|e| e.name.clone())
                .unwrap_or_else(|| "Unknown".into());

            println!("Revoking device: {} ({})", target_name, device_id);

            // Revoke + rekey: rotates root key, re-encrypts ciphers, writes keywrap
            let result = handle.revoke_device_and_rekey(device_id)?;

            // Clean activity index
            baluard_core::device_manager::DeviceActivityIndex::remove_device(path, &device_id)?;

            println!("Revoked device: {}", result.revoked_name);
            println!("New epoch: {}", result.new_epoch);
            println!("Device revoked. All ciphers re-encrypted. Keywrap written.");
            println!("IMPORTANT: Rotate git credentials (deploy key/PAT) on GitHub/GitLab.");
            Ok(())
        }
    }
}

/// Enroll this device into an existing vault using the recovery phrase.
///
/// Non-destructive: existing devices remain in the registry. Requires the
/// vault's `enrollment_policy` to be `Personal`. This is the "lost all
/// devices" recovery path — the recovery phrase proves root authority.
pub fn handle_enroll_with_phrase(
    mode: ConnectMode,
    vault_path: &str,
    phrase: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use baluard_core::device_manager::{DeviceManager, EnrollmentPayload};
    use baluard_core::vault::handle::VaultHandle;

    // Resolve phrase: flag > env var > prompt
    let phrase_str = match phrase {
        Some(p) => {
            warn_argv_secret("--phrase");
            p.to_string()
        }
        None => match std::env::var("BALUARD_RECOVERY_PHRASE") {
            Ok(p) => {
                warn_argv_secret("BALUARD_RECOVERY_PHRASE");
                p
            }
            Err(_) => {
                eprintln!("Recovery phrase required. Enter 24 words separated by spaces:");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                input.trim().to_string()
            }
        },
    };

    // Validate phrase shape (24 words)
    let word_count = phrase_str.split_whitespace().count();
    if word_count != 24 {
        return Err(format!("Recovery phrase must be exactly 24 words, got {word_count}").into());
    }

    // Warn the user about what this does
    eprintln!("⚠️  WARNING: This will add this device to an existing vault.");
    eprintln!("    The recovery phrase is the vault's root authority.");
    eprintln!("    Anyone with this phrase has full access to the vault.");
    eprintln!("    Only proceed if you trust the source of this phrase.");
    eprint!("Type 'enroll' to confirm: ");
    use std::io::Write;
    std::io::stderr().flush()?;
    let mut confirm = String::new();
    std::io::stdin().read_line(&mut confirm)?;
    if confirm.trim() != "enroll" {
        return Err("Aborted.".into());
    }

    match mode {
        ConnectMode::Daemon => {
            // Route through daemon
            let resp = client::request_to(
                "vault.enroll_with_phrase",
                &serde_json::json!({ "phrase": phrase_str }).to_string(),
                None,
            )?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("Device enrolled into existing vault via recovery phrase.");
            println!("Reload the vault to use the new enrollment.");
            Ok(())
        }
        ConnectMode::Direct => {
            let path = Path::new(vault_path);

            // Build EnrollmentPayload for this device
            let (x25519_secret, x25519_public) =
                baluard_core::crypto::hpke_wrap::generate_x25519_keypair();
            let (ed25519_signing, ed25519_verifying) =
                baluard_core::crypto::signature::generate_ed25519_keypair();

            let payload = EnrollmentPayload {
                device_id: uuid::Uuid::new_v4(),
                encryption_public_key: hex::encode(x25519_public.to_bytes()),
                signing_public_key: hex::encode(
                    baluard_core::crypto::signature::verifying_key_bytes(&ed25519_verifying),
                ),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                nonce: {
                    let mut bytes = [0u8; 32];
                    getrandom::getrandom(&mut bytes).expect("OS RNG");
                    hex::encode(bytes)
                },
                name: hostname().unwrap_or_else(|| "New Device".to_string()),
                vault_id: None,
                epoch: None,
                registry_version: None,
            };

            // Open DeviceManager and call enroll_with_recovery_phrase
            let mut dm = DeviceManager::load_from_vault(path)?;

            // PR-4 fix: fail-closed on settings read. Previously
            // `if let Ok(handle)` fell through to enrollment on read error.
            // Now a parse/open failure aborts enrollment.
            let handle = VaultHandle::open(path)
                .map_err(|e| format!("failed to read vault settings: {e}"))?;
            let settings = handle.get_settings().map_err(|e| format!("{e}"))?;

            // Peer review fix: pass the policy to the core method (PR-3
            // core-level enforcement). Don't pre-check here — the method
            // enforces. Pre-checking here is redundant and TOCTOU-prone.
            let result = dm.enroll_with_recovery_phrase(
                &payload,
                &phrase_str,
                x25519_secret,
                ed25519_signing,
                settings.enrollment_policy,
            )?;

            // Persist device-privkey for this device using the keys returned
            // by the method (same keys the registry and keywrap were built
            // with — guarantees consistency).
            let privkey_data = serde_json::json!({
                "device_id": result.device_id.to_string(),
                "x25519_private": hex::encode(result.x25519_secret.to_bytes()),
                "ed25519_private": hex::encode(result.ed25519_signing.to_bytes()),
            });
            let privkey_path = path.join("meta/device-privkey.json");
            let privkey_tmp = privkey_path.with_extension("json.tmp");
            std::fs::write(
                &privkey_tmp,
                serde_json::to_string_pretty(&privkey_data).unwrap(),
            )?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&privkey_tmp, std::fs::Permissions::from_mode(0o600));
            }
            std::fs::rename(&privkey_tmp, &privkey_path)?;
            let _ = baluard_core::vault::device_privkey::write_device_id(path, result.device_id);

            println!(
                "Device enrolled: {} ({})",
                result.entry.name, result.device_id
            );
            println!("Enrollment policy: phrase-based (non-destructive).");
            println!("Existing devices in the registry remain enrolled.");
            Ok(())
        }
    }
}

fn hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
}

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

/// P8b: append a signed revocation entry for a bad commit and push it.
#[cfg(feature = "git-sync")]
pub fn handle_sync_revoke(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    commit: &str,
    reason: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            let payload = serde_json::json!({ "commit": commit, "reason": reason }).to_string();
            let resp = client::request_to("sync.revoke", &payload, socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("{}", resp.payload);
            Ok(())
        }
        ConnectMode::Direct => sync_revoke_direct(vault_path, commit, reason),
    }
}

#[cfg(feature = "git-sync")]
fn sync_revoke_direct(
    vault_path: &str,
    commit: &str,
    reason: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(vault_path);
    // Revocation commits are signed: unlock first (devkey seal).
    let handle = unlock_vault_direct(vault_path)?;
    let seal = handle.devkey_seal();
    let engine = baluard_core::sync::engine::SyncEngine::new(
        path,
        &first_device_id(vault_path),
        seal.as_ref(),
    );
    engine.recover_state()?;
    let repo = engine.open_repo()?;
    let seq = engine.append_revocation(&repo, commit, reason)?;
    // Ride the normal push so the manifest reaches peers under branch
    // protection (append-only, never a force-push).
    engine.push(&repo, "origin")?;
    println!("Revoked {commit} (entry #{seq}). Manifest pushed.");
    Ok(())
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

/// `baluard sync clone <provider> <repo>`: clone a remote vault from a
/// provider into the local registry via the daemon's job flow
/// (clone_start -> poll clone_progress -> clone_finalize). Daemon-only: clone
/// registers a brand-new vault entry, which is a host-level operation that
/// does not fit the per-vault `--direct` model.
pub fn handle_sync_clone(
    mode: ConnectMode,
    _vault_path: &str,
    socket: Option<&str>,
    provider: &str,
    repo: &str,
    slug_override: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(mode, ConnectMode::Direct) {
        return Err(
            "Clone requires the daemon (it registers a new vault). Run without --direct.".into(),
        );
    }
    let host = match provider {
        "github" => "github.com",
        "gitlab" => "gitlab.com",
        "codeberg" => "codeberg.org",
        other => return Err(format!("Unknown provider: {other}").into()),
    };
    let clone_url = format!("https://{host}/{repo}.git");
    let slug = slug_override
        .map(str::to_string)
        .unwrap_or_else(|| repo.rsplit('/').next().unwrap_or(repo).to_string());

    let (out_slug, _path) = poll_clone_job(
        &start_clone_job(&clone_url, Some(provider), &slug, &slug, socket)?,
        socket,
    )?;
    println!("Unlock with: baluard --vault {out_slug} unlock");
    println!(
        "If this device was never enrolled, run: baluard enroll-with-phrase --vault {out_slug}"
    );
    Ok(())
}

/// POST `vault.clone_start` for a clone URL. `provider` is an optional
/// credential hint (stored provider token for https); empty = none.
fn start_clone_job(
    clone_url: &str,
    provider: Option<&str>,
    slug: &str,
    display_name: &str,
    socket: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let start_payload = serde_json::json!({
        "clone_url": clone_url,
        "provider": provider.unwrap_or(""),
        "slug": slug,
        "display_name": display_name,
    })
    .to_string();
    let resp = client::request_to("vault.clone_start", &start_payload, socket)?;
    if !resp.success {
        return Err(resp.error_message.into());
    }
    serde_json::from_str::<serde_json::Value>(&resp.payload)?["job_id"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "daemon returned no job_id".into())
}

/// Poll a clone job to completion (10-minute deadline), printing progress,
/// then finalize it. Returns (slug, path).
fn poll_clone_job(
    job_id: &str,
    socket: Option<&str>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
    let mut last_pct = u32::MAX;
    loop {
        if std::time::Instant::now() > deadline {
            return Err("clone timed out".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
        let resp = client::request_to(
            "vault.clone_progress",
            &serde_json::json!({ "job_id": job_id }).to_string(),
            socket,
        )?;
        if !resp.success {
            return Err(resp.error_message.into());
        }
        let v: serde_json::Value = serde_json::from_str(&resp.payload)?;
        let phase = v["phase"].as_str().unwrap_or("");
        let done = v["done"].as_bool().unwrap_or(false);
        let pct = v["pct"].as_u64().unwrap_or(0) as u32;
        if pct != last_pct {
            let objs = v["objects_received"].as_u64().unwrap_or(0);
            println!("Cloning... {pct}% ({objs} objects, {phase})");
            last_pct = pct;
        }
        if done || phase == "failed" {
            break;
        }
    }

    let resp = client::request_to(
        "vault.clone_finalize",
        &serde_json::json!({ "job_id": job_id }).to_string(),
        socket,
    )?;
    if !resp.success {
        return Err(resp.error_message.into());
    }
    let v: serde_json::Value = serde_json::from_str(&resp.payload)?;
    let slug = v["slug"].as_str().unwrap_or("?").to_string();
    let path = v["path"].as_str().unwrap_or("?").to_string();
    let objects = v["objects"].as_u64().unwrap_or(0);
    let bytes = v["bytes"].as_u64().unwrap_or(0);
    println!("Cloned vault '{slug}' to {path} ({objects} objects, {bytes} bytes).");
    Ok((slug, path))
}

/// `baluard sync clone-url <url>`: clone a vault from a plain git URL
/// (https://, ssh://, git@host:path) via the daemon's job flow. Daemon-only
/// for the same reason as `sync clone`: cloning registers a new vault.
/// Authentication comes from the user's own git setup — ssh-agent for ssh
/// URLs, a connected provider token (or BALUARD_GIT_TOKEN) for https.
/// Baluard never stores or prompts for credentials here.
pub fn handle_sync_clone_url(
    mode: ConnectMode,
    socket: Option<&str>,
    url: &str,
    slug_override: Option<&str>,
    provider_override: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(mode, ConnectMode::Direct) {
        return Err(
            "Clone requires the daemon (it registers a new vault). Run without --direct.".into(),
        );
    }
    if let Some(p) = provider_override {
        if !matches!(p, "github" | "gitlab" | "codeberg") {
            return Err(format!("Unknown provider: {p}").into());
        }
    }
    // Slug default: last URL path segment, minus a .git suffix.
    let slug = slug_override.map(str::to_string).unwrap_or_else(|| {
        url.trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("vault")
            .trim_end_matches("/")
            .strip_suffix(".git")
            .unwrap_or_else(|| {
                url.trim_end_matches('/')
                    .rsplit('/')
                    .next()
                    .unwrap_or("vault")
            })
            .to_string()
    });

    let job_id = start_clone_job(url, provider_override, &slug, &slug, socket)?;
    let (out_slug, path) = poll_clone_job(&job_id, socket)?;
    println!("Unlock with: baluard --vault {out_slug} unlock");
    println!(
        "If this device was never enrolled, run: baluard enroll-with-phrase --vault {out_slug}"
    );
    let _ = path;
    Ok(())
}

// ── Sync direct implementations ──

#[cfg(feature = "git-sync")]
fn sync_init_direct(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(vault_path);
    // P2: enrolled vaults refuse unsigned commits — unlock to load the
    // signing key (BALUARD_PASSWORD env or TTY prompt).
    let handle = unlock_vault_direct(vault_path)?;
    let seal = handle.devkey_seal();
    let engine = baluard_core::sync::engine::SyncEngine::new(
        path,
        &first_device_id(vault_path),
        seal.as_ref(),
    );
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
    let engine =
        baluard_core::sync::engine::SyncEngine::new(path, &first_device_id(vault_path), None);
    let repo = engine.open_repo()?;
    engine.add_remote(&repo, "origin", url)?;
    println!("Remote 'origin' set to: {url}");
    Ok(())
}

#[cfg(feature = "git-sync")]
fn sync_push_direct(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(vault_path);
    // P2: committing requires the signing key — unlock first.
    let handle = unlock_vault_direct(vault_path)?;
    let seal = handle.devkey_seal();
    let engine = baluard_core::sync::engine::SyncEngine::new(
        path,
        &first_device_id(vault_path),
        seal.as_ref(),
    );
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
    // P2: a pull may write a signed merge commit — unlock first. Also
    // invalidate the local-only cipher index (keyless): pulled ciphers land
    // on disk without touching it.
    let handle = unlock_vault_direct(vault_path)?;
    let seal = handle.devkey_seal();
    let engine = baluard_core::sync::engine::SyncEngine::new(
        path,
        &first_device_id(vault_path),
        seal.as_ref(),
    );
    engine.recover_state()?;
    let repo = engine.open_repo()?;
    let result = engine.pull(&repo, "origin")?;
    match result {
        baluard_core::sync::engine::PullResult::AlreadyUpToDate => println!("Already up to date."),
        baluard_core::sync::engine::PullResult::FastForward => {
            baluard_core::sync::engine::SyncEngine::invalidate_local_index(path);
            println!("Fast-forwarded to latest.")
        }
        baluard_core::sync::engine::PullResult::Merged => {
            baluard_core::sync::engine::SyncEngine::invalidate_local_index(path);
            println!("Merged remote changes.")
        }
        baluard_core::sync::engine::PullResult::Conflict { files, .. } => {
            let file_list = files.join(", ");
            return Err(format!("merge conflict in {file_list}. Resolution required.").into());
        }
    }
    Ok(())
}

#[cfg(feature = "git-sync")]
fn sync_status_direct(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(vault_path);
    let engine =
        baluard_core::sync::engine::SyncEngine::new(path, &first_device_id(vault_path), None);
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
    let engine =
        baluard_core::sync::engine::SyncEngine::new(path, &first_device_id(vault_path), None);
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

fn first_device_id(vault_path: &str) -> String {
    let path = Path::new(vault_path);
    let reg_path = path.join("meta/devices.json");
    if reg_path.exists() {
        if let Ok(data) = std::fs::read_to_string(&reg_path) {
            let reg: std::result::Result<baluard_core::devices::DeviceRegistry, _> =
                serde_json::from_str(&data);
            if let Ok(reg) = reg {
                // C5: identity is the device UUID (names are encrypted in
                // settings.enc; single-device vaults are the norm here).
                if let Some((id, _)) = reg.devices.iter().next() {
                    return id.to_string();
                }
            }
        }
    }
    String::new()
}

pub fn prompt_password(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    if std::env::var_os("BALUARD_NO_PROMPT").is_some() {
        return Ok(String::new());
    }
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        use std::io::{BufRead, Write};
        eprint!("{prompt}");
        std::io::stderr().flush()?;
        let mut buf = String::new();
        std::io::stdin().lock().read_line(&mut buf)?;
        return Ok(buf.trim_end_matches(&['\r', '\n'][..]).to_string());
    }
    match rpassword::prompt_password(prompt) {
        Ok(pw) => Ok(pw),
        Err(_) => {
            use std::io::{BufRead, Write};
            eprint!("{prompt}");
            std::io::stderr().flush()?;
            let mut buf = String::new();
            std::io::stdin().lock().read_line(&mut buf)?;
            Ok(buf.trim_end_matches(&['\r', '\n'][..]).to_string())
        }
    }
}

/// Warn that a secret arrived via a CLI flag or environment variable and is
/// therefore readable by any same-user process (`ps` output, `/proc/*/cmdline`,
/// `/proc/*/environ`). Audit C15: keep the flags (scripted flows need them),
/// but the interactive prompt must be the advertised path.
pub fn warn_argv_secret(flag: &str) {
    eprintln!(
        "warning: {flag} exposes its secret to other processes on this machine; prefer the interactive prompt."
    );
}

// ── Edit cipher ──

#[allow(clippy::too_many_arguments)] // Pre-existing: many fields, already structured
pub fn handle_edit(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    id: &str,
    name: Option<String>,
    favorite: Option<bool>,
    folder: Option<String>,
    tags: Option<Vec<String>>,
) -> Result<(), Box<dyn std::error::Error>> {
    if name.is_none() && favorite.is_none() && folder.is_none() && tags.is_none() {
        eprintln!("Nothing to edit. Use --name, --favorite, --folder, or --tags.");
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
    if let Some(ref t) = tags {
        let filtered: Vec<String> = t.iter().filter(|s| !s.is_empty()).cloned().collect();
        payload["tags"] = serde_json::json!(filtered);
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
            let mut handle = unlock_vault_direct(vault_path)?;

            let cipher_id = uuid::Uuid::parse_str(id).map_err(|_| "invalid UUID")?;
            let existing = handle.get_cipher(cipher_id)?;
            let existing_cipher = match existing {
                CipherRead::Decrypted(c) => c,
                CipherRead::Locked(_) => return Err("Cipher not found or vault locked".into()),
            };

            let input = baluard_core::types::CipherInput {
                name: name.clone().unwrap_or_else(|| existing_cipher.name.clone()),
                folder_id: folder
                    .as_ref()
                    .map(|f| {
                        uuid::Uuid::parse_str(f)
                            .map_err(|e| format!("Invalid folder UUID '{f}': {e}"))
                    })
                    .transpose()?
                    .or(existing_cipher.folder_id),
                kind: existing_cipher.kind.clone(),
                favorite: favorite.unwrap_or(existing_cipher.favorite),
                reprompt: existing_cipher.reprompt,
                notes: existing_cipher.notes.clone(),
                custom_fields: existing_cipher.custom_fields.clone(),
                created_at: Some(existing_cipher.created_at),
                password_history: existing_cipher.password_history.clone(),
                attachments: existing_cipher.attachments.clone(),
                archived: existing_cipher.archived,
                tags: tags
                    .map(|t| t.into_iter().filter(|s| !s.is_empty()).collect())
                    .unwrap_or_else(|| existing_cipher.tags.clone()),
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
        .ok_or("Usage: baluard settings set key=value")?;

    let payload = match key {
        "vault_timeout" => {
            // Validate via the core parser so the daemon never sees garbage.
            let policy = baluard_core::vault::manifest::VaultTimeout::from_token(value);
            serde_json::json!({ "vault_timeout": policy.as_token() })
        }
        "theme" => serde_json::json!({"theme": value}),
        "default_uri_match" => {
            let strategy = baluard_core::types::UriMatchStrategy::from_str_strict(value)
                .map_err(|e| format!("Invalid URI match strategy: {e}"))?;
            serde_json::json!({"default_uri_match": serde_json::to_value(strategy)?})
        }
        _ => {
            return Err(format!(
                "Unknown setting: {key}. Available: vault_timeout, theme, default_uri_match"
            )
            .into());
        }
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
    vault_path: &str,
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
            let mut handle = unlock_vault_direct(vault_path)?;
            let id = handle.create_folder(name)?;
            println!("Folder created: {id}");
            Ok(())
        }
    }
}

pub fn handle_folder_list(
    mode: ConnectMode,
    vault_path: &str,
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
            println!("{:<36} NAME", "ID");
            for f in &folders {
                let id = f["id"].as_str().unwrap_or("?");
                let name = f["name"].as_str().unwrap_or("?");
                println!("{id} {name}");
            }
            Ok(())
        }
        ConnectMode::Direct => {
            let handle = unlock_vault_direct(vault_path)?;
            let folders = handle.list_folders()?;
            if folders.is_empty() {
                println!("No folders.");
                return Ok(());
            }
            println!("{:<36} NAME", "ID");
            for f in &folders {
                println!("{} {}", f.id, f.name);
            }
            Ok(())
        }
    }
}

pub fn handle_folder_rename(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    id: &str,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let folder_id = uuid::Uuid::parse_str(id).map_err(|e| format!("Invalid folder UUID: {e}"))?;
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
            let mut handle = unlock_vault_direct(vault_path)?;
            handle.rename_folder(folder_id, name)?;
            println!("Folder renamed.");
            Ok(())
        }
    }
}

pub fn handle_folder_delete(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let folder_id = uuid::Uuid::parse_str(id).map_err(|e| format!("Invalid folder UUID: {e}"))?;
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
            let mut handle = unlock_vault_direct(vault_path)?;
            handle.delete_folder(folder_id)?;
            println!("Folder deleted. Entries moved to unassigned.");
            Ok(())
        }
    }
}

// ── Import ──

pub fn handle_import(
    socket: Option<&str>,
    format: &str,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let import_format = baluard_core::import::ImportFormat::from_name(format).ok_or_else(
        || -> Box<dyn std::error::Error> {
            format!(
                "Unknown format: {format}. Supported: {:?}",
                baluard_core::import::ImportFormat::all_names()
            )
            .into()
        },
    )?;

    ensure_unlocked_daemon(socket)?;

    // Pre-read file size check (prevent OOM on large files)
    const MAX_IMPORT_SIZE: u64 = 50 * 1024 * 1024; // 50MB
    let file_meta = std::fs::metadata(path).map_err(|e| format!("Failed to stat {path}: {e}"))?;
    if file_meta.len() > MAX_IMPORT_SIZE {
        return Err(format!(
            "Import file too large: {} bytes (max {} bytes)",
            file_meta.len(),
            MAX_IMPORT_SIZE
        )
        .into());
    }

    // For 1PUX, read as binary and base64-encode
    let payload = match import_format {
        baluard_core::import::ImportFormat::OnePassword1pux => {
            let bytes = std::fs::read(path).map_err(|e| format!("Failed to read {path}: {e}"))?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            serde_json::json!({"format": format, "data": b64}).to_string()
        }
        _ => {
            let file_data =
                std::fs::read_to_string(path).map_err(|e| format!("Failed to read {path}: {e}"))?;
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
    eprintln!(
        "WARNING: Export file will contain UNENCRYPTED secrets (passwords, cards, SSH keys)."
    );
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

    baluard_core::secret_file::write_secret_file(
        std::path::Path::new(path),
        resp.payload.as_bytes(),
    )
    .map_err(|e| format!("Failed to write {path}: {e}"))?;

    println!("Export complete: {path}");
    Ok(())
}

// ── Health Report ──

pub fn handle_health(socket: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    ensure_unlocked_daemon(socket)?;

    let resp = client::request_to("vault.health", "", socket)?;
    if !resp.success {
        return Err(resp.error_message.into());
    }

    let report: serde_json::Value = serde_json::from_str(&resp.payload)?;

    let weak = report["weak"].as_array().map(|a| a.len()).unwrap_or(0);
    let reused = report["reused"].as_array().map(|a| a.len()).unwrap_or(0);
    let old = report["old"].as_array().map(|a| a.len()).unwrap_or(0);

    println!("=== Password Health Report ===");
    println!();

    if weak > 0 {
        println!("Weak passwords ({}):", weak);
        for entry in report["weak"]
            .as_array()
            .expect("len > 0 verified by `weak` count")
        {
            println!(
                "  {} - {}",
                entry["name"].as_str().unwrap_or("?"),
                entry["reason"].as_str().unwrap_or("")
            );
        }
        println!();
    }

    if reused > 0 {
        println!("Reused passwords ({}):", reused);
        for entry in report["reused"]
            .as_array()
            .expect("len > 0 verified by `reused` count")
        {
            println!(
                "  {} - {}",
                entry["name"].as_str().unwrap_or("?"),
                entry["reason"].as_str().unwrap_or("")
            );
        }
        println!();
    }

    if old > 0 {
        println!("Old passwords ({}):", old);
        for entry in report["old"]
            .as_array()
            .expect("len > 0 verified by `old` count")
        {
            println!(
                "  {} - {}",
                entry["name"].as_str().unwrap_or("?"),
                entry["reason"].as_str().unwrap_or("")
            );
        }
        println!();
    }

    if weak == 0 && reused == 0 && old == 0 {
        println!("All passwords are healthy. No issues found.");
    }

    Ok(())
}

// ── Attachment Commands ──

pub fn handle_attach_upload(
    socket: Option<&str>,
    cipher_id: &str,
    file_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_unlocked_daemon(socket)?;

    let mut data = std::fs::read(file_path)?;
    if data.len() > baluard_core::vault::attachment::MAX_ATTACHMENT_SIZE {
        return Err(format!("File too large: {} bytes (max 1.9MB)", data.len()).into());
    }

    let filename = std::path::Path::new(file_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "attachment".into());

    use base64::Engine;
    let payload = serde_json::json!({
        "cipher_id": cipher_id,
        "filename": filename,
        "data_base64": base64::engine::general_purpose::STANDARD.encode(&data),
    })
    .to_string();

    // Zeroize file data after encoding
    use zeroize::Zeroize;
    data.zeroize();

    let resp = client::request_to("vault.attach_upload", &payload, socket)?;
    if !resp.success {
        return Err(resp.error_message.into());
    }

    let result: serde_json::Value = serde_json::from_str(&resp.payload)?;
    println!("Uploaded: {} ({})", result["filename"], result["id"]);
    Ok(())
}

pub fn handle_attach_download(
    socket: Option<&str>,
    cipher_id: &str,
    attachment_id: &str,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_unlocked_daemon(socket)?;

    let payload = serde_json::json!({
        "cipher_id": cipher_id,
        "attachment_id": attachment_id,
    })
    .to_string();

    let resp = client::request_to("vault.attach_download", &payload, socket)?;
    if !resp.success {
        return Err(resp.error_message.into());
    }

    let result: serde_json::Value = serde_json::from_str(&resp.payload)?;
    use base64::Engine;
    let data_b64 = result["data_base64"]
        .as_str()
        .ok_or_else(|| "daemon response missing data_base64 field".to_string())?;
    let mut data = base64::engine::general_purpose::STANDARD.decode(data_b64)?;
    // Owner-only from the first byte; rename replaces any pre-planted symlink (C14)
    baluard_core::secret_file::write_secret_file(std::path::Path::new(output_path), &data)?;

    // Zeroize after writing
    use zeroize::Zeroize;
    data.zeroize();

    println!(
        "Downloaded: {} ({} bytes) -> {}",
        result["filename"], result["size"], output_path
    );
    Ok(())
}

pub fn handle_attach_delete(
    socket: Option<&str>,
    cipher_id: &str,
    attachment_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_unlocked_daemon(socket)?;

    let payload = serde_json::json!({
        "cipher_id": cipher_id,
        "attachment_id": attachment_id,
    })
    .to_string();

    let resp = client::request_to("vault.attach_delete", &payload, socket)?;
    if !resp.success {
        return Err(resp.error_message.into());
    }

    println!("Attachment deleted.");
    Ok(())
}

pub fn handle_attach_list(
    socket: Option<&str>,
    cipher_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_unlocked_daemon(socket)?;

    let payload = serde_json::json!({ "id": cipher_id }).to_string();
    let resp = client::request_to("vault.get_cipher", &payload, socket)?;
    if !resp.success {
        return Err(resp.error_message.into());
    }

    let cipher: serde_json::Value = serde_json::from_str(&resp.payload)?;
    let attachments = cipher["attachments"].as_array();

    match attachments {
        Some(list) if !list.is_empty() => {
            println!("Attachments for {}:", cipher_id);
            for a in list {
                let size = a["size"].as_u64().unwrap_or(0);
                let size_str = if size > 1024 * 1024 {
                    format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
                } else if size > 1024 {
                    format!("{:.1} KB", size as f64 / 1024.0)
                } else {
                    format!("{} bytes", size)
                };
                println!(
                    "  {} {} {} {}",
                    a["id"].as_str().unwrap_or("?"),
                    a["filename"].as_str().unwrap_or("?"),
                    size_str,
                    a["mime_type"].as_str().unwrap_or("")
                );
            }
        }
        _ => println!("No attachments found for {}.", cipher_id),
    }

    Ok(())
}

// ── Tag commands ──

pub fn handle_tag_create(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            ensure_unlocked_daemon(socket)?;
            let resp = client::request_to("tag.create", name, socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("Tag '{}' created.", name);
            Ok(())
        }
        ConnectMode::Direct => {
            let mut handle = unlock_vault_direct(vault_path)?;
            handle.create_tag(name)?;
            println!("Tag '{}' created.", name);
            Ok(())
        }
    }
}

pub fn handle_tag_list(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            ensure_unlocked_daemon(socket)?;
            let resp = client::request_to("tag.list", "", socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            let tags: Vec<String> = serde_json::from_str(&resp.payload)?;
            if tags.is_empty() {
                println!("No tags found.");
            } else {
                for tag in &tags {
                    println!("{tag}");
                }
            }
            Ok(())
        }
        ConnectMode::Direct => {
            let handle = unlock_vault_direct(vault_path)?;
            let tags = handle.list_tags()?;
            if tags.is_empty() {
                println!("No tags found.");
            } else {
                for tag in &tags {
                    println!("{tag}");
                }
            }
            Ok(())
        }
    }
}

pub fn handle_tag_rename(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    old: &str,
    new: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            ensure_unlocked_daemon(socket)?;
            let payload = serde_json::json!({"old": old, "new": new}).to_string();
            let resp = client::request_to("tag.rename", &payload, socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("Tag '{}' renamed to '{}'.", old, new);
            Ok(())
        }
        ConnectMode::Direct => {
            let mut handle = unlock_vault_direct(vault_path)?;
            let updated = handle.rename_tag(old, new)?;
            println!(
                "Tag '{}' renamed to '{}' ({} entries updated).",
                old, new, updated
            );
            Ok(())
        }
    }
}

pub fn handle_tag_delete(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            ensure_unlocked_daemon(socket)?;
            let resp = client::request_to("tag.delete", name, socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            let result: serde_json::Value = serde_json::from_str(&resp.payload)?;
            let updated = result["updated"].as_u64().unwrap_or(0);
            println!("Tag '{}' removed from {} entries.", name, updated);
            Ok(())
        }
        ConnectMode::Direct => {
            let mut handle = unlock_vault_direct(vault_path)?;
            let updated = handle.delete_tag(name)?;
            println!("Tag '{}' removed from {} entries.", name, updated);
            Ok(())
        }
    }
}

// ── Vaults ──

// ── Passkey commands (Phase 1) ──

pub fn handle_passkey_list(
    mode: &ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    rp_id: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = serde_json::json!({
        "rp_id": rp_id,
    })
    .to_string();
    match mode {
        ConnectMode::Daemon => {
            let resp = client::request_to("passkey.list", &payload, socket)?;
            if !resp.success {
                return Err(format!("Daemon error: {}", resp.error_message).into());
            }
            let parsed: serde_json::Value = serde_json::from_str(&resp.payload).unwrap_or_default();
            println!("{}", serde_json::to_string_pretty(&parsed)?);
        }
        ConnectMode::Direct => {
            let handle = unlock_vault_direct(vault_path)?;
            let metas = handle.list_cipher_meta()?;
            let mut passkeys = Vec::new();
            use baluard_core::vault::handle::CipherRead;
            for meta in &metas {
                if meta.cipher_type != baluard_core::types::CipherType::Login {
                    continue;
                }
                if let Ok(CipherRead::Decrypted(ref c)) = handle.get_cipher(meta.id) {
                    if let baluard_core::types::CipherKind::Login(data) = &c.kind {
                        if let Some(ref fido2_list) = data.fido2_credentials {
                            for pk in fido2_list {
                                if rp_id.is_none_or(|rp| pk.rp_id == rp) {
                                    passkeys.push(serde_json::json!({
                                        "id": meta.id,
                                        "name": meta.name,
                                        "rp_id": pk.rp_id,
                                        "rp_name": pk.rp_name,
                                        "user_name": pk.user_name,
                                        "counter": pk.counter,
                                        "credential_id": pk.credential_id,
                                        "private_key_missing": pk.private_key_missing,
                                        "created": pk.creation_date,
                                    }));
                                }
                            }
                        }
                    }
                }
            }
            println!("{}", serde_json::to_string_pretty(&passkeys)?);
        }
    }
    Ok(())
}

pub fn handle_passkey_delete(
    mode: &ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    id: &str,
    credential_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = serde_json::json!({ "id": id, "credential_id": credential_id }).to_string();
    match mode {
        ConnectMode::Daemon => {
            let resp = client::request_to("passkey.delete", &payload, socket)?;
            if !resp.success {
                return Err(format!("Daemon error: {}", resp.error_message).into());
            }
        }
        ConnectMode::Direct => {
            let mut handle = unlock_vault_direct(vault_path)?;
            let uuid = uuid::Uuid::parse_str(id)?;
            use baluard_core::vault::handle::CipherRead;
            let cipher = match handle.get_cipher(uuid) {
                Ok(CipherRead::Decrypted(c)) => c,
                _ => return Err("Cipher not found".into()),
            };
            match &cipher.kind {
                baluard_core::types::CipherKind::Login(data) => {
                    let mut fido2_list = match data.fido2_credentials.clone() {
                        Some(list) if !list.is_empty() => list,
                        _ => return Err("Cipher has no passkeys".into()),
                    };
                    let before = fido2_list.len();
                    fido2_list.retain(|pk| pk.credential_id != credential_id);
                    if fido2_list.len() == before {
                        return Err(format!("Credential not found: {credential_id}").into());
                    }
                    if fido2_list.is_empty()
                        && data.username.is_none()
                        && data.password.is_none()
                        && data.uris.is_empty()
                        && data.totp_uri.is_none()
                    {
                        drop(cipher);
                        return handle.delete_cipher(uuid).map_err(|e| e.into());
                    }
                    let updated_data = baluard_core::types::LoginData {
                        fido2_credentials: if fido2_list.is_empty() {
                            None
                        } else {
                            Some(fido2_list)
                        },
                        ..data.clone()
                    };
                    let input = baluard_core::types::CipherInput {
                        name: cipher.name.clone(),
                        folder_id: cipher.folder_id,
                        favorite: cipher.favorite,
                        reprompt: cipher.reprompt,
                        tags: cipher.tags.clone(),
                        kind: baluard_core::types::CipherKind::Login(updated_data),
                        notes: cipher.notes.clone(),
                        custom_fields: cipher.custom_fields.clone(),
                        created_at: Some(cipher.created_at),
                        password_history: cipher.password_history.clone(),
                        attachments: cipher.attachments.clone(),
                        archived: cipher.archived,
                    };
                    drop(cipher);
                    handle.update_cipher(uuid, &input)?;
                }
                _ => return Err("Not a Login cipher".into()),
            }
        }
    }
    println!("Passkey deleted.");
    Ok(())
}

pub fn handle_passkey_rename(
    mode: &ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    id: &str,
    credential_id: &str,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload =
        serde_json::json!({ "id": id, "credential_id": credential_id, "name": name }).to_string();
    match mode {
        ConnectMode::Daemon => {
            let resp = client::request_to("passkey.rename", &payload, socket)?;
            if !resp.success {
                return Err(format!("Daemon error: {}", resp.error_message).into());
            }
        }
        ConnectMode::Direct => {
            let mut handle = unlock_vault_direct(vault_path)?;
            let uuid = uuid::Uuid::parse_str(id)?;
            use baluard_core::vault::handle::CipherRead;
            let cipher = match handle.get_cipher(uuid) {
                Ok(CipherRead::Decrypted(c)) => c,
                _ => return Err("Cipher not found".into()),
            };
            match &cipher.kind {
                baluard_core::types::CipherKind::Login(data) => {
                    let mut fido2_list = match data.fido2_credentials.clone() {
                        Some(list) if !list.is_empty() => list,
                        _ => return Err("Cipher has no passkeys".into()),
                    };
                    let found = fido2_list
                        .iter_mut()
                        .find(|pk| pk.credential_id == credential_id);
                    match found {
                        Some(pk) => pk.name = Some(name.to_string()),
                        None => return Err(format!("Credential not found: {credential_id}").into()),
                    }
                    let updated_data = baluard_core::types::LoginData {
                        fido2_credentials: Some(fido2_list),
                        ..data.clone()
                    };
                    let input = baluard_core::types::CipherInput {
                        name: cipher.name.clone(),
                        folder_id: cipher.folder_id,
                        favorite: cipher.favorite,
                        reprompt: cipher.reprompt,
                        tags: cipher.tags.clone(),
                        kind: baluard_core::types::CipherKind::Login(updated_data),
                        notes: cipher.notes.clone(),
                        custom_fields: cipher.custom_fields.clone(),
                        created_at: Some(cipher.created_at),
                        password_history: cipher.password_history.clone(),
                        attachments: cipher.attachments.clone(),
                        archived: cipher.archived,
                    };
                    handle.update_cipher(uuid, &input)?;
                }
                _ => return Err("Not a Login cipher".into()),
            }
        }
    }
    println!("Passkey renamed.");
    Ok(())
}

pub fn handle_vaults(action: &VaultAction, cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        VaultAction::Add { path, slug } => vaults_add(path, slug.as_deref()),
        VaultAction::List => vaults_list(cli),
        VaultAction::Switch { slug } => vaults_switch(slug, cli),
        VaultAction::Close { slug } => vaults_close(slug, cli),
        VaultAction::SetDefault { slug } => vaults_set_default(slug, cli),
        VaultAction::Prune { dry_run } => vaults_prune(*dry_run),
        VaultAction::Detach {
            slug,
            delete_from_disk,
        } => vaults_detach(slug, *delete_from_disk, cli),
    }
}

/// `baluard vaults add <path>`: register an already-existing vault
/// directory (moved from another machine, restored backup, manual clone)
/// so it appears in the app again. Non-destructive: nothing is opened,
/// switched, or unsealed. Fails closed on directories without a
/// `.baluard` marker — only real Baluard vaults get registered.
fn vaults_add(
    path_str: &str,
    slug_override: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw = Path::new(path_str);
    if !raw.is_dir() {
        return Err(format!("Not a directory: {path_str}").into());
    }
    let path = std::fs::canonicalize(raw).map_err(|e| format!("Cannot resolve {path_str}: {e}"))?;

    let marker =
        baluard_core::vault::registry::BaluardMarker::read_from_vault(&path)?.ok_or_else(|| {
            format!(
                "Not a Baluard vault: {} has no .baluard marker.",
                path.display()
            )
        })?;

    // Slug: flag > marker slug > directory name. Validated either way —
    // it keys registry lookups and daemon paths (C11 class).
    let slug = slug_override
        .map(str::to_string)
        .or_else(|| {
            if marker.slug.is_empty() {
                None
            } else {
                Some(marker.slug.clone())
            }
        })
        .unwrap_or_else(|| {
            path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "vault".to_string())
        });
    baluard_core::vault::slug::validate_slug(&slug)
        .map_err(|e| format!("Invalid vault slug '{slug}': {e}"))?;

    let mut reg = baluard_core::vault::registry::VaultRegistry::load_locked()?;
    if reg.exists(&slug) {
        return Err(format!(
            "A vault '{slug}' is already registered. Pick a different --slug or remove the existing entry first."
        )
        .into());
    }
    // Same directory under a different slug = double-attach; refuse. Canonicalize
    // existing registry paths so symlinks and alternate spellings cannot bypass.
    if reg
        .vaults
        .values()
        .any(|v| std::fs::canonicalize(&v.path).map_or_else(|_| v.path == path, |cp| cp == path))
    {
        return Err(
            "This directory is already registered under a different slug. Detach it first: baluard vaults detach <slug>"
                .into(),
        );
    }

    // Best-effort remote URL (nice for `vaults list`; never fatal).
    let remote_url = std::process::Command::new("git")
        .arg("-C")
        .arg(&path)
        .args(["config", "--get", "remote.origin.url"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|u| !u.is_empty());

    let vault_id = marker.vault_id;
    reg.add(baluard_core::vault::registry::VaultEntry {
        slug: slug.clone(),
        display_name: slug.clone(),
        path: path.clone(),
        provider: None,
        remote_url,
        last_synced: None,
        last_opened: None,
        vault_id,
    })?;
    reg.save_locked()?;

    println!("Registered vault '{slug}' at {}.", path.display());
    println!("Open it with:     baluard vaults switch {slug}");
    println!("If this device was never enrolled, run: baluard enroll-with-phrase --vault {slug}");
    Ok(())
}

/// Print every registered vault with its in-daemon state. Prefers the
/// daemon's `vaults.list` (which joins the registry with the in-memory
/// map) so the STATE column is accurate; falls back to a registry-only
/// read when the daemon is not running.
fn vaults_list(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    // Try the daemon first for live state.
    let daemon_rows: Option<Vec<serde_json::Value>> = (|| {
        let resp = client::request_to("vaults.list", "", cli.socket.as_deref()).ok()?;
        if !resp.success {
            return None;
        }
        let v: serde_json::Value = serde_json::from_str(&resp.payload).ok()?;
        v.get("vaults").and_then(|a| a.as_array()).cloned()
    })();

    if let Some(rows) = daemon_rows {
        if rows.is_empty() {
            println!("No vaults registered.");
            println!("Create one with: baluard init");
            return Ok(());
        }
        println!(
            "  {:<24} {:<20} {:<10} {:<10} PROVIDER",
            "SLUG", "NAME", "STATE", "ACTIVE"
        );
        println!("  {}", "-".repeat(82));
        for row in &rows {
            let slug = row["slug"].as_str().unwrap_or("");
            let name = row["display_name"].as_str().unwrap_or("");
            let presence = row["presence"].as_str().unwrap_or("closed");
            let active = if row["active"].as_bool().unwrap_or(false) {
                "*"
            } else {
                " "
            };
            let provider = row["provider"].as_str().unwrap_or("");
            println!(
                "  {:<24} {:<20} {:<10} {:<9} {}",
                slug, name, presence, active, provider
            );
        }
        println!();
        println!(
            "  STATE: unlocked = keys resident | locked = open, keys zeroized | closed = not loaded"
        );
        println!("  ACTIVE: '*' marks the live focus vault.");
        return Ok(());
    }

    // Daemon not reachable: fall back to a registry-only read.
    let reg = baluard_core::vault::registry::VaultRegistry::load_locked().unwrap_or_default();
    if reg.vaults.is_empty() {
        println!("No vaults registered.");
        println!("Create one with: baluard init");
        return Ok(());
    }
    eprintln!("(daemon not reachable; showing registry only — state column unavailable)");
    println!("{:<30} {:<20} PATH", "SLUG", "NAME");
    println!("{}", "-".repeat(80));
    let mut slugs: Vec<&str> = reg.vaults.keys().map(|s| s.as_str()).collect();
    slugs.sort();
    for slug in slugs {
        let entry = reg
            .vaults
            .get(slug)
            .expect("slug sourced from vaults.keys()");
        let active_marker = if reg.active_vault.as_deref() == Some(slug) {
            "*"
        } else {
            " "
        };
        println!(
            "{active_marker}{:<29} {:<20} {}",
            slug,
            entry.display_name,
            entry.path.display()
        );
    }
    Ok(())
}

/// Flip the live active vault via the daemon. If the target is locked (or
/// not yet loaded), prompt for the master password and unlock it first.
/// Per the Phase 6 keep-unlocked model, switching to an already-unlocked
/// vault is instant — no KDF, no re-prompt, and the previously active
/// vault stays unlocked on its own auto-lock schedule.
fn vaults_switch(slug: &str, cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    // First: ensure the slug is registered. The daemon errors if it isn't.
    let reg = baluard_core::vault::registry::VaultRegistry::load_locked()?;
    if !reg.exists(slug) {
        eprintln!("error: vault '{slug}' not found in registry");
        eprintln!("Registered vaults:");
        for s in reg.list_slugs() {
            eprintln!("  {s}");
        }
        std::process::exit(1);
    }

    // Try the daemon switch. If the slug isn't open in the map yet, the
    // daemon returns an error pointing at `baluard unlock --vault <slug>`;
    // we drive that unlock inline so `switch` is one command.
    let payload = serde_json::json!({ "slug": slug }).to_string();
    let resp = client::request_to("vaults.switch", &payload, cli.socket.as_deref())?;
    if resp.success {
        println!("Active vault: {slug}");
        return Ok(());
    }

    // The daemon refused (slug not open, or locked). Treat either case as
    // "unlock then re-switch". Prompt for the master password and call
    // vault.unlock with the slug — that opens + unlocks + inserts into
    // the map + makes it active in one round-trip.
    if resp.error_message.contains("not open")
        || resp.error_message.contains("locked")
        || resp.error_message.contains("No active")
    {
        let mut password = prompt_password(&format!("Master password for '{slug}': "))?;
        let unlock_payload = serde_json::json!({ "slug": slug, "password": password }).to_string();
        password.zeroize();
        let unlock_resp =
            client::request_to("vault.unlock", &unlock_payload, cli.socket.as_deref())?;
        if !unlock_resp.success {
            return Err(format!("Unlock failed: {}", unlock_resp.error_message).into());
        }
        println!("Active vault: {slug} (unlocked)");
        return Ok(());
    }

    Err(resp.error_message.into())
}

/// Remove a vault from the daemon's in-memory map. Keys zeroize once any
/// in-flight request drains. The vault stays registered for re-opening.
fn vaults_close(slug: &str, cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let payload = serde_json::json!({ "slug": slug }).to_string();
    let resp = client::request_to("vaults.close", &payload, cli.socket.as_deref())?;
    if !resp.success {
        return Err(resp.error_message.into());
    }
    println!("Vault '{slug}' closed (removed from daemon map).");
    Ok(())
}

/// Persist `active_vault` in the registry so the next daemon launch picks
/// this vault as the default focus.
fn vaults_set_default(slug: &str, cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let payload = serde_json::json!({ "slug": slug }).to_string();
    let resp = client::request_to("vaults.set_active", &payload, cli.socket.as_deref())?;
    if !resp.success {
        return Err(resp.error_message.into());
    }
    println!("Default vault for next launch: {slug}");
    Ok(())
}

/// Drop registry entries whose vault directory no longer exists on disk.
/// Reads/writes the registry directly (no daemon needed), so it works even
/// when the daemon is not running. If the active vault is among the stale,
/// the first remaining slug (alphabetical) is promoted so a daemon launch
/// still auto-selects a usable vault instead of landing on a stale pointer.
fn vaults_prune(dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    use baluard_core::vault::registry::VaultRegistry;

    let mut reg = VaultRegistry::load_locked()?;

    // Collect stale slugs: the entry exists in the registry but its vault
    // directory is gone. Sorted for stable, reviewable output.
    let stale: Vec<String> = {
        let mut s: Vec<String> = reg
            .vaults
            .iter()
            .filter(|(_, e)| !std::path::Path::new(&e.path).exists())
            .map(|(slug, _)| slug.clone())
            .collect();
        s.sort();
        s
    };

    if stale.is_empty() {
        println!(
            "No stale vault entries. Registry has {} vault(s).",
            reg.vaults.len()
        );
        return Ok(());
    }

    if dry_run {
        println!("Would remove {} stale entr(y/ies):", stale.len());
    } else {
        println!("Removing {} stale entr(y/ies):", stale.len());
    }
    for slug in &stale {
        let path = reg
            .vaults
            .get(slug)
            .map(|e| e.path.display().to_string())
            .unwrap_or_default();
        println!("  {slug}  ->  {path}");
    }

    if dry_run {
        println!("\n(dry run; registry unchanged. Re-run without --dry-run to apply.)");
        return Ok(());
    }

    for slug in &stale {
        reg.remove(slug); // also clears active_vault if it was this slug
    }

    // Promote a successor if pruning nulled the active pointer.
    if reg.active_vault.is_none() && !reg.vaults.is_empty() {
        let mut remaining: Vec<&String> = reg.vaults.keys().collect();
        remaining.sort();
        if let Some(next) = remaining.first() {
            reg.active_vault = Some((*next).clone());
            println!("\nActive vault was pruned; promoted '{next}'.");
        }
    }

    let kept = reg.vaults.len();
    reg.save_locked()?;
    println!("\nDone. {kept} vault(s) remain in the registry.");
    Ok(())
}

/// Detach a vault from Baluard (drop the registry entry). Without
/// `--delete-from-disk` the directory is left untouched; with it the
/// directory is removed after the user types the slug a second time as
/// confirmation. The two-step gate mirrors the desktop modal's "type the
/// vault name" arm so the CLI cannot silently nuke a vault with one
/// command.
fn vaults_detach(
    slug: &str,
    delete_from_disk: bool,
    cli: &Cli,
) -> Result<(), Box<dyn std::error::Error>> {
    if delete_from_disk {
        eprintln!("About to detach AND delete vault '{slug}' from disk. This is permanent.");
        eprintln!("Type the slug '{slug}' to confirm:");
        let mut confirm = String::new();
        std::io::stdin().read_line(&mut confirm)?;
        let confirm = confirm.trim();
        if confirm != slug {
            return Err(format!(
                "Confirmation does not match (got '{confirm}', expected '{slug}'). Aborted."
            )
            .into());
        }
    }

    // `destructive` carries the same bool as `delete_from_disk`. The CLI
    // has already required the user to retype the slug above, so the
    // .baluard marker gate would just be a second, redundant check
    // that traps users when their marker is stale/corrupted (which is
    // exactly the case this command exists to clean up). Binding once
    // makes the "they are always the same" invariant explicit at the
    // call site.
    let destructive = delete_from_disk;
    let payload = serde_json::json!({
        "slug": slug,
        "delete_from_disk": destructive,
        "force": destructive,
    })
    .to_string();
    let resp = client::request_to("vaults.detach", &payload, cli.socket.as_deref())?;
    if !resp.success {
        return Err(resp.error_message.into());
    }

    if delete_from_disk {
        println!("Detached '{slug}' from Baluard and deleted its directory from disk.");
    } else {
        println!(
            "Detached '{slug}' from Baluard. Directory left on disk (re-attach with `baluard open <path>`)."
        );
    }
    Ok(())
}
