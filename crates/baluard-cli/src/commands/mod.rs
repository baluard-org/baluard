//! CLI command implementations.
//!
//! Each vault command supports two modes:
//! - Daemon: routes through baluard-daemon via Unix socket (default)
//! - Direct: calls baluard-core directly (fallback, --direct flag)

use crate::Cli;
use crate::CollectionAction;
use crate::ConnectMode;
use crate::MemberAction;
use crate::ProviderAction;
use crate::VaultAction;
use crate::client;

use std::path::Path;

use baluard_core::types::{CipherInput, KdfProfile};
use baluard_core::vault::handle::{CipherRead, VaultHandle};
use base64::Engine;
use zeroize::{Zeroize, Zeroizing};

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
    family: bool,
    json: bool,
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

    if !json {
        println!("Creating vault...");
    }

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
            if !json {
                println!("Vault path: {}", p.display());
            }
            p
        } else {
            std::path::PathBuf::from(vault_path)
        }
    } else {
        std::path::PathBuf::from(vault_path)
    };

    let (mut handle, secrets) =
        baluard_core::vault::creation::VaultCreator::new(&resolved_path, &password, "this-device")
            .kdf_profile(profile)
            .profile(display_name.clone(), None)
            .slug(slug.clone())
            .preferences(theme, lang.clone(), vault_timeout)
            .family(family)
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
            merge_opt_in: None,
            merge_ceiling_seen: false,
        })?;
        reg.set_active(s)?;
        reg.save_locked()?;
    }

    // Family wizard (interactive only; JSON mode stays one machine line
    // and scripts mint invites through the daemon routes). The kit
    // already exists at birth; the phrase prints exactly once.
    if family && !json && is_tty() {
        print_family_wizard(&mut handle, &secrets);
    }

    // Scripting/harness mode: one JSON line, no decorated output, no
    // interactive verification. Callers parse the phrase to enroll other
    // devices (multi-device E2E flows).
    if json {
        println!(
            "{}",
            serde_json::json!({
                "vault_id": secrets.vault_id.to_string(),
                "device_id": secrets.device_id.to_string(),
                "path": resolved_path.display().to_string(),
                "slug": slug,
                "trust_fingerprint": hex::encode(secrets.trust_fingerprint),
                "recovery_phrase": secrets.recovery_phrase.phrase(),
            })
        );
        return Ok(());
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

/// Family-spaces wizard (plan section 7): show the kit phrase once,
/// then optionally mint the co-guardian invite and per-child invites
/// with per-person collections. Interactive-only; every step after the
/// kit display is skippable.
fn print_family_wizard(
    handle: &mut baluard_core::vault::VaultHandle,
    secrets: &baluard_core::vault::creation::CeremonySecrets,
) {
    use baluard_core::vault::collections::CollectionAccess;
    use baluard_core::vault::members::MemberRole;
    use baluard_core::vault::templates::{EmbeddedTemplate, TemplateGrant};

    if let Some(kit) = &secrets.kit_phrase {
        println!();
        println!("=== FAMILY RECOVERY KIT (write this down, separately!) ===");
        let words: Vec<&str> = kit.split_whitespace().collect();
        for (i, word) in words.iter().enumerate() {
            if i % 8 != 0 {
                print!(" ");
            }
            print!("{:>2}. {:<8}", i + 1, word);
            if i % 8 == 7 || i == words.len() - 1 {
                println!();
            }
        }
        println!("=== END FAMILY RECOVERY KIT ===");
        println!("This phrase recovers the FAMILY vault when no guardian");
        println!("can act. Store it apart from the vault recovery phrase.");
    }

    let shared = handle
        .get_settings()
        .ok()
        .and_then(|s| s.family_shared_collection);
    let Some(shared_id) = shared else {
        return; // not a family vault or setup incomplete: nothing to mint
    };
    let shared_grants = |name: &str| EmbeddedTemplate {
        name: name.into(),
        grants: vec![TemplateGrant {
            collection_id: shared_id,
            access: CollectionAccess::Read,
            expires_in_days: None,
        }],
    };

    // Co-guardian: Admin rank, the Level 2 code check happens during
    // their own join (the wizard only mints the invite).
    let guardian =
        prompt_password_optional("Invite a co-guardian now? Their name (Enter to skip): ");
    if !guardian.is_empty() {
        let username =
            prompt_password_optional("  Their forge username for repo access (Enter for none): ");
        let username = (!username.is_empty()).then_some(username);
        match handle.invite_create_with_embedded_grants(
            MemberRole::Admin,
            username,
            shared_grants("Co-guardian (Shared read)"),
            false,
        ) {
            Ok(code) => {
                println!("  Co-guardian invite created.");
                println!("  Code (send it to them): {code}");
                println!("  They verify identity with the Level 2 code check");
                println!("  during their own join - nothing to do here.");
            }
            Err(e) => eprintln!("  error: co-guardian invite failed: {e}"),
        }
    }

    // Children and wards: Editor rank, flagged minor, one collection
    // per child. Forge username optional - without one they sync
    // through a guardian's pull (no repo seat).
    loop {
        let child = prompt_password_optional("Add a child or ward? Their name (Enter to finish): ");
        if child.is_empty() {
            break;
        }
        let username = prompt_password_optional(
            "  Their forge username (Enter for none - they sync via a guardian): ",
        );
        let username = (!username.is_empty()).then_some(username);
        let made = (|| -> Result<String, baluard_core::BaluardError> {
            let collection = handle.collection_create(&child)?;
            let mut grants = shared_grants(&format!("{child} (Shared read + own collection)"));
            grants.grants.push(TemplateGrant {
                collection_id: collection,
                access: CollectionAccess::Write,
                expires_in_days: None,
            });
            let code = handle.invite_create_with_embedded_grants(
                MemberRole::Editor,
                username,
                grants,
                true,
            )?;
            Ok(code)
        })();
        match made {
            Ok(code) => {
                println!("  Collection '{child}' created; invite minted.");
                println!("  Code (send it to them): {code}");
                println!("  They join as a flagged minor with Editor rank,");
                println!("  Shared read, and their own collection.");
            }
            Err(e) => eprintln!("  error: invite for {child} failed: {e}"),
        }
    }
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
    let mut password = daemon_master_password("Master password: ")?;
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

// ── Trash ──

fn print_trash_row(c: &serde_json::Value) {
    let id = c["_meta"]["id"].as_str().unwrap_or("?");
    let name = c["_meta"]["name"].as_str().unwrap_or("?");
    let ctype = c["_meta"]["cipher_type"].as_str().unwrap_or("login");
    let username = c["_meta"]["username"].as_str().unwrap_or("");
    println!("{id}  [{ctype:>10}]  {name}  {username}");
}

// ── G7/G8/G9/G11p1 shared helpers ──

fn require_daemon(mode: ConnectMode, what: &str) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(mode, ConnectMode::Direct) {
        return Err(format!("{what} requires daemon mode; drop --direct").into());
    }
    Ok(())
}

fn post(
    socket: Option<&str>,
    action: &str,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let resp = client::request_to(action, &payload.to_string(), socket)?;
    if !resp.success {
        return Err(resp.error_message.into());
    }
    Ok(serde_json::from_str(&resp.payload)?)
}

/// Resolve a user-supplied cipher reference (UUID or case-insensitive name
/// substring) against the daemon's vault.list. Ambiguous substrings list
/// the candidates instead of guessing.
fn resolve_cipher_id(
    socket: Option<&str>,
    target: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    if uuid::Uuid::parse_str(target).is_ok() {
        return Ok(target.to_string());
    }
    let data = post(socket, "vault.list", &serde_json::json!({}))?;
    let needle = target.to_lowercase();
    let mut hits: Vec<(String, String)> = Vec::new();
    for c in data["ciphers"].as_array().cloned().unwrap_or_default() {
        let name = c["name"].as_str().unwrap_or("").to_lowercase();
        if name.contains(&needle) {
            hits.push((
                c["id"].as_str().unwrap_or("").to_string(),
                c["name"].as_str().unwrap_or("").to_string(),
            ));
        }
    }
    match hits.len() {
        0 => Err(format!("no entry matches '{target}'").into()),
        1 => Ok(hits.remove(0).0),
        _ => {
            let mut msg = format!("'{target}' matches several entries:\n");
            for (id, name) in &hits {
                msg.push_str(&format!("  {id}  {name}\n"));
            }
            Err(msg.into())
        }
    }
}

/// Resolve a user-supplied collection reference (UUID or exact name).
fn resolve_collection_id(
    socket: Option<&str>,
    target: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    if uuid::Uuid::parse_str(target).is_ok() {
        return Ok(target.to_string());
    }
    let data = post(socket, "collections.list", &serde_json::json!({}))?;
    let rows = data["collections"].as_array().cloned().unwrap_or_default();
    let mut hits: Vec<(String, String)> = Vec::new();
    for c in rows {
        if c["name"].as_str() == Some(target) {
            hits.push((
                c["id"].as_str().unwrap_or("").to_string(),
                c["name"].as_str().unwrap_or("").to_string(),
            ));
        }
    }
    match hits.len() {
        0 => Err(format!("no collection named '{target}'").into()),
        1 => Ok(hits.remove(0).0),
        _ => {
            let mut msg = format!("'{target}' names several collections:\n");
            for (id, _) in &hits {
                msg.push_str(&format!("  {id}\n"));
            }
            Err(msg.into())
        }
    }
}

// ── Generator (G7) ──

#[allow(clippy::too_many_arguments)]
pub fn handle_generate(
    mode: ConnectMode,
    socket: Option<&str>,
    kind: &str,
    length: Option<usize>,
    words: Option<usize>,
    no_upper: bool,
    no_numbers: bool,
    no_symbols: bool,
    sep: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (value, value_kind, params) = match kind {
        "password" => {
            let d = baluard_core::generator::PasswordOptions::default();
            let opts = baluard_core::generator::PasswordOptions {
                length: length.unwrap_or(d.length),
                upper: !no_upper,
                numbers: !no_numbers,
                symbols: !no_symbols,
            };
            let v = baluard_core::generator::generate_password(&opts).map_err(|e| e.to_string())?;
            let params = serde_json::json!({
                "length": opts.length,
                "upper": opts.upper,
                "numbers": opts.numbers,
                "symbols": opts.symbols,
            });
            (v, "password", params)
        }
        "passphrase" => {
            let d = baluard_core::generator::PassphraseOptions::default();
            let opts = baluard_core::generator::PassphraseOptions {
                word_count: words.unwrap_or(d.word_count),
                separator: sep.to_string(),
                upper: !no_upper,
                number: !no_numbers,
                symbol: !no_symbols,
            };
            let v =
                baluard_core::generator::generate_passphrase(&opts).map_err(|e| e.to_string())?;
            let params = serde_json::json!({
                "length": opts.word_count,
                "upper": opts.upper,
                "numbers": opts.number,
                "symbols": opts.symbol,
                "separator": opts.separator,
            });
            (v, "passphrase", params)
        }
        other => return Err(format!("unknown kind '{other}'; use password or passphrase").into()),
    };

    // Best-effort history, desktop parity: an open vault records the
    // generation, but the command never blocks or fails on it.
    if matches!(mode, ConnectMode::Daemon) {
        let payload = serde_json::json!({ "value": value, "kind": value_kind, "params": params });
        let _ = client::request_to("generator.history_add", &payload.to_string(), socket);
    }

    println!("{value}");
    Ok(())
}

// ── TOTP (G7) ──

pub fn handle_totp(
    mode: ConnectMode,
    socket: Option<&str>,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    require_daemon(mode, "totp")?;
    ensure_unlocked_daemon(socket)?;
    let id = resolve_cipher_id(socket, target)?;
    let data = post(socket, "cipher.totp_code", &serde_json::json!({ "id": id }))?;
    let code = data["code"].as_str().unwrap_or("");
    let expires_at = data["expires_at"].as_i64().unwrap_or(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let remaining = expires_at.saturating_sub(now);
    println!("{code}  (valid for {remaining}s)");
    Ok(())
}

// ── SSH keygen (G7) ──

pub fn handle_ssh_keygen(
    mode: ConnectMode,
    socket: Option<&str>,
    key_type: &str,
    comment: &str,
    store: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    require_daemon(mode, "ssh-keygen")?;
    ensure_unlocked_daemon(socket)?;
    let mut payload = serde_json::json!({ "type": key_type });
    if !comment.is_empty() {
        payload["comment"] = serde_json::json!(comment);
    }
    let data = post(socket, "ssh.generate_key", &payload)?;
    let public = data["public_key"].as_str().unwrap_or("");
    let fingerprint = data["fingerprint"].as_str().unwrap_or("");
    let private = data["private_key"].as_str().unwrap_or("");
    println!("Public key:");
    println!("{public}");
    println!();
    println!("Fingerprint:");
    println!("{fingerprint}");
    println!();
    println!("Private key (shown once; store it in the vault or a key file):");
    println!("{private}");

    if let Some(name) = store {
        let input = CipherInput {
            name: name.to_string(),
            kind: baluard_core::types::CipherKind::SshKey(baluard_core::types::SshKeyData {
                private_key: Some(private.to_string()),
                public_key: Some(public.to_string()),
                key_fingerprint: Some(fingerprint.to_string()),
            }),
            ..Default::default()
        };
        handle_add(mode, "", socket, input)?;
        println!("Stored as '{name}'.");
    }
    Ok(())
}

// ── Providers (G16 + G8) ──

pub fn handle_provider(
    mode: ConnectMode,
    socket: Option<&str>,
    action: &ProviderAction,
) -> Result<(), Box<dyn std::error::Error>> {
    require_daemon(mode, "provider")?;
    match action {
        ProviderAction::Connect {
            provider,
            pat,
            instance,
            client_id,
        } => {
            let mut base = serde_json::json!({ "provider": provider });
            if let Some(i) = instance {
                base["instance_url"] = serde_json::json!(i);
            }
            if let Some(c) = client_id {
                base["client_id"] = serde_json::json!(c);
            }
            if *pat {
                let token = prompt_password("Personal access token: ")?;
                base["token"] = serde_json::json!(token);
                let data = post(socket, "provider.connect_pat", &base)?;
                println!("Connected as {}.", data["username"].as_str().unwrap_or("?"));
                return Ok(());
            }
            let session = post(socket, "provider.connect_start", &base)?;
            println!(
                "Open {} and enter the code:",
                session["verification_uri"].as_str().unwrap_or("")
            );
            println!("    {}", session["user_code"].as_str().unwrap_or(""));
            let mut interval = session["interval_secs"].as_u64().unwrap_or(5).max(1);
            let mut session = session.clone();
            loop {
                std::thread::sleep(std::time::Duration::from_secs(interval));
                // The poll payload carries the session plus the same
                // config overrides (B2: config must ride every call).
                let mut poll = session.clone();
                if let Some(i) = instance {
                    poll["instance_url"] = serde_json::json!(i);
                }
                if let Some(c) = client_id {
                    poll["client_id"] = serde_json::json!(c);
                }
                let data = post(socket, "provider.connect_poll", &poll)?;
                match data["status"].as_str().unwrap_or("") {
                    "pending" => {}
                    "slow_down" => {
                        interval = data["interval_secs"].as_u64().unwrap_or(interval + 5);
                        session["interval_secs"] = serde_json::json!(interval);
                    }
                    "expired" => return Err("device flow expired; run connect again".into()),
                    "success" => {
                        println!("Connected as {}.", data["username"].as_str().unwrap_or("?"));
                        return Ok(());
                    }
                    other => return Err(format!("unexpected poll status: {other}").into()),
                }
            }
        }
        ProviderAction::List => {
            let data = post(socket, "provider.list", &serde_json::json!({}))?;
            let mut names: Vec<&String> = data
                .as_object()
                .map(|o| o.keys().collect())
                .unwrap_or_default();
            names.sort();
            for name in names {
                let v = &data[name];
                let connected = v["connected"].as_bool().unwrap_or(false);
                let method = v["auth_method"].as_str().unwrap_or("");
                if connected {
                    let user = v["username"].as_str().unwrap_or("");
                    println!("{name:<10} connected  {user}  ({method})");
                } else {
                    println!("{name:<10} not connected  ({method})");
                }
            }
            Ok(())
        }
        ProviderAction::Status { provider } => {
            let data = post(
                socket,
                "provider.status",
                &serde_json::json!({ "provider": provider }),
            )?;
            if data["connected"].as_bool() == Some(false) {
                println!("{provider} not connected.");
            } else if data["valid"].as_bool() == Some(true) {
                println!(
                    "{provider} token valid for {} ({}).",
                    data["username"].as_str().unwrap_or("?"),
                    data["email"].as_str().unwrap_or("no email")
                );
            } else {
                println!(
                    "{provider} token INVALID: {}",
                    data["error"].as_str().unwrap_or("unknown error")
                );
            }
            Ok(())
        }
        ProviderAction::Disconnect { provider } => {
            post(
                socket,
                "provider.disconnect",
                &serde_json::json!({ "provider": provider }),
            )?;
            println!("{provider} disconnected; stored token revoked where possible.");
            Ok(())
        }
        ProviderAction::Repos { provider } => {
            let data = post(
                socket,
                "provider.repos",
                &serde_json::json!({ "provider": provider }),
            )?;
            for r in data.as_array().cloned().unwrap_or_default() {
                println!(
                    "{}  {}",
                    r["full_name"].as_str().unwrap_or(""),
                    r["clone_url"].as_str().unwrap_or("")
                );
            }
            Ok(())
        }
        ProviderAction::VaultRepos { provider } => {
            let data = post(
                socket,
                "provider.vault_repos",
                &serde_json::json!({ "provider": provider }),
            )?;
            for r in data.as_array().cloned().unwrap_or_default() {
                let slug = r["vault_slug"].as_str().unwrap_or("-");
                println!("{}  (vault: {slug})", r["full_name"].as_str().unwrap_or(""));
            }
            Ok(())
        }
        ProviderAction::CreateRepo { provider, name } => {
            // Not sentinel-exempt (unlike list/connect): the daemon gate
            // demands an unlocked vault for repo creation.
            ensure_unlocked_daemon(socket)?;
            let data = post(
                socket,
                "provider.create_repo",
                &serde_json::json!({ "provider": provider, "name": name }),
            )?;
            println!(
                "Created private repository {}.",
                data["full_name"].as_str().unwrap_or(name)
            );
            if let Some(url) = data["clone_url"].as_str() {
                println!("Clone URL: {url}");
            }
            Ok(())
        }
    }
}

// ── Root-key rotation (G9) ──

pub fn handle_rotate_root(
    mode: ConnectMode,
    socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    require_daemon(mode, "rotate-root")?;
    ensure_unlocked_daemon(socket)?;
    post(socket, "space.rotate_root", &serde_json::json!({}))?;
    println!("Root key rotated. Other enrolled devices adopt the new key on their next unlock.");
    println!("Attachments, settings, and the recovery escrow were re-wrapped to the new key.");
    Ok(())
}

// ── Collections (G11 phase 1) ──

pub fn handle_collections(
    mode: ConnectMode,
    socket: Option<&str>,
    action: &CollectionAction,
) -> Result<(), Box<dyn std::error::Error>> {
    require_daemon(mode, "collections")?;
    match action {
        CollectionAction::List => {
            ensure_unlocked_daemon(socket)?;
            let data = post(socket, "collections.list", &serde_json::json!({}))?;
            let rows = data["collections"].as_array().cloned().unwrap_or_default();
            if rows.is_empty() {
                println!("No collections.");
                return Ok(());
            }
            for c in rows {
                let id = c["id"].as_str().unwrap_or("");
                let name = c["name"].as_str().unwrap_or("");
                let access = c["access"].as_str().unwrap_or("");
                println!("{id}  {name}  ({access})");
                for g in c["grants"].as_array().cloned().unwrap_or_default() {
                    let kind = g["kind"].as_str().unwrap_or("member");
                    let gid = g["id"].as_str().unwrap_or("");
                    let gacc = g["access"].as_str().unwrap_or("");
                    let exp = g["expires_at"]
                        .as_u64()
                        .map(|e| format!(" until {e}"))
                        .unwrap_or_default();
                    println!("    {kind} {gid}  {gacc}{exp}");
                }
            }
            Ok(())
        }
        CollectionAction::Delete { collection } => {
            ensure_unlocked_daemon(socket)?;
            let id = resolve_collection_id(socket, collection)?;
            post(
                socket,
                "collections.delete",
                &serde_json::json!({ "id": id }),
            )?;
            println!("Deleted collection.");
            Ok(())
        }
        CollectionAction::Create { name } => {
            ensure_unlocked_daemon(socket)?;
            let data = post(
                socket,
                "collections.create",
                &serde_json::json!({ "name": name }),
            )?;
            println!(
                "Created collection {} ({}).",
                data["name"].as_str().unwrap_or(name),
                data["id"].as_str().unwrap_or("")
            );
            Ok(())
        }
        CollectionAction::Assign { cipher, to } => {
            ensure_unlocked_daemon(socket)?;
            let cipher_id = resolve_cipher_id(socket, cipher)?;
            let mut payload = serde_json::json!({ "cipher_id": cipher_id });
            if let Some(t) = to {
                payload["collection_id"] = serde_json::json!(resolve_collection_id(socket, t)?);
            }
            post(socket, "cipher.set_collection", &payload)?;
            match to {
                Some(t) => println!("Assigned to {t}."),
                None => println!("Removed from its collection."),
            }
            Ok(())
        }
        CollectionAction::Grant {
            collection,
            kind,
            target_id,
            access,
            expires_at,
        } => {
            ensure_unlocked_daemon(socket)?;
            let id = resolve_collection_id(socket, collection)?;
            let mut payload = serde_json::json!({
                "id": id,
                "kind": kind,
                "target_id": target_id,
                "access": access,
            });
            if let Some(e) = expires_at {
                payload["expires_at"] = serde_json::json!(e);
            }
            post(socket, "collections.grant", &payload)?;
            println!("Granted {access} on {collection} to {kind} {target_id}.");
            Ok(())
        }
        CollectionAction::Revoke {
            collection,
            kind,
            target_id,
        } => {
            ensure_unlocked_daemon(socket)?;
            let id = resolve_collection_id(socket, collection)?;
            post(
                socket,
                "collections.revoke",
                &serde_json::json!({ "id": id, "kind": kind, "target_id": target_id }),
            )?;
            println!("Revoked {kind} {target_id}'s access to {collection}.");
            Ok(())
        }
    }
}

// ── Groups, policies, space lifecycle, activity (G11 phase 2) ──

pub fn handle_groups(
    mode: ConnectMode,
    socket: Option<&str>,
    action: &crate::GroupAction,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::GroupAction;
    require_daemon(mode, "groups")?;
    let (route, payload): (&str, serde_json::Value) = match action {
        GroupAction::List => ("groups.list", serde_json::json!({})),
        GroupAction::Create { name } => {
            ("groups.create", serde_json::json!({ "name": name.trim() }))
        }
        GroupAction::Rename { id, name } => (
            "groups.rename",
            serde_json::json!({ "id": id.trim(), "name": name.trim() }),
        ),
        GroupAction::Delete { id, .. } => ("groups.delete", serde_json::json!({ "id": id.trim() })),
        GroupAction::AddMember { id, member_id } => (
            "groups.member_add",
            serde_json::json!({ "id": id.trim(), "member_id": member_id.trim() }),
        ),
        GroupAction::RemoveMember { id, member_id } => (
            "groups.member_remove",
            serde_json::json!({ "id": id.trim(), "member_id": member_id.trim() }),
        ),
    };
    ensure_unlocked_daemon(socket)?;
    if let GroupAction::Delete { yes, .. } = action {
        confirm_destructive(
            *yes,
            "delete",
            "access given only through the group is removed",
        )?;
    }
    let data = post(socket, route, &payload)?;
    match action {
        GroupAction::List => {
            for g in data["groups"].as_array().cloned().unwrap_or_default() {
                let members: Vec<&str> = g["members"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|m| m.as_str()).collect())
                    .unwrap_or_default();
                println!(
                    "{}  {}",
                    g["id"].as_str().unwrap_or("?"),
                    g["name"].as_str().unwrap_or("?")
                );
                if members.is_empty() {
                    println!("  (no members)");
                } else {
                    for m in members {
                        println!("  {m}");
                    }
                }
            }
        }
        GroupAction::Create { .. } => {
            println!("Group created: {}.", data["id"].as_str().unwrap_or("?"))
        }
        GroupAction::Rename { .. } => println!("Group renamed."),
        GroupAction::Delete { .. } => {
            println!("Group deleted. Access given only through it is removed.")
        }
        GroupAction::AddMember { .. } => println!("Member added to group."),
        GroupAction::RemoveMember { .. } => println!("Member removed from group."),
    }
    Ok(())
}

pub fn handle_policies(
    mode: ConnectMode,
    socket: Option<&str>,
    action: &crate::PolicyAction,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::PolicyAction;
    require_daemon(mode, "policies")?;
    ensure_unlocked_daemon(socket)?;
    match action {
        PolicyAction::List => {
            let data = post(socket, "policies.list", &serde_json::json!({}))?;
            println!("{}", serde_json::to_string_pretty(&data["policies"])?);
            Ok(())
        }
        PolicyAction::Set { json } => {
            let parsed: serde_json::Value = serde_json::from_str(json.trim())
                .map_err(|e| format!("policy payload must be a JSON object: {e}"))?;
            if !parsed.is_object() {
                return Err("policy payload must be a JSON object".into());
            }
            post(socket, "policies.set", &parsed)?;
            println!("Policies updated.");
            Ok(())
        }
    }
}

pub fn handle_space(
    mode: ConnectMode,
    socket: Option<&str>,
    action: &crate::SpaceAction,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::SpaceAction;
    require_daemon(mode, "space")?;
    let (route, payload): (&str, serde_json::Value) = match action {
        SpaceAction::Prepare => ("space.prepare", serde_json::json!({})),
        SpaceAction::Status => ("space.status", serde_json::json!({})),
        SpaceAction::Flip => ("space.flip", serde_json::json!({})),
        SpaceAction::SetPurpose { purpose } => (
            "space.set_purpose",
            serde_json::json!({ "purpose": purpose.trim() }),
        ),
        SpaceAction::KitEnable => ("space.kit_enable", serde_json::json!({})),
        SpaceAction::KitDisable { .. } => ("space.kit_disable", serde_json::json!({})),
        SpaceAction::KitStatus => ("space.kit_status", serde_json::json!({})),
        SpaceAction::Migrate { clone_url } => (
            "space.migrate",
            serde_json::json!({ "clone_url": clone_url.trim() }),
        ),
    };
    ensure_unlocked_daemon(socket)?;
    if let SpaceAction::KitDisable { yes } = action {
        confirm_destructive(
            *yes,
            "disable",
            "a lost guardian could lock everyone out without a kit",
        )?;
    }
    let data = post(socket, route, &payload)?;
    match action {
        SpaceAction::Prepare
        | SpaceAction::Status
        | SpaceAction::Flip
        | SpaceAction::Migrate { .. } => {
            println!("{}", serde_json::to_string(&data)?);
        }
        SpaceAction::SetPurpose { purpose } => {
            println!("Purpose set to {}.", purpose.trim());
        }
        SpaceAction::KitEnable => match data["phrase"].as_str() {
            Some(p) => {
                println!("Recovery kit phrase (shown once; store it safely):");
                println!("{p}");
            }
            None => println!("Recovery kit updated (a second admin confirmed)."),
        },
        SpaceAction::KitDisable { .. } => println!(
            "Recovery kit removed ({}).",
            if data["removed"].as_bool().unwrap_or(false) {
                "kit existed"
            } else {
                "no kit present"
            }
        ),
        SpaceAction::KitStatus => {
            if data["enabled"].as_bool().unwrap_or(false) {
                println!("Recovery kit is enabled.");
            } else {
                println!(
                    "Recovery kit is NOT enabled. Enable one so a lost guardian cannot lock everyone out."
                );
            }
        }
    }
    Ok(())
}

pub fn handle_activity(
    mode: ConnectMode,
    socket: Option<&str>,
    limit: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    require_daemon(mode, "activity")?;
    ensure_unlocked_daemon(socket)?;
    let data = post(
        socket,
        "activity.events",
        &serde_json::json!({ "limit": limit }),
    )?;
    for e in data.as_array().cloned().unwrap_or_default() {
        println!(
            "{}  {}  {}  {}",
            e["seq"].as_u64().unwrap_or(0),
            e["at"].as_u64().unwrap_or(0),
            e["kind"].as_str().unwrap_or("?"),
            e["detail"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

// ── Members + pending asks (G11 phase 1) ──

/// Contact cards and the Level 2 identity check. Daemon-only: the
/// address book is vault state, same as members.
pub fn handle_contacts(
    mode: ConnectMode,
    socket: Option<&str>,
    action: &crate::ContactAction,
) -> Result<(), Box<dyn std::error::Error>> {
    require_daemon(mode, "contacts")?;
    match action {
        crate::ContactAction::List => {
            ensure_unlocked_daemon(socket)?;
            let data = post(socket, "contacts.list", &serde_json::json!({}))?;
            for c in data["contacts"].as_array().cloned().unwrap_or_default() {
                let trust = c["trust"].as_str().unwrap_or("channel");
                println!(
                    "{}  {}  {}",
                    c["identity_signing_pubkey"].as_str().unwrap_or("?"),
                    trust,
                    c["display_name"].as_str().unwrap_or("?")
                );
                println!(
                    "    code: {}",
                    c["verification_code"].as_str().unwrap_or("?")
                );
            }
            let n = data["contacts"].as_array().map(|a| a.len()).unwrap_or(0);
            println!("{n} contact(s)");
        }
        crate::ContactAction::MyCard => {
            ensure_unlocked_daemon(socket)?;
            let data = post(socket, "contacts.my_card", &serde_json::json!({}))?;
            println!("card: {}", data["card"].as_str().unwrap_or("?"));
            println!(
                "code: {}",
                data["verification_code"].as_str().unwrap_or("?")
            );
            println!(
                "Compare the code with your contact over a channel you both trust, then `contacts verify <their pubkey>`."
            );
        }
        crate::ContactAction::Import { code } => {
            ensure_unlocked_daemon(socket)?;
            let data = post(
                socket,
                "contacts.import_card",
                &serde_json::json!({ "card": code }),
            )?;
            println!(
                "Contact imported: {}",
                data["display_name"].as_str().unwrap_or("ok")
            );
            println!("Unverified. Compare codes, then `contacts verify <pubkey>`.");
        }
        crate::ContactAction::Verify { pubkey } => {
            ensure_unlocked_daemon(socket)?;
            post(
                socket,
                "contacts.mark_verified",
                &serde_json::json!({ "identity_signing_pubkey": pubkey }),
            )?;
            println!("Contact verified. Admin rank is now available for this member.");
        }
        crate::ContactAction::Remove { pubkey } => {
            ensure_unlocked_daemon(socket)?;
            post(
                socket,
                "contacts.remove",
                &serde_json::json!({ "identity_signing_pubkey": pubkey }),
            )?;
            println!("Contact removed.");
        }
    }
    Ok(())
}

pub fn handle_members(
    mode: ConnectMode,
    socket: Option<&str>,
    action: &MemberAction,
) -> Result<(), Box<dyn std::error::Error>> {
    require_daemon(mode, "members")?;
    match action {
        MemberAction::List => {
            ensure_unlocked_daemon(socket)?;
            let data = post(socket, "members.list", &serde_json::json!({}))?;
            for m in data["members"].as_array().cloned().unwrap_or_default() {
                let marker = if m["is_self"].as_bool().unwrap_or(false) {
                    "*"
                } else {
                    " "
                };
                let role = m["role"].as_str().unwrap_or("?");
                let name = m["display_name"].as_str().unwrap_or("");
                let email = m["email"].as_str().unwrap_or("");
                let flags = match (
                    m["reset"].as_bool().unwrap_or(false),
                    m["removed"].as_bool().unwrap_or(false),
                ) {
                    (true, _) => "  [reset pending]",
                    (_, true) => "  [removed]",
                    _ => "",
                };
                println!(
                    "{marker} {}  {role:<8}  {name}  {email}{flags}",
                    m["id"].as_str().unwrap_or("")
                );
            }
            if let Some(role) = data["your_role"].as_str() {
                println!();
                println!("You are {role}.");
            }
            Ok(())
        }
        MemberAction::Invite { role, username } => {
            ensure_unlocked_daemon(socket)?;
            let mut payload = serde_json::json!({ "role": role });
            if let Some(u) = username {
                payload["transport_username"] = serde_json::json!(u.trim());
            }
            let data = post(socket, "members.invite", &payload)?;
            println!("Invite code (send out of band, one-time):");
            println!("{}", data["code"].as_str().unwrap_or(""));
            match data["seat_error"].as_str() {
                Some(e) if !e.is_empty() => println!("clone access: NOT granted ({e})"),
                _ if data["seat_granted"].as_bool().unwrap_or(false) => {
                    println!("clone access: granted (read-only until approved)");
                }
                _ => println!("clone access: not requested"),
            }
            Ok(())
        }
        MemberAction::Stage { code } => {
            ensure_unlocked_daemon(socket)?;
            let data = post(
                socket,
                "requests.stage",
                &serde_json::json!({ "intro_code": code.trim() }),
            )?;
            println!(
                "Staged. Confirm with: baluard members approve-join {}",
                data["req_id"].as_str().unwrap_or("<req_id>")
            );
            Ok(())
        }
        MemberAction::SetRole { member_id, role } => {
            ensure_unlocked_daemon(socket)?;
            let role = role.trim().to_lowercase();
            let data = post(
                socket,
                "members.set_role",
                &serde_json::json!({ "member_id": member_id.trim(), "role": role }),
            )?;
            if data["changed"].as_bool().unwrap_or(false) {
                println!(
                    "Role updated: {} is now {}.",
                    member_id.trim(),
                    data["role"].as_str().unwrap_or(&role)
                );
            } else {
                println!("No change: already {}.", role);
            }
            Ok(())
        }
        MemberAction::ReplaceDevice {
            member_id,
            no_revoke,
        } => {
            ensure_unlocked_daemon(socket)?;
            let data = post(
                socket,
                "members.replace_device",
                &serde_json::json!({
                    "member_id": member_id.trim(),
                    "revoke_device": !no_revoke
                }),
            )?;
            println!(
                "Device replaced. Successor member: {}.",
                data["successor"].as_str().unwrap_or("?")
            );
            println!("Replacement invite code (shown once; give it to the member):");
            println!("{}", data["invite_code"].as_str().unwrap_or(""));
            println!(
                "Collections rotated: {}.",
                data["collections_rotated"].as_u64().unwrap_or(0)
            );
            if let Some(err) = data["revoke_error"].as_str() {
                if !err.is_empty() {
                    println!("Revoke-and-rekey stopped: {err}");
                }
            }
            for f in data["rotation_failed"]
                .as_array()
                .cloned()
                .unwrap_or_default()
            {
                if let Some(msg) = f.as_str() {
                    println!("Rotation failed: {msg}");
                }
            }
            Ok(())
        }
        MemberAction::Remove {
            member_ids,
            yes,
            offline_override,
        } => {
            ensure_unlocked_daemon(socket)?;
            confirm_destructive(
                *yes,
                "remove",
                "removal rotates the keys of every collection these members could open",
            )?;
            let data = post(
                socket,
                "members.remove",
                &serde_json::json!({
                    "member_ids": member_ids,
                    "offline_override": offline_override
                }),
            )?;
            println!(
                "Removed {} member(s).",
                data["removed"].as_array().map(|a| a.len()).unwrap_or(0)
            );
            println!(
                "Forge seats struck: {}. Collection keys rotated (new epoch).",
                data["seats_struck"].as_u64().unwrap_or(0)
            );
            for s in data["unstruck_seats"]
                .as_array()
                .cloned()
                .unwrap_or_default()
            {
                if let Some(m) = s.as_str() {
                    println!("Seat not struck: {m}");
                }
            }
            Ok(())
        }
        MemberAction::Reset { member_id, yes } => {
            ensure_unlocked_daemon(socket)?;
            confirm_destructive(
                *yes,
                "reset",
                "the member's groups and grants are pruned; they rejoin with the code below",
            )?;
            let data = post(
                socket,
                "members.reset",
                &serde_json::json!({ "member_id": member_id.trim() }),
            )?;
            println!(
                "Member reset. Successor row: {}.",
                data["successor_id"].as_str().unwrap_or("?")
            );
            let code = data["reset_code"]
                .as_str()
                .filter(|c| !c.is_empty())
                .ok_or("daemon returned no reset code; the member cannot rejoin without it")?;
            println!("Reset code (one-time; give it to the member to rejoin):");
            println!("{code}");
            println!("Re-grant their shared folders and groups after they rejoin.");
            Ok(())
        }
        MemberAction::Transfer { member_id, yes } => {
            ensure_unlocked_daemon(socket)?;
            confirm_destructive(
                *yes,
                "transfer",
                "you keep admin rank; the target becomes owner",
            )?;
            post(
                socket,
                "members.transfer",
                &serde_json::json!({ "member_id": member_id.trim() }),
            )?;
            println!("Ownership transferred to {}.", member_id.trim());
            Ok(())
        }
        MemberAction::Claim { member_id } => {
            ensure_unlocked_daemon(socket)?;
            let data = post(
                socket,
                "members.claim",
                &serde_json::json!({ "member_id": member_id.trim() }),
            )?;
            if data["executed"].as_bool().unwrap_or(false) {
                println!(
                    "Ownership claimed: {} is now the owner. This rides the next sync.",
                    member_id.trim()
                );
            } else if data["armed"].as_bool().unwrap_or(false) {
                let until = data["window_until"].as_u64().unwrap_or(0);
                let days = until.saturating_sub(now_secs()) / 86_400;
                println!(
                    "Claim armed: the current owner has {days} day(s) to cancel it with members contest-cancel."
                );
                println!(
                    "The claim executes automatically after the window (window_until: {until})."
                );
            } else {
                println!("Claim recorded.");
            }
            Ok(())
        }
        MemberAction::ContestStatus => {
            ensure_unlocked_daemon(socket)?;
            let data = post(socket, "members.contest_status", &serde_json::json!({}))?;
            if data["pending"].as_bool().unwrap_or(false) {
                let until = data["window_until"].as_u64().unwrap_or(0);
                let days = until.saturating_sub(now_secs()) / 86_400;
                println!(
                    "Ownership claim pending: {} -> {} ({} day(s) left).",
                    data["old_owner_id"].as_str().unwrap_or("?"),
                    data["new_owner_id"].as_str().unwrap_or("?"),
                    days
                );
                println!("Cancel with members contest-cancel (owner only).");
            } else {
                println!("No ownership claim is pending.");
            }
            Ok(())
        }
        MemberAction::ContestCancel => {
            ensure_unlocked_daemon(socket)?;
            post(socket, "members.contest_cancel", &serde_json::json!({}))?;
            println!("Pending ownership claim cancelled.");
            Ok(())
        }
        MemberAction::SetEmail {
            member_id,
            email,
            clear,
        } => {
            ensure_unlocked_daemon(socket)?;
            if *clear && email.is_some() {
                return Err("pass either --email or --clear, not both".into());
            }
            if !*clear && email.is_none() {
                return Err("pass --email <address> to set one, or --clear to remove it".into());
            }
            let value = if *clear {
                serde_json::Value::Null
            } else {
                let v = email.as_deref().unwrap_or("").trim();
                if v.is_empty() {
                    return Err("empty --email; use --clear to remove the address".into());
                }
                serde_json::json!(v)
            };
            post(
                socket,
                "members.set_email",
                &serde_json::json!({ "member_id": member_id.trim(), "email": value }),
            )?;
            if *clear {
                println!("Email cleared.");
            } else {
                println!("Email updated.");
            }
            Ok(())
        }
        MemberAction::SetMinor { member_id, minor } => {
            ensure_unlocked_daemon(socket)?;
            post(
                socket,
                "members.set_minor",
                &serde_json::json!({ "member_id": member_id.trim(), "minor": minor }),
            )?;
            if *minor {
                println!("Minor flag set.");
            } else {
                println!("Minor flag cleared.");
            }
            Ok(())
        }
        MemberAction::Leave => {
            ensure_unlocked_daemon(socket)?;
            let data = post(socket, "members.leave", &serde_json::json!({}))?;
            println!(
                "Departure request filed for member {}. An admin approves it with members approve-leave.",
                data["member_id"].as_str().unwrap_or("?")
            );
            Ok(())
        }
        MemberAction::Leaves => {
            ensure_unlocked_daemon(socket)?;
            let data = post(socket, "members.leave_list", &serde_json::json!({}))?;
            let rows = data["pending"].as_array().cloned().unwrap_or_default();
            if rows.is_empty() {
                println!("No pending departures.");
                return Ok(());
            }
            for r in rows {
                println!(
                    "{}  {:<8}  {}",
                    r["member_id"].as_str().unwrap_or("?"),
                    r["role"].as_str().unwrap_or("?"),
                    r["display_name"].as_str().unwrap_or("")
                );
            }
            Ok(())
        }
        MemberAction::ApproveLeave {
            member_id,
            yes,
            offline_override,
        } => {
            ensure_unlocked_daemon(socket)?;
            confirm_destructive(
                *yes,
                "approve-leave",
                "this rotates every collection key the leaver could open and re-issues the kit",
            )?;
            let data = post(
                socket,
                "members.leave_approve",
                &serde_json::json!({
                    "member_id": member_id.trim(),
                    "offline_override": offline_override
                }),
            )?;
            println!(
                "Departure executed ({}). Collections rotated: {}.",
                data["reason"].as_str().unwrap_or("left"),
                data["collections_rotated"].as_u64().unwrap_or(0)
            );
            if let Some(p) = data["new_kit_phrase"].as_str() {
                println!("New recovery kit phrase (shown once; store it safely):");
                println!("{p}");
            }
            for f in data["rotation_failed"]
                .as_array()
                .cloned()
                .unwrap_or_default()
            {
                if let Some(m) = f.as_str() {
                    println!("Rotation failed: {m}");
                }
            }
            if let Some(e) = data["kit_reissue_failed"].as_str() {
                println!("Kit re-issue failed: {e}");
            }
            Ok(())
        }
        MemberAction::Requests => {
            ensure_unlocked_daemon(socket)?;
            // Two queues: pending joins (requests.*) and collection
            // access asks (collections.requests_*). Different id fields,
            // so each section names its own approve command.
            let joins = post(socket, "requests.list", &serde_json::json!({}))?;
            let join_rows = joins["requests"].as_array().cloned().unwrap_or_default();
            println!("Pending joins:");
            if join_rows.is_empty() {
                println!("  (none)");
            }
            for r in &join_rows {
                let secret = if r["secret_ok"].as_bool().unwrap_or(false) {
                    "verified"
                } else {
                    "UNVERIFIED"
                };
                println!(
                    "  {}  {}  <{}>  [{secret}]",
                    r["req_id"].as_str().unwrap_or(""),
                    r["display_name"].as_str().unwrap_or("?"),
                    r["email"].as_str().unwrap_or(""),
                );
            }
            if !join_rows.is_empty() {
                println!("  Confirm: baluard members approve-join <req_id>");
            }
            println!();
            println!("Collection access asks:");
            let asks = post(socket, "collections.requests_list", &serde_json::json!({}))?;
            let rows = asks["requests"].as_array().cloned().unwrap_or_default();
            if rows.is_empty() {
                println!("  (none)");
            }
            for r in &rows {
                println!(
                    "  {}  {}  asks {} on {} ({}){}",
                    r["request_id"].as_str().unwrap_or(""),
                    r["requester_member_id"].as_str().unwrap_or(""),
                    r["requester_name"].as_str().unwrap_or("?"),
                    r["collection_name"].as_str().unwrap_or("?"),
                    r["access"].as_str().unwrap_or("?"),
                    match r["note"].as_str() {
                        Some(n) if !n.is_empty() => format!("  note: {n}"),
                        _ => String::new(),
                    }
                );
            }
            if !rows.is_empty() {
                println!("  Approve: baluard members approve <request_id> <requester_member_id>");
            }
            Ok(())
        }
        MemberAction::ApproveJoin { req_id } => {
            ensure_unlocked_daemon(socket)?;
            let data = post(
                socket,
                "requests.approve",
                &serde_json::json!({ "req_id": req_id }),
            )?;
            println!(
                "Joined as member {}{}.",
                data["member_id"].as_str().unwrap_or("?"),
                if data["seat_upgraded"].as_bool().unwrap_or(false) {
                    " (forge seat granted)"
                } else {
                    ""
                },
            );
            Ok(())
        }
        MemberAction::DenyJoin { req_id } => {
            ensure_unlocked_daemon(socket)?;
            post(
                socket,
                "requests.deny",
                &serde_json::json!({ "req_id": req_id }),
            )?;
            println!("Join request dropped.");
            Ok(())
        }
        MemberAction::Approve {
            request_id,
            requester_member_id,
        } => {
            ensure_unlocked_daemon(socket)?;
            let data = post(
                socket,
                "collections.requests_approve",
                &serde_json::json!({
                    "request_id": request_id,
                    "requester_member_id": requester_member_id,
                }),
            )?;
            println!(
                "Approved: {} now has {} on {}.",
                data["requester_name"].as_str().unwrap_or("requester"),
                data["access"].as_str().unwrap_or("?"),
                data["collection_name"].as_str().unwrap_or("?"),
            );
            Ok(())
        }
        MemberAction::Deny {
            request_id,
            requester_member_id,
        } => {
            ensure_unlocked_daemon(socket)?;
            post(
                socket,
                "collections.requests_deny",
                &serde_json::json!({
                    "request_id": request_id,
                    "requester_member_id": requester_member_id,
                }),
            )?;
            println!("Denied.");
            Ok(())
        }
    }
}

/// vault.search (G24 step 6): the CLI's executable spec of the daemon
/// fan-out contract. Daemon-only - the merge-eligibility machinery lives in
/// the daemon's host map, so --direct has nothing to fan out over.
/// Custom-remote credentials: set or clear (device-local, gitignored).
pub fn handle_credentials(
    mode: ConnectMode,
    socket: Option<&str>,
    action: crate::CredentialsAction,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::CredentialsAction as CA;
    require_daemon(mode, "credentials")?;
    ensure_unlocked_daemon(socket)?;
    let payload = match action {
        CA::Set {
            host,
            token,
            username,
            ssh_passphrase,
            key_file,
        } => {
            use base64::Engine as _;
            let mut obj = serde_json::Map::new();
            obj.insert("host".into(), serde_json::Value::String(host));
            if let Some(v) = token {
                obj.insert("token".into(), serde_json::Value::String(v));
            }
            if let Some(v) = username {
                obj.insert("username".into(), serde_json::Value::String(v));
            }
            if let Some(v) = ssh_passphrase {
                obj.insert("ssh_passphrase".into(), serde_json::Value::String(v));
            }
            if let Some(path) = key_file {
                let pem = std::fs::read_to_string(&path)
                    .map_err(|e| format!("cannot read the key file: {e}"))?;
                let b64 = base64::engine::general_purpose::STANDARD.encode(pem.as_bytes());
                obj.insert("ssh_key_b64".into(), serde_json::Value::String(b64));
            }
            serde_json::Value::Object(obj).to_string()
        }
        CA::Clear {
            token,
            username,
            ssh_passphrase,
            key,
        } => {
            let mut obj = serde_json::Map::new();
            if let Some(host) = std::env::var("BALUARD_CREDENTIALS_HOST").ok() {
                obj.insert("host".into(), serde_json::Value::String(host));
            } else {
                // The route requires a host even on clear; read the
                // vault's current origin so `credentials clear` needs no
                // flags.
                let resp = client::request_to("vault.remote_url", "{}", socket)?;
                if !resp.success {
                    return Err(resp.error_message.into());
                }
                let url: serde_json::Value = serde_json::from_str(&resp.payload)?;
                let host = baluard_core::sync::credentials::extract_host(
                    url["url"].as_str().unwrap_or(""),
                )
                .unwrap_or_default();
                obj.insert("host".into(), serde_json::Value::String(host));
            }
            if token {
                obj.insert("token".into(), serde_json::Value::String(String::new()));
            }
            if username {
                obj.insert("username".into(), serde_json::Value::String(String::new()));
            }
            if ssh_passphrase {
                obj.insert(
                    "ssh_passphrase".into(),
                    serde_json::Value::String(String::new()),
                );
            }
            if key {
                obj.insert(
                    "ssh_key_b64".into(),
                    serde_json::Value::String(String::new()),
                );
            }
            serde_json::Value::Object(obj).to_string()
        }
    };
    let resp = client::request_to("vault.git_credentials_set", &payload, socket)?;
    if !resp.success {
        return Err(resp.error_message.into());
    }
    println!("Credentials stored.");
    Ok(())
}

/// Custom-remote test connection (ls-remote pre-flight).
pub fn handle_git_probe(
    mode: ConnectMode,
    socket: Option<&str>,
    url: &str,
    token: Option<String>,
    username: Option<String>,
    ssh_passphrase: Option<String>,
    key_file: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    require_daemon(mode, "git-probe")?;
    use base64::Engine as _;
    let mut obj = serde_json::Map::new();
    obj.insert("url".into(), serde_json::Value::String(url.to_string()));
    if token.is_some() || username.is_some() || ssh_passphrase.is_some() || key_file.is_some() {
        let mut c = serde_json::Map::new();
        if let Some(v) = token {
            c.insert("token".into(), serde_json::Value::String(v));
        }
        if let Some(v) = username {
            c.insert("username".into(), serde_json::Value::String(v));
        }
        if let Some(v) = ssh_passphrase {
            c.insert("ssh_passphrase".into(), serde_json::Value::String(v));
        }
        if let Some(path) = key_file {
            let pem = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read the key file: {e}"))?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(pem.as_bytes());
            c.insert("ssh_key_b64".into(), serde_json::Value::String(b64));
        }
        obj.insert("credentials".into(), serde_json::Value::Object(c));
    }
    let resp = client::request_to(
        "git.git_probe",
        &serde_json::Value::Object(obj).to_string(),
        socket,
    )?;
    if !resp.success {
        return Err(resp.error_message.into());
    }
    let data: serde_json::Value = serde_json::from_str(&resp.payload)?;
    if data["ok"].as_bool().unwrap_or(false) {
        println!("Connection OK.");
        return Ok(());
    }
    let kind = data["kind"].as_str().unwrap_or("unreachable");
    let detail = data["detail"].as_str().unwrap_or("");
    match kind {
        "host-untrusted" => {
            // Surface the trust flow inputs from the marker JSON.
            let marker: serde_json::Value =
                serde_json::from_str(detail).unwrap_or(serde_json::Value::Null);
            let inner = &marker["host_key_untrusted"];
            let h = inner["host"].as_str().unwrap_or("");
            let fp = inner["fingerprint"].as_str().unwrap_or("");
            let kt = inner["key_type"].as_str().unwrap_or("");
            let aid = inner["attempt_id"].as_str().unwrap_or("");
            println!("The server's host key is not trusted yet.");
            println!("Host: {h}");
            println!("Key type: {kt}");
            println!("Fingerprint: {fp}");
            if inner["known_other_type"].as_bool() == Some(true) {
                println!("Note: this host already has a key of another type in known_hosts.");
            }
            println!("Trust it with: baluard git-trust {aid}");
            std::process::exit(2);
        }
        _ => {
            println!("Connection failed ({kind}): {detail}");
            std::process::exit(1);
        }
    }
}

/// Bless a daemon-observed SSH host key.
pub fn handle_git_trust(
    mode: ConnectMode,
    socket: Option<&str>,
    attempt_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    require_daemon(mode, "git-trust")?;
    let payload = serde_json::json!({ "attempt_id": attempt_id }).to_string();
    let resp = client::request_to("git.git_hostkey_trust", &payload, socket)?;
    if !resp.success {
        return Err(resp.error_message.into());
    }
    let data: serde_json::Value = serde_json::from_str(&resp.payload)?;
    println!(
        "Host key trusted: {} ({})",
        data["host"].as_str().unwrap_or(""),
        data["fingerprint"].as_str().unwrap_or("")
    );
    Ok(())
}

pub fn handle_search(
    mode: ConnectMode,
    socket: Option<&str>,
    query: &str,
    all: bool,
    vault_slug: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(mode, ConnectMode::Direct) {
        return Err("search requires daemon mode (multi-vault fan-out); drop --direct".into());
    }
    ensure_unlocked_daemon(socket)?;
    let payload = serde_json::json!({
        "query": query,
        "all": all,
        "vault_slug": vault_slug.unwrap_or(""),
    });
    let resp = client::request_to("vault.search", &payload.to_string(), socket)?;
    if !resp.success {
        return Err(resp.error_message.into());
    }
    let data: serde_json::Value = serde_json::from_str(&resp.payload)?;
    let rows = data["matches"].as_array().cloned().unwrap_or_default();
    if rows.is_empty() {
        println!("No matches.");
        return Ok(());
    }
    for c in &rows {
        print_search_row(c);
    }
    println!();
    println!("{} match(es)", rows.len());
    Ok(())
}

fn print_search_row(c: &serde_json::Value) {
    let fav = if c["favorite"].as_bool().unwrap_or(false) {
        "*"
    } else {
        " "
    };
    let id = c["id"].as_str().unwrap_or("");
    let ctype = c["cipher_type"].as_str().unwrap_or("login").to_lowercase();
    let name = c["name"].as_str().unwrap_or("");
    let username = c["username"].as_str().unwrap_or("");
    // Attribution renders only when the row came from a named vault
    // (--all / --vault); a plain active-vault search prints list-style.
    let vault = c["vault_name"].as_str().unwrap_or("");
    if vault.is_empty() {
        println!("{fav} {id}  [{ctype:>10}]  {name}  {username}");
    } else {
        println!("{fav} {id}  [{ctype:>10}]  {name}  {username}  ({vault})");
    }
}

pub fn handle_trash_list(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            ensure_unlocked_daemon(socket)?;
            let resp = client::request_to("vault.list_full", "", socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            let data: serde_json::Value = serde_json::from_str(&resp.payload)?;
            let trash = data["trash"].as_array();
            match trash {
                None => println!("Trash is empty."),
                Some(entries) if entries.is_empty() => println!("Trash is empty."),
                Some(entries) => {
                    for c in entries {
                        print_trash_row(c);
                    }
                    println!();
                    println!("{} entr(y|ies) in trash", entries.len());
                }
            }
            Ok(())
        }
        ConnectMode::Direct => {
            let path = Path::new(vault_path);
            let handle = if std::env::var("BALUARD_PASSWORD").is_ok() {
                unlock_vault_direct(vault_path)?
            } else {
                VaultHandle::open(path)?
            };
            if !handle.is_unlocked() {
                let ids = handle.list_trash_ids()?;
                for id in &ids {
                    println!("{id}");
                }
                println!("{} entr(y|ies) (locked, unlock for details)", ids.len());
                return Ok(());
            }
            let entries = handle.list_trash_entries()?;
            if entries.is_empty() {
                println!("Trash is empty.");
                return Ok(());
            }
            for (id, _) in &entries {
                if let Ok(baluard_core::vault::handle::CipherRead::Decrypted(ref c)) =
                    handle.get_cipher(*id)
                {
                    let ctype = format!("{:?}", c.kind.cipher_type()).to_lowercase();
                    let username = match &c.kind {
                        baluard_core::types::CipherKind::Login(data) => {
                            data.username.as_deref().unwrap_or("")
                        }
                        _ => "",
                    };
                    println!("{id}  [{ctype:>10}]  {}  {username}", c.name);
                }
            }
            println!();
            println!("{} entr(y|ies) in trash", entries.len());
            Ok(())
        }
    }
}

pub fn handle_trash_restore(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let cipher_id = uuid::Uuid::parse_str(id).map_err(|_| "invalid UUID")?;
    match mode {
        ConnectMode::Daemon => {
            ensure_unlocked_daemon(socket)?;
            let resp = client::request_to("vault.trash.restore", id, socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("Restored.");
            Ok(())
        }
        ConnectMode::Direct => {
            unlock_vault_direct(vault_path)?.restore_cipher(cipher_id)?;
            println!("Restored.");
            Ok(())
        }
    }
}

/// Purge scope phrasing: `--days 0` wipes everything (desktop Empty Trash
/// parity); otherwise the daemon only removes trash older than N days.
fn purge_scope(days: u32) -> String {
    if days == 0 {
        "entire trash".to_string()
    } else {
        format!("trash older than {days} day(s)")
    }
}

pub fn handle_trash_purge(
    mode: ConnectMode,
    vault_path: &str,
    socket: Option<&str>,
    days: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            ensure_unlocked_daemon(socket)?;
            let resp = client::request_to("vault.trash.purge", &days.to_string(), socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            let count = serde_json::from_str::<serde_json::Value>(&resp.payload)?["purged_count"]
                .as_u64()
                .unwrap_or(0);
            println!(
                "{count} entr(y|ies) permanently deleted ({}).",
                purge_scope(days)
            );
            Ok(())
        }
        ConnectMode::Direct => {
            let count = unlock_vault_direct(vault_path)?.purge_old_trash(days)?;
            println!(
                "{count} entr(y|ies) permanently deleted ({}).",
                purge_scope(days)
            );
            Ok(())
        }
    }
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
    yes: bool,
    socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use baluard_core::device_manager::{DeviceManager, EnrollmentPayload};

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
    if !yes {
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
    }

    match mode {
        ConnectMode::Daemon => {
            // Route through daemon
            let resp = client::request_to(
                "vault.enroll_with_phrase",
                &serde_json::json!({ "phrase": phrase_str }).to_string(),
                socket,
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

            // Open DeviceManager and enroll. The policy comes from
            // settings.dec decrypted inside core with the phrase-recovered
            // root key — a locked vault cannot read it, so callers never
            // guess (locked reads misreport Strict).
            let mut dm = DeviceManager::load_from_vault(path)?;

            let result = dm.enroll_with_recovery_phrase(
                &payload,
                &phrase_str,
                x25519_secret,
                ed25519_signing,
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

/// Commit pending local changes without touching the network. Deliberately
/// direct-only: there is no daemon route because committing is local-only
/// state, and the seed/demo flow needs it headless.
pub fn handle_sync_commit(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    sync_commit_direct(vault_path)
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
fn sync_commit_direct(vault_path: &str) -> Result<(), Box<dyn std::error::Error>> {
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
    } else {
        println!("Nothing to commit.");
    }
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
    let mut engine = baluard_core::sync::engine::SyncEngine::new(
        path,
        &first_device_id(vault_path),
        seal.as_ref(),
    );
    if let Some(vk) = handle.enroll_verify_key() {
        engine = engine.with_enroll_verify_key(vk);
    }
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
fn sync_commit_direct(_: &str) -> Result<(), Box<dyn std::error::Error>> {
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
/// Master password for daemon-mode operations. Resolution order:
/// BALUARD_PASSWORD env, piped stdin, TTY prompt. Under BALUARD_NO_PROMPT
/// an empty answer would burn a server-side rate-limit failure, so it is
/// an error instead of a silent empty string.
fn daemon_master_password(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    if let Ok(pw) = std::env::var("BALUARD_PASSWORD") {
        return Ok(pw);
    }
    if std::env::var_os("BALUARD_NO_PROMPT").is_some() {
        return Err(
            "BALUARD_NO_PROMPT is set but BALUARD_PASSWORD is not; refusing to send an empty master password"
                .into(),
        );
    }
    prompt_password(prompt)
}

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

    let mut password = daemon_master_password("Master password: ")?;
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
    baluard_core::vault::device_privkey::local_device_id(Path::new(vault_path))
}

/// Gate for irreversible member operations. --yes skips; a terminal
/// gets a typed confirmation; anything else (scripts without --yes)
/// refuses rather than guessing.
pub fn confirm_destructive(
    yes: bool,
    word: &str,
    consequence: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if yes {
        return Ok(());
    }
    if std::env::var_os("BALUARD_NO_PROMPT").is_some() {
        return Err(
            "refusing without confirmation under BALUARD_NO_PROMPT; pass --yes to proceed"
                .to_string()
                .into(),
        );
    }
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        use std::io::{BufRead, Write};
        println!("This is irreversible: {consequence}.");
        print!("Type '{word}' to confirm: ");
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        if line.trim().trim_matches(['\'', '"']) == word {
            return Ok(());
        }
    }
    Err("refusing without confirmation; pass --yes to proceed"
        .to_string()
        .into())
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
                collection_id: None,
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

// ── Space settings (sharing policy knobs) ──

pub fn handle_space_settings_get(
    mode: ConnectMode,
    socket: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ConnectMode::Daemon => {
            ensure_unlocked_daemon(socket)?;
            let resp = client::request_to("space.settings", "", socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("{}", resp.payload);
            Ok(())
        }
        ConnectMode::Direct => {
            eprintln!("Space settings requires daemon mode. Use --socket or start the daemon.");
            std::process::exit(1);
        }
    }
}

/// Space policy knobs accept a fixed vocabulary; validate values CLI-side
/// so the daemon never sees garbage (same convention as handle_settings_set).
fn parse_space_knob(key: &str, value: &str) -> Result<serde_json::Value, String> {
    fn bool_val(v: &str) -> Result<bool, String> {
        if v.eq_ignore_ascii_case("true") {
            Ok(true)
        } else if v.eq_ignore_ascii_case("false") {
            Ok(false)
        } else {
            Err(String::from("expected true or false"))
        }
    }

    let mut partial = serde_json::Map::new();
    match key {
        "guest_enabled" | "allow_viewer_export" => {
            let b = bool_val(value).map_err(|e| format!("{key}: {e}"))?;
            partial.insert(key.to_string(), serde_json::json!(b));
        }
        "space_invite_authority" => {
            if !matches!(value, "owners" | "admins") {
                return Err("space_invite_authority must be owners or admins".into());
            }
            partial.insert(key.to_string(), serde_json::json!(value));
        }
        "trash_policy" => {
            if !matches!(value, "admins_only" | "write_scope_can_trash") {
                return Err("trash_policy must be admins_only or write_scope_can_trash".into());
            }
            partial.insert(key.to_string(), serde_json::json!(value));
        }
        "join_approval" => {
            if !matches!(value, "manual" | "code") {
                return Err("join_approval must be manual or code".into());
            }
            partial.insert(key.to_string(), serde_json::json!(value));
        }
        "restore_policy" => {
            if value != "admins_only" {
                return Err("restore_policy must be admins_only".into());
            }
            partial.insert(key.to_string(), serde_json::json!(value));
        }
        "default_add_collection" => {
            // A UUID string; existence is the daemon's check (the CLI
            // has no collections view of the target vault).
            uuid::Uuid::parse_str(value).map_err(|_| {
                "default_add_collection must be a cipher-collection UUID".to_string()
            })?;
            partial.insert(key.to_string(), serde_json::json!(value));
        }
        "collection_create_authority" => {
            if !matches!(value, "admins" | "editors") {
                return Err("collection_create_authority must be admins or editors".into());
            }
            partial.insert(key.to_string(), serde_json::json!(value));
        }
        "quorum_admin_ops" => {
            let n: u32 = value.parse().map_err(|_| {
                String::from("quorum_admin_ops must be a whole number between 1 and 5")
            })?;
            // Mirror the daemon's S4-3 bound exactly; rejecting here gives a
            // clearer error than a round-trip to space.settings_set.
            if !(1..=5).contains(&n) {
                return Err("quorum_admin_ops must be between 1 and 5".into());
            }
            partial.insert(key.to_string(), serde_json::json!(n));
        }
        _ => {
            return Err(format!(
                "Unknown space knob: {key}. Available: guest_enabled, allow_viewer_export, space_invite_authority, trash_policy, join_approval, restore_policy, collection_create_authority, quorum_admin_ops, default_add_collection"
            ));
        }
    }
    Ok(serde_json::Value::Object(partial))
}

pub fn handle_space_settings_set(
    mode: ConnectMode,
    socket: Option<&str>,
    kv: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (key, value) = kv
        .split_once('=')
        .ok_or("Usage: baluard settings space-set key=value")?;
    let payload = parse_space_knob(key, value)?;

    match mode {
        ConnectMode::Daemon => {
            ensure_unlocked_daemon(socket)?;
            let resp = client::request_to("space.settings_set", &payload.to_string(), socket)?;
            if !resp.success {
                return Err(resp.error_message.into());
            }
            println!("Space setting updated.");
            Ok(())
        }
        ConnectMode::Direct => {
            eprintln!("Space settings requires daemon mode. Use --socket or start the daemon.");
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

    let encrypted = import_format == baluard_core::import::ImportFormat::BaluardEncrypted;

    // Binary sniff before any text read: a .bldbak container fed to a text
    // parser would fail with a confusing decode error instead of a hint.
    if !encrypted {
        use std::io::Read;
        let mut head = [0u8; 6];
        let got = std::fs::File::open(path)
            .and_then(|mut f| f.read_exact(&mut head))
            .ok();
        if got == Some(()) && &head == baluard_core::import::backup_container::MAGIC {
            return Err(format!(
                "{path} is an encrypted Baluard backup. Use: baluard import baluard-encrypted {path}"
            )
            .into());
        }
    }

    ensure_unlocked_daemon(socket)?;

    // Pre-read file size check (prevent OOM on large files). Path-passthrough
    // formats (encrypted backups) skip it: the daemon reads the file itself.
    if !encrypted {
        const MAX_IMPORT_SIZE: u64 = 50 * 1024 * 1024; // 50MB
        let file_meta =
            std::fs::metadata(path).map_err(|e| format!("Failed to stat {path}: {e}"))?;
        if file_meta.len() > MAX_IMPORT_SIZE {
            return Err(format!(
                "Import file too large: {} bytes (max {} bytes)",
                file_meta.len(),
                MAX_IMPORT_SIZE
            )
            .into());
        }
    }

    // For 1PUX, read as binary and base64-encode
    let payload = match import_format {
        baluard_core::import::ImportFormat::OnePassword1pux => {
            let bytes = std::fs::read(path).map_err(|e| format!("Failed to read {path}: {e}"))?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            serde_json::json!({"format": format, "data": b64}).to_string()
        }
        baluard_core::import::ImportFormat::BaluardEncrypted => {
            // Path passthrough: the file never crosses the socket (§8).
            let passphrase = backup_passphrase(false)?;
            let payload = serde_json::json!({
                "format": format,
                "passphrase": passphrase.as_str(),
                "in_path": path,
            })
            .to_string();
            println!("Importing from {path} (format: {format})...");
            let resp = client::request_to("vault.import", &payload, socket)?;
            let mut payload = payload;
            payload.zeroize();
            if !resp.success {
                return Err(resp.error_message.into());
            }
            let result: serde_json::Value = serde_json::from_str(&resp.payload)?;
            println!("Import complete:");
            println!("  Imported: {}", result["imported"].as_u64().unwrap_or(0));
            println!("  Skipped:  {}", result["skipped"].as_u64().unwrap_or(0));
            return Ok(());
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

/// Backup-passphrase resolution (docs/plan-encrypted-backup.md §8):
/// BALUARD_BACKUP_PASSPHRASE env first (scripting/E2E; --generate is then
/// ignored with a note), else --generate prints a fresh 6-word passphrase
/// once, else the user types it twice — a typo would produce a backup that
/// passes auto-verify but that nobody can ever open.
fn backup_passphrase(generate: bool) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    if let Ok(pw) = std::env::var("BALUARD_BACKUP_PASSPHRASE") {
        if !pw.is_empty() {
            if generate {
                eprintln!(
                    "Note: --generate ignored; BALUARD_BACKUP_PASSPHRASE is set (scripting mode)."
                );
            }
            return Ok(Zeroizing::new(pw));
        }
    }
    if generate {
        let opts = baluard_core::generator::PassphraseOptions {
            word_count: 6,
            ..Default::default()
        };
        let pw = baluard_core::generator::generate_passphrase(&opts).map_err(|e| e.to_string())?;
        println!("Backup passphrase (shown once — save it now): {pw}");
        return Ok(Zeroizing::new(pw));
    }
    if std::env::var("BALUARD_NO_PROMPT").as_deref() == Ok("1") {
        return Err(
            "No BALUARD_BACKUP_PASSPHRASE set and prompts are disabled (BALUARD_NO_PROMPT=1)"
                .into(),
        );
    }
    let pw = prompt_password("Backup passphrase: ")?;
    let confirm = prompt_password("Confirm backup passphrase: ")?;
    if pw != confirm {
        return Err("Backup passphrases do not match".into());
    }
    let mut confirm = confirm;
    confirm.zeroize();
    Ok(Zeroizing::new(pw))
}

pub fn handle_export(
    socket: Option<&str>,
    format: &str,
    path: &str,
    encrypted: bool,
    generate: bool,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_unlocked_daemon(socket)?;

    if encrypted && format != "baluard" {
        eprintln!(
            "Note: --format is ignored with --encrypted (the container wraps a baluard backup)."
        );
    }

    let passphrase = if encrypted {
        Some(backup_passphrase(generate)?)
    } else {
        None
    };

    if passphrase.is_none() {
        // Warn about plaintext secrets
        eprintln!(
            "WARNING: Export file will contain UNENCRYPTED secrets (passwords, cards, SSH keys)."
        );
        eprintln!("         Delete the file after use. Do not upload to cloud storage.");
    }

    // Confirm overwrite if file exists
    if std::path::Path::new(path).exists() && !force {
        println!("File '{path}' already exists. Overwrite? [y/N] ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            println!("Export cancelled.");
            return Ok(());
        }
    }

    if let Some(pw) = &passphrase {
        // Path-based transport (§8): the daemon writes the container
        // itself; only the summary rides back over the socket.
        println!("Exporting encrypted backup...");
        let payload = serde_json::json!({
            "format": "baluard-encrypted",
            "passphrase": pw.as_str(),
            "out_path": path,
        })
        .to_string();
        let resp = client::request_to("vault.export", &payload, socket)?;
        let mut payload = payload;
        payload.zeroize();
        if !resp.success {
            return Err(resp.error_message.into());
        }
        let result: serde_json::Value = serde_json::from_str(&resp.payload)?;
        let written = result["written_bytes"].as_u64().unwrap_or(0);
        println!("Encrypted backup written: {path} ({written} bytes)");
        // The daemon's check covers the bytes it built; re-read the file
        // from disk so a truncated or clobbered write cannot pass silently.
        let meta = std::fs::metadata(path)?;
        if meta.len() != written {
            return Err(format!(
                "Backup verification failed: file holds {} bytes, expected {written}",
                meta.len()
            )
            .into());
        }
        let mut head = [0u8; 6];
        {
            use std::io::Read;
            std::fs::File::open(path)?.read_exact(&mut head)?;
        }
        if &head != b"BLDBAK" {
            return Err("Backup verification failed: file is not a Baluard backup".into());
        }
        println!(
            "Backup checked: {} entries.",
            result["entries"].as_u64().unwrap_or(0)
        );
        return Ok(());
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
                        collection_id: None,
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
                        collection_id: None,
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
        VaultAction::CopyItems {
            source,
            target,
            ciphers,
            all,
        } => vaults_copy_items(source, target, ciphers, *all, cli),
        VaultAction::Repoint { slug, url } => vaults_repoint(slug, url),
        VaultAction::RecoverKit { slug, device_name } => {
            vaults_recover_kit(slug, device_name.as_deref())
        }
    }
}

/// `baluard vaults copy-items <source> <target>`: the founding flow
/// (family-spaces step 8b). Daemon-only — both vaults must be unlocked
/// in the daemon so the copy bridges two open sessions. Ids are
/// validated CLI-side so a typo fails before any read.
fn vaults_copy_items(
    source: &str,
    target: &str,
    ciphers: &[String],
    all: bool,
    cli: &Cli,
) -> Result<(), Box<dyn std::error::Error>> {
    if !all && ciphers.is_empty() {
        return Err("nothing to copy: pass --cipher <uuid> (repeatable) or --all".into());
    }
    let mut ids = Vec::with_capacity(ciphers.len());
    for c in ciphers {
        let id = uuid::Uuid::parse_str(c).map_err(|_| {
            format!("'{c}' is not a cipher UUID (use 'baluard --vault {source} list' to find ids)")
        })?;
        ids.push(id.to_string());
    }
    let payload = serde_json::json!({
        "source": source,
        "target": target,
        "cipher_ids": ids,
        "all": all,
    })
    .to_string();
    let resp = crate::client::request_to("vaults.copy_items", &payload, cli.socket.as_deref())?;
    if !resp.success {
        return Err(format!("copy failed: {}", resp.error_message).into());
    }
    let v: serde_json::Value = serde_json::from_str(&resp.payload)?;
    let copied = v["copied"].as_u64().unwrap_or(0);
    println!("Copied {copied} entries into '{target}'.");
    if let Some(failed) = v["failed"].as_array() {
        for f in failed {
            println!(
                "  failed {}: {}",
                f["cipher_id"].as_str().unwrap_or("?"),
                f["error"].as_str().unwrap_or("unknown error")
            );
        }
    }
    let att = v["attachments_not_copied"].as_u64().unwrap_or(0);
    if att > 0 {
        println!("  {att} attachment(s) were not copied - re-add them from the original files.");
    }
    Ok(())
}

/// `baluard vaults repoint <slug> <url>`: re-point a registered vault's
/// sync origin to a new URL without announcing. The S3-8 escape hatch
/// for missed migrations and manual moves; the in-app migrate is the
/// normal path (it announces, so every device follows automatically).
/// Keyless: the repo config is plain git state, no unlock needed.
fn vaults_repoint(slug: &str, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    baluard_core::sync::engine::validate_git_url(url)?;
    let reg = baluard_core::vault::registry::VaultRegistry::load_locked()?;
    let entry = reg
        .get(slug)
        .ok_or_else(|| format!("vault '{slug}' not found in registry"))?;
    let vault_path = std::path::PathBuf::from(&entry.path);
    if !vault_path.is_dir() {
        return Err(format!("vault directory missing: {}", entry.path.display()).into());
    }
    let engine = baluard_core::sync::engine::SyncEngine::new(&vault_path, "cli", None);
    let repo = engine.open_repo()?;
    repo.remote_set_url("origin", url)
        .map_err(|e| format!("repoint failed: {e}"))?;
    if let Ok(mut cfg) = repo.config() {
        let _ = cfg.set_str("baluard.adopted-remote", url);
    }
    println!("Sync address for '{slug}' is now {url}");
    Ok(())
}

/// `baluard vaults recover-kit <slug>`: recover a lost admin device on
/// a FRESH clone of a Space using the Space Recovery Kit phrase. The
/// phrase unwraps the Root Key, the canary verifies the vault, and the
/// new device binds to the live Owner member row — then unlock with
/// the master password as usual and pull. Direct-core by design: the
/// ceremony is one local op on a clone and needs no daemon session.
fn vaults_recover_kit(
    slug: &str,
    device_name: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let reg = baluard_core::vault::registry::VaultRegistry::load_locked()?;
    let entry = reg
        .get(slug)
        .ok_or_else(|| format!("vault '{slug}' not found in registry"))?;
    let vault_path = std::path::PathBuf::from(&entry.path);
    if !vault_path.is_dir() {
        return Err(format!("vault directory missing: {}", entry.path.display()).into());
    }
    // Harness/scripting overrides: BALUARD_RECOVERY_PHRASE and
    // BALUARD_PASSWORD (via the shared helper) keep this flow unattended.
    let phrase = match std::env::var("BALUARD_RECOVERY_PHRASE") {
        Ok(p) => p,
        Err(_) => prompt_password("Recovery phrase (24 words): ")?,
    };
    let password = daemon_master_password("New master password for this device: ")?;
    let device_name = match device_name {
        Some(name) => name.to_string(),
        None => {
            print!("Device name: ");
            use std::io::Write;
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line.trim().to_string()
        }
    };
    let device_id = baluard_core::vault::handle::VaultHandle::recover_device_with_kit(
        &vault_path,
        &phrase,
        &password,
        &device_name,
    )?;
    println!("Device recovered ({device_id}).");
    println!("Unlock with your master password, then pull to catch up.");
    Ok(())
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
        merge_opt_in: None,
        merge_ceiling_seen: false,
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
        let mut password = daemon_master_password(&format!("Master password for '{slug}': "))?;
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
