//! Update check + self-update for the baluard CLI.
//!
//! Release artifacts live on GitHub Releases under stable names
//! (`Baluard-cli-<platform>.tar.gz`); integrity is anchored by the signed
//! `SHA256SUMS` (minisign, key in `updater.pub` at the workspace root).
//! The background check runs at most once per 24h per machine; the notice
//! prints to stderr until the installed version catches up.

use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use minisign_verify::{PublicKey, Signature};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REPO: &str = "baluard-org/baluard";
const API_BASE: &str = "https://api.github.com";
const DOWNLOAD_BASE: &str = "https://github.com";
const CHECK_INTERVAL_SECS: u64 = 24 * 60 * 60;
// Stage dirs newer than this belong to a live concurrent self-update.
const STAGE_IDLE_SECS: u64 = 60 * 60;
const CHECK_TIMEOUT_SECS: u64 = 5;
const DOWNLOAD_TIMEOUT_SECS: u64 = 300;
// The tauri signer's signature mode (prehashed vs legacy) is not pinned
// here; allow_legacy accepts both because the mode rides in the signature
// file itself.
const ALLOW_LEGACY_MINISIGN: bool = true;

// include_str! reaches the workspace root (not packaged standalone); the
// same key is embedded inline in desktop/src-tauri/tauri.conf.json and must
// rotate together with it.
const MINISIGN_PUBKEY: &str = include_str!("../../../updater.pub");

#[derive(Serialize, Deserialize)]
struct UpdateState {
    last_check: u64,
    latest: Option<String>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn current_version() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("workspace version is valid semver")
}

fn parse_tag(tag: &str) -> Result<Version> {
    let bare = tag.strip_prefix('v').unwrap_or(tag);
    Version::parse(bare).with_context(|| format!("release tag '{tag}' is not semver"))
}

fn exe_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

fn mise_managed(exe: &Path) -> bool {
    if exe.components().any(|c| c.as_os_str() == "mise") {
        return true;
    }
    std::env::var_os("MISE_DATA_DIR")
        .filter(|d| !d.is_empty())
        .map(|d| {
            let dir = PathBuf::from(d);
            // canonicalize matches the \\?\ form a canonicalized current_exe
            // yields on windows; without it the prefix compare never matches.
            let dir = dir.canonicalize().unwrap_or(dir);
            exe.starts_with(&dir)
        })
        .unwrap_or(false)
}

/// Release asset carrying the CLI + daemon binaries for this build target.
fn cli_asset_name() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("Baluard-cli-amd64.tar.gz"),
        ("macos", "aarch64") => Ok("Baluard-cli-darwin-arm64.tar.gz"),
        ("windows", "x86_64") => Ok("Baluard-cli-windows-x86_64.tar.gz"),
        ("macos", "x86_64") => Err(anyhow!(
            "no macOS Intel CLI build is published; baluard self-update is unavailable on this platform"
        )),
        _ => Err(anyhow!(
            "baluard self-update is unavailable on this platform"
        )),
    }
}

fn state_needs_refresh(state: Option<&UpdateState>, now: u64) -> bool {
    match state {
        None => true,
        Some(s) => now.saturating_sub(s.last_check) >= CHECK_INTERVAL_SECS,
    }
}

fn read_state(path: &Path) -> Option<UpdateState> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn write_state(path: &Path, state: &UpdateState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string(state)?)?;
    Ok(())
}

fn fetch_latest(client: &reqwest::blocking::Client, api_base: &str) -> Result<Version> {
    let url = format!("{api_base}/repos/{REPO}/releases/latest");
    let resp = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .context("update check request failed")?
        .error_for_status()
        .context("update check request failed")?;
    let json: serde_json::Value = resp.json().context("update check response was not JSON")?;
    let tag = json
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("update check response has no tag_name"))?;
    parse_tag(tag)
}

fn download(client: &reqwest::blocking::Client, base: &str, name: &str) -> Result<Vec<u8>> {
    let url = format!("{base}/{name}");
    let resp = client
        .get(&url)
        .send()
        .with_context(|| format!("failed to download {name}"))?
        .error_for_status()
        .with_context(|| format!("failed to download {name}"))?;
    resp.bytes()
        .map(|b| b.to_vec())
        .with_context(|| format!("failed to download {name}"))
}

/// Constant-time hex digest compare (both inputs are fixed-length hex).
fn digests_equal(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Extract the line for `asset` from SHA256SUMS content.
fn expected_digest(sums: &str, asset: &str) -> Result<String> {
    sums.lines()
        .filter_map(|line| {
            let (hash, name) = line.split_once(char::is_whitespace)?;
            Some((hash.trim(), name.trim()))
        })
        .find(|(_, name)| *name == asset)
        .map(|(hash, _)| hash.to_ascii_lowercase())
        .ok_or_else(|| anyhow!("SHA256SUMS has no entry for {asset}"))
}

fn verify_sums(pk: &PublicKey, sums: &str, sig: &str) -> Result<()> {
    let sig = Signature::decode(sig).context("SHA256SUMS.sig is not a valid minisign signature")?;
    pk.verify(sums.as_bytes(), &sig, ALLOW_LEGACY_MINISIGN)
        .map_err(|_| anyhow!("SHA256SUMS signature verification failed"))
}

/// The release pipeline signs with the tauri signer, which wraps the
/// minisign signature text in one base64 line; accept the wrapped form
/// and the plain form.
fn decode_sig_artifact(bytes: &str) -> String {
    use base64::Engine as _;
    match base64::engine::general_purpose::STANDARD.decode(bytes.trim()) {
        Ok(decoded) if decoded.starts_with(b"untrusted comment:") => {
            String::from_utf8(decoded).unwrap_or_else(|_| bytes.to_string())
        }
        _ => bytes.to_string(),
    }
}

fn extract_archive(tgz: &[u8], dest: &Path) -> Result<Vec<PathBuf>> {
    let gz = flate2::read::GzDecoder::new(tgz);
    let mut archive = tar::Archive::new(gz);
    let wanted = [exe_name("baluard"), exe_name("baluard-daemon")];
    let mut found: Vec<String> = Vec::with_capacity(2);
    let mut unpacked: Vec<PathBuf> = Vec::with_capacity(2);
    let entries = archive
        .entries()
        .context("failed to read archive entries")?;
    for entry in entries {
        let mut entry = entry?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        // Join by file_name only: tar entries cannot escape dest
        let name = entry
            .path()?
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !wanted.contains(&name) {
            continue;
        }
        if found.iter().any(|n| n == &name) {
            bail!("release archive contains duplicate entries for {name}");
        }
        let out = dest.join(&name);
        entry
            .unpack(&out)
            .with_context(|| format!("failed to unpack {name}"))?;
        found.push(name);
        unpacked.push(out);
    }
    for want in &wanted {
        if !found.iter().any(|n| n == want) {
            bail!("release archive does not contain {want}");
        }
    }
    Ok(unpacked)
}

#[cfg(unix)]
fn copy_mode(staged: &Path, target: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = target
        .metadata()
        .map(|m| m.permissions().mode())
        .unwrap_or(0o755);
    fs::set_permissions(staged, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn copy_mode(_staged: &Path, _target: &Path) -> Result<()> {
    Ok(())
}

/// Atomically move `staged` onto `target`. On Windows a running exe cannot
/// be unlinked, so the live binary is renamed aside first.
fn replace_binary(staged: &Path, target: &Path) -> Result<()> {
    copy_mode(staged, target)?;
    let file = fs::File::open(staged)?;
    file.sync_all()?;
    drop(file);
    #[cfg(windows)]
    let old = {
        let name = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let old = target.with_file_name(format!("{name}.old"));
        if target.exists() {
            fs::rename(target, &old)
                .with_context(|| format!("failed to back up {}", target.display()))?;
        }
        old
    };
    fs::rename(staged, target)
        .with_context(|| format!("failed to replace {}", target.display()))?;
    #[cfg(windows)]
    {
        let _ = fs::remove_file(&old);
    }
    Ok(())
}

fn clean_stale(target_dir: &Path) {
    // .new/.old only ever exist on windows (rename-aside dance); on unix
    // those names would be user files this code never created.
    if cfg!(windows) {
        for name in [exe_name("baluard"), exe_name("baluard-daemon")] {
            for suffix in [".new", ".old"] {
                let candidate = target_dir.join(format!("{name}{suffix}"));
                if candidate.exists() {
                    let _ = fs::remove_file(&candidate);
                }
            }
        }
    }
    if let Ok(entries) = fs::read_dir(target_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with(".baluard-update-") {
                continue;
            }
            // A concurrent self-update's live stage dir must survive; only
            // sweep dirs idle long enough to be crash leftovers. Unreadable
            // mtime: leave it alone.
            let idle = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .map(|age| age >= std::time::Duration::from_secs(STAGE_IDLE_SECS))
                .unwrap_or(false);
            if idle {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }
}

/// Defense against a replayed (validly signed) older release served through
/// the mutable latest/download alias: the staged CLI must report a version
/// at least as new as the running one before anything is replaced.
fn verify_staged_version(staged: &Path, current: &Version) -> Result<()> {
    let out = std::process::Command::new(staged)
        .arg("--version")
        .output()
        .with_context(|| {
            format!(
                "could not execute the staged binary at {}",
                staged.display()
            )
        })?;
    if !out.status.success() {
        bail!("the staged binary failed to report its version");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let reported = text
        .split_whitespace()
        .last()
        .ok_or_else(|| anyhow!("--version produced no output"))?;
    let reported = Version::parse(reported)
        .with_context(|| format!("staged binary reported an unparsable version '{reported}'"))?;
    if reported < *current {
        bail!("refusing to install release {reported}, older than the running {current}");
    }
    Ok(())
}

fn check_client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .user_agent(format!("baluard-cli/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(CHECK_TIMEOUT_SECS))
        .build()?)
}

fn download_client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .user_agent(format!("baluard-cli/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(DOWNLOAD_TIMEOUT_SECS))
        .build()?)
}

/// Refresh the update-check state at most once per CHECK_INTERVAL_SECS.
/// Silent: network or state-file failures must never disturb a command.
/// last_check is recorded even on failure so one bad run cannot hammer
/// the GitHub API.
fn refresh_if_due() {
    let path = baluard_core::paths::update_state_path();
    let state = read_state(&path);
    if !state_needs_refresh(state.as_ref(), now_secs()) {
        return;
    }
    let mut next = state.unwrap_or(UpdateState {
        last_check: 0,
        latest: None,
    });
    next.last_check = now_secs();
    if let Ok(client) = check_client() {
        if let Ok(latest) = fetch_latest(&client, API_BASE) {
            next.latest = Some(latest.to_string());
        }
    }
    let _ = write_state(&path, &next);
}

fn notice_text(latest: &Version, current: &Version, mise: bool) -> Option<String> {
    if latest <= current {
        return None;
    }
    let how = if mise {
        "mise upgrade github:baluard-org/baluard".to_string()
    } else {
        "baluard self-update".to_string()
    };
    Some(format!(
        "Baluard {latest} is available (installed {current}). Update: {how}"
    ))
}

/// Daily check + update notice. Runs on every command, gated so scripts,
/// agents, CI, and non-interactive output stay clean.
pub fn startup_notice() {
    if cfg!(debug_assertions) {
        return;
    }
    if std::env::var_os("BALUARD_NO_UPDATE_CHECK").is_some() {
        return;
    }
    if std::env::var_os("CI").is_some_and(|v| !v.is_empty()) {
        return;
    }
    if std::env::var("BALUARD_AGENT").ok().as_deref() == Some("1") {
        return;
    }
    if !std::io::stderr().is_terminal() {
        return;
    }
    refresh_if_due();
    let exe = std::env::current_exe().ok();
    let mise = exe.as_deref().map(mise_managed).unwrap_or(false);
    if let Some(state) = read_state(&baluard_core::paths::update_state_path()) {
        if let Some(latest) = state.latest.as_deref().and_then(|v| Version::parse(v).ok()) {
            if let Some(msg) = notice_text(&latest, &current_version(), mise) {
                eprintln!("{msg}");
            }
        }
    }
}

/// `baluard self-update`: fetch the latest stable release, verify it against
/// the signed SHA256SUMS, and replace the CLI + daemon binaries in place.
/// Never downgrades; refuses to fight mise-managed installs.
pub fn self_update() -> Result<()> {
    let exe = std::env::current_exe().context("cannot locate the running binary")?;
    let exe = fs::canonicalize(exe).context("cannot resolve the running binary path")?;
    if mise_managed(&exe) {
        bail!("this binary is managed by mise; run `mise upgrade github:baluard-org/baluard`");
    }
    let target_dir = exe
        .parent()
        .ok_or_else(|| anyhow!("binary has no parent directory"))?
        .to_path_buf();
    let asset = cli_asset_name()?;
    let client = download_client()?;
    let pk =
        PublicKey::decode(MINISIGN_PUBKEY).context("embedded updater public key is invalid")?;
    self_update_from(&client, API_BASE, DOWNLOAD_BASE, asset, &target_dir, &pk)
}

fn self_update_from(
    client: &reqwest::blocking::Client,
    api_base: &str,
    download_base: &str,
    asset: &str,
    target_dir: &Path,
    pk: &PublicKey,
) -> Result<()> {
    let current = current_version();
    let latest = fetch_latest(client, api_base)?;
    if latest <= current {
        if current > latest {
            println!(
                "baluard {current} is newer than the latest published release ({latest}); no update."
            );
        } else {
            println!("baluard {current} is up to date.");
        }
        return Ok(());
    }

    println!("Updating baluard {current} -> {latest} ...");
    let archive = download(client, download_base, asset)?;
    let sums = download(client, download_base, "SHA256SUMS")?;
    let sig = download(client, download_base, "SHA256SUMS.sig")?;

    let sums = String::from_utf8(sums).context("SHA256SUMS is not valid UTF-8")?;
    let sig = String::from_utf8(sig).context("SHA256SUMS.sig is not valid UTF-8")?;
    let sig = decode_sig_artifact(&sig);
    verify_sums(pk, &sums, &sig)?;
    let expected = expected_digest(&sums, asset)?;
    let actual = sha256_hex(&archive);
    if !digests_equal(&expected, &actual) {
        bail!("checksum mismatch for {asset}: release does not match the signed SHA256SUMS");
    }

    // Stage next to the target: same filesystem, rename stays atomic.
    // Sweep stale leftovers BEFORE creating this run's stage dir: the
    // glob below would delete it otherwise.
    clean_stale(target_dir);
    let stage_dir = target_dir.join(format!(".baluard-update-{}", std::process::id()));
    fs::create_dir_all(&stage_dir)?;
    let unpacked = extract_archive(&archive, &stage_dir)?;
    verify_staged_version(&stage_dir.join(exe_name("baluard")), &current)?;
    // Daemon first: a mid-flight failure can then never leave a new CLI
    // driving an old daemon. Backups stay in the stage dir until success.
    let mut ordered: Vec<(PathBuf, String, PathBuf)> = Vec::with_capacity(unpacked.len());
    for staged in unpacked {
        let name = staged
            .file_name()
            .ok_or_else(|| anyhow!("unpacked entry has no file name"))?
            .to_string_lossy()
            .into_owned();
        let target = target_dir.join(&name);
        ordered.push((staged, name, target));
    }
    ordered.sort_by_key(|(_, name, _)| *name == exe_name("baluard"));
    let mut replaced: Vec<(PathBuf, PathBuf)> = Vec::new();
    let result: Result<Vec<String>> = (|| {
        let mut updated = Vec::new();
        for (staged, name, target) in &ordered {
            let backup = stage_dir.join(format!("{name}.previous"));
            if target.exists() {
                fs::copy(target, &backup)
                    .with_context(|| format!("failed to back up {}", target.display()))?;
            }
            if let Err(e) = replace_binary(staged, target) {
                for (t, b) in replaced.iter().rev() {
                    if b.exists() {
                        let _ = fs::copy(b, t);
                    }
                }
                return Err(e.context("update aborted, previous binaries restored"));
            }
            replaced.push((target.clone(), backup));
            updated.push(name.clone());
        }
        Ok(updated)
    })();
    let _ = fs::remove_dir_all(&stage_dir);
    let updated = result?;

    println!("Updated {} to {latest}.", updated.join(" + "));
    if updated.iter().any(|n| n.contains("baluard-daemon")) {
        println!("If baluard-daemon is running, restart it to pick up the new binary.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn parses_release_tags() {
        assert_eq!(parse_tag("0.1.0").unwrap(), v("0.1.0"));
        assert_eq!(parse_tag("v0.2.1").unwrap(), v("0.2.1"));
        assert_eq!(parse_tag("1.2.3-beta.1").unwrap(), v("1.2.3-beta.1"));
        assert!(parse_tag("banana").is_err());
        assert!(parse_tag("0.1").is_err());
    }

    #[test]
    fn refresh_cadence_matches_24h_gate() {
        let fresh = UpdateState {
            last_check: 100,
            latest: None,
        };
        assert!(!state_needs_refresh(
            Some(&fresh),
            100 + CHECK_INTERVAL_SECS - 1
        ));
        assert!(state_needs_refresh(Some(&fresh), 100 + CHECK_INTERVAL_SECS));
        assert!(state_needs_refresh(None, 0));
        // Clock skew must not loop into a refresh storm.
        assert!(!state_needs_refresh(Some(&fresh), 0));
    }

    #[test]
    fn notice_only_for_newer_versions() {
        let cur = v("0.1.3");
        assert_eq!(
            notice_text(&v("0.2.0"), &cur, false).unwrap(),
            "Baluard 0.2.0 is available (installed 0.1.3). Update: baluard self-update"
        );
        assert_eq!(
            notice_text(&v("0.2.0"), &cur, true).unwrap(),
            "Baluard 0.2.0 is available (installed 0.1.3). Update: mise upgrade github:baluard-org/baluard"
        );
        assert!(notice_text(&v("0.1.3"), &cur, false).is_none());
        assert!(notice_text(&v("0.1.2"), &cur, false).is_none());
    }

    #[test]
    fn prerelease_is_older_than_release() {
        let cur = v("0.1.3-beta.1");
        assert!(notice_text(&v("0.1.3"), &cur, false).is_some());
        assert!(notice_text(&v("0.1.3-beta.1"), &cur, false).is_none());
    }

    #[test]
    fn sums_lookup_is_exact_by_asset_name() {
        let sums = "abc123  Baluard-cli-amd64.tar.gz\ndef456  Baluard-amd64.deb\n";
        assert_eq!(
            expected_digest(sums, "Baluard-cli-amd64.tar.gz").unwrap(),
            "abc123"
        );
        assert!(expected_digest(sums, "Baluard-cli-amd64.tar.gz.sig").is_err());
        assert!(expected_digest(sums, "missing.tar.gz").is_err());
    }

    #[test]
    fn digest_compare_rejects_mismatches() {
        let h = sha256_hex(b"payload");
        assert!(digests_equal(&h, &h));
        assert!(!digests_equal(&h, &sha256_hex(b"other")));
        assert!(!digests_equal(&h, "short"));
    }

    #[test]
    fn real_release_sums_signature_verifies() {
        // Public artifacts of release 0.1.0: proves the embedded key and
        // the tauri signer output stay compatible (format drift tripwire).
        let sums = include_str!("../tests/fixtures/SHA256SUMS");
        let sig = include_str!("../tests/fixtures/SHA256SUMS.sig");
        let pk = PublicKey::decode(MINISIGN_PUBKEY).unwrap();
        let sig_text = decode_sig_artifact(sig);
        verify_sums(&pk, sums, &sig_text).expect("real release signature must verify");
        let tampered = format!("0{}", sums);
        assert!(verify_sums(&pk, &tampered, &sig_text).is_err());
    }

    /// Offline minisign signer: legacy-format signatures over raw bytes,
    /// built with the same Ed25519 primitive minisign uses. Confirms our
    /// understanding of the format against the real verifier.
    struct TestSigner {
        signing: ed25519_dalek::SigningKey,
        key_id: [u8; 8],
    }
    impl TestSigner {
        fn new() -> Self {
            let mut key_id = [0u8; 8];
            getrandom::getrandom(&mut key_id).unwrap();
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).unwrap();
            Self {
                signing: ed25519_dalek::SigningKey::from_bytes(&seed),
                key_id,
            }
        }
        fn public_key_text(&self) -> String {
            let mut bin = Vec::new();
            bin.extend_from_slice(b"Ed");
            bin.extend_from_slice(&self.key_id);
            bin.extend_from_slice(self.signing.verifying_key().as_bytes());
            format!(
                "untrusted comment: minisign public key (test)\n{}\n",
                base64::engine::general_purpose::STANDARD.encode(bin)
            )
        }
        fn sign_legacy(&self, data: &[u8]) -> String {
            use ed25519_dalek::Signer;
            let mut bin1 = Vec::new();
            bin1.extend_from_slice(b"Ed");
            bin1.extend_from_slice(&self.key_id);
            bin1.extend_from_slice(&self.signing.sign(data).to_bytes());
            let trusted = "test";
            // Global signature covers sig bytes + trusted comment text
            // (without the "trusted comment: " prefix, without newline).
            let mut global_input = Vec::new();
            global_input.extend_from_slice(&bin1[10..]);
            global_input.extend_from_slice(trusted.as_bytes());
            let global = self.signing.sign(&global_input).to_bytes();
            format!(
                "untrusted comment: signature (test)\n{}\ntrusted comment: {trusted}\n{}\n",
                base64::engine::general_purpose::STANDARD.encode(bin1),
                base64::engine::general_purpose::STANDARD.encode(global)
            )
        }
    }

    #[test]
    fn minisign_format_roundtrip_with_test_key() {
        let signer = TestSigner::new();
        let sums = "cafe  Baluard-cli-amd64.tar.gz\n";
        let sig = signer.sign_legacy(sums.as_bytes());
        let pk = PublicKey::decode(&signer.public_key_text()).unwrap();
        let decoded = Signature::decode(&sig).unwrap();
        pk.verify(sums.as_bytes(), &decoded, true).unwrap();
        assert!(pk.verify(b"tampered", &decoded, true).is_err());
    }

    #[test]
    fn extraction_unpacks_binaries() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        let payload: &[u8] = b"#!/bin/sh\necho hi\n";
        for name in [
            exe_name("baluard"),
            "sub/".to_owned() + &exe_name("baluard-daemon"),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append_data(&mut header, name, payload).unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&builder.into_inner().unwrap()).unwrap();
        let tgz = gz.finish().unwrap();

        let unpacked = extract_archive(&tgz, dir.path()).unwrap();
        assert_eq!(unpacked.len(), 2);
        for p in &unpacked {
            assert!(p.starts_with(dir.path()));
            assert!(p.exists());
            assert!(p.parent().unwrap() == dir.path());
        }
    }

    /// Hand-rolled ustar entry: tar::Builder refuses to write `..` paths,
    /// and the adversary does not use our builder.
    fn raw_tar_entry(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut block = [0u8; 512];
        block[..name.len()].copy_from_slice(name.as_bytes());
        block[100..107].copy_from_slice(b"0000644");
        block[108..115].copy_from_slice(b"0000000");
        block[116..123].copy_from_slice(b"0000000");
        block[124..136].copy_from_slice(format!("{:011o}\0", payload.len()).as_bytes());
        block[136..147].copy_from_slice(b"00000000000");
        block[156] = b'0';
        block[257..262].copy_from_slice(b"ustar");
        block[263..265].copy_from_slice(b"00");
        for b in &mut block[148..156] {
            *b = b' ';
        }
        let sum: u32 = block.iter().map(|b| *b as u32).sum();
        block[148..156].copy_from_slice(format!("{:06o}\0 ", sum).as_bytes());
        let mut out = block.to_vec();
        out.extend_from_slice(payload);
        let pad = (512 - payload.len() % 512) % 512;
        out.resize(out.len() + pad, 0);
        out
    }

    #[test]
    fn extraction_refuses_traversal_entries() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        let payload: &[u8] = b"evil";
        for name in [exe_name("baluard"), exe_name("baluard-daemon")] {
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_cksum();
            builder.append_data(&mut header, name, payload).unwrap();
        }
        let mut raw = builder.into_inner().unwrap();
        raw.extend(raw_tar_entry("../evil", payload));
        raw.extend(vec![0u8; 1024]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&raw).unwrap();
        let tgz = gz.finish().unwrap();

        let unpacked = extract_archive(&tgz, dir.path()).expect("both binaries must extract");
        assert_eq!(unpacked.len(), 2);
        assert!(unpacked.iter().all(|p| p.starts_with(dir.path())));
        assert!(!dir.path().join("evil").exists());
        assert!(!outside.path().join("evil").exists());
    }

    #[test]
    fn extraction_fails_when_binaries_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        let payload: &[u8] = b"x";
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "unrelated.txt", payload)
            .unwrap();
        let tgz = builder.into_inner().unwrap();
        assert!(extract_archive(&tgz, dir.path()).is_err());
    }

    #[test]
    fn replace_binary_swaps_content_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join(exe_name("baluard"));
        fs::write(&target, b"old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o750)).unwrap();
        }
        let staged = dir.path().join(exe_name("baluard.new"));
        fs::write(&staged, b"new").unwrap();
        replace_binary(&staged, &target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert!(!staged.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o750
            );
        }
    }

    /// Full install pipeline against a local fake release server:
    /// fetch -> verify -> replace, minus the GitHub endpoints. The served
    /// CLI entry is a real executable (the version probe spawns it); a
    /// shebang script only works on unix.
    #[cfg(unix)]
    #[test]
    fn self_update_installs_from_local_release() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let signer = TestSigner::new();
        let pk = PublicKey::decode(&signer.public_key_text()).unwrap();
        let cli_script = format!("#!/bin/sh\necho baluard {}\n", env!("CARGO_PKG_VERSION"));
        let mut builder = tar::Builder::new(Vec::new());
        {
            let mut header = tar::Header::new_gnu();
            header.set_size(cli_script.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, exe_name("baluard"), cli_script.as_bytes())
                .unwrap();
        }
        {
            let daemon_payload: &[u8] = b"new-binary";
            let mut header = tar::Header::new_gnu();
            header.set_size(daemon_payload.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, exe_name("baluard-daemon"), daemon_payload)
                .unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&builder.into_inner().unwrap()).unwrap();
        let archive = gz.finish().unwrap();
        // Sanity: what we serve must round-trip through our own extractor.
        {
            let probe_dir = tempfile::tempdir().unwrap();
            let probe = extract_archive(&archive, probe_dir.path()).unwrap();
            assert_eq!(probe.len(), 2);
        }
        let asset = "Baluard-cli-amd64.tar.gz";
        let sums = format!("{}  {asset}\n", sha256_hex(&archive));
        let sums_sig = signer.sign_legacy(sums.as_bytes());
        let tag_json = format!("{{\"tag_name\":\"9.9.9\"}}");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let _server = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                while !buf.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => buf.push(byte[0]),
                    }
                }
                let path = String::from_utf8_lossy(&buf)
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("")
                    .to_string();
                let (status, body): (&str, Vec<u8>) = if path.ends_with("releases/latest") {
                    ("200 OK", tag_json.clone().into_bytes())
                } else if path.ends_with(".sig") {
                    ("200 OK", sums_sig.clone().into_bytes())
                } else if path.ends_with("SHA256SUMS") {
                    ("200 OK", sums.clone().into_bytes())
                } else if path.ends_with(asset) {
                    ("200 OK", archive.clone())
                } else {
                    ("404 Not Found", b"{}".to_vec())
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(head.as_bytes()).unwrap();
                stream.write_all(&body).unwrap();
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let target_dir = dir.path().join("bin");
        fs::create_dir_all(&target_dir).unwrap();
        let target = target_dir.join(exe_name("baluard"));
        fs::write(&target, b"old-binary").unwrap();

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        self_update_from(
            &client,
            &format!("http://127.0.0.1:{port}"),
            &format!("http://127.0.0.1:{port}"),
            asset,
            &target_dir,
            &pk,
        )
        .unwrap();
        assert_eq!(fs::read(&target).unwrap(), cli_script.as_bytes());
        let daemon = target_dir.join(exe_name("baluard-daemon"));
        assert_eq!(fs::read(&daemon).unwrap(), b"new-binary");
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn asset_name_matches_host() {
        assert_eq!(cli_asset_name().unwrap(), "Baluard-cli-amd64.tar.gz");
    }
}
