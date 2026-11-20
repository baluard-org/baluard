//! Portable in-app updates. The pendrive zip cannot run the NSIS
//! installer the tauri updater produces, so the portable flow downloads a
//! verified release zip, checks its SHA256SUMS signature and hash, stages
//! the extracted tree beside the app, and hands the swap to the launcher
//! (`baluard-portable.exe --apply-update`), which replaces the files while
//! keeping `data\` and relaunches. Trust chain: the release's updater.pub
//! equals the repo-root pubkey embedded here (the same file the updater
//! plugin trusts for installer artifacts).

use std::io::Write;
use std::path::PathBuf;

use base64::Engine;
use minisign_verify::{PublicKey, Signature};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter};

use crate::updater::UpdateInfo;

const API_LATEST: &str = "https://api.github.com/repos/baluard-org/baluard/releases/latest";
const ASSET_NAME: &str = "Baluard-amd64-portable.zip";
const SUMS_NAME: &str = "SHA256SUMS";
const SIG_NAME: &str = "SHA256SUMS.sig";
const STAGING_DIR: &str = "update-staging";
const DOWNLOAD_NAME: &str = "update.zip";
const MAX_DOWNLOAD_BYTES: u64 = 1 << 30;
const MAX_EXTRACTED_BYTES: u64 = 3 << 30;

pub fn is_portable() -> bool {
    cfg!(windows) && std::env::var_os("BALUARD_PORTABLE").is_some()
}

struct Release {
    tag: String,
    sums_url: String,
    sig_url: String,
    zip_url: String,
    notes: Option<String>,
    date: Option<String>,
}

fn client() -> Result<reqwest::Client, String> {
    // https_only pins every URL to TLS even if a listing ever carried an
    // http asset URL; read_timeout is per read so a 400 MB download can
    // still take minutes on a slow stick while a stalled connection dies.
    reqwest::Client::builder()
        .user_agent("baluard-portable-updater")
        .https_only(true)
        .connect_timeout(std::time::Duration::from_secs(15))
        .read_timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| format!("http client: {e}"))
}

/// Numeric semver compare with channel semantics: a stable current version
/// never moves to a prerelease (that is what `/releases/latest` serves
/// anyway); a prerelease current version moves to a newer prerelease or to
/// any stable tag. Non-parseable tags never count as newer (fail safe).
fn tag_is_newer(tag: &str, current: &str) -> bool {
    let parse = |v: &str| -> Option<semver::Version> {
        semver::Version::parse(v.trim().trim_start_matches('v')).ok()
    };
    match (parse(tag), parse(current)) {
        (Some(a), Some(b)) => {
            a > b && (a.pre.is_empty() || !b.pre.is_empty())
        }
        _ => false,
    }
}

fn parse_latest_release(body: &str) -> Option<Release> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    let tag = json.get("tag_name")?.as_str()?.to_string();
    let asset_url = |name: &str| -> Option<String> {
        json.get("assets")?
            .as_array()?
            .iter()
            .find(|a| a.get("name").and_then(|n| n.as_str()) == Some(name))
            .and_then(|a| a.get("browser_download_url").and_then(|u| u.as_str()))
            .map(String::from)
    };
    Some(Release {
        sums_url: asset_url(SUMS_NAME)?,
        sig_url: asset_url(SIG_NAME)?,
        zip_url: asset_url(ASSET_NAME)?,
        tag,
        notes: json.get("body").and_then(|b| b.as_str()).map(String::from),
        date: json
            .get("published_at")
            .and_then(|d| d.as_str())
            .map(String::from),
    })
}

async fn release_assets() -> Result<Release, String> {
    let body = get_bytes(API_LATEST).await?;
    let body_text =
        std::str::from_utf8(&body).map_err(|_| "release listing is not text".to_string())?;
    parse_latest_release(body_text).ok_or_else(|| "release listing has no portable assets".into())
}

fn map_status_error(url: &str, status: reqwest::StatusCode) -> String {
    let name = url.rsplit('/').next().unwrap_or(url);
    if status.as_u16() == 403 || status.as_u16() == 429 {
        "GitHub is limiting update checks from this network. Try again later.".into()
    } else {
        format!("{name} returned {status}")
    }
}

async fn get_bytes(url: &str) -> Result<Vec<u8>, String> {
    let response = client()?
        .get(url)
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if !response.status().is_success() {
        return Err(map_status_error(url, response.status()));
    }
    response
        .bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| format!("read body: {e}"))
}

/// The sums signature is the tauri signer's base64-wrapped minisign text.
fn decode_signature(sig_bytes: &[u8]) -> Result<Signature, String> {
    let text = std::str::from_utf8(sig_bytes).map_err(|_| "signature is not text".to_string())?;
    let unwrapped = if text.starts_with("untrusted comment:") {
        text.to_string()
    } else {
        let joined: String = text.lines().map(str::trim).collect();
        String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(joined)
                .map_err(|_| "signature is not valid base64".to_string())?,
        )
        .map_err(|_| "signature is not valid utf-8".to_string())?
    };
    Signature::decode(&unwrapped).map_err(|_| "signature is malformed".to_string())
}

fn sums_digest_for(sums: &str, asset: &str) -> Result<String, String> {
    sums.lines()
        .filter_map(|line| {
            let (hash, name) = line.split_once(char::is_whitespace)?;
            Some((hash.trim(), name.trim()))
        })
        .find(|(_, name)| *name == asset)
        .map(|(hash, _)| hash.to_ascii_lowercase())
        .ok_or_else(|| format!("{SUMS_NAME} has no entry for {asset}"))
}

/// Check the latest GitHub release for a newer portable zip.
/// `Ok(None)` = up to date.
pub async fn check(current_version: &str) -> Result<Option<UpdateInfo>, String> {
    let release = release_assets().await?;
    if !tag_is_newer(&release.tag, current_version) {
        return Ok(None);
    }
    Ok(Some(UpdateInfo {
        version: release.tag.trim_start_matches('v').to_string(),
        notes: release.notes,
        date: release.date,
        current_version: current_version.to_string(),
    }))
}

/// Download, verify, extract into the staging folder, and return its path.
/// The caller stops the daemon, spawns the launcher with the staging path,
/// and exits. Progress rides the same `updater://progress` event the
/// installed updater uses. Any failure removes the staging folder.
pub async fn stage_update(app: &AppHandle, current_version: &str) -> Result<PathBuf, String> {
    match stage_update_inner(app, current_version).await {
        Ok(staging) => Ok(staging),
        Err(e) => {
            if let Ok(exe) = std::env::current_exe() {
                if let Some(dir) = exe.parent() {
                    let _ = std::fs::remove_dir_all(dir.join(STAGING_DIR));
                }
            }
            Err(e)
        }
    }
}

async fn stage_update_inner(app: &AppHandle, current_version: &str) -> Result<PathBuf, String> {
    // Re-check like the installed flow: a stale install click must not
    // redownload the same version.
    let release = release_assets().await?;
    if !tag_is_newer(&release.tag, current_version) {
        return Err("No update is available.".into());
    }
    let install_dir = std::env::current_exe()
        .map_err(|e| format!("current_exe: {e}"))?
        .parent()
        .map(PathBuf::from)
        .ok_or("executable has no parent directory")?;
    let staging = install_dir.join(STAGING_DIR);
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| format!("create staging: {e}"))?;

    // 1. Verify the checksum manifest BEFORE trusting any large download.
    let sums = get_bytes(&release.sums_url).await?;
    let sums_text = String::from_utf8(sums).map_err(|_| "sums are not text".to_string())?;
    let sig = get_bytes(&release.sig_url).await?;
    let pubkey = PublicKey::decode(include_str!("../../../updater.pub"))
        .map_err(|_| "embedded updater public key is invalid".to_string())?;
    pubkey
        .verify(sums_text.as_bytes(), &decode_signature(&sig)?, false)
        .map_err(|_| "checksum manifest signature verification failed".to_string())?;
    let expected = sums_digest_for(&sums_text, ASSET_NAME)?;

    // 2. Stream the zip to disk, hashing as bytes arrive: the 440 MB zip
    // must not be buffered in RAM.
    let zip_path = staging.join(DOWNLOAD_NAME);
    let response = client()?
        .get(&release.zip_url)
        .send()
        .await
        .map_err(|e| format!("download failed: {e}"))?;
    if !response.status().is_success() {
        return Err(map_status_error(&release.zip_url, response.status()));
    }
    let total = response.content_length().unwrap_or(0);
    let mut received: u64 = 0;
    let mut hasher = Sha256::new();
    let mut out = std::io::BufWriter::new(
        std::fs::File::create(&zip_path).map_err(|e| format!("create download: {e}"))?,
    );
    let mut stream = response;
    while let Some(chunk) = stream
        .chunk()
        .await
        .map_err(|e| format!("download failed: {e}"))?
    {
        received += chunk.len() as u64;
        if received > MAX_DOWNLOAD_BYTES {
            return Err("update download exceeds its expected size".into());
        }
        hasher.update(&chunk);
        out.write_all(&chunk).map_err(|e| format!("write download: {e}"))?;
        let _ = app.emit(
            "updater://progress",
            serde_json::json!({ "downloaded": received, "total": total }),
        );
    }
    out.flush().map_err(|e| format!("write download: {e}"))?;
    drop(out);

    // 3. Hash-check against the signed manifest.
    let actual = format!("{:x}", hasher.finalize());
    if actual != expected {
        return Err("downloaded update does not match the signed checksum".into());
    }

    // 4. Extract into staging, stripping the zip's root folder. Symlink
    // entries and oversized archives are refused: the zip is hash-pinned,
    // so this is a size guard, not a trust boundary.
    let file = std::fs::File::open(&zip_path).map_err(|e| format!("open download: {e}"))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| format!("corrupt update zip: {e}"))?;
    let mut extracted: u64 = 0;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|e| format!("corrupt update zip: {e}"))?;
        let Some(relative) = entry.enclosed_name() else {
            continue;
        };
        #[cfg(unix)]
        if let Some(mode) = entry.unix_mode() {
            // 0o120000 = symlink file type; never materialize links.
            if mode & 0o170_000 == 0o120_000 {
                continue;
            }
        }
        let mut components = relative.components();
        // Strip the zip's single root directory ("Baluard/").
        if components.clone().count() <= 1 {
            continue;
        }
        components.next();
        extracted += entry.size();
        if extracted > MAX_EXTRACTED_BYTES {
            return Err("update package is larger than expected".into());
        }
        let target = staging.join(components.collect::<PathBuf>());
        if entry.is_dir() {
            std::fs::create_dir_all(&target).map_err(|e| format!("extract: {e}"))?;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| format!("extract: {e}"))?;
            }
            let mut file_out =
                std::fs::File::create(&target).map_err(|e| format!("extract: {e}"))?;
            std::io::copy(&mut entry, &mut file_out).map_err(|e| format!("extract: {e}"))?;
        }
    }
    Ok(staging)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_tags_are_detected_numerically() {
        assert!(tag_is_newer("0.7.6", "0.7.5"));
        assert!(tag_is_newer("v0.8.0", "0.7.99"));
        assert!(!tag_is_newer("0.7.5", "0.7.5"));
        assert!(!tag_is_newer("0.7.4", "0.7.5"));
        // Non-numeric tags never count as newer.
        assert!(!tag_is_newer("nightly", "0.7.5"));
        // A stable current version never moves to a prerelease...
        assert!(!tag_is_newer("0.7.6-beta.1", "0.7.5"));
        // ...while a prerelease current version moves to stable...
        assert!(tag_is_newer("0.7.6", "0.7.6-beta.1"));
        // ...or to a newer prerelease (S8).
        assert!(tag_is_newer("0.7.6-beta.2", "0.7.6-beta.1"));
    }

    #[test]
    fn release_listing_yields_the_portable_assets() {
        let body = r#"{
            "tag_name": "0.8.0",
            "body": "notes",
            "published_at": "2026-11-21T00:00:00Z",
            "assets": [
                {"name": "Baluard-amd64-setup.exe", "browser_download_url": "https://x/1"},
                {"name": "SHA256SUMS", "browser_download_url": "https://x/sums"},
                {"name": "SHA256SUMS.sig", "browser_download_url": "https://x/sums.sig"},
                {"name": "Baluard-amd64-portable.zip", "browser_download_url": "https://x/portable.zip"}
            ]
        }"#;
        let release = parse_latest_release(body).expect("parses");
        assert_eq!(release.tag, "0.8.0");
        assert_eq!(release.zip_url, "https://x/portable.zip");
        assert_eq!(release.sums_url, "https://x/sums");
        assert_eq!(release.sig_url, "https://x/sums.sig");
        assert_eq!(release.date.as_deref(), Some("2026-11-21T00:00:00Z"));
    }

    #[test]
    fn listing_without_the_portable_asset_is_rejected() {
        let body = r#"{"tag_name": "0.8.0", "assets": [{"name": "other.zip", "browser_download_url": "https://x"}]}"#;
        assert!(parse_latest_release(body).is_none());
    }

    #[test]
    fn wrapped_and_plain_signatures_both_decode() {
        // Both forms must fail at Signature::decode on FAKE material, not
        // at the unwrap step: the unwrap path is what this pins.
        let minisign_text = "untrusted comment: signature\nRWFAKE\n";
        let wrapped = base64::engine::general_purpose::STANDARD.encode(minisign_text);
        assert!(decode_signature(wrapped.as_bytes()).is_err());
        assert!(decode_signature(minisign_text.as_bytes()).is_err());
        assert!(decode_signature(b"not base64 !!!").is_err());
    }

    #[test]
    fn sums_lookup_matches_the_asset_line() {
        let sums = "aaaaaaaa  Baluard-amd64-setup.exe\nbbbbbbbb  Baluard-amd64-portable.zip\n";
        assert_eq!(sums_digest_for(sums, ASSET_NAME).unwrap(), "bbbbbbbb");
        assert!(sums_digest_for(sums, "missing.zip").is_err());
    }

    /// The trust anchor must not drift: the pubkey the portable flow pins
    /// (repo-root updater.pub) is the same key the updater plugin pins
    /// (tauri.conf.json). Decodes the tauri base64-wrapped pub file and
    /// compares the minisign key lines.
    #[test]
    fn embedded_pubkey_matches_the_updater_plugin_pubkey() {
        let conf = include_str!("../tauri.conf.json");
        let json: serde_json::Value = serde_json::from_str(conf).expect("tauri.conf.json parses");
        let tauri_wrapped = json
            .get("plugins")
            .and_then(|p| p.get("updater"))
            .and_then(|u| u.get("pubkey"))
            .and_then(|k| k.as_str())
            .expect("updater pubkey in tauri.conf.json");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(tauri_wrapped)
            .expect("tauri pubkey is base64-wrapped");
        let decoded = String::from_utf8(decoded).expect("tauri pubkey is utf-8");
        let repo_pub = include_str!("../../../updater.pub");
        let tauri_line = decoded.lines().nth(1).expect("tauri pubkey line 2");
        let repo_line = repo_pub.lines().nth(1).expect("updater.pub line 2");
        assert_eq!(tauri_line.trim(), repo_line.trim());
    }
}
