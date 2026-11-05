//! Signed in-app updates (D79). Rust-command API only: the webview never
//! sees the updater plugin's JS surface, so no updater capability is needed
//! and GitHub stays out of the CSP `connect-src`.
//!
//! Endpoints are NOT in tauri.conf.json: the channel is derived from the
//! running version (a prerelease follows `updates-beta`, a stable release
//! follows `updates-stable`), and the plugin's target fallback
//! (`{os}-{arch}-{installer}` then bare `{os}-{arch}`) is why the manifest
//! publishes only installer-suffixed keys for Linux — never a bare
//! `linux-x86_64`. macOS and Windows use the bare keys `darwin-aarch64`
//! and `windows-x86_64`.

use serde::Serialize;
use tauri::{AppHandle, Emitter, State, Url};
use tauri_plugin_updater::UpdaterExt;

pub const PUBKEY_PLACEHOLDER: &str = "REPLACE_WITH_UPDATER_PUBLIC_KEY";

const RELEASES_BASE: &str = "https://github.com/baluard-org/baluard/releases";

#[derive(Debug, Clone, Serialize)]
pub(crate) struct UpdaterStatus {
    pub configured: bool,
    pub channel: &'static str,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct UpdateInfo {
    pub version: String,
    pub notes: Option<String>,
    pub date: Option<String>,
    pub current_version: String,
}

/// A prerelease (any `-suffix` per semver) follows the beta channel;
/// everything else follows stable.
fn is_prerelease(version: &str) -> bool {
    version.contains('-')
}

fn channel_for_version(version: &str) -> &'static str {
    if is_prerelease(version) {
        "beta"
    } else {
        "stable"
    }
}

fn channel_endpoint(channel: &str) -> Result<Url, String> {
    Url::parse(&format!(
        "{RELEASES_BASE}/download/updates-{channel}/latest.json"
    ))
    .map_err(|e| format!("invalid updater endpoint: {e}"))
}

fn configured(app: &AppHandle) -> bool {
    // D79: only the AppImage self-updates. On deb/rpm/Flatpak/Snap the
    // package manager owns updates; the embedded pubkey would otherwise
    // make updater_status promise an updater that can never resolve its
    // manifest entry (TargetNotFound) on a manual check. The AppImage
    // runtime always exports $APPIMAGE; extracted-run inherits it too.
    #[cfg(target_os = "linux")]
    if std::env::var_os("APPIMAGE").is_none() {
        return false;
    }
    let Some(updater) = app.config().plugins.0.get("updater") else {
        return false;
    };
    match updater.get("pubkey").and_then(|k| k.as_str()) {
        Some(key) => !key.is_empty() && key != PUBKEY_PLACEHOLDER,
        None => false,
    }
}

// Single version source: the desktop crate's Cargo manifest. The tauri
// config carries no version field; Config.version could silently drift from
// the daemon handshake's BALUARD_DAEMON_VERSION (each parses its manifest
// independently), so everything reads package_info instead.
fn app_version(app: &AppHandle) -> String {
    app.package_info().version.to_string()
}

fn builder(app: &AppHandle) -> Result<tauri_plugin_updater::UpdaterBuilder, String> {
    let channel = channel_for_version(&app_version(&app));
    let endpoint = channel_endpoint(channel)?;
    app.updater_builder()
        .endpoints(vec![endpoint])
        .map_err(|e| format!("updater endpoint rejected: {e}"))
}

fn update_info(update: &tauri_plugin_updater::Update) -> UpdateInfo {
    UpdateInfo {
        version: update.version.clone(),
        notes: update.body.clone(),
        date: update.date.map(|d| d.to_string()),
        current_version: update.current_version.clone(),
    }
}

#[tauri::command]
pub(crate) async fn updater_status(app: AppHandle) -> UpdaterStatus {
    UpdaterStatus {
        configured: configured(&app),
        channel: channel_for_version(&app_version(&app)),
        version: app_version(&app),
    }
}

/// Check the channel manifest. `Ok(None)` = up to date.
#[tauri::command]
pub(crate) async fn updater_check(app: AppHandle) -> Result<Option<UpdateInfo>, String> {
    if !configured(&app) {
        return Err("Updates are not configured in this build.".into());
    }
    let updater = builder(&app)?.build().map_err(|e| e.to_string())?;
    let update = updater.check().await.map_err(|e| e.to_string())?;
    Ok(update.as_ref().map(update_info))
}

/// Prepare, download, stop the daemon, install, relaunch.
///
/// Sequence (D79): the daemon drains its sync cycles and locks every vault
/// BEFORE any byte is trusted; it is stopped and waited out before the
/// binary is replaced; a failed install rolls the daemon back. `install`
/// replaces the running binary, then `app.restart()` execs into the new
/// version — this command never returns Ok on success.
///
/// Serialized by INSTALL_IN_FLIGHT: the frontend's installing() signal
/// guards its own button, but the command is reachable through raw IPC.
#[tauri::command]
pub(crate) async fn updater_install(
    app: AppHandle,
    daemon: State<'_, std::sync::Mutex<Option<crate::Daemon>>>,
) -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, Ordering};
    static INSTALL_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
    if INSTALL_IN_FLIGHT.swap(true, Ordering::SeqCst) {
        return Err("An update is already in progress.".into());
    }
    let result = install_inner(app, daemon).await;
    if result.is_err() {
        // The success path restarts the process and never gets here.
        INSTALL_IN_FLIGHT.store(false, Ordering::SeqCst);
    }
    result
}

async fn install_inner(
    app: AppHandle,
    daemon: State<'_, std::sync::Mutex<Option<crate::Daemon>>>,
) -> Result<(), String> {
    if !configured(&app) {
        return Err("Updates are not configured in this build.".into());
    }
    let updater = builder(&app)?.build().map_err(|e| e.to_string())?;
    let update = match updater.check().await.map_err(|e| e.to_string())? {
        Some(update) => update,
        None => return Err("No update is available.".into()),
    };

    // 1. Download FIRST, while the app still works: the vaults stay open
    // and usable during the transfer. Only the final install needs the
    // daemon stopped. (M1: a download that fails never locks anything.)
    let app_for_events = app.clone();
    let version = update.version.clone();
    let mut received: u64 = 0;
    let downloaded = update
        .download(
            move |chunk, total| {
                received += chunk as u64;
                let _ = app_for_events.emit(
                    "updater://progress",
                    serde_json::json!({ "downloaded": received, "total": total }),
                );
            },
            || {},
        )
        .await;

    let bytes = match downloaded {
        Ok(bytes) => bytes,
        Err(e) => return Err(format!("Download failed: {e}")),
    };

    // 2. Drain + lock. A sync that will not finish refuses the update.
    // Named-pipe IPC covers Windows since the transport port, so all
    // three OSes drain the same way. A restart here only makes sense for
    // our own (replaced) sidecar: an adopted daemon belongs to a CLI
    // session and must be left running.
    crate::send_request("system.prepare_update", "")
        .map_err(|e| {
            if !crate::daemon_ctl::daemon_is_adopted() {
                let _ = crate::daemon_ctl::restart_daemon(&app);
            }
            format!("Cannot prepare for the update: {e}")
        })?;

    // 3. Stop the daemon and hold the door: nothing respawns it until the
    // new version starts (or this rollback path does). A daemon that will
    // not die releases the gate again — the adopt-or-replace startup rules
    // must keep applying, so the suppression flag may not outlive this call.
    crate::daemon_ctl::suppress_respawn();
    if let Err(e) = crate::daemon_ctl::stop_daemon_and_wait(daemon.inner()) {
        crate::daemon_ctl::clear_respawn_suppression();
        return Err(format!("The security service could not be stopped: {e}"));
    }

    let version_for_log = version.clone();
    let installed = tauri::async_runtime::spawn_blocking(move || {
        update.install(&bytes).map_err(|e| e.to_string())
    })
    .await;
    let installed = match installed {
        Ok(r) => r,
        Err(join_err) => {
            // The suppression gate must never outlive a failed update, or
            // the app stays daemon-less until relaunch.
            crate::daemon_ctl::clear_respawn_suppression();
            if !crate::daemon_ctl::daemon_is_adopted() {
                let _ = crate::daemon_ctl::restart_daemon(&app);
            }
            log::error!("update to {version_for_log}: installer task panicked: {join_err}");
            return Err("Installation failed.".into());
        }
    };

    if let Err(e) = installed {
        log::error!("update to {version_for_log} failed after download: {e}");
        let _ = crate::daemon_ctl::restart_daemon(&app);
        return Err(format!("Installation failed: {e}"));
    }

    log::info!("update to {version} installed; restarting");
    app.restart();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_versions_follow_the_stable_channel() {
        assert_eq!(channel_for_version("0.1.0"), "stable");
        assert_eq!(channel_for_version("1.0.0"), "stable");
    }

    #[test]
    fn prerelease_versions_follow_the_beta_channel() {
        assert_eq!(channel_for_version("0.2.0-beta.1"), "beta");
        assert_eq!(channel_for_version("1.0.0-rc.1"), "beta");
    }

    #[test]
    fn endpoints_point_at_the_channel_tags() {
        assert_eq!(
            channel_endpoint("stable").unwrap().as_str(),
            "https://github.com/baluard-org/baluard/releases/download/updates-stable/latest.json"
        );
        assert_eq!(
            channel_endpoint("beta").unwrap().as_str(),
            "https://github.com/baluard-org/baluard/releases/download/updates-beta/latest.json"
        );
    }
}
