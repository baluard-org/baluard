//! Native-messaging host manifest self-registration.
//!
//! macOS has no installer step, so the daemon registers the bridge
//! manifests itself and refreshes them every startup, keeping the
//! manifest `path` pointed at the running bundle. The daemon only
//! registers when running from inside an installed bundle: a dev-tree
//! daemon (`target/debug`) must never repoint a user's manifests at
//! itself, which is how the 2026-07 stale-manifest incident looked from
//! the other side.

use std::fs;
use std::path::{Path, PathBuf};

pub const HOST_NAME: &str = "app.baluard.browser";
pub const LEGACY_HOST_NAME: &str = "xyz.actitud.baluard";
const FIREFOX_EXTENSION_ID: &str = "baluard@actitud.xyz";

/// Public Chrome Web Store ID: the store URL carries it, so it is not a
/// secret and is safe to hardcode like the Firefox add-on ID. The env
/// override exists for unpacked dev extensions with a derived ID.
const CHROME_STORE_ID: &str = "nmkmfkmdhbifkjdhioejeoegcjpaiijl";

/// Chrome-family browser base dirs under the applications-data root.
/// Channel variants and Opera included; a browser that is not installed
/// (no base dir) is skipped, so the list can be generous.
const CHROME_FAMILY_DIRS: &[&str] = &[
    "Google/Chrome",
    "Google/Chrome Beta",
    "Google/Chrome Dev",
    "Google/Chrome Canary",
    "Chromium",
    "BraveSoftware/Brave-Browser",
    "BraveSoftware/Brave-Origin",
    "BraveSoftware/Brave-Browser-Beta",
    "BraveSoftware/Brave-Browser-Nightly",
    "Microsoft Edge",
    "Microsoft Edge Beta",
    "Microsoft Edge Dev",
    "Microsoft Edge Canary",
    "Arc/User Data",
    "Dia/User Data",
    "Vivaldi",
    "com.operasoftware.Opera",
];

/// Chrome extension ID in effect for this build: the env override or the
/// store ID. Never None, so the Chrome family always registers.
fn chrome_ext_id() -> &'static str {
    option_env!("BALUARD_CHROME_EXTENSION_ID").unwrap_or(CHROME_STORE_ID)
}

/// Outcome of a registration pass: how many manifests were written
/// (or, on the Linux non-AppImage cleanup sweep, removed) and the
/// per-browser errors that did not stop the remaining browsers.
#[derive(Default, Debug, PartialEq)]
pub struct RegistrationReport {
    pub written: usize,
    pub errors: Vec<String>,
}

impl RegistrationReport {
    #[allow(dead_code)]
    fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Write both host-name manifests into every installed browser's
/// NativeMessagingHosts dir under `apps_root` (`~/Library/Application
/// Support` on macOS). Chrome-family browsers get `allowed_origins`
/// pinning the store ID; the Firefox manifests carry `allowed_extensions`
/// with the fixed add-on ID. One browser failing does not stop the
/// others; the errors ride the report.
pub fn register_at(apps_root: &Path, nmh_path: &Path, report: &mut RegistrationReport) {
    let id = chrome_ext_id();
    for rel in CHROME_FAMILY_DIRS {
        let base = apps_root.join(rel);
        if !base.is_dir() {
            continue;
        }
        let dir = base.join("NativeMessagingHosts");
        if let Err(e) =
            fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))
        {
            report.errors.push(e);
            continue;
        }
        for name in [HOST_NAME, LEGACY_HOST_NAME] {
            match chrome_manifest(name, nmh_path, id)
                .and_then(|doc| write_manifest(&dir.join(format!("{name}.json")), &doc))
            {
                Ok(()) => report.written += 1,
                Err(e) => report.errors.push(e),
            }
        }
    }

    // Firefox keeps its profile home in a sibling dir of the shared
    // Mozilla dir where the manifests live; either existing means a
    // Firefox-family install to register for.
    if apps_root.join("Firefox").is_dir() || apps_root.join("Mozilla").is_dir() {
        let dir = apps_root.join("Mozilla/NativeMessagingHosts");
        if let Err(e) =
            fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))
        {
            report.errors.push(e);
            return;
        }
        for name in [HOST_NAME, LEGACY_HOST_NAME] {
            match firefox_manifest(name, nmh_path)
                .and_then(|doc| write_manifest(&dir.join(format!("{name}.json")), &doc))
            {
                Ok(()) => report.written += 1,
                Err(e) => report.errors.push(e),
            }
        }
    }
}

/// Windows variant: browsers read the manifest path from the registry
/// keys the NSIS installer writes, so the JSON files themselves just live
/// beside the daemon executable. `serde_json` escapes the backslashes in
/// the path field. The Firefox manifests carry a distinct filename: the
/// host name collides with the chrome-family files (the registry keys,
/// not filenames, carry the name).
pub fn register_beside_exec(exe_dir: &Path, report: &mut RegistrationReport) {
    let id = chrome_ext_id();
    let nmh_path = exe_dir.join("baluard-nmh.exe");
    let write =
        |doc: Result<String, String>, file: String, report: &mut RegistrationReport| match doc
            .and_then(|doc| write_manifest(&exe_dir.join(file), &doc))
        {
            Ok(()) => report.written += 1,
            Err(e) => report.errors.push(e),
        };
    for name in [HOST_NAME, LEGACY_HOST_NAME] {
        write(
            chrome_manifest(name, &nmh_path, id),
            format!("{name}.json"),
            &mut *report,
        );
    }
    for name in [HOST_NAME, LEGACY_HOST_NAME] {
        write(
            firefox_manifest(name, &nmh_path),
            format!("{name}.firefox.json"),
            &mut *report,
        );
    }
}

/// Startup entry point for the daemon (all platforms). Portable builds
/// (BALUARD_PORTABLE, e.g. the pendrive zip) never register: the stick can
/// vanish between launches, and the pass must not repoint a guest machine
/// or an installed copy at a dead path.
pub fn register_for_current_exec() -> RegistrationReport {
    register_dispatch(std::env::var_os("BALUARD_PORTABLE").is_some())
}

fn register_dispatch(portable: bool) -> RegistrationReport {
    if portable {
        return RegistrationReport::default();
    }
    // Mobile targets (android, ios) compile this crate via UniFFI but
    // never register browser-bridge manifests.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    let registered = register_for_current_exec_impl();
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )))]
    let registered = RegistrationReport::default();
    registered
}

/// macOS: bundle-only guard, so a
/// dev-tree or `cargo run` daemon never repoints the user's manifests at
/// build artifacts. Windows: manifests beside the executable, no guard
/// needed (the registry keys point at the install dir, which dev runs do
/// not touch). Reached only when `register_dispatch` saw no
/// `BALUARD_PORTABLE`.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn register_for_current_exec_impl() -> RegistrationReport {
    let mut report = RegistrationReport::default();
    let Ok(exe) = std::env::current_exe() else {
        report
            .errors
            .push("current_exe unavailable; browser bridge not registered".into());
        return report;
    };
    let Some(exe_dir) = exe.parent() else {
        report
            .errors
            .push("current_exe has no parent; browser bridge not registered".into());
        return report;
    };

    #[cfg(target_os = "macos")]
    {
        let nmh_path = exe_dir.join("baluard-nmh");
        if !running_from_installed_bundle(&exe, &nmh_path) {
            return report;
        }
        let Some(apps_root) = dirs::data_dir() else {
            report
                .errors
                .push("no application data dir; browser bridge not registered".into());
            return report;
        };
        register_at(&apps_root, &nmh_path, &mut report);
    }

    #[cfg(target_os = "windows")]
    {
        register_beside_exec(exe_dir, &mut report);
    }

    report
}

/// The macOS install layout: the daemon and its NMH sibling live in
/// <App>.app/Contents/MacOS/. Dev builds and `cargo run` never match.
#[cfg(any(target_os = "macos", test))]
fn running_from_installed_bundle(exe: &Path, nmh_path: &Path) -> bool {
    exe.to_str().is_some_and(|p| p.contains("/Contents/MacOS/")) && nmh_path.is_file()
}

/// Linux has installers for deb/rpm, but the AppImage has no install
/// step at all: the daemon registers the bridge manifests itself when
/// it runs from an AppImage (the `APPIMAGE` env marker). The mountpoint
/// changes every launch, so the NMH binary is first staged to a stable
/// path under the data dir and the manifests point there. Every other
/// Linux format owns its own manifests (deb/rpm drop system-wide ones),
/// so a non-AppImage daemon only sweeps user-level manifests a past
/// AppImage run left behind - otherwise they would shadow the package
/// manifests forever, pointing at a staged binary nothing updates.
/// The sweep is guarded to installed daemons: a `cargo target` daemon
/// must never touch a real user's manifests, the same rule as the
/// macOS bundle guard (2026-07 stale-manifest incident).
#[cfg(target_os = "linux")]
fn register_for_current_exec_impl() -> RegistrationReport {
    let mut report = RegistrationReport::default();
    let (Some(config), Some(home)) = (dirs::config_dir(), dirs::home_dir()) else {
        report
            .errors
            .push("no config/home dirs; browser bridge not registered".into());
        return report;
    };
    let from_appimage = std::env::var_os("APPIMAGE").is_some();
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(_) => {
            report
                .errors
                .push("current_exe unavailable; browser bridge not registered".into());
            return report;
        }
    };
    linux_register_body(
        &exe,
        from_appimage,
        &config,
        &home,
        &stable_nmh_path(),
        &mut report,
    );
    report
}

/// Body of the Linux startup pass without env/exe resolution, so tests
/// can drive the AppImage and cleanup branches directly.
#[cfg(any(target_os = "linux", test))]
fn linux_register_body(
    exe: &Path,
    from_appimage: bool,
    config: &Path,
    home: &Path,
    stable_nmh: &Path,
    report: &mut RegistrationReport,
) {
    if !from_appimage {
        if !is_installed_linux_daemon(exe) {
            return;
        }
        remove_appimage_manifests(config, home, stable_nmh, report);
        return;
    }
    let Some(exe_dir) = exe.parent() else {
        report
            .errors
            .push("current_exe has no parent; browser bridge not registered".into());
        return;
    };
    let mounted = exe_dir.join("baluard-nmh");
    if !mounted.is_file() {
        report.errors.push(
            "AppImage carries no baluard-nmh beside the daemon; browser bridge not registered"
                .into(),
        );
        return;
    }
    let Some(stage_dir) = stable_nmh.parent() else {
        report
            .errors
            .push("staging path has no parent; browser bridge not registered".into());
        return;
    };
    let stable = match stage_stable_nmh(&mounted, stage_dir) {
        Ok(path) => path,
        Err(e) => {
            report.errors.push(e);
            return;
        }
    };
    register_linux_user(config, home, &stable, report);
}

/// Cargo target dirs are the dev-tree marker; packaged daemons live
/// under /usr/bin, /usr/local/bin, or inside an AppImage mount.
#[cfg(any(target_os = "linux", test))]
fn is_installed_linux_daemon(exe: &Path) -> bool {
    !exe.to_str().is_some_and(|p| p.contains("/target/"))
}

/// Where the staged NMH binary lives. Stable across AppImage relaunches
/// (the squashfs mountpoint is new every run); honors BALUARD_DATA_DIR
/// like every other location in paths.rs.
#[cfg(target_os = "linux")]
fn stable_nmh_path() -> PathBuf {
    crate::paths::data_dir().join("nmh").join("baluard-nmh")
}

/// Chrome-family browsers keep user-level manifests under their config
/// dir (~/.config/<dir>/NativeMessagingHosts). Generous list; browsers
/// that are not installed (no base dir) are skipped.
#[cfg(any(target_os = "linux", test))]
const LINUX_CHROME_CONFIG_DIRS: &[&str] = &[
    "google-chrome",
    "google-chrome-beta",
    "google-chrome-unstable",
    "chromium",
    "BraveSoftware/Brave-Browser",
    "BraveSoftware/Brave-Browser-Beta",
    "BraveSoftware/Brave-Browser-Nightly",
    "microsoft-edge",
    "microsoft-edge-beta",
    "microsoft-edge-dev",
    "vivaldi",
    "opera",
];

/// Write both host-name manifests for every installed browser under the
/// Linux user dirs (Chrome family under the config home, Firefox under
/// ~/.mozilla/native-messaging-hosts). `written` counts manifests
/// written; per-browser errors do not stop the remaining browsers.
#[cfg(any(target_os = "linux", test))]
pub fn register_linux_user(
    config_home: &Path,
    home: &Path,
    nmh_path: &Path,
    report: &mut RegistrationReport,
) {
    let id = chrome_ext_id();
    for rel in LINUX_CHROME_CONFIG_DIRS {
        let base = config_home.join(rel);
        if !base.is_dir() {
            continue;
        }
        let dir = base.join("NativeMessagingHosts");
        if let Err(e) =
            fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))
        {
            report.errors.push(e);
            continue;
        }
        for name in [HOST_NAME, LEGACY_HOST_NAME] {
            match chrome_manifest(name, nmh_path, id)
                .and_then(|doc| write_manifest(&dir.join(format!("{name}.json")), &doc))
            {
                Ok(()) => report.written += 1,
                Err(e) => report.errors.push(e),
            }
        }
    }
    if home.join(".mozilla").is_dir() {
        let dir = home.join(".mozilla/native-messaging-hosts");
        if let Err(e) =
            fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))
        {
            report.errors.push(e);
            return;
        }
        for name in [HOST_NAME, LEGACY_HOST_NAME] {
            match firefox_manifest(name, nmh_path)
                .and_then(|doc| write_manifest(&dir.join(format!("{name}.json")), &doc))
            {
                Ok(()) => report.written += 1,
                Err(e) => report.errors.push(e),
            }
        }
    }
}

/// Remove user-level manifests whose content is exactly what an AppImage
/// run writes for `stable_nmh`. Foreign content (user-edited, package-era)
/// is never touched. `written` counts removals.
#[cfg(any(target_os = "linux", test))]
fn remove_appimage_manifests(
    config_home: &Path,
    home: &Path,
    stable_nmh: &Path,
    report: &mut RegistrationReport,
) {
    let id = chrome_ext_id();
    let remove_matching =
        |path: &Path, expected: Result<String, String>, report: &mut RegistrationReport| {
            let expected = match expected {
                Ok(contents) => contents,
                Err(e) => {
                    report.errors.push(e);
                    return;
                }
            };
            if fs::read(path).is_ok_and(|cur| cur == expected.as_bytes()) {
                match fs::remove_file(path) {
                    Ok(()) => report.written += 1,
                    Err(e) => report
                        .errors
                        .push(format!("remove {}: {e}", path.display())),
                }
            }
        };
    for rel in LINUX_CHROME_CONFIG_DIRS {
        let dir = config_home.join(rel).join("NativeMessagingHosts");
        if !dir.is_dir() {
            continue;
        }
        for name in [HOST_NAME, LEGACY_HOST_NAME] {
            remove_matching(
                &dir.join(format!("{name}.json")),
                chrome_manifest(name, stable_nmh, id),
                &mut *report,
            );
        }
    }
    let dir = home.join(".mozilla/native-messaging-hosts");
    if dir.is_dir() {
        for name in [HOST_NAME, LEGACY_HOST_NAME] {
            remove_matching(
                &dir.join(format!("{name}.json")),
                firefox_manifest(name, stable_nmh),
                &mut *report,
            );
        }
    }
}

/// Copy the mounted NMH binary to the stable staging dir when absent or
/// changed, so an AppImage update restages on the next daemon start.
/// Unchanged binaries are left untouched (no rewrite). Returns the
/// staged path.
#[cfg(any(target_os = "linux", test))]
fn stage_stable_nmh(mounted: &Path, stage_dir: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(stage_dir).map_err(|e| format!("create {}: {e}", stage_dir.display()))?;
    let stable = stage_dir.join("baluard-nmh");
    let differs = match (fs::read(mounted), fs::read(&stable)) {
        (Ok(m), Ok(s)) => m != s,
        _ => true,
    };
    if differs {
        fs::copy(mounted, &stable).map_err(|e| format!("stage {}: {e}", stable.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&stable, fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("chmod {}: {e}", stable.display()))?;
        }
    }
    Ok(stable)
}

/// Store-only ID shape: Chrome derives store IDs from the public key,
/// which lands in [a-p].
fn valid_chrome_ext_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

fn chrome_manifest(name: &str, nmh_path: &Path, ext_id: &str) -> Result<String, String> {
    debug_assert!(
        valid_chrome_ext_id(ext_id),
        "BALUARD_CHROME_EXTENSION_ID override is not a Chrome extension ID: {ext_id}"
    );
    serde_json::to_string(&serde_json::json!({
        "name": name,
        "description": "Baluard bridge",
        "path": nmh_path,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{ext_id}/")],
    }))
    .map_err(|e| e.to_string())
}

fn firefox_manifest(name: &str, nmh_path: &Path) -> Result<String, String> {
    serde_json::to_string(&serde_json::json!({
        "name": name,
        "description": "Baluard bridge",
        "path": nmh_path,
        "type": "stdio",
        "allowed_extensions": [FIREFOX_EXTENSION_ID],
    }))
    .map_err(|e| e.to_string())
}

/// Skip unchanged content (browsers may read concurrently) and replace
/// via temp file + rename so a reader never sees a truncated manifest.
fn write_manifest(path: &Path, contents: &str) -> Result<(), String> {
    if fs::read(path).is_ok_and(|cur| cur == contents.as_bytes()) {
        return Ok(());
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, contents).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORE_ID: &str = CHROME_STORE_ID;

    #[test]
    fn portable_dispatch_skips_registration() {
        let report = register_dispatch(true);
        assert!(report.is_clean(), "{:?}", report.errors);
        assert_eq!(report.written, 0);
    }

    fn reg(apps: &Path, nmh: &Path) -> RegistrationReport {
        let mut report = RegistrationReport::default();
        register_at(apps, nmh, &mut report);
        report
    }

    #[test]
    fn writes_both_host_names_for_installed_browsers() {
        let t = tempfile::tempdir().unwrap();
        let apps = t.path().join("Application Support");
        fs::create_dir_all(apps.join("Google/Chrome")).unwrap();
        fs::create_dir_all(apps.join("BraveSoftware/Brave-Origin")).unwrap();
        let nmh = t.path().join("App.app/Contents/MacOS/baluard-nmh");

        let report = reg(&apps, &nmh);
        assert!(report.is_clean(), "{:?}", report.errors);
        assert_eq!(report.written, 4, "two manifests per installed browser");

        for browser in ["Google/Chrome", "BraveSoftware/Brave-Origin"] {
            for name in [HOST_NAME, LEGACY_HOST_NAME] {
                let d: serde_json::Value = serde_json::from_str(
                    &fs::read_to_string(
                        apps.join(browser)
                            .join("NativeMessagingHosts")
                            .join(format!("{name}.json")),
                    )
                    .unwrap(),
                )
                .unwrap();
                assert_eq!(d["name"], name);
                assert_eq!(d["path"], &*nmh.to_string_lossy());
                assert_eq!(d["type"], "stdio");
                assert_eq!(
                    d["allowed_origins"][0],
                    format!("chrome-extension://{STORE_ID}/")
                );
            }
        }
    }

    #[test]
    fn skips_browsers_that_are_not_installed() {
        let t = tempfile::tempdir().unwrap();
        let report = reg(t.path(), &t.path().join("nmh"));
        assert_eq!(report.written, 0);
        assert!(report.is_clean());
        assert!(
            !t.path().join("Google").exists(),
            "no dirs for absent browsers"
        );
    }

    #[test]
    fn firefox_gets_extension_allowlist_without_chrome_family() {
        // Only the Firefox profile home exists: Mozilla manifests are
        // written, the Chrome family is skipped for absence.
        let t = tempfile::tempdir().unwrap();
        fs::create_dir_all(t.path().join("Firefox")).unwrap();
        let nmh = t.path().join("App.app/Contents/MacOS/baluard-nmh");

        let report = reg(t.path(), &nmh);
        assert_eq!(report.written, 2);
        for name in [HOST_NAME, LEGACY_HOST_NAME] {
            let d: serde_json::Value = serde_json::from_str(
                &fs::read_to_string(
                    t.path()
                        .join("Mozilla/NativeMessagingHosts")
                        .join(format!("{name}.json")),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(d["allowed_extensions"][0], FIREFOX_EXTENSION_ID);
            assert!(d.get("allowed_origins").is_none());
        }
    }

    #[test]
    fn refreshes_a_stale_manifest() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("Google/Chrome/NativeMessagingHosts");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(format!("{LEGACY_HOST_NAME}.json")),
            r#"{"name":"xyz.actitud.baluard","path":"/old/dev/tree/nmh","allowed_origins":["chrome-extension://egboinddfefkdeiojglldggnmompjpje/"]}"#,
        )
        .unwrap();

        let nmh = t.path().join("App.app/Contents/MacOS/baluard-nmh");
        reg(t.path(), &nmh);
        let d: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(dir.join(format!("{LEGACY_HOST_NAME}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(d["path"], &*nmh.to_string_lossy());
        assert_eq!(
            d["allowed_origins"][0],
            format!("chrome-extension://{STORE_ID}/")
        );
    }

    #[test]
    fn unchanged_manifests_are_not_rewritten() {
        let t = tempfile::tempdir().unwrap();
        let apps = t.path().join("Application Support");
        fs::create_dir_all(apps.join("Google/Chrome")).unwrap();
        let nmh = t.path().join("App.app/Contents/MacOS/baluard-nmh");

        reg(&apps, &nmh);
        let manifest = apps
            .join("Google/Chrome/NativeMessagingHosts")
            .join(format!("{HOST_NAME}.json"));
        let first_mtime = fs::metadata(&manifest).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        reg(&apps, &nmh);
        let second_mtime = fs::metadata(&manifest).unwrap().modified().unwrap();
        assert_eq!(
            first_mtime, second_mtime,
            "identical content skips the write"
        );
    }

    #[test]
    fn one_broken_browser_dir_does_not_stop_the_others() {
        let t = tempfile::tempdir().unwrap();
        let apps = t.path().join("Application Support");
        fs::create_dir_all(apps.join("Google/Chrome")).unwrap();
        fs::create_dir_all(apps.join("Firefox")).unwrap();
        // Chromium's NativeMessagingHosts resolves to a FILE:
        // create_dir_all of the manifest dir fails, simulating a
        // root-owned or otherwise unwritable entry.
        fs::create_dir_all(apps.join("Chromium")).unwrap();
        fs::write(apps.join("Chromium/NativeMessagingHosts"), b"not a dir").unwrap();
        let nmh = t.path().join("App.app/Contents/MacOS/baluard-nmh");

        let report = reg(&apps, &nmh);
        assert_eq!(report.errors.len(), 1, "chromium's dir creation fails once");
        assert!(
            report.written >= 4,
            "chrome family and firefox still registered"
        );
        assert!(
            apps.join("Google/Chrome/NativeMessagingHosts")
                .join(format!("{HOST_NAME}.json"))
                .is_file()
        );
        assert!(apps.join("Mozilla/NativeMessagingHosts").is_dir());
    }

    #[test]
    fn macos_guard_skips_non_bundle_and_missing_nmh() {
        let t = tempfile::tempdir().unwrap();
        let exe = t.path().join("dev/target/debug/baluard-daemon");
        fs::create_dir_all(exe.parent().unwrap()).unwrap();
        fs::write(&exe, b"").unwrap();
        // Not under Contents/MacOS: skipped even with the NMH present.
        let report = register_at_guarded_for_test(&exe);
        assert_eq!(report.written, 0);

        // In a bundle path but the NMH binary is missing: skipped.
        let exe = t.path().join("Baluard.app/Contents/MacOS/baluard-daemon");
        fs::create_dir_all(exe.parent().unwrap()).unwrap();
        fs::write(&exe, b"").unwrap();
        let report = register_at_guarded_for_test(&exe);
        assert_eq!(report.written, 0);
    }

    // --- Linux AppImage registration ---

    fn reg_linux(config: &Path, home: &Path, nmh: &Path) -> RegistrationReport {
        let mut report = RegistrationReport::default();
        register_linux_user(config, home, nmh, &mut report);
        report
    }

    #[test]
    fn linux_writes_user_manifests_for_installed_browsers() {
        let t = tempfile::tempdir().unwrap();
        let config = t.path().join("config");
        let home = t.path().join("home");
        fs::create_dir_all(config.join("google-chrome")).unwrap();
        fs::create_dir_all(config.join("BraveSoftware/Brave-Browser")).unwrap();
        fs::create_dir_all(home.join(".mozilla")).unwrap();
        let nmh = t.path().join("stage/baluard-nmh");

        let report = reg_linux(&config, &home, &nmh);
        assert!(report.is_clean(), "{:?}", report.errors);
        assert_eq!(report.written, 6, "two per chrome dir + two for firefox");

        let chrome: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(
                config
                    .join("google-chrome/NativeMessagingHosts")
                    .join(format!("{HOST_NAME}.json")),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(chrome["path"], &*nmh.to_string_lossy());
        assert_eq!(
            chrome["allowed_origins"][0],
            format!("chrome-extension://{STORE_ID}/")
        );
        let firefox: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(
                home.join(".mozilla/native-messaging-hosts")
                    .join(format!("{HOST_NAME}.json")),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(firefox["allowed_extensions"][0], FIREFOX_EXTENSION_ID);
    }

    #[test]
    fn linux_skips_absent_browsers_without_creating_dirs() {
        let t = tempfile::tempdir().unwrap();
        let config = t.path().join("config");
        let home = t.path().join("home");
        fs::create_dir_all(config.join("chromium")).unwrap();

        let report = reg_linux(&config, &home, &t.path().join("nmh"));
        assert_eq!(report.written, 2);
        assert!(!home.join(".mozilla").exists(), "firefox not invented");
    }

    #[test]
    fn staging_copies_when_absent_and_replaces_when_different() {
        let t = tempfile::tempdir().unwrap();
        let mounted = t.path().join("mount/usr/bin/baluard-nmh");
        fs::create_dir_all(mounted.parent().unwrap()).unwrap();
        fs::write(&mounted, b"binary-v1").unwrap();
        let stage = t.path().join("stage");

        let stable = stage_stable_nmh(&mounted, &stage).unwrap();
        assert_eq!(stable, stage.join("baluard-nmh"));
        assert_eq!(fs::read(&stable).unwrap(), b"binary-v1");

        // Identical staging is a no-op: the file is not rewritten.
        let mtime = fs::metadata(&stable).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        stage_stable_nmh(&mounted, &stage).unwrap();
        assert_eq!(
            fs::metadata(&stable).unwrap().modified().unwrap(),
            mtime,
            "unchanged binary is not recopied"
        );

        // An update replaces the staged copy.
        fs::write(&mounted, b"binary-v2").unwrap();
        stage_stable_nmh(&mounted, &stage).unwrap();
        assert_eq!(fs::read(&stable).unwrap(), b"binary-v2");
    }

    #[test]
    fn cleanup_removes_appimage_manifests_keeps_foreign() {
        let t = tempfile::tempdir().unwrap();
        let config = t.path().join("config");
        let home = t.path().join("home");
        fs::create_dir_all(config.join("google-chrome/NativeMessagingHosts")).unwrap();
        fs::create_dir_all(home.join(".mozilla/native-messaging-hosts")).unwrap();
        let stable = t.path().join("stage/baluard-nmh");

        // What an AppImage run would have written: removed.
        for name in [HOST_NAME, LEGACY_HOST_NAME] {
            fs::write(
                config
                    .join("google-chrome/NativeMessagingHosts")
                    .join(format!("{name}.json")),
                chrome_manifest(name, &stable, STORE_ID).unwrap(),
            )
            .unwrap();
            fs::write(
                home.join(".mozilla/native-messaging-hosts")
                    .join(format!("{name}.json")),
                firefox_manifest(name, &stable).unwrap(),
            )
            .unwrap();
        }

        // A foreign manifest (user-edited or deb-era): kept.
        let foreign = config
            .join("google-chrome/NativeMessagingHosts")
            .join(format!("{LEGACY_HOST_NAME}.json"));
        fs::write(
            &foreign,
            r#"{"name":"xyz.actitud.baluard","path":"/usr/bin/baluard-nmh"}"#,
        )
        .unwrap();

        let mut report = RegistrationReport::default();
        remove_appimage_manifests(&config, &home, &stable, &mut report);
        assert!(report.is_clean(), "{:?}", report.errors);
        assert_eq!(
            report.written, 3,
            "three own manifests removed; the fourth is foreign"
        );
        assert!(
            !config
                .join("google-chrome/NativeMessagingHosts")
                .join(format!("{HOST_NAME}.json"))
                .exists()
        );
        for name in [HOST_NAME, LEGACY_HOST_NAME] {
            assert!(
                !home
                    .join(".mozilla/native-messaging-hosts")
                    .join(format!("{name}.json"))
                    .exists()
            );
        }
        assert!(foreign.is_file(), "foreign manifest untouched");
    }

    #[test]
    fn linux_guard_dev_tree_daemon_never_touches_manifests() {
        let t = tempfile::tempdir().unwrap();
        let config = t.path().join("config");
        let home = t.path().join("home");
        fs::create_dir_all(config.join("google-chrome/NativeMessagingHosts")).unwrap();
        let stable = t.path().join("stage/baluard-nmh");
        // A manifest exactly what an AppImage run would have written.
        fs::write(
            config
                .join("google-chrome/NativeMessagingHosts")
                .join(format!("{HOST_NAME}.json")),
            chrome_manifest(HOST_NAME, &stable, STORE_ID).unwrap(),
        )
        .unwrap();

        // Dev-tree daemon (cargo target dir) doing a plain run: no-op.
        let dev_exe = t.path().join("repo/target/debug/baluard-daemon");
        let mut report = RegistrationReport::default();
        linux_register_body(&dev_exe, false, &config, &home, &stable, &mut report);
        assert_eq!(report.written, 0, "dev run cleans nothing");
        assert!(
            config
                .join("google-chrome/NativeMessagingHosts")
                .join(format!("{HOST_NAME}.json"))
                .is_file()
        );

        // Same dev-tree daemon but flagged as running from an AppImage:
        // it registers (the guard is about installed-ness for cleanup).
        fs::create_dir_all(dev_exe.parent().unwrap()).unwrap();
        fs::write(dev_exe.parent().unwrap().join("baluard-nmh"), b"nmh").unwrap();
        let mut report = RegistrationReport::default();
        linux_register_body(&dev_exe, true, &config, &home, &stable, &mut report);
        assert!(report.written >= 2, "appimage run registers");
    }

    /// Test seam for the macOS bundle guard without current_exe.
    fn register_at_guarded_for_test(exe: &Path) -> RegistrationReport {
        let mut report = RegistrationReport::default();
        let nmh_path = exe.parent().unwrap().join("baluard-nmh");
        if !running_from_installed_bundle(exe, &nmh_path) {
            return report;
        }
        let apps = tempfile::tempdir().unwrap();
        register_at(apps.path(), &nmh_path, &mut report);
        report
    }

    #[test]
    fn windows_beside_exec_covers_chrome_and_firefox() {
        let t = tempfile::tempdir().unwrap();
        let mut report = RegistrationReport::default();
        register_beside_exec(t.path(), &mut report);
        assert_eq!(report.written, 4, "2 chrome + 2 firefox");
        let chrome: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(t.path().join(format!("{HOST_NAME}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            chrome["allowed_origins"][0],
            format!("chrome-extension://{STORE_ID}/")
        );
        let firefox: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(t.path().join(format!("{HOST_NAME}.firefox.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(firefox["allowed_extensions"][0], FIREFOX_EXTENSION_ID);
    }

    #[test]
    fn windows_manifest_escapes_backslash_paths() {
        // A literal backslash inside a path component is a valid POSIX
        // filename, so the Linux test can exercise the JSON escaping the
        // Windows exe_dir produces.
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("weird\\name");
        fs::create_dir_all(&dir).unwrap();
        let mut report = RegistrationReport::default();
        register_beside_exec(&dir, &mut report);
        let raw = fs::read_to_string(dir.join(format!("{HOST_NAME}.json"))).unwrap();
        assert!(
            raw.contains("weird\\\\name"),
            "backslash must be JSON-escaped: {raw}"
        );
        let d: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(d["path"], &*dir.join("baluard-nmh.exe").to_string_lossy());
    }
}
