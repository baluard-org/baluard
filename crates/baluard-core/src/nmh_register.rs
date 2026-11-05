//! Native-messaging host manifest self-registration.
//!
//! The deb/rpm packages ship manifest files system-wide and the NSIS
//! installer writes the Windows registry keys, but the macOS .app has no
//! installer step at all. Without self-registration a fresh macOS install
//! leaves the browser extension unable to launch the bridge (the popup
//! falls back to "open the app"). The daemon refreshes the manifests on
//! every startup, so app updates re-point the manifest `path` by
//! themselves and removed installs stop being refreshed.

use std::fs;
use std::path::Path;

pub const HOST_NAME: &str = "app.baluard.browser";
pub const LEGACY_HOST_NAME: &str = "xyz.actitud.baluard";
const FIREFOX_EXTENSION_ID: &str = "baluard@actitud.xyz";

/// Browser base dirs under the applications-data root. A browser that is
/// not installed (no base dir) is skipped — creating manifests for absent
/// browsers is harmless clutter at best.
const CHROME_FAMILY_DIRS: &[&str] = &[
    "Google/Chrome",
    "Chromium",
    "BraveSoftware/Brave-Browser",
    "BraveSoftware/Brave-Origin",
    "Microsoft Edge",
    "Arc/User Data",
    "Vivaldi",
];

/// Write both host-name manifests into every installed browser's
/// NativeMessagingHosts dir under `apps_root` (`~/Library/Application
/// Support` on macOS). Chrome-family browsers get `allowed_origins`
/// pinning `chrome_ext_id` (None skips the whole family: a manifest
/// without an origin to allow would refuse every connect anyway); the
/// Firefox manifests carry `allowed_extensions` with the fixed add-on ID.
/// Returns the number of manifests written; best-effort callers treat the
/// count as informational.
pub fn register_at(
    apps_root: &Path,
    nmh_path: &Path,
    chrome_ext_id: Option<&str>,
) -> Result<usize, String> {
    let mut written = 0usize;
    if let Some(id) = chrome_ext_id {
        validate_chrome_ext_id(id)?;
        for rel in CHROME_FAMILY_DIRS {
            let base = apps_root.join(rel);
            if !base.is_dir() {
                continue;
            }
            let dir = base.join("NativeMessagingHosts");
            fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
            for name in [HOST_NAME, LEGACY_HOST_NAME] {
                write_manifest(
                    &dir.join(format!("{name}.json")),
                    &chrome_manifest(name, nmh_path, id)?,
                )?;
                written += 1;
            }
        }
    }

    let mozilla = apps_root.join("Mozilla");
    if mozilla.is_dir() {
        let dir = mozilla.join("NativeMessagingHosts");
        fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        for name in [HOST_NAME, LEGACY_HOST_NAME] {
            write_manifest(
                &dir.join(format!("{name}.json")),
                &firefox_manifest(name, nmh_path)?,
            )?;
            written += 1;
        }
    }
    Ok(written)
}

/// Windows variant: browsers read the manifest path from the registry
/// keys the NSIS installer writes, so the JSON files themselves just live
/// beside the daemon executable. `serde_json` escapes the backslashes in
/// the path field.
pub fn register_beside_exec(exe_dir: &Path, chrome_ext_id: Option<&str>) -> Result<usize, String> {
    let mut written = 0usize;
    let nmh_path = exe_dir.join("baluard-nmh.exe");
    if let Some(id) = chrome_ext_id {
        validate_chrome_ext_id(id)?;
        for name in [HOST_NAME, LEGACY_HOST_NAME] {
            write_manifest(
                &exe_dir.join(format!("{name}.json")),
                &chrome_manifest(name, &nmh_path, id)?,
            )?;
            written += 1;
        }
    }
    Ok(written)
}

/// Startup entry point for the daemon: resolve the running executable and
/// the platform data root, then register. Gated to the platforms without
/// a packaging-level registration story.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn register_for_current_exec() -> Result<usize, String> {
    let chrome_id = option_env!("BALUARD_CHROME_EXTENSION_ID");
    #[cfg(target_os = "macos")]
    {
        let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
        let exe_dir = exe.parent().ok_or("current_exe has no parent")?;
        let nmh_path = exe_dir.join("baluard-nmh");
        let apps_root = dirs::data_dir().ok_or("no application data dir")?;
        register_at(&apps_root, &nmh_path, chrome_id)
    }
    #[cfg(target_os = "windows")]
    {
        let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
        let exe_dir = exe.parent().ok_or("current_exe has no parent")?;
        register_beside_exec(exe_dir, chrome_id)
    }
}

fn validate_chrome_ext_id(id: &str) -> Result<(), String> {
    let ok = id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "BALUARD_CHROME_EXTENSION_ID is not a Chrome extension ID: {id}"
        ))
    }
}

fn chrome_manifest(name: &str, nmh_path: &Path, ext_id: &str) -> Result<String, String> {
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

fn write_manifest(path: &Path, contents: &str) -> Result<(), String> {
    fs::write(path, contents).map_err(|e| format!("write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORE_ID: &str = "nmkmfkmdhbifkjdhioejeoegcjpaiijl";

    #[test]
    fn writes_both_host_names_for_installed_browsers() {
        let t = tempfile::tempdir().unwrap();
        let apps = t.path().join("Application Support");
        fs::create_dir_all(apps.join("Google/Chrome")).unwrap();
        fs::create_dir_all(apps.join("BraveSoftware/Brave-Origin")).unwrap();
        let nmh = t.path().join("App.app/Contents/MacOS/baluard-nmh");

        let n = register_at(&apps, &nmh, Some(STORE_ID)).unwrap();
        assert_eq!(n, 4, "two manifests per installed browser");

        for browser in ["Google/Chrome", "BraveSoftware/Brave-Origin"] {
            for name in [HOST_NAME, LEGACY_HOST_NAME] {
                let p = apps
                    .join(browser)
                    .join("NativeMessagingHosts")
                    .join(format!("{name}.json"));
                let d: serde_json::Value =
                    serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
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
        let n = register_at(t.path(), &t.path().join("nmh"), Some(STORE_ID)).unwrap();
        assert_eq!(n, 0);
        assert!(
            !t.path().join("Google").exists(),
            "no dirs for absent browsers"
        );
    }

    #[test]
    fn firefox_gets_extension_allowlist_even_without_a_chrome_id() {
        let t = tempfile::tempdir().unwrap();
        fs::create_dir_all(t.path().join("Mozilla")).unwrap();
        let nmh = t.path().join("App.app/Contents/MacOS/baluard-nmh");

        let n = register_at(t.path(), &nmh, None).unwrap();
        assert_eq!(n, 2);
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
        register_at(t.path(), &nmh, Some(STORE_ID)).unwrap();
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
    fn invalid_chrome_id_is_refused_loudly() {
        let t = tempfile::tempdir().unwrap();
        fs::create_dir_all(t.path().join("Google/Chrome")).unwrap();
        let err = register_at(t.path(), &t.path().join("nmh"), Some("short")).unwrap_err();
        assert!(err.contains("not a Chrome extension ID"), "{err}");
        assert!(
            !t.path().join("Google/Chrome/NativeMessagingHosts").exists(),
            "nothing written on invalid id"
        );
    }

    #[test]
    fn windows_beside_exec_writes_escaped_manifest_paths() {
        let t = tempfile::tempdir().unwrap();
        let n = register_beside_exec(t.path(), Some(STORE_ID)).unwrap();
        assert_eq!(n, 2);
        let d: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(t.path().join(format!("{HOST_NAME}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            d["path"],
            &*t.path().join("baluard-nmh.exe").to_string_lossy()
        );
        assert_eq!(
            d["allowed_origins"][0],
            format!("chrome-extension://{STORE_ID}/")
        );
    }
}
