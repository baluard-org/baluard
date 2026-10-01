//! Baluard desktop Tauri backend.
//!
//! - Starts baluard-daemon on launch, stops on quit
//! - Window close hides to system tray
//! - Proxies vault operations via Protobuf-over-Unix-socket

use prost::Message;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use tauri::menu::MenuBuilder;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WindowEvent};
use tauri_plugin_shell::ShellExt;

/// Maximum response size (5MB — daemon caps at 4MB, plus headroom)
const MAX_RESPONSE_SIZE: u64 = 5 * 1024 * 1024;

/// Generated Protobuf types
mod proto {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/baluard.auth.rs"));
}

use proto::{GatewayRequest, GatewayResponse};

// ── Daemon child process ──

use tauri_plugin_shell::process::CommandChild;

struct Daemon(Option<CommandChild>);
impl Drop for Daemon {
    fn drop(&mut self) {
        // Send SIGTERM first so daemon can zeroize keys gracefully.
        // CommandChild::kill() sends SIGKILL which bypasses signal handlers.
        #[cfg(unix)]
        {
            if let Some(ref child) = self.0 {
                let pid = child.pid() as i32;
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }
                // Give daemon 200ms to zeroize keys before forcing kill
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        // SIGKILL fallback (or primary on non-Unix)
        // CommandChild::kill() takes ownership
        if let Some(child) = self.0.take() {
            let _ = child.kill();
        }
    }
}

// ── Socket path ──

#[cfg(unix)]
fn default_socket_path() -> PathBuf {
    baluard_core::paths::socket_path()
}

// ── Wire protocol ──

fn encode_varint(mut value: u64, buf: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
}

fn decode_varint(data: &[u8]) -> Result<(u64, usize), String> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = 0;
    while i < data.len() {
        let byte = data[i];
        value |= ((byte & 0x7F) as u64) << shift;
        i += 1;
        if byte & 0x80 == 0 {
            return Ok((value, i));
        }
        shift += 7;
        if shift >= 70 {
            return Err("Varint overflow".into());
        }
    }
    Err("Incomplete varint".into())
}

#[cfg(unix)]
fn send_request(action: &str, payload: &str) -> Result<String, String> {
    send_request_with_token(action, payload, "", "").map(|(data, _)| data)
}

/// Send a Protobuf request with session token + slug. Returns (payload, optional_new_token).
/// `slug` (Phase 6 / M2): target vault; empty = active vault.
#[cfg(unix)]
fn send_request_with_token(action: &str, payload: &str, token: &str, slug: &str) -> Result<(String, Option<String>), String> {
    use std::os::unix::net::UnixStream;

    let socket = default_socket_path();
    let mut stream = UnixStream::connect(&socket)
        .map_err(|e| format!("Cannot connect to daemon at {}: {}", socket.display(), e))?;

    // I/O timeouts to prevent UI freeze
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("Set timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("Set timeout: {e}"))?;

    let req = GatewayRequest {
        action: action.to_string(),
        payload: payload.to_string(),
        session_token: token.to_string(),
        slug: slug.to_string(),
    };
    let body = req.encode_to_vec();

    let mut header = Vec::with_capacity(10);
    encode_varint(body.len() as u64, &mut header);
    stream.write_all(&header).map_err(|e| format!("Write: {e}"))?;
    stream.write_all(&body).map_err(|e| format!("Write: {e}"))?;
    stream.flush().map_err(|e| format!("Flush: {e}"))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| format!("Shutdown: {e}"))?;

    // Bounded read to prevent memory exhaustion
    let mut buf = Vec::with_capacity(4096);
    stream
        .take(MAX_RESPONSE_SIZE)
        .read_to_end(&mut buf)
        .map_err(|e| format!("Read: {e}"))?;
    if buf.is_empty() {
        return Err("Daemon closed connection".into());
    }
    if buf.len() as u64 >= MAX_RESPONSE_SIZE {
        return Err("Response exceeds maximum frame size".into());
    }

    let (resp_len, offset) = decode_varint(&buf)?;
    let end = offset + resp_len as usize;
    if end > buf.len() {
        return Err("Response truncated".into());
    }

    let resp = GatewayResponse::decode(&buf[offset..end]).map_err(|e| format!("Decode: {e}"))?;
    log::debug!("daemon -> action={} success={}", action, resp.success);

    if resp.success {
        let new_token = if resp.session_token.is_empty() {
            None
        } else {
            Some(resp.session_token)
        };
        Ok((resp.payload, new_token))
    } else {
        log::warn!("daemon error: action={} error={}", action, resp.error_message);
        Err(resp.error_message)
    }
}

#[cfg(not(unix))]
fn send_request_with_token(_action: &str, _payload: &str, _token: &str, _slug: &str) -> Result<(String, Option<String>), String> {
    Err("IPC not yet implemented on this platform".into())
}

// ── Tauri commands ──

/// D2: the only daemon actions the desktop UI may issue. Built from the
/// `daemon("...")` call sites in `desktop/src`. The webview is the least-
/// trusted component in this architecture: without this gate every
/// host-level (pre-token) route — including the deliberately CLI-only
/// destructive arms — is reachable from JS. Adding a new action to the UI
/// requires extending this list (a debug-build warning names the action on
/// denial, so a miss is loud in development, not silent in production).
const DESKTOP_ALLOWED_ACTIONS: &[&str] = &[
    // bridge (browser extension pairing)
    "bridge.list",
    "bridge.pair_approve",
    "bridge.pair_start",
    "bridge.pending",
    "bridge.revoke",
    // ciphers
    "cipher.totp_code",
    "vault.active",
    "vault.add",
    "vault.archive",
    "vault.attach_download",
    "vault.avatar.get",
    "vault.avatar.set",
    "vault.delete",
    "vault.get",
    "vault.import",
    "vault.export",
    "vault.list",
    "vault.list_full",
    "vault.trash.purge",
    "vault.trash.restore",
    "vault.unarchive",
    "vault.update",
    // vault lifecycle / unlock
    "vault.create",
    "space.create",
    "vault.info",
    "vault.is_admin_device",
    "vault.lock",
    "vault.open",
    "vault.unlock",
    // quick unlock
    "vault.biometric_disable",
    "vault.biometric_enable",
    "vault.biometric_status",
    "vault.biometric_unlock",
    "vault.pin_disable",
    "vault.pin_enable",
    "vault.pin_status",
    "vault.pin_unlock",
    // multi-vault
    "vaults.close",
    "vaults.detach",
    "vaults.list",
    "vaults.list_full_all",
        "cipher.set_collection",
        "collections.create",
        "templates.create",
        "templates.list",
        "templates.delete",
        "collections.sweep",
        "collections.list",
        "collections.rename",
        "collections.delete",
        "collections.grant",
        "collections.revoke",
        // S4-2: group management.
        "groups.list",
        "groups.create",
        "groups.rename",
        "groups.delete",
        "groups.member_add",
        "groups.member_remove",
        // S3-7a: space meta key groundwork.
        "space.prepare",
        "space.status",
        "space.flip",
        "space.migrate",
        "space.remote",
        "space.settings",
        "space.settings_set",
        // S4-1: sensitive-op approvals (quorum knob).
        "approvals.list",
        "access.review",
        "activity.timeline",
        "policies.set",
        "policies.list",
        // S4-7: Space Recovery Kit (admin surfaces).
        "space.kit_enable",
        "space.kit_disable",
        "space.kit_status",
        // S2: item-sharing send/receive surfaces.
        "reveals.export_guest",
        "packages.import",
        "reveals.open_contact",
        "reveals.open_guest",
        // S2 UI: address book + contact-flavor send.
        "contacts.list",
        "contacts.my_card",
        "contacts.import_card",
        "contacts.mark_verified",
        "contacts.remove",
        "outbox.publish",
        "outbox.unpublish",
        "outbox.revoke",
        "outbox.list",
        "outbox.link",
        "outbox.links",
        "outbox.forget",
        "outbox.read",
        "outbox.entries",
        "outbox.resync",
        "reveals.export_contact",
        "packages.export",
        // S3-6: request-access JIT surfaces.
        "collections.request_access",
        "collections.requests_mine",
        "collections.requests_withdraw",
        "collections.requests_list",
        "collections.requests_approve",
        "collections.requests_deny",
        "collections.catalog_set",
        "collections.catalog_list",
        // People surface: members, join queue, notices, activity.
        "members.list",
        "members.invite",
        "members.remove",
        "members.reset",
        "members.transfer",
        "members.claim",
        "requests.list",
        "requests.approve",
        "requests.deny",
        "notices.list",
        "activity.events",
        "activity.refusals",
    "vaults.register_local",
    "vaults.switch",
    // clone from provider
    "vault.clone_finalize",
    "vault.clone_progress",
    "vault.clone_start",
    "vault.setup_sync",
    "vault.device_activity",
    // device fleet
    "device.revoke",
    // folders / tags
    "folder.create",
    "folder.delete",
    "folder.rename",
    "tag.delete",
    // passkeys
    "passkey.delete",
    // settings
    "settings.get",
    "settings.set",
    "locale.save",
    // generator / ssh
    "generator.history_add",
    "generator.history_clear",
    "generator.history_list",
    "ssh.generate_key",
    "favicon.get",
    // sync
    "sync.autosync_nudge_pull",
    "sync.autosync_status",
    "sync.conflict",
    "sync.conflict.resolve",
    "sync.removal_notice",
    "sync.disconnect",
    "sync.pull",
    "sync.push",
    "sync.status_json",
    // providers
    "provider.create_repo",
    "provider.disconnect",
    "provider.list",
    "provider.oauth_status_web",
    "provider.status",
];

fn desktop_action_allowed(action: &str) -> bool {
    DESKTOP_ALLOWED_ACTIONS.contains(&action)
}

/// D2: destructive daemon params the desktop never sends. Checked against
/// top-level JSON object keys only — never substrings — so cipher names or
/// note text containing e.g. "force" cannot trip the gate. Non-JSON payloads
/// (raw ids) and non-object JSON (strings/numbers) pass: no such action has
/// these params.
fn payload_has_desktop_forbidden_keys(payload: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(payload)
        .ok()
        .and_then(|v| {
            v.as_object().map(|o| {
                o.contains_key("delete_from_disk") || o.contains_key("force")
            })
        })
        .unwrap_or(false)
}

#[derive(Serialize)]
struct DaemonResponse {
    success: bool,
    payload: String,
    error: String,
}

#[tauri::command]
async fn daemon_request(
    action: String,
    payload: String,
    slug: Option<String>,
    app: AppHandle,
) -> DaemonResponse {
    // D2: the webview gets exactly the action set the UI uses — no more.
    // Checked before any state access so a denial costs nothing.
    if !desktop_action_allowed(&action) {
        #[cfg(debug_assertions)]
        log::warn!("[desktop] D2 deny: action={action} not in DESKTOP_ALLOWED_ACTIONS");
        return DaemonResponse {
            success: false,
            payload: String::new(),
            error: format!("Action '{action}' is not available in the desktop app"),
        };
    }
    // D2: the destructive detach params (delete_from_disk/force) are the
    // CLI's escape hatch, never the webview's.
    if payload_has_desktop_forbidden_keys(&payload) {
        #[cfg(debug_assertions)]
        log::warn!("[desktop] D2 deny: action={action} payload carries a forbidden key");
        return DaemonResponse {
            success: false,
            payload: String::new(),
            error: "This operation is only available through the command line".into(),
        };
    }

    let store = app.state::<Mutex<SessionStore>>();
    log::debug!("[desktop] -> action={action} slug={slug:?} payload_len={}", payload.len());

    // Resolve the effective slug for THIS request. When the caller omits it,
    // the daemon targets the active vault — but the token check is still
    // per-vault, so we must send the ACTIVE vault's token. Fall back to the
    // tracked active_slug to look it up. (M2/Phase 6: no-slug requests like
    // `vault.list_full` would otherwise send an empty token and be rejected.)
    let active_slug = store.lock().unwrap().active_slug.clone();
    let effective_slug = slug.clone().or(active_slug.clone());
    let stored_token = effective_slug
        .as_ref()
        .and_then(|s| store.lock().unwrap().tokens.get(s).map(|z| z.as_str().to_owned()))
        .unwrap_or_default();

    // The socket read/write is blocking (up to the 30s read timeout). Running
    // it inline stalls the webview event loop — the spinner SolidJS renders
    // never paints. spawn_blocking moves it to the Tokio blocking pool so the
    // main thread keeps servicing paint/input events. This is the single most
    // impactful fix for UI freezes during long ops (sync.pull/push,
    // vault.unlock, git operations).
    let slug_for_call = slug.clone().unwrap_or_default();
    let action_for_call = action.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        send_request_with_token(&action_for_call, &payload, &stored_token, &slug_for_call)
    })
    .await;

    // spawn_blocking returns Result<inner, JoinError>; flatten so the inner
    // socket result drives the same token bookkeeping below.
    let socket_result: Result<(String, Option<String>), String> = match result {
        Ok(inner) => inner,
        Err(join_err) => Err(format!("IPC task failed: {join_err}")),
    };

    match socket_result {
        Ok((data, new_token)) => {
            log::debug!("[desktop] <- action={action} success=true payload_len={}", data.len());
            let mut st = store.lock().unwrap();
            // On lock for a slug, drop that slug's token. On unlock/create,
            // store the returned token under the slug.
            if action == "vault.lock" {
                if let Some(s) = &slug {
                    st.tokens.remove(s);
                    if st.active_slug.as_deref() == Some(s.as_str()) {
                        st.active_slug = None;
                    }
                } else {
                    // No slug: legacy lock-all path. Clear everything.
                    st.tokens.clear();
                    st.active_slug = None;
                }
            } else if let Some(t) = new_token {
                // File the token under the slug. Prefer the explicit slug;
                // otherwise parse it from the response payload (vault.unlock /
                // vault.create always return {slug}). If neither yields a slug,
                // don't store — a slug-less token would never be read back.
                let key = slug.clone().or_else(|| {
                    serde_json::from_str::<serde_json::Value>(&data)
                        .ok()
                        .and_then(|v| v["slug"].as_str().map(String::from))
                });
                if let Some(k) = key {
                    st.tokens.insert(k.clone(), zeroize::Zeroizing::new(t));
                    // Unlock/create make the vault active.
                    st.active_slug = Some(k);
                }
            } else {
                // No new token issued (e.g. vaults.switch flips an already-
                // unlocked vault). Still track the active focus from the
                // response so subsequent slug-less requests resolve right.
                if (action == "vaults.switch" || action == "vaults.set_active")
                    && let Some(a) = serde_json::from_str::<serde_json::Value>(&data)
                        .ok()
                        .and_then(|v| v["active"].as_str().map(String::from))
                {
                    st.active_slug = Some(a);
                }
            }
            DaemonResponse {
                success: true,
                payload: data,
                error: String::new(),
            }
        }
        Err(e) => {
            log::warn!("[desktop] <- action={action} error={e}");
            // M1: only drop the TARGETED slug's token on a token/lock error.
            // Clearing the whole map on a slug-less error caused a re-unlock
            // storm across every open vault. For slug-less errors we leave
            // the map alone — the 30s heartbeat + next-request rejection is
            // the backstop. Match the specific daemon error strings, not a
            // bare "locked" substring (too broad — "locked" appears in many
            // unrelated messages).
            let is_token_or_lock_err = e.contains("session token")
                || e.contains("Vault is locked");
            if is_token_or_lock_err {
                let target = slug.as_ref().or(active_slug.as_ref());
                if let Some(s) = target {
                    let mut st = store.lock().unwrap();
                    st.tokens.remove(s);
                    if st.active_slug.as_deref() == Some(s.as_str()) {
                        st.active_slug = None;
                    }
                }
            }
            DaemonResponse {
                success: false,
                payload: String::new(),
                error: e,
            }
        },
    }
}

/// Check if daemon is reachable via ping (avoids phantom connections).
/// D5: async + spawn_blocking — the sync version did a blocking socket
/// read (up to the 30s timeout) on the main UI thread.
#[tauri::command]
async fn daemon_status() -> bool {
    tauri::async_runtime::spawn_blocking(|| send_request("ping", "").is_ok())
        .await
        .unwrap_or(false)
}

/// Reveal the main window once the frontend has finished loading and rendering,
/// avoiding the white flash.
#[tauri::command]
fn show_window(window: tauri::WebviewWindow) {
    let _ = window.show();
    let _ = window.set_focus();
    // The webview loaded and rendered: the previous run did NOT die before
    // presenting. Clear the Linux watchdog marker here — logout/shutdown
    // SIGTERMs never reach RunEvent::Exit and must not read as crashes.
    #[cfg(target_os = "linux")]
    render::clear_marker();
}

/// D1: save the recovery phrase to a user-chosen file — dialog AND write
/// both Rust-side. Replaces `write_text_file(path, contents)`, which
/// accepted any path from the webview (the "scope" was a comment, not
/// code). The webview now passes only the contents; it never holds a
/// filesystem path, and no arbitrary-path write command exists at all.
/// Written through `write_secret_file`: 0600 from the first byte, atomic
/// rename, symlinks replaced not followed.
///
/// Returns `Ok(false)` when the user cancels the dialog (no file written,
/// not an error). Peer-review follow-up: the blocking dialog + write run on
/// the blocking pool (D5 consistency) so an open dialog parks no async
/// worker for the full user-hesitation window.
#[tauri::command]
async fn save_recovery_phrase(app: AppHandle, contents: String) -> Result<bool, String> {
    use tauri_plugin_dialog::DialogExt;

    let saved = tauri::async_runtime::spawn_blocking(move || -> Result<bool, String> {
        let picked = app
            .dialog()
            .file()
            .add_filter("Text", &["txt"])
            .set_file_name("baluard-recovery-phrase.txt")
            .blocking_save_file();

        let path = match picked {
            None => return Ok(false), // user cancelled
            Some(tauri_plugin_dialog::FilePath::Path(p)) => p,
            // Non-file URL (e.g. a remote location): refuse rather than guess.
            Some(_) => return Err("Unsupported save location".into()),
        };

        baluard_core::secret_file::write_secret_file(&path, contents.as_bytes())
            .map_err(|e| e.to_string())?;
        Ok(true)
    })
    .await
    .map_err(|e| format!("save task failed: {e}"))??;
    Ok(saved)
}

// ── D4: clipboard concealment marker ──
//
// Adds the platform's "this clipboard entry is sensitive" marker to the
// CURRENT clipboard contents, right after the webview's copy lands, so
// clipboard-history tools and cloud clipboard sync skip the entry:
//   macOS:   org.nspasteboard.ConcealedType (Paste, Maccy, Alfred, ...)
//   Windows: ExcludeClipboardContentFromMonitorProcessing (cloud sync)
//            + CanIncludeInClipboardHistory = 0 (Win10+ clipboard history)
//   Linux:   no cross-desktop marker exists on X11/Wayland (KDE's
//            x-kde-passwordManagerHint cannot be attached to a selection
//            the webview already owns) — the 30s auto-clear is the floor.
// Best-effort by design: failures log, never surface. Concealment layers
// on top of the auto-clear, it does not replace it.
mod clipboard_conceal {
    pub fn mark_current() {
        #[cfg(target_os = "macos")]
        macos_mark();
        #[cfg(target_os = "windows")]
        windows_mark();
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        log::debug!("[desktop] clipboard concealment: no platform marker on this OS");
    }

    #[cfg(target_os = "macos")]
    fn macos_mark() {
        use objc2_app_kit::NSPasteboard;
        use objc2_foundation::{NSData, NSString};

        let pb = NSPasteboard::generalPasteboard();
        let concealed = NSString::from_str("org.nspasteboard.ConcealedType");
        let empty = NSData::new();
        // NSPasteboardType is a NSString alias; adding the type to the
        // existing pasteboard entry does not clear the copied text.
        if !pb.setData_forType(Some(&empty), &concealed) {
            log::warn!("[desktop] pasteboard refused the ConcealedType marker");
        }
    }

    #[cfg(target_os = "windows")]
    fn windows_mark() {
        // Raw Win32 FFI (stable ABI, immune to windows-crate version churn):
        // add the two documented marker formats to the CURRENT clipboard.
        // SetClipboardData without EmptyClipboard adds a format alongside
        // the webview's text instead of replacing it.
        use std::ffi::c_void;

        #[link(name = "user32")]
        unsafe extern "system" {
            fn OpenClipboard(hwnd_new_owner: *mut c_void) -> i32;
            fn CloseClipboard() -> i32;
            fn RegisterClipboardFormatW(lpsz_format: *const u16) -> u32;
            fn SetClipboardData(u_format: u32, h_mem: *mut c_void) -> *mut c_void;
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GlobalAlloc(u_flags: u32, dw_bytes: usize) -> *mut c_void;
            fn GlobalLock(h_mem: *mut c_void) -> *mut c_void;
            fn GlobalUnlock(h_mem: *mut c_void) -> i32;
            fn GlobalFree(h_mem: *mut c_void) -> *mut c_void;
        }
        const GMEM_MOVEABLE: u32 = 0x0002;
        const GMEM_ZEROINIT: u32 = 0x0040;

        for name in [
            "ExcludeClipboardContentFromMonitorProcessing",
            "CanIncludeInClipboardHistory",
        ] {
            let mut wide: Vec<u16> = name.encode_utf16().collect();
            wide.push(0);
            unsafe {
                // Transient ownership races are not uncommon on Windows: skip
                // THIS marker, still try the next one.
                if OpenClipboard(std::ptr::null_mut()) == 0 {
                    log::warn!("[desktop] clipboard concealment: OpenClipboard failed");
                    continue;
                }
                let fmt = RegisterClipboardFormatW(wide.as_ptr());
                let mut ok = false;
                if fmt != 0 {
                    // GMEM_ZEROINIT: if GlobalLock ever fails, SetClipboardData
                    // still sees a zeroed block (the marker payload is DWORD 0).
                    let h = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, 4);
                    if !h.is_null() {
                        let p = GlobalLock(h);
                        if !p.is_null() {
                            // DWORD 0 = exclude (CanInclude=0 means excluded;
                            // for Exclude... presence is what matters)
                            (p as *mut u32).write_unaligned(0);
                            GlobalUnlock(h);
                        }
                        if SetClipboardData(fmt, h).is_null() {
                            // Ownership not taken; free to avoid the leak.
                            GlobalFree(h);
                        } else {
                            ok = true;
                        }
                    }
                }
                if !ok {
                    log::warn!("[desktop] clipboard concealment: marker {name} not set");
                }
                CloseClipboard();
            }
        }
    }
}

/// D4: mark the current clipboard entry as concealed (see
/// `clipboard_conceal`). Called from JS right after a secret copy.
#[tauri::command]
async fn clipboard_mark_concealed(app: AppHandle) -> Result<(), String> {
    app.run_on_main_thread(clipboard_conceal::mark_current)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn update_tray_icon(_app: AppHandle, _is_dark: bool) -> Result<(), String> {
    #[cfg(not(target_os = "macos"))]
    {
        if let Some(tray) = _app.tray_by_id("main") {
            let icon_bytes = if _is_dark {
                include_bytes!("../icons/tray_white.png").as_slice()
            } else {
                include_bytes!("../icons/tray_black.png").as_slice()
            };
            let icon = tauri::image::Image::from_bytes(icon_bytes).map_err(|e| e.to_string())?;
            tray.set_icon(Some(icon)).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Stored session tokens obtained from daemon at unlock/create, keyed by
/// vault slug. Per Phase 6, each unlocked vault has its own token; a
/// vault-A token is rejected for any vault-B operation. The frontend keeps
/// a `Map<slug, token>` in lockstep with this.
///
/// `active_slug` tracks which vault the UI is currently focused on. The
/// daemon resolves a slug-less request to the active vault, but it STILL
/// requires that vault's session token — so for a slug-less request we look
/// up the token under `active_slug`. Updated on unlock/create/switch/
/// set_active. Without this, `vault.list_full` (always slug-less) would send
/// an empty token and be rejected with "Invalid session token".
struct SessionStore {
    tokens: std::collections::HashMap<String, zeroize::Zeroizing<String>>,
    active_slug: Option<String>,
}

/// Phase 6 / T15 / M4: blur-lock debounce state.
///
/// `WindowEvent::Focused(false)` fires on every focus loss (alt-tab, native
/// file dialogs, Spotlight, even tooltips). Locking all vaults on each would
/// be punishing for a daily driver. We arm a short debounce: on blur, set
/// `blurred` and schedule a lock after `BLUR_LOCK_DELAY`; if focus returns
/// within that window (transient blur), the pending lock is aborted. Genuine
/// app-switches (blurred longer than the delay) still lock.
struct BlurLockState {
    blurred: std::sync::atomic::AtomicBool,
    pending: std::sync::Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
}

/// Debounce window for blur-triggered lock-all. Transient blurs (menus,
/// tooltips, brief alt-tab) within this window do NOT lock; genuine
/// app-switches (blurred longer) do. Tuned for password-manager UX: short
/// enough to be secure, long enough to ignore UI chatter.
const BLUR_LOCK_DELAY: std::time::Duration = std::time::Duration::from_millis(1500);

// ── Desktop app preferences (app-global, pre-unlock) ──
//
// Lives at <data_dir>/desktop-prefs.json in plaintext. Unlike VaultSettings
// (per-vault, encrypted), these are client-level behaviors that must apply on
// the login screen and across every vault. The tray/dock presence is not a
// vault property, so it does not belong in settings.enc.

/// App-global desktop preferences. Plaintext on disk; no secrets.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct DesktopPrefs {
    /// Tray-only mode: hide the app from the macOS Dock / Windows+Linux
    /// taskbar. The window stays reachable via the tray icon. Closing the
    /// window still hides it to the tray (unchanged).
    #[serde(default)]
    tray_only: bool,
    /// Linux compatible-rendering preference. `None` = automatic (decided
    /// at each launch from GPU detection + crash recovery). `Some(true)`
    /// forces the WebKitGTK workaround on, `Some(false)` forces it off.
    /// See the `render` module for the decision order.
    #[serde(default)]
    compatible_rendering: Option<bool>,
}

fn desktop_prefs_path() -> std::path::PathBuf {
    baluard_core::paths::data_dir().join("desktop-prefs.json")
}

/// Load desktop prefs; missing/corrupt file falls back to default (tray off).
/// Never propagates an error — a bad prefs file must not block app launch.
fn load_desktop_prefs() -> DesktopPrefs {
    match std::fs::read_to_string(desktop_prefs_path()) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => DesktopPrefs::default(),
    }
}

/// Persist desktop prefs. Best-effort: logs on failure but does not abort —
/// the in-memory apply still takes effect for this session.
fn save_desktop_prefs(prefs: &DesktopPrefs) {
    let path = desktop_prefs_path();
    if let Err(e) = std::fs::create_dir_all(path.parent().unwrap_or_else(|| std::path::Path::new("."))) {
        log::warn!("[desktop] prefs dir create failed: {e}");
        return;
    }
    match serde_json::to_string_pretty(prefs) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                log::warn!("[desktop] prefs write failed: {e}");
            }
        }
        Err(e) => log::warn!("[desktop] prefs serialize failed: {e}"),
    }
}

/// Apply tray-only mode to the OS chrome.
///
/// macOS: switch the activation policy. `Accessory` removes the Dock icon
/// (menu-bar-tray app); `Regular` restores it. This is the canonical macOS
/// mechanism and is dynamic at runtime.
/// Windows/Linux: no activation-policy equivalent, so toggle the window's
/// taskbar button via `set_skip_taskbar`. The tray icon remains the anchor.
///
/// Returns `Err` if the OS call failed so the caller (set_tray_only command)
/// can surface it to the UI instead of falsely reporting success. The prefs
/// file write is handled separately by the caller and stays best-effort.
fn apply_tray_only(app: &AppHandle, tray_only: bool) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let policy = if tray_only {
            tauri::ActivationPolicy::Accessory
        } else {
            tauri::ActivationPolicy::Regular
        };
        app.set_activation_policy(policy)
            .map_err(|e| format!("set_activation_policy: {e}"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let w = app
            .get_webview_window("main")
            .ok_or_else(|| "main window not found".to_string())?;
        w.set_skip_taskbar(tray_only)
            .map_err(|e| format!("set_skip_taskbar: {e}"))
    }
}

/// Read desktop prefs (for the Settings UI to reflect current state).
#[tauri::command]
fn get_desktop_prefs() -> DesktopPrefs {
    load_desktop_prefs()
}

/// Toggle tray-only mode: persist + apply immediately.
///
/// The prefs file write is best-effort (logged on failure, matching the
/// theme/locale persistence pattern): a failed write doesn't block the
/// in-session apply. The OS-apply failure DOES propagate so the UI doesn't
/// falsely report success when the Dock/taskbar state didn't actually change.
#[tauri::command]
fn set_tray_only(app: AppHandle, enabled: bool) -> Result<(), String> {
    // Load-mutate-save: the prefs struct carries more than one field now;
    // reconstructing it here would silently wipe the others.
    let mut prefs = load_desktop_prefs();
    prefs.tray_only = enabled;
    save_desktop_prefs(&prefs);
    apply_tray_only(&app, enabled)
}

// ── Linux compatible rendering (WebKitGTK DMABUF workaround) ──
//
// WebKitGTK's DMABUF renderer blank-windows or corrupts on some Linux GPU
// stacks (proprietary NVIDIA most commonly; see Tauri's "Linux Graphics
// Issues" doc). The standard fix is WEBKIT_DISABLE_DMABUF_RENDERER=1.
// Baluard decides it here so non-technical users never touch env vars.
//
// Decision order at launch:
//   1. user/distro env var set  → never touched, reported as-is
//   2. explicit pref            → Some(true)/Some(false) wins
//   3. automatic                → proprietary NVIDIA present, OR the
//                                 previous run never presented a window
//                                 (crash marker). The recovery trigger is
//                                 session-only and surfaced on the login
//                                 screen; making it permanent is a
//                                 Settings toggle.
//
// Marker semantics: written at every Linux launch, cleared the moment the
// frontend calls `show_window` (webview loaded and rendered — the failure
// signal is "died before presenting", not merely "ended uncleanly": logout
// and shutdown SIGTERM the app and must not read as crashes). `RunEvent::Exit`
// clears it too, as a backstop for sessions that never reached the frontend.
#[cfg(target_os = "linux")]
mod render {
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Workaround active for this session (env var on or pref on).
    pub static ACTIVE: AtomicBool = AtomicBool::new(false);
    /// The crash-recovery heuristic triggered THIS session (implies ACTIVE).
    pub static RECOVERY: AtomicBool = AtomicBool::new(false);

    fn marker_path() -> std::path::PathBuf {
        baluard_core::paths::data_dir().join("render-watchdog.flag")
    }

    fn nvidia_proprietary_present() -> bool {
        std::path::Path::new("/proc/driver/nvidia/version").exists()
            || std::path::Path::new("/sys/module/nvidia").exists()
    }

    /// Decide + apply. Must run before the Tauri Builder: it is the only
    /// safe point for `env::set_var` (unsafe in edition 2024, no concurrent
    /// threads yet) and WebKitGTK reads the variable at renderer init.
    /// Returns whether the workaround is active.
    pub fn init() -> bool {
        if let Some(v) = std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER") {
            let on = v == "1";
            ACTIVE.store(on, Ordering::Relaxed);
            return on;
        }
        let prefs = super::load_desktop_prefs();
        let saw_marker = marker_path().exists();
        let enable = match prefs.compatible_rendering {
            Some(v) => v,
            None => {
                let heuristic = nvidia_proprietary_present() || saw_marker;
                RECOVERY.store(heuristic && saw_marker, Ordering::Relaxed);
                heuristic
            }
        };
        if enable {
            // SAFETY: single-threaded startup — called from `run()` before
            // the Tauri Builder spawns any thread or loads WebKitGTK.
            unsafe {
                std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
            }
        }
        ACTIVE.store(enable, Ordering::Relaxed);
        enable
    }

    /// Crash marker: written at every Linux launch, cleared when the
    /// window presents (`show_window`) or on clean exit (`RunEvent::Exit`).
    /// Presence at the NEXT launch means the previous run died before it
    /// ever rendered — the blank-window signature. Constant content, no
    /// secrets. Parent dir is created on demand: a first-run crash must
    /// still leave the marker behind.
    pub fn write_marker() {
        let path = marker_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&path, b"1");
    }

    pub fn clear_marker() {
        let _ = std::fs::remove_file(marker_path());
    }
}

/// Linux rendering state for the UI: drives the login-screen recovery
/// notice and the Settings toggle. One round trip covers both.
#[derive(Debug, Serialize)]
struct RenderState {
    linux: bool,
    active: bool,
    recovery: bool,
    setting: Option<bool>,
}

#[tauri::command]
fn get_render_state() -> RenderState {
    #[cfg(target_os = "linux")]
    {
        RenderState {
            linux: true,
            active: render::ACTIVE.load(std::sync::atomic::Ordering::Relaxed),
            recovery: render::RECOVERY.load(std::sync::atomic::Ordering::Relaxed),
            setting: load_desktop_prefs().compatible_rendering,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        RenderState {
            linux: false,
            active: false,
            recovery: false,
            setting: None,
        }
    }
}

/// Persist the compatible-rendering preference. `None` = automatic.
/// WebKitGTK reads the env var at renderer init, so the change applies on
/// the NEXT launch; the UI says so. Never an OS call, never fails visibly.
#[tauri::command]
fn set_compatible_rendering(value: Option<bool>) {
    let mut prefs = load_desktop_prefs();
    prefs.compatible_rendering = value;
    save_desktop_prefs(&prefs);
}

// ── App entry ──

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Linux: decide the WebKitGTK rendering workaround first (see the
    // `render` module). Must precede the Builder: set_var is unsafe in
    // edition 2024 and only safe pre-thread-spawn, and WebKitGTK reads the
    // variable when the webview initializes.
    #[cfg(target_os = "linux")]
    {
        if render::init() {
            eprintln!("[desktop] compatible rendering enabled (WEBKIT_DISABLE_DMABUF_RENDERER=1)");
        }
        render::write_marker();
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_biometry::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(Mutex::new(None::<Daemon>))
        .manage(Mutex::new(SessionStore {
            tokens: std::collections::HashMap::new(),
            active_slug: None,
        }))
        .manage(BlurLockState {
            blurred: std::sync::atomic::AtomicBool::new(false),
            pending: std::sync::Mutex::new(None),
        })
        .setup(|app| {
            // Always log to file for debuggability.
            // BALUARD_LOG_DIR overrides log directory; defaults to socket dir.
            // BALUARD_DEBUG=1 enables Debug level; otherwise Warn.
            let log_dir = if let Ok(dir) = std::env::var("BALUARD_LOG_DIR") {
                std::path::PathBuf::from(dir)
            } else {
                default_socket_path().parent()
                    .expect("socket path has parent").to_path_buf()
            };
            let _ = std::fs::create_dir_all(&log_dir);

            let level = if std::env::var("BALUARD_DEBUG").unwrap_or_default() == "1" {
                log::LevelFilter::Debug
            } else {
                log::LevelFilter::Warn
            };

            app.handle().plugin(
                tauri_plugin_log::Builder::default()
                    .level(level)
                    .target(tauri_plugin_log::Target::new(
                        tauri_plugin_log::TargetKind::Folder {
                            path: log_dir,
                            file_name: Some("desktop.log".into()),
                        },
                    ))
                    .rotation_strategy(tauri_plugin_log::RotationStrategy::KeepOne)
                    .build(),
            )?;

            // Always stop any existing daemon and start fresh.
            // Prevents stale daemon from a previous Tauri session from serving
            // outdated code after a sidecar rebuild.
            #[cfg(unix)]
            {
                // Kill only processes whose binary is exactly "baluard-daemon".
                // Do NOT use lsof -t -U — on macOS it can return PIDs of unrelated
                // processes (OrbStack, Docker, Ice, Ghostty, etc.) that hold Unix sockets.
                let socket = default_socket_path();
                if let Ok(output) = std::process::Command::new("pgrep")
                    .args(["-x", "baluard-daemon"])
                    .output()
                {
                    let pids = String::from_utf8_lossy(&output.stdout);
                    for pid in pids.split_whitespace() {
                        if let Ok(p) = pid.parse::<i32>() {
                            unsafe { libc::kill(p, libc::SIGTERM); }
                            log::info!("Stopped old daemon pid={p}");
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(300));
                let _ = std::fs::remove_file(&socket);

                // Use tauri-plugin-shell sidecar for bundle-relative binary path.
                // Binary must exist at src-tauri/binaries/baluard-daemon-{target-triple}
                //
                // Let the daemon resolve the vault from the registry's
                // active_vault field. No --vault-path needed — the daemon
                // reads <data_dir>/registry.json on startup (P1).
                log::info!("Starting daemon with --socket {}",
                    socket.display());

                    let sidecar_command = app.shell().sidecar("baluard-daemon")
                        .map_err(|e| format!("Sidecar not found: {e}"))?;

                    let sidecar_command = sidecar_command
                        .args(["--socket", default_socket_path().to_str().unwrap_or("/tmp/baluard.sock")]);

                    // Spawn the daemon. We MUST keep the stdout/stderr receiver alive
                    // — dropping it closes the pipe and the daemon can fail on EPIPE
                    // (or, more importantly, we lose the daemon's startup error output).
                    // Forward events to the desktop log in Tauri's async runtime.
                    let (mut rx, child) = sidecar_command.spawn()
                        .map_err(|e| format!("Failed to start daemon: {e}"))?;

                    tauri::async_runtime::spawn(async move {
                        use tauri_plugin_shell::process::CommandEvent;
                        while let Some(event) = rx.recv().await {
                            match event {
                                CommandEvent::Stdout(b) => {
                                    log::info!("[daemon] {}", String::from_utf8_lossy(&b).trim_end());
                                }
                                CommandEvent::Stderr(b) => {
                                    log::warn!("[daemon] {}", String::from_utf8_lossy(&b).trim_end());
                                }
                                CommandEvent::Error(e) => log::error!("[daemon] {e}"),
                                CommandEvent::Terminated(t) => {
                                    log::warn!("[daemon] terminated code={:?} signal={:?}", t.code, t.signal);
                                    break;
                                }
                                _ => {}
                            }
                        }
                    });

                    let state = app.state::<Mutex<Option<Daemon>>>();
                    *state.lock().unwrap() = Some(Daemon(Some(child)));
                    log::info!("Daemon started via sidecar");

                    // Wait for daemon readiness (up to 5s — first launch may
                    // spend time on Argon2id KDF when initializing the vault).
                    for attempt in 0..50 {
                        if send_request("ping", "").is_ok() {
                            log::info!("Daemon ready after {}ms", attempt * 100);
                            break;
                        }
                        if attempt == 49 {
                            return Err("Daemon failed to start within 5s. Check logs/daemon.log and logs/desktop.log for the daemon's error output.".into());
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
            }

            // Set window icon explicitly so it shows correctly in alt+tab / cmd+tab
            // even during dev mode (bundle icons only apply to installed apps).
            if let Some(w) = app.get_webview_window("main") {
                let icon = tauri::image::Image::from_bytes(
                    include_bytes!("../icons/128x128.png")
                )?;
                w.set_icon(icon)?;
            }

            // System tray
            let show = tauri::menu::MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
            let quit = tauri::menu::MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = MenuBuilder::new(app)
                .item(&show)
                .separator()
                .item(&quit)
                .build()?;

            let tray_icon = tauri::image::Image::from_bytes(
                include_bytes!("../icons/tray_black.png")
            )?;

            let _tray = TrayIconBuilder::with_id("main")
                .icon(tray_icon)
                .icon_as_template(true)
                .tooltip("Baluard")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                })
                .build(app)?;

            // Apply tray-only preference at startup so the Dock / taskbar
            // state is correct from the first frame (no dock-icon flash on
            // macOS). Loaded from <data_dir>/desktop-prefs.json.
            let prefs = load_desktop_prefs();
            if prefs.tray_only {
                // Best-effort: a failure here must NOT abort app launch. Log
                // and continue; the user can re-toggle from Settings.
                if let Err(e) = apply_tray_only(app.handle(), true) {
                    log::warn!("[desktop] startup tray-only apply failed: {e}");
                }
            }

            // Record the rendering decision in the log now that the file
            // logger is attached (the decision itself happened in run(),
            // before the builder).
            #[cfg(target_os = "linux")]
            if render::ACTIVE.load(std::sync::atomic::Ordering::Relaxed) {
                log::info!(
                    "[desktop] compatible rendering active (recovery={})",
                    render::RECOVERY.load(std::sync::atomic::Ordering::Relaxed)
                );
            }

            Ok(())
        })
        // Window events → defensive (policy-driven) lock.
        //
        // Phase 6 / T15: when the main window loses focus (app resign-active)
        // we ask the daemon to lock only the vaults whose timeout policy is
        // `Immediately`. Other policies (Minutes / OnAppExit) are
        // honored: backgrounding the app alone no longer forces a lock.
        // Close still hides to tray.
        //
        // NOTE: OS suspend / screen-lock hooks are platform-specific and
        // not yet wired here. Tauri v2 has no cross-platform power-event
        // API; the remaining pieces are:
        //   macOS:  NSWorkspaceDidSleepNotification / NSWorkspaceScreensDidSleepNotification
        //   Linux:  org.freedesktop.login1.Manager PrepareForSleep (D-Bus)
        //   Windows: WM_POWERBROADCAST (PBT_APMQUERYSUSPEND) / SessionSwitch (WTS_SESSION_LOCK)
        // Window blur covers the common "switched away from the app" case
        // today; the OS hooks above are the follow-up.
        .on_window_event(|window, event| {
            match event {
                WindowEvent::CloseRequested { api, .. } => {
                    api.prevent_close();
                    let _ = window.hide();
                }
                WindowEvent::Focused(false) => {
                    // M4: arm a debounced lock-all. Transient blurs (menus,
                    // tooltips, brief alt-tab) cancel before the delay elapses;
                    // genuine app-switches lock after BLUR_LOCK_DELAY.
                    let app = window.app_handle();
                    if let Some(blur) = app.try_state::<BlurLockState>() {
                        blur.blurred
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                        // Cancel any previously-armed lock.
                        if let Some(handle) = blur.pending.lock().unwrap().take() {
                            handle.abort();
                        }
                        // The whole debounce (sleep + recheck + lock + clear)
                        // runs on the blocking pool. This avoids needing
                        // `tokio::time::sleep` (tokio is not a direct dep of
                        // this crate; `tauri::async_runtime` doesn't re-export
                        // its timer) and keeps the synchronous `send_request`
                        // off the async runtime. `abort()` cancels the thread
                        // (the JoinHandle, not the OS thread) — the sleep may
                        // run to completion on abort, but the blurred flag is
                        // rechecked before locking so an aborted-then-focused
                        // window won't spuriously lock.
                        let app_handle = app.clone();
                        let handle = tauri::async_runtime::spawn(async move {
                            let app_for_blocking = app_handle.clone();
                            let _ = tauri::async_runtime::spawn_blocking(
                                move || -> bool {
                                    std::thread::sleep(BLUR_LOCK_DELAY);
                                    // Re-check the flag: a Focused(true) during
                                    // the sleep sets it to false + aborts us.
                                    let Some(blur) =
                                        app_for_blocking.try_state::<BlurLockState>()
                                    else {
                                        return false;
                                    };
                                    if !blur
                                        .blurred
                                        .load(std::sync::atomic::Ordering::Relaxed)
                                    {
                                        return false;
                                    }
                                    let _ = send_request("vaults.on_app_blur", "");
                                    log::info!(
                                        "[desktop] window blur (debounced) → on_app_blur fired"
                                    );
                                    true
                                },
                            )
                            .await;
                            // NOTE: we deliberately do NOT clear the per-vault
                            // token cache here. `on_app_blur` only locks vaults
                            // whose policy is `Immediately`; a `Minutes`/`Never`
                            // vault stays unlocked and must keep its token.
                            // Clearing all tokens would make unlocked vaults
                            // appear locked (empty token → daemon rejection).
                            // The daemon remains authoritative; the frontend's
                            // 30s heartbeat re-syncs per-vault presence.
                        });
                        *blur.pending.lock().unwrap() = Some(handle);
                    }
                }
                WindowEvent::Focused(true) => {
                    // Focus returned: cancel any pending blur-lock and clear
                    // the blurred flag.
                    if let Some(blur) = window.app_handle().try_state::<BlurLockState>() {
                        blur.blurred
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                        if let Some(handle) = blur.pending.lock().unwrap().take() {
                            handle.abort();
                        }
                    }
                }
                _ => {}
            }
        })
        .invoke_handler(tauri::generate_handler![
            daemon_request,
            daemon_status,
            show_window,
            update_tray_icon,
            save_recovery_phrase,
            clipboard_mark_concealed,
            get_desktop_prefs,
            set_tray_only,
            get_render_state,
            set_compatible_rendering
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            // macOS: clicking the dock icon while the app is already running
            // (its window hidden to tray on close) fires RunEvent::Reopen.
            // Without this handler the app stays hidden — only the tray icon
            // restored it. Show + focus the main window on reopen. Showing an
            // already-visible window is a harmless no-op, so we don't gate on
            // `has_open_windows` (which stays true while the window exists but
            // is hidden, making it an unreliable visibility signal here).
            // RunEvent::Reopen exists only on macOS (cfg-gated upstream), so
            // the arm is gated to match; other platforms match nothing here.
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = event {
                if let Some(w) = app_handle.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            // Linux: clean exit clears the watchdog marker so the next
            // launch does not read this run as a rendering crash. A
            // SIGKILL / blank-window force-quit skips this and leaves the
            // marker behind (that is the signal).
            #[cfg(target_os = "linux")]
            if let tauri::RunEvent::Exit = event {
                render::clear_marker();
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = (app_handle, &event);
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    // D2: the audit's acceptance test — the deliberately CLI-only destructive
    // arm must be unreachable from the webview even though `vaults.detach`
    // itself is allowed (the safe detach is a UI feature).
    #[test]
    fn d2_destructive_detach_params_are_denied() {
        assert!(desktop_action_allowed("vaults.detach"));
        assert!(payload_has_desktop_forbidden_keys(
            "{\"slug\":\"a\",\"delete_from_disk\":true}"
        ));
        assert!(payload_has_desktop_forbidden_keys(
            "{\"slug\":\"a\",\"force\":true}"
        ));
        // The safe arm the UI actually sends passes.
        assert!(!payload_has_desktop_forbidden_keys("{\"slug\":\"a\"}"));
    }

    #[test]
    fn d2_key_check_is_not_a_substring_match() {
        // A cipher name containing the word must not trip the gate: the
        // forbidden string is a nested value, not a top-level key.
        assert!(!payload_has_desktop_forbidden_keys(
            "{\"name\":\"force field login\"}"
        ));
    }

    #[test]
    fn d2_non_object_payloads_pass_the_param_gate() {
        // folder.delete sends a raw id; trash.purge sends a bare number.
        assert!(!payload_has_desktop_forbidden_keys("abc-123"));
        assert!(!payload_has_desktop_forbidden_keys("\"0\""));
        assert!(!payload_has_desktop_forbidden_keys("0"));
    }

    #[test]
    fn d2_allowlist_blocks_unlisted_actions() {
        // Everything the UI calls is allowed…
        for a in ["vault.unlock", "vaults.detach", "sync.pull", "bridge.pair_start"] {
            assert!(desktop_action_allowed(a), "{a} should be allowed");
        }
        // …and host-level routes the UI never calls are not. `ping` goes
        // through daemon_status, not daemon_request; passkey ceremony
        // routes have no desktop caller yet; provider connect PAT flows are
        // CLI/NMH territory.
        for a in ["ping", "vaults.set_active", "passkey.finish_register", "provider.connect_pat"] {
            assert!(!desktop_action_allowed(a), "{a} should be denied");
        }
    }
}
