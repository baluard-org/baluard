//! Baluard desktop Tauri backend.
//!
//! - Starts baluard-daemon on launch, stops on quit
//! - Window close hides to system tray
//! - Proxies vault operations via Protobuf-over-Unix-socket

use prost::Message;
use serde::Serialize;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use tauri::menu::MenuBuilder;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Manager, State, WindowEvent};
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

#[derive(Serialize)]
struct DaemonResponse {
    success: bool,
    payload: String,
    error: String,
}

#[tauri::command]
fn daemon_request(
    action: String,
    payload: String,
    slug: Option<String>,
    store: State<Mutex<SessionStore>>,
) -> DaemonResponse {
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

    match send_request_with_token(&action, &payload, &stored_token, slug.as_deref().unwrap_or("")) {
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
                if action == "vaults.switch" || action == "vaults.set_active" {
                    if let Some(a) = serde_json::from_str::<serde_json::Value>(&data)
                        .ok()
                        .and_then(|v| v["active"].as_str().map(String::from))
                    {
                        st.active_slug = Some(a);
                    }
                }
            }
            DaemonResponse {
                success: true,
                payload: data,
                error: String::new(),
            }
        }
        Err(ref e) => {
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
                error: e.clone(),
            }
        },
    }
}

/// Check if daemon is reachable via ping (avoids phantom connections)
#[tauri::command]
fn daemon_status() -> bool {
    send_request("ping", "").is_ok()
}

/// Lock every currently-unlocked vault (Phase 6 defensive primitive).
///
/// Fired by the desktop on screen-lock / system sleep / app-resign-active
/// (window blur) so a device becoming unattended caps multi-vault key
/// exposure immediately instead of waiting for each vault's idle timer.
/// Clears the per-vault session token map on success; the daemon zeroizes
/// all key material. Non-blocking on daemon errors (a down daemon has no
/// keys to lock).
#[tauri::command]
fn lock_all_vaults(store: State<Mutex<SessionStore>>) -> bool {
    log::info!("[desktop] system event → lock_all_vaults");
    // Clear our token cache first so the frontend treats every vault as
    // locked even if the daemon RPC is slow.
    let mut st = store.lock().unwrap();
    st.tokens.clear();
    st.active_slug = None;
    drop(st);
    match send_request("vaults.lock_all", "") {
        Ok(payload) => {
            log::info!("[desktop] lock_all succeeded: {payload}");
            true
        }
        // Daemon unreachable or returned a daemon-level error string: a
        // down daemon has no keys to lock, and we already cleared the token
        // cache above so the frontend state is consistent.
        Err(e) => {
            log::warn!("[desktop] lock_all RPC failed: {e}");
            false
        }
    }
}

/// Reveal the main window once the frontend has finished loading and rendering,
/// avoiding the white flash.
#[tauri::command]
fn show_window(window: tauri::WebviewWindow) {
    let _ = window.show();
    let _ = window.set_focus();
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

// ── App entry ──

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
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

            let _tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
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
            lock_all_vaults,
            show_window
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
