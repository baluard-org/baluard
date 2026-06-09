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
    send_request_with_token(action, payload, "").map(|(data, _)| data)
}

/// Send a Protobuf request with session token. Returns (payload, optional_new_token).
#[cfg(unix)]
fn send_request_with_token(action: &str, payload: &str, token: &str) -> Result<(String, Option<String>), String> {
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
fn send_request_with_token(_action: &str, _payload: &str, _token: &str) -> Result<(String, Option<String>), String> {
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
    token: State<SessionToken>,
) -> DaemonResponse {
    log::debug!("[desktop] -> action={action} payload_len={}", payload.len());

    // Inject stored session token into request
    let stored_token = token.0.lock().unwrap()
        .as_ref().map(|z| z.as_str().to_owned()).unwrap_or_default();

    match send_request_with_token(&action, &payload, &stored_token) {
        Ok((data, new_token)) => {
            log::debug!("[desktop] <- action={action} success=true payload_len={}", data.len());
            // On lock, clear the session token
            if action == "vault.lock" {
                *token.0.lock().unwrap() = None;
            } else if let Some(t) = new_token {
                // Store token returned by unlock/create
                *token.0.lock().unwrap() = Some(zeroize::Zeroizing::new(t));
            }
            DaemonResponse {
                success: true,
                payload: data,
                error: String::new(),
            }
        }
        Err(ref e) => {
            log::warn!("[desktop] <- action={action} error={e}");
            // Clear stale token on session/auth errors so next request
            // doesn't keep sending an invalid token
            if e.contains("session token") || e.contains("locked") || e.contains("Vault is") {
                *token.0.lock().unwrap() = None;
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

/// Stored session token obtained from daemon at unlock/create.
/// Zeroizes on drop for consistent security posture with the rest of the codebase.
struct SessionToken(Mutex<Option<zeroize::Zeroizing<String>>>);

// ── App entry ──

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_biometry::init())
        .manage(Mutex::new(None::<Daemon>))
        .manage(SessionToken(Mutex::new(None::<zeroize::Zeroizing<String>>)))
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
                // Default vault path lives alongside the socket.
                let socket_dir = socket.parent()
                    .expect("socket path has no parent").to_path_buf();
                let vault_path = socket_dir.join("vault");
                log::info!("Starting daemon with --vault-path {} --socket {}",
                    vault_path.display(), socket.display());

                    let sidecar_command = app.shell().sidecar("baluard-daemon")
                        .map_err(|e| format!("Sidecar not found: {e}"))?;

                    let sidecar_command = sidecar_command
                        .args(["--vault-path", vault_path.to_str().unwrap_or("."),
                               "--socket", default_socket_path().to_str().unwrap_or("/tmp/baluard.sock")]);

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
        // Close → hide to tray instead of quitting
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![daemon_request, daemon_status])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
