//! IDtty desktop Tauri backend.
//!
//! - Starts idtty-daemon on launch, stops on quit
//! - Window close hides to system tray
//! - Proxies vault operations via Protobuf-over-Unix-socket

use prost::Message;
use serde::Serialize;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::menu::MenuBuilder;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Manager, WindowEvent};

/// Generated Protobuf types
mod proto {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/idtty.auth.rs"));
}

use proto::{GatewayRequest, GatewayResponse};

// ── Daemon child process (shared across setup + on_window_event) ──

struct Daemon(std::process::Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        // SIGTERM the daemon; let it clean up gracefully
        if let Err(e) = self.0.kill() {
            log::warn!("Failed to kill daemon: {e}");
        }
        let _ = self.0.wait();
    }
}

// ── Socket path ──

fn default_socket_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
            let dir = PathBuf::from(xdg);
            if dir.is_dir() {
                return dir.join("idtty.sock");
            }
        }
        PathBuf::from("/tmp/idtty.sock")
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("idtty")
                .join("idtty.sock");
        }
        PathBuf::from("/tmp/idtty.sock")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        PathBuf::from("/tmp/idtty.sock")
    }
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

fn send_request(action: &str, payload: &str) -> Result<String, String> {
    let socket = default_socket_path();
    let mut stream = UnixStream::connect(&socket)
        .map_err(|e| format!("Cannot connect to daemon at {}: {}", socket.display(), e))?;

    let req = GatewayRequest {
        action: action.to_string(),
        payload: payload.to_string(),
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

    let mut buf = Vec::with_capacity(4096);
    stream
        .read_to_end(&mut buf)
        .map_err(|e| format!("Read: {e}"))?;
    if buf.is_empty() {
        return Err("Daemon closed connection".into());
    }

    let (resp_len, offset) = decode_varint(&buf)?;
    let end = offset + resp_len as usize;
    if end > buf.len() {
        return Err("Response truncated".into());
    }

    let resp = GatewayResponse::decode(&buf[offset..end]).map_err(|e| format!("Decode: {e}"))?;
    if resp.success {
        Ok(resp.payload)
    } else {
        Err(resp.error_message)
    }
}

// ── Tauri commands ──

#[derive(Serialize)]
struct DaemonResponse {
    success: bool,
    payload: String,
    error: String,
}

#[tauri::command]
fn daemon_request(action: String, payload: String) -> DaemonResponse {
    match send_request(&action, &payload) {
        Ok(data) => DaemonResponse {
            success: true,
            payload: data,
            error: String::new(),
        },
        Err(e) => DaemonResponse {
            success: false,
            payload: String::new(),
            error: e,
        },
    }
}

/// Check if daemon is reachable (for UI status display)
#[tauri::command]
fn daemon_status() -> bool {
    let socket = default_socket_path();
    UnixStream::connect(&socket).is_ok()
}

// ── App entry ──

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(Mutex::new(None::<Daemon>))
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                    .level(log::LevelFilter::Info)
                    .build(),
                )?;
            }

            // Start daemon if not already running
            let socket = default_socket_path();
            let daemon_running = socket.exists() && UnixStream::connect(&socket).is_ok();
            if !daemon_running {
                let child = std::process::Command::new("idtty-daemon")
                    .spawn()
                    .map_err(|e| format!("Failed to start daemon: {e}"))?;
                let state = app.state::<Mutex<Option<Daemon>>>();
                *state.lock().unwrap() = Some(Daemon(child));
                log::info!("Daemon started");
            } else {
                log::info!("Daemon already running");
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
                .tooltip("IDtty")
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
