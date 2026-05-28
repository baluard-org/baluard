//! IDtty desktop Tauri backend.
//!
//! Proxies vault operations to idtty-daemon via Protobuf-over-Unix-socket.

use prost::Message;
use serde::Serialize;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use tauri::menu::MenuBuilder;
use tauri::tray::TrayIconBuilder;
use tauri::Manager;

/// Generated Protobuf types
mod proto {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/idtty.auth.rs"));
}

use proto::{GatewayRequest, GatewayResponse};

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

// ── App entry ──

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            // System tray with Show/Quit
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
                .show_menu_on_left_click(true)
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
                .build(app)?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![daemon_request])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
