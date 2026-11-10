//! Linux tray as a pure StatusNotifierItem via ksni.
//!
//! GNOME ships no SNI host at all, so tray visibility there needs a shell
//! extension (AppIndicator Support, Tray Icons Reloaded, Tray Icons, or the
//! newer Status Icons). All of them speak the same StatusNotifierItem
//! protocol this module exports. When no host is up — GNOME without an
//! extension — the service stays alive watching for one, and the frontend is
//! told once per session so it can point the user at those extensions
//! instead of the app silently having no tray.

use std::sync::atomic::{AtomicBool, Ordering};

use tauri::{AppHandle, Emitter, Manager};

use crate::MAIN_TRAY_ID;

/// Event emitted to the frontend when no StatusNotifier host is reachable.
/// The frontend shows the install-an-extension guidance once per session.
pub(crate) const TRAY_HOST_OFFLINE_EVENT: &str = "tray://host-offline";

/// PNG bytes must become ARGB32 rows (per-pixel A,R,G,B in memory, straight
/// alpha) for the SNI IconPixmap property.
fn rgba_to_argb32(rgba: &[u8]) -> Vec<u8> {
    let px = rgba.len() / 4;
    let mut out = Vec::with_capacity(px * 4);
    for p in 0..px {
        let r = rgba[p * 4];
        let g = rgba[p * 4 + 1];
        let b = rgba[p * 4 + 2];
        let a = rgba[p * 4 + 3];
        out.extend_from_slice(&[a, r, g, b]);
    }
    out
}

fn icon_from_png(png: &[u8]) -> ksni::Icon {
    let img = tauri::image::Image::from_bytes(png).expect("bundled tray icon decodes");
    ksni::Icon {
        width: img.width() as i32,
        height: img.height() as i32,
        data: rgba_to_argb32(img.rgba()),
    }
}

fn show_main_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// XDG_CURRENT_DESKTOP is a colon-separated list; GNOME variants all carry a
/// "gnome" component (ubuntu:GNOME, gnome-flashback:GNOME, ...).
fn desktop_is_gnome(xdg_current_desktop: Option<&str>) -> bool {
    xdg_current_desktop
        .map(|d| d.split(':').any(|p| p.eq_ignore_ascii_case("gnome")))
        .unwrap_or(false)
}

pub(crate) struct LinuxTray {
    app: AppHandle,
    /// The theme listener flips this; hosts re-read IconPixmap on update.
    dark: bool,
    icon_light: ksni::Icon,
    icon_dark: ksni::Icon,
    /// watcher_offline can fire on every gnome-shell restart; the frontend
    /// toasts only the first one per session.
    host_offline_noted: AtomicBool,
}

impl LinuxTray {
    pub(crate) fn new(app: AppHandle, dark: bool) -> Self {
        Self {
            dark,
            icon_light: icon_from_png(include_bytes!("../icons/tray_white.png")),
            icon_dark: icon_from_png(include_bytes!("../icons/tray_black.png")),
            app,
            host_offline_noted: AtomicBool::new(false),
        }
    }

    pub(crate) fn set_dark(&mut self, dark: bool) {
        self.dark = dark;
    }
}

impl ksni::Tray for LinuxTray {
    fn id(&self) -> String {
        MAIN_TRAY_ID.to_string()
    }

    fn title(&self) -> String {
        "Baluard".into()
    }

    fn status(&self) -> ksni::Status {
        ksni::Status::Active
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        vec![if self.dark {
            self.icon_dark.clone()
        } else {
            self.icon_light.clone()
        }]
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            icon_name: String::new(),
            icon_pixmap: Vec::new(),
            title: "Baluard".into(),
            description: "Baluard is running in the background".into(),
        }
    }

    // SNI Activate is the left click on every host implementation we target.
    fn activate(&mut self, _x: i32, _y: i32) {
        show_main_window(&self.app);
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        vec![
            ksni::menu::StandardItem {
                label: "Show".into(),
                activate: Box::new(|t: &mut Self| show_main_window(&t.app)),
                ..Default::default()
            }
            .into(),
            ksni::MenuItem::Separator,
            ksni::menu::StandardItem {
                label: "Quit".into(),
                activate: Box::new(|t: &mut Self| t.app.exit(0)),
                ..Default::default()
            }
            .into(),
        ]
    }

    fn watcher_offline(&self, reason: ksni::OfflineReason) -> bool {
        // Keep the service alive: installing a tray extension takes effect
        // the moment its host appears, without restarting Baluard.
        if !self.host_offline_noted.swap(true, Ordering::Relaxed) {
            let gnome = desktop_is_gnome(std::env::var("XDG_CURRENT_DESKTOP").ok().as_deref());
            if gnome {
                log::debug!("[desktop] tray watcher offline: {reason:?}");
                let _ = self.app.emit(TRAY_HOST_OFFLINE_EVENT, ());
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::rgba_to_argb32;

    #[test]
    fn rgba_maps_to_argb_byte_order() {
        // One red opaque pixel, one transparent white pixel.
        let rgba = [255u8, 0, 0, 255, 255, 255, 255, 0];
        assert_eq!(
            rgba_to_argb32(&rgba),
            vec![255, 255, 0, 0, 0, 255, 255, 255]
        );
    }

    #[test]
    fn gnome_detection_matches_component_paths() {
        assert!(super::desktop_is_gnome(Some("GNOME")));
        assert!(super::desktop_is_gnome(Some("ubuntu:GNOME")));
        assert!(super::desktop_is_gnome(Some("gnome-flashback:GNOME")));
        assert!(!super::desktop_is_gnome(Some("KDE")));
        assert!(!super::desktop_is_gnome(None));
    }
}
