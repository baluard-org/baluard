//! Linux tray as a pure StatusNotifierItem via ksni.
//!
//! GNOME ships no SNI host at all, so tray visibility there needs a shell
//! extension (AppIndicator Support, Tray Icons Reloaded, Tray Icons, or the
//! newer Status Icons). All of them speak the same StatusNotifierItem
//! protocol this module exports. When no host is up — GNOME without an
//! extension — the service stays alive watching for one, and the frontend is
//! told once per session so it can point the user at those extensions
//! instead of the app silently having no tray.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tauri::{AppHandle, Emitter, Manager};

/// Event emitted to the frontend when no StatusNotifier host is reachable.
/// The frontend shows the install-an-extension guidance once per session.
pub(crate) const TRAY_HOST_OFFLINE_EVENT: &str = "tray://host-offline";

/// SNI Id hosts key per-item settings on; distinct from the tauri tray id.
const TRAY_ID: &str = "baluard";

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

/// Decode a bundled PNG into an SNI icon; None means the bytes are corrupt
/// (build-time asset damage) and the caller falls back + logs.
fn icon_from_png(png: &[u8]) -> Option<ksni::Icon> {
    let img = tauri::image::Image::from_bytes(png).ok()?;
    Some(ksni::Icon {
        width: img.width() as i32,
        height: img.height() as i32,
        data: rgba_to_argb32(img.rgba()),
    })
}

/// 1x1 fully transparent icon: keeps the item alive and honest if a bundled
/// glyph ever fails to decode, without panicking a spawned task silently.
fn blank_icon() -> ksni::Icon {
    ksni::Icon {
        width: 1,
        height: 1,
        data: vec![0, 0, 0, 0],
    }
}

/// "Dark" means the surrounding surface is dark, so the LIGHT glyph is the
/// visible one — same convention as the tauri tray path (isDark -> white).
fn pixmap_for_theme(dark: bool, light_glyph: &ksni::Icon, dark_glyph: &ksni::Icon) -> ksni::Icon {
    if dark {
        light_glyph.clone()
    } else {
        dark_glyph.clone()
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
    /// Shared with LinuxTrayState so the app can query current liveness.
    host_offline: Arc<AtomicBool>,
    /// The theme listener flips this; hosts re-read IconPixmap on update.
    dark: bool,
    icon_light_glyph: ksni::Icon,
    icon_dark_glyph: ksni::Icon,
    /// Guidance fires only for registration failures (no host at startup),
    /// never for transient watcher drops a tray-extension user sees on shell
    /// restarts.
    guidance_emitted: AtomicBool,
}

impl LinuxTray {
    pub(crate) fn new(app: AppHandle, dark: bool, host_offline: Arc<AtomicBool>) -> Self {
        let icon_light_glyph = icon_from_png(include_bytes!("../icons/tray_white.png"))
            .unwrap_or_else(|| {
                log::error!("[desktop] tray_white.png failed to decode");
                blank_icon()
            });
        let icon_dark_glyph = icon_from_png(include_bytes!("../icons/tray_black.png"))
            .unwrap_or_else(|| {
                log::error!("[desktop] tray_black.png failed to decode");
                blank_icon()
            });
        Self {
            dark,
            icon_light_glyph,
            icon_dark_glyph,
            app,
            host_offline,
            guidance_emitted: AtomicBool::new(false),
        }
    }

    pub(crate) fn set_dark(&mut self, dark: bool) {
        self.dark = dark;
    }
}

impl ksni::Tray for LinuxTray {
    fn id(&self) -> String {
        TRAY_ID.to_string()
    }

    fn title(&self) -> String {
        "Baluard".into()
    }

    fn status(&self) -> ksni::Status {
        ksni::Status::Active
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        vec![pixmap_for_theme(
            self.dark,
            &self.icon_light_glyph,
            &self.icon_dark_glyph,
        )]
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

    fn watcher_online(&self) {
        self.host_offline.store(false, Ordering::Relaxed);
    }

    fn watcher_offline(&self, reason: ksni::OfflineReason) -> bool {
        self.host_offline.store(true, Ordering::Relaxed);
        // Registration failure = no host when we came up: the target user for
        // the guidance. Transient drops (OfflineReason::No, e.g. a gnome-shell
        // restart under an existing extension) must not nag.
        let registration_failed = matches!(reason, ksni::OfflineReason::Error(_));
        if registration_failed
            && !self.guidance_emitted.swap(true, Ordering::Relaxed)
            && desktop_is_gnome(std::env::var("XDG_CURRENT_DESKTOP").ok().as_deref())
        {
            log::debug!("[desktop] tray watcher offline: {reason:?}");
            let _ = self.app.emit(TRAY_HOST_OFFLINE_EVENT, ());
        }
        // Keep the service alive: installing a tray extension takes effect
        // the moment its host appears, without restarting Baluard.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{blank_icon, desktop_is_gnome, pixmap_for_theme, rgba_to_argb32};

    fn icon_with(marker: u8) -> ksni::Icon {
        ksni::Icon {
            width: 1,
            height: 1,
            data: vec![255, marker, marker, marker],
        }
    }

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
    fn dark_theme_selects_the_light_glyph() {
        let light = icon_with(0x11);
        let dark = icon_with(0x22);
        assert_eq!(pixmap_for_theme(true, &light, &dark).data, light.data);
        assert_eq!(pixmap_for_theme(false, &light, &dark).data, dark.data);
    }

    #[test]
    fn gnome_detection_matches_component_paths() {
        assert!(desktop_is_gnome(Some("GNOME")));
        assert!(desktop_is_gnome(Some("ubuntu:GNOME")));
        assert!(desktop_is_gnome(Some("gnome-flashback:GNOME")));
        assert!(!desktop_is_gnome(Some("KDE")));
        assert!(!desktop_is_gnome(None));
    }

    #[test]
    fn blank_icon_is_transparent_single_pixel() {
        let b = blank_icon();
        assert_eq!((b.width, b.height), (1, 1));
        assert_eq!(b.data, vec![0, 0, 0, 0]);
    }
}
