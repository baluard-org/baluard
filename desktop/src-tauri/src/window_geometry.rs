//! Persist and clamp the main window's on-screen rectangle.
//!
//! Nothing else in the app manages geometry, so a window dragged partly
//! off-screen (or parked under a panel) stays there across restarts. The
//! saved rect is clamped into the monitor that contains its center before
//! reuse, so a window saved on a disconnected screen still comes back
//! reachable. Wayland compositors ignore client-side positioning, so the
//! clamp is advisory there by platform contract; it fully applies on X11,
//! macOS, and Windows.
//!
//! Coordinate contract (tao is asymmetric per platform): `x`/`y` is the
//! origin as consumed by `set_position` — the frame origin on macOS and
//! Windows, the client origin on Linux (GTK `move_`); `width`/`height` is
//! the CLIENT size everywhere, matched by `set_size`. Saving and restoring
//! must use matched pairs or the window drifts (grows by the title bar on
//! Linux) every close/relaunch cycle.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub struct SavedGeometry {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

/// Clamp a window rect so it fits inside the monitor rect. A saved size
/// larger than the monitor collapses to the monitor size; the position
/// then pins to the monitor origin. Degenerate monitors (zero extent)
/// keep the saved values untouched.
pub fn clamp_geometry(
    mon_x: i32,
    mon_y: i32,
    mon_w: u32,
    mon_h: u32,
    g: SavedGeometry,
) -> SavedGeometry {
    if mon_w == 0 || mon_h == 0 {
        return g;
    }
    let width = g.width.min(mon_w).max(1);
    let height = g.height.min(mon_h).max(1);
    let max_x = mon_x + (mon_w - width) as i32;
    let max_y = mon_y + (mon_h - height) as i32;
    SavedGeometry {
        width,
        height,
        x: g.x.clamp(mon_x, max_x),
        y: g.y.clamp(mon_y, max_y),
    }
}

/// Parse a persisted geometry document. Rejects zero or negative extents
/// so a corrupted file can never shrink the window to nothing.
pub fn parse_saved(raw: &str) -> Option<SavedGeometry> {
    let g: SavedGeometry = serde_json::from_str(raw).ok()?;
    (g.width > 0 && g.height > 0).then_some(g)
}

/// Index of the monitor whose bounds contain the saved rect's center
/// point — the closest statement of "which screen was this window on".
/// None when no monitor contains it (disconnected setup); callers then
/// fall back to the current monitor so the clamp still lands safely.
pub fn monitor_index_for_center(
    monitors: &[(i32, i32, u32, u32)],
    g: &SavedGeometry,
) -> Option<usize> {
    let cx = g.x + g.width as i32 / 2;
    let cy = g.y + g.height as i32 / 2;
    monitors.iter().position(|&(mx, my, mw, mh)| {
        mw > 0 && mh > 0 && cx >= mx && cx < mx + mw as i32 && cy >= my && cy < my + mh as i32
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MON: (i32, i32, u32, u32) = (0, 0, 1920, 1080);

    fn geo(x: i32, y: i32, w: u32, h: u32) -> SavedGeometry {
        SavedGeometry {
            x,
            y,
            width: w,
            height: h,
        }
    }

    #[test]
    fn inside_the_monitor_is_untouched() {
        let g = geo(100, 100, 1200, 700);
        assert_eq!(clamp_geometry(MON.0, MON.1, MON.2, MON.3, g), g);
    }

    #[test]
    fn off_screen_right_and_bottom_are_pulled_back() {
        let g = clamp_geometry(MON.0, MON.1, MON.2, MON.3, geo(5000, 4000, 1200, 700));
        assert_eq!((g.x, g.y), (1920 - 1200, 1080 - 700));
    }

    #[test]
    fn negative_positions_clamp_to_the_origin() {
        let g = clamp_geometry(MON.0, MON.1, MON.2, MON.3, geo(-900, -500, 1200, 700));
        assert_eq!((g.x, g.y), (0, 0));
    }

    #[test]
    fn oversized_windows_collapse_to_the_monitor() {
        let g = clamp_geometry(MON.0, MON.1, MON.2, MON.3, geo(-50, -50, 4000, 3000));
        assert_eq!((g.width, g.height, g.x, g.y), (1920, 1080, 0, 0));
    }

    #[test]
    fn secondary_monitor_offsets_are_respected() {
        // Monitor to the right of the primary: x range [1920, 4800].
        let g = clamp_geometry(1920, 0, 2880, 1080, geo(-100, 200, 1200, 700));
        assert_eq!(g.x, 1920);
        assert_eq!(g.y, 200);
    }

    #[test]
    fn degenerate_monitor_keeps_the_saved_values() {
        let g = geo(50, 60, 800, 600);
        assert_eq!(clamp_geometry(0, 0, 0, 0, g), g);
    }

    #[test]
    fn parse_rejects_garbage_and_zero_extents() {
        assert!(parse_saved("not json").is_none());
        assert!(parse_saved(r#"{"x":0,"y":0,"width":0,"height":600}"#).is_none());
        let parsed = parse_saved(r#"{"x":10,"y":20,"width":1200,"height":700}"#).unwrap();
        assert_eq!(parsed, geo(10, 20, 1200, 700),);
    }

    #[test]
    fn monitor_center_picks_the_containing_screen() {
        let monitors = [(0, 0, 1920, 1080), (1920, 0, 2880, 1080)];
        assert_eq!(
            monitor_index_for_center(&monitors, &geo(2400, 300, 1200, 700)),
            Some(1)
        );
        assert_eq!(
            monitor_index_for_center(&monitors, &geo(100, 300, 1200, 700)),
            Some(0)
        );
    }

    #[test]
    fn monitor_center_off_every_screen_is_none() {
        let monitors = [(0, 0, 1920, 1080)];
        // Center at (-5000, -5000): a screen that no longer exists.
        assert_eq!(
            monitor_index_for_center(&monitors, &geo(-5600, -5350, 1200, 700)),
            None
        );
    }

    #[test]
    fn monitor_degenerate_entries_are_skipped() {
        let monitors = [(0, 0, 0, 0), (1920, 0, 2880, 1080)];
        assert_eq!(
            monitor_index_for_center(&monitors, &geo(2400, 300, 1200, 700)),
            Some(1)
        );
    }
}
