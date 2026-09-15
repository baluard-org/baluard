// Vault timeout policy presets (mirrors baluard-core VaultTimeout).
//
// Single source of truth for the dropdown options shown in SettingsModal
// and the SetupScreen wizard. The wire token is the
// value sent to the daemon's `settings.set` (`{ vault_timeout: token }`).
//
// The OS power-event triggers from the Bitwarden reference UI (On system
// lock / sleep / idle) are intentionally absent: they require platform hooks
// that are not yet wired (see the TODO in desktop/src-tauri/src/lib.rs).
// Fail-closed over shipping options that silently do nothing.

/// Ordered preset list for the dropdown.
export const VAULT_TIMEOUT_PRESETS = [
  { token: "immediately", minutes: 0 },
  { token: "1m", minutes: 1 },
  { token: "5m", minutes: 5 },
  { token: "10m", minutes: 10 },
  { token: "15m", minutes: 15 },
  { token: "30m", minutes: 30 },
  { token: "1h", minutes: 60 },
  { token: "4h", minutes: 240 },
  { token: "on_app_exit", minutes: null },
];

/// Default selection when no setting is stored / value is unrecognized.
export const DEFAULT_VAULT_TIMEOUT = "15m";

/// Map a stored token to a known preset token, defaulting on miss.
/// Falls back to the default for anything unrecognized.
export function normalizeVaultTimeout(raw) {
  if (raw == null) return DEFAULT_VAULT_TIMEOUT;
  const s = String(raw).trim().toLowerCase();
  if (s === "") return DEFAULT_VAULT_TIMEOUT;
  // Known preset token?
  if (VAULT_TIMEOUT_PRESETS.some((p) => p.token === s)) return s;
  // Bare integer or "Nm"/"Nh" -> normalize to a preset token by minutes.
  const mins = parseMinutes(s);
  if (mins != null) return minutesToToken(mins);
  return DEFAULT_VAULT_TIMEOUT;
}

function parseMinutes(s) {
  if (/^\d+$/.test(s)) return parseInt(s, 10);
  const h = s.match(/^(\d+)h$/);
  if (h) return parseInt(h[1], 10) * 60;
  const m = s.match(/^(\d+)m$/);
  if (m) return parseInt(m[1], 10);
  return null;
}

/// Map an arbitrary minutes value to the closest preset token. If it matches
/// a preset exactly, use it; otherwise send the canonical "{n}m" token so the
/// user's explicit value is preserved (the daemon accepts arbitrary minutes).
function minutesToToken(mins) {
  const exact = VAULT_TIMEOUT_PRESETS.find((p) => p.minutes === mins);
  if (exact) return exact.token;
  return `${mins}m`;
}
