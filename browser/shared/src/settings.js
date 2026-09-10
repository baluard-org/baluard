// Extension settings (chrome.storage.local). No secrets, ever.
//
// Shape: { inlineAutofill: boolean, copyTotp: boolean, clipboardClearSeconds: number }
// Default ON for parity with 1Password/Bitwarden: the inline menu never
// auto-fills (icon click + entry click = two user gestures) and shows only
// entry names/usernames (same metadata the toolbar badge already queries).
// copyTotp: after a user-initiated fill, the fresh code is copied to the
// clipboard (cleared per clipboardClearSeconds) for the next 2FA page.
// clipboardClearSeconds applies to everything the extension copies
// (passwords, usernames, codes); 0 disables auto-clear. Users who prefer
// zero page surface turn it off (Decision 9 posture).

const SETTINGS_KEY = "settings";

export const DEFAULT_SETTINGS = {
  inlineAutofill: true,
  copyTotp: true,
  clipboardClearSeconds: 60,
};

// The only clipboard auto-clear choices the UI offers (seconds; 0 = never).
// Exported for tests + UI option lists.
export const CLEAR_SECONDS_CHOICES = [0, 10, 30, 60, 120];

// Coerce a stored value into a valid choice; anything else falls back to
// the 60s default. Accepts numeric strings (storage round-trips). Null and
// undefined fail toward the default too: a corrupted value must never
// disable the clear (that would be the "never" choice by accident).
export function normalizeClearSeconds(v) {
  if (v === null || v === undefined || v === "") return 60;
  const n = Number(v);
  return CLEAR_SECONDS_CHOICES.includes(n) ? n : 60;
}

export async function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get([SETTINGS_KEY], (res) => {
      const stored = res && res[SETTINGS_KEY];
      resolve({ ...DEFAULT_SETTINGS, ...(stored || {}) });
    });
  });
}

// Merge `patch` into the stored settings and return the new full settings.
export async function updateSettings(patch) {
  const current = await getSettings();
  const next = { ...current, ...patch };
  await new Promise((resolve) => {
    chrome.storage.local.set({ [SETTINGS_KEY]: next }, () => resolve());
  });
  return next;
}
