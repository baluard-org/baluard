// Extension settings (chrome.storage.local). No secrets, ever.
//
// Shape: { inlineAutofill: boolean }
// Default ON for parity with 1Password/Bitwarden: the inline menu never
// auto-fills (icon click + entry click = two user gestures) and shows only
// entry names/usernames (same metadata the toolbar badge already queries).
// Users who prefer zero page surface turn it off (Decision 9 posture).

const SETTINGS_KEY = "settings";

export const DEFAULT_SETTINGS = { inlineAutofill: true };

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
