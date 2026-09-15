// Provider display-name helper (code-health R11).
// Single source for provider → i18n label resolution; the desktop locales
// carry the branded names under sync.provider*.
const LABEL_KEYS = {
  github: "providerGitHub",
  gitlab: "providerGitLab",
  codeberg: "providerCodeberg",
};

export function providerLabel(t, key) {
  if (!key) return "";
  const k = LABEL_KEYS[key];
  // Unknown provider: fall back to a title-cased raw key so new backends
  // never render an untranslated key path.
  return k ? t(`sync.${k}`) : key.charAt(0).toUpperCase() + key.slice(1);
}
