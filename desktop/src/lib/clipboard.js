/**
 * L1 fix: shared clipboard utility with auto-clear.
 *
 * All components that copy secrets should use this instead of calling
 * `navigator.clipboard.writeText()` directly. The auto-clear timer
 * limits how long the secret lives in the OS clipboard/clipboard
 * history. Only clears if the clipboard still contains our value
 * (avoids stomping on a user-initiated copy of something else).
 *
 * @param {string} value - the secret to copy
 * @param {object} [opts]
 * @param {number} [opts.autoClearMs=30000] - ms before auto-clearing (0 = disable)
 * @returns {Promise<void>}
 */
export async function copyToClipboard(value, opts = {}) {
  const autoClearMs = opts.autoClearMs ?? 30000;
  await navigator.clipboard.writeText(value);

  if (autoClearMs > 0) {
    setTimeout(async () => {
      try {
        const current = await navigator.clipboard.readText();
        if (current === value) {
          await navigator.clipboard.writeText("");
        }
      } catch {
        // Clipboard read may be denied by browser permissions.
        // Best-effort; if we can't read, we won't try to clear.
      }
    }, autoClearMs);
  }
}
