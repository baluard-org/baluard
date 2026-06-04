import { IconClock, IconUser } from "./Icon.jsx";
import { createSignal, Show } from "solid-js";
import { daemon } from "../lib/daemon.js";
import { buildBiometricEnablePayload } from "../lib/payload.js";

export default function AutoLockButton() {
  const [showSettings, setShowSettings] = createSignal(false);
  const [lockMinutes, setLockMinutes] = createSignal(15);
  const [saved, setSaved] = createSignal(false);

  async function saveAutoLock() {
    try {
      await daemon("settings.set", JSON.stringify({ auto_lock_minutes: lockMinutes() }));
      setSaved(true);
      setTimeout(() => setSaved(false), 1500);
    } catch (e) {
      // Non-critical
    }
  }

  async function loadSetting() {
    try {
      const data = JSON.parse(await daemon("settings.get"));
      if (data.auto_lock_minutes) setLockMinutes(data.auto_lock_minutes);
    } catch (e) {}
  }

  return (
    <div class="relative">
      <button
        onClick={() => { const next = !showSettings(); setShowSettings(next); if (next) loadSetting(); }}
        title="Auto-lock settings"
        class="p-2 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-[var(--color-muted)] hover:text-[var(--color-text)] transition-all cursor-pointer bg-[var(--color-card)]"
      >
        <IconClock class="w-4 h-4" />
      </button>
      <Show when={showSettings()}>
        <div class="absolute bottom-full right-0 mb-2 bg-[var(--color-card)] border border-[var(--color-border)] rounded-xl shadow-xl p-4 w-56 z-50">
          <div class="text-xs font-bold text-[var(--color-text)] mb-3">Auto-lock timeout</div>
          <div class="flex items-center gap-2 mb-3">
            <input
              type="number"
              min="1"
              max="120"
              value={lockMinutes()}
              onInput={e => setLockMinutes(parseInt(e.target.value) || 15)}
              class="w-20 px-3 py-2 rounded-lg bg-[var(--color-sidebar)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] text-center"
            />
            <span class="text-xs text-[var(--color-muted)]">minutes</span>
          </div>
          <button
            onClick={saveAutoLock}
            class="w-full py-1.5 rounded-lg bg-[var(--color-primary)] text-[var(--color-primary-text)] text-xs font-bold transition-all cursor-pointer"
          >
            {saved() ? "Saved" : "Save"}
          </button>
          <div class="text-[10px] text-[var(--color-muted)] mt-2">Vault locks after inactivity</div>

          {/* Biometric Unlock */}
          <div class="border-t border-[var(--color-border)] mt-3 pt-3">
            <div class="flex items-center justify-between">
              <div class="text-xs font-bold text-[var(--color-text)]">Quick Unlock</div>
              <button
                onClick={async () => {
                  try {
                    const status = JSON.parse(await daemon("vault.biometric_status"));
                    if (status.enabled) {
                      await daemon("vault.biometric_disable");
                    } else {
                      const password = prompt("Enter master password to enable Quick Unlock:");
                      if (password) {
                        await daemon("vault.biometric_enable", JSON.stringify(buildBiometricEnablePayload(password)));
                      }
                    }
                    loadSetting();
                  } catch (e) { alert(e.message); }
                }}
                class="p-1.5 rounded-lg transition-colors cursor-pointer text-[var(--color-muted)] hover:text-[var(--color-primary)]"
                title="Store unlock secret in OS keychain (biometric protected)"
              >
                <IconUser class="w-5 h-5" />
              </button>
            </div>
            <div class="text-[10px] text-[var(--color-muted)] mt-1">Unlock with biometric or device PIN</div>
          </div>
        </div>
      </Show>
    </div>
  );
}
