import { IconMonitor } from "./Icon.jsx";
import { onMount, Show, For } from "solid-js";
import { useVault } from "../context/VaultContext.jsx";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";

export default function DeviceFleetPanel() {
  const vault = useVault();
  const { t } = useI18n();

  onMount(() => {
    vault.refreshDeviceFleet?.();
  });

  const fleet = () => vault.deviceFleet() || [];

  function getStatusBadge(lastPush) {
    if (!lastPush) return { label: t("devices.statusUnknown"), color: "bg-slate-600", textColor: "text-slate-300" };
    const diff = Date.now() - new Date(lastPush).getTime();
    const days = diff / (1000 * 60 * 60 * 24);
    if (days < 7) return { label: t("devices.statusActive"), color: "bg-emerald-600", textColor: "text-emerald-200" };
    if (days < 30) return { label: t("devices.statusIdle"), color: "bg-yellow-600", textColor: "text-yellow-200" };
    if (days < 90) return { label: t("devices.statusStale"), color: "bg-orange-600", textColor: "text-orange-200" };
    return { label: t("devices.statusDormant"), color: "bg-red-600", textColor: "text-red-200" };
  }

  async function revokeDevice(deviceId, deviceName) {
    if (!confirm(t("devices.revokeConfirm", { name: deviceName }))) return;
    try {
      await daemon("device.revoke", deviceId);
      vault.setRevokeWarning({ name: deviceName });
      // Refresh fleet to reflect revocation
      vault.refreshDeviceFleet();
    } catch (e) {
      alert(t("devices.revocationFailed", { error: e, id: deviceId }));
    }
  }

  return (
    <div class="flex-1 overflow-y-auto p-8 space-y-6">
      <h2 class="text-xl font-extrabold text-[var(--color-text)]">{t("devices.title")}</h2>
      <p class="text-xs text-[var(--color-muted)]">{t("devices.subtitle")}</p>

      <Show when={vault.revokeWarning()}>
        <div class="p-4 rounded-xl bg-red-950/30 border border-red-900/30 space-y-3">
          <h4 class="text-xs font-bold text-red-400 uppercase tracking-wider">{t("devices.revokedTitle")}</h4>
          <p class="text-xs text-red-300 leading-relaxed">
            {t("devices.revokedDesc", { name: vault.revokeWarning().name })}
          </p>
          <ol class="text-xs text-red-300 list-decimal list-inside space-y-1">
            <li>{t("devices.revokeStep1")}</li>
            <li>{t("devices.revokeStep2")}</li>
            <li>{t("devices.revokeStep3")}</li>
          </ol>
          <label class="flex items-center gap-2 mt-3 cursor-pointer">
            <input type="checkbox" onChange={(e) => { if (e.target.checked) vault.setRevokeWarning(null); }} class="accent-red-500" />
            <span class="text-xs text-red-300">{t("devices.revokeRotatedLabel")}</span>
          </label>
        </div>
      </Show>

      <Show when={fleet().length === 0}>
        <div class="text-center py-12 text-[var(--color-muted)]">
          <p class="text-sm">{t("devices.emptyTitle")}</p>
          <p class="text-xs mt-2">{t("devices.emptySubtitle")}</p>
        </div>
      </Show>

      <div class="space-y-3">
        <For each={fleet()}>
          {(device) => {
            const badge = getStatusBadge(device.last_push);
            return (
              <div class="p-4 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] hover:border-[var(--color-primary)] transition-all space-y-3">
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] flex items-center justify-center">
                      <IconMonitor class="w-5 h-5 text-[var(--color-primary)]" />
                    </div>
                    <div>
                      <p class="text-sm font-bold text-[var(--color-text)]">{device.name} <Show when={device.id === vault.selfDeviceId()}><span class="text-[10px] font-normal text-[var(--color-primary)] bg-[var(--color-primary)]/10 px-1.5 py-0.5 rounded-md ml-1">{t("devices.thisDevice")}</span></Show></p>
                      <p class="text-xs text-[var(--color-muted)] font-mono">{device.id?.substring(0, 8)}...</p>
                    </div>
                  </div>
                  <span class={`px-2 py-1 rounded-lg text-xs font-bold ${badge.color} ${badge.textColor}`}>{badge.label}</span>
                </div>
                <div class="grid grid-cols-3 gap-3 text-xs">
                  <div>
                    <p class="text-[var(--color-muted)]">{t("devices.lastSync")}</p>
                    <p class="text-[var(--color-text)] font-medium">{device.last_push ? new Date(device.last_push).toLocaleDateString() : t("devices.never")}</p>
                  </div>
                  <div>
                    <p class="text-[var(--color-muted)]">{t("devices.epoch")}</p>
                    <p class="text-[var(--color-text)] font-medium">{device.epoch ?? "-"}</p>
                  </div>
                  <div>
                    <p class="text-[var(--color-muted)]">{t("devices.lastCommit")}</p>
                    <p class="text-[var(--color-text)] font-mono">{device.last_commit?.substring(0, 7) || "-"}</p>
                  </div>
                </div>
                <div class="flex justify-end pt-1">
                  <Show when={vault.selfDeviceId() && device.id !== vault.selfDeviceId()}>
                    <button
                      onClick={() => revokeDevice(device.id, device.name)}
                      class="px-3 py-1.5 rounded-lg text-xs font-bold bg-red-950/20 text-red-400 border border-red-900/30 hover:bg-red-950/40 transition-all cursor-pointer"
                    >
                      {t("devices.revoke")}
                    </button>
                  </Show>
                </div>
              </div>
            );
          }}
        </For>
      </div>
    </div>
  );
}
