import { createSignal, onSettled, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { useI18n } from "../i18n/index.jsx";
import { updaterStatus } from "../lib/update.js";
import IconInfo from "./IconInfo.jsx";

/**
 * The Settings "About" pane: the installed version and the product tagline,
 * mirroring mobile's About card. The version comes from the updater
 * command's single manifest source so it can never drift from what runs.
 */
export default function AboutTab() {
  const { t } = useI18n();
  const [version, setVersion] = createSignal("");
  const [daemonVersion, setDaemonVersion] = createSignal("");

  // Sync callback: an async onSettled returns a Promise, which Solid reads
  // as an invalid cleanup value.
  onSettled(() => {
    void (async () => {
      try {
        const status = await updaterStatus();
        if (status?.version) setVersion(status.version);
      } catch {
        // No version line rather than a wrong one.
      }
      // The running daemon's build, for bug reports: the support docs ask
      // for daemon.log and the daemon version together.
      try {
        const v = await invoke("daemon_version");
        if (v?.version) setDaemonVersion(v.version);
      } catch {
        // Same: absent beats wrong.
      }
    })();
  });

  return (
    <div class="space-y-4">
      <div>
        <p class="text-xs font-bold text-[var(--color-text)]">{t("settings.aboutTitle")}</p>
        <div class="mt-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)]/30 p-6 flex items-center gap-4">
          <div class="shrink-0 w-12 h-12 rounded-lg bg-[var(--color-primary)]/10 flex items-center justify-center">
            <IconInfo class="w-6 h-6 text-[var(--color-primary)]" />
          </div>
          <div class="min-w-0">
            <p data-testid="about-version" class="text-lg font-bold text-[var(--color-text)] truncate">
              <Show when={version()} fallback="Baluard">
                Baluard v{version()}
              </Show>
            </p>
            <Show when={daemonVersion()}>
              <p data-testid="about-daemon" class="text-xs text-[var(--color-muted)] truncate">
                {t("settings.aboutDaemon")} v{daemonVersion()}
              </p>
            </Show>
            <p class="text-sm text-[var(--color-muted)] truncate">{t("settings.aboutSubtitle")}</p>
          </div>
        </div>
      </div>
    </div>
  );
}
