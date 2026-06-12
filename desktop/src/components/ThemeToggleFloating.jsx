import { Show } from "solid-js";
import { IconMonitor, IconMoon, IconSun } from "./Icon.jsx";
import { theme, setTheme } from "../context/themeSignal.js";
import { useI18n } from "../i18n/index.jsx";

const CYCLE = ["dark", "light", "system"];

export default function ThemeToggleFloating() {
  const { t } = useI18n();

  return (
    <button
      onClick={() => {
        const idx = CYCLE.indexOf(theme());
        setTheme(CYCLE[(idx + 1) % CYCLE.length]);
      }}
      class="theme-toggle-floating absolute top-4 right-4 p-2 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-[var(--color-muted)] hover:text-[var(--color-text)] transition-all cursor-pointer bg-[var(--color-card)] z-10"
      title={t("settings.toggleTheme")}
      aria-label={t("settings.toggleTheme")}
    >
      <Show when={theme() === "system"} fallback={
        <Show when={theme() === "dark"} fallback={<IconMoon class="w-4 h-4" />}>
          <IconSun class="w-4 h-4" />
        </Show>
      }>
        <IconMonitor class="w-4 h-4" />
      </Show>
    </button>
  );
}
