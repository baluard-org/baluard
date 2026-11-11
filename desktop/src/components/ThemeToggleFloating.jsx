import { Show } from "solid-js";
import { IconMoon, IconSun } from "./Icon.jsx";
import { resolvedTheme, toggleTheme } from "../context/themeSignal.js";
import { useI18n } from "../i18n/index.jsx";

// Icon shows the theme the press will switch TO (action convention): a dark
// screen shows the sun. The full three-way setting lives in Settings.
export default function ThemeToggleFloating() {
  const { t } = useI18n();
  const target = () => (resolvedTheme() === "light" ? "dark" : "light");

  return (
    <button
      onClick={toggleTheme}
      // fixed, not absolute: a positioned ancestor is this engine's
      // mis-resolution target (WebKit 26 anchored the button against a
      // collapsed containing block, half off the window's left edge), and
      // a fixed box always resolves against the viewport.
      class="theme-toggle-floating fixed top-4 right-4 p-2 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors cursor-pointer bg-[var(--color-card)] z-10"
      title={t(target() === "light" ? "settings.switchToLight" : "settings.switchToDark")}
      aria-label={t(target() === "light" ? "settings.switchToLight" : "settings.switchToDark")}
    >
      <Show when={target() === "light"} fallback={<IconMoon class="w-4 h-4" />}>
        <IconSun class="w-4 h-4" />
      </Show>
    </button>
  );
}
