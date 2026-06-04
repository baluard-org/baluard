import { Show } from "solid-js";
import { IconMoon, IconSun } from "./Icon.jsx";
import { theme, setTheme } from "../context/themeSignal.js";

export default function ThemeToggleFloating() {
  return (
    <button
      onClick={() => setTheme(theme() === "dark" ? "light" : "dark")}
      class="absolute top-4 right-4 p-2 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-[var(--color-muted)] hover:text-[var(--color-text)] transition-all cursor-pointer bg-[var(--color-card)] z-10"
      title="Toggle theme"
    >
      <Show when={theme() === "dark"} fallback={
        <IconMoon class="w-4 h-4" />
      }>
        <IconSun class="w-4 h-4" />
      </Show>
    </button>
  );
}
