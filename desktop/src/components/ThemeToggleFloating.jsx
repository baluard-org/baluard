import { Show } from "solid-js";
import { useApp } from "../context/AppContext.jsx";

function ThemeToggleFloating() {
  const { theme, setTheme } = useApp();
  return (
    <div class="absolute top-4 right-4 z-50">
      <button
        onClick={() => setTheme(theme() === "dark" ? "light" : "dark")}
        class="p-2.5 rounded-xl bg-[var(--color-sidebar)] hover:bg-[var(--color-card)] border border-[var(--color-border)] text-slate-400 hover:text-white transition-all cursor-pointer shadow-md"
        title="Toggle Theme"
      >
        <Show when={theme() === "dark"} fallback={
          <svg class="w-4.5 h-4.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m0-12.728l.707.707m12.728 12.728l.707.707M12 8a4 4 0 100 8 4 4 0 000-8z"/></svg>
        }>
          <svg class="w-4.5 h-4.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
        </Show>
      </button>
    </div>
  );
}

export { ThemeToggleFloating };
