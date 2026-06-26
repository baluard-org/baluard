import { createSignal, createEffect, createRoot } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

const mql = typeof window !== "undefined" ? window.matchMedia("(prefers-color-scheme: light)") : null;

function systemIsLight() {
  return mql ? mql.matches : false;
}

function resolveEffective(t) {
  return t === "system" ? (systemIsLight() ? "light" : "dark") : t;
}

export const [theme, setTheme] = createSignal(
  (() => {
    try {
      const stored = localStorage.getItem("baluard-theme");
      return stored || "system";
    } catch { return "system"; }
  })()
);

function applyTheme() {
  const isLight = resolveEffective(theme()) === "light";
  document.body.classList.toggle("light-theme", isLight);
  try {
    invoke("update_tray_icon", { isDark: !isLight }).catch(() => {});
  } catch { /* noop */ }
}

// Wrap in createRoot so the effect has its own owner. Module-level
// createEffect (outside any render context) triggers a SolidJS dev
// warning ("computations created outside a `createRoot` or `render`
// will never be disposed") and, more importantly, can corrupt the
// reactive root tracking for signal updates fired in the same tick
// (e.g. a setSignal call from an async event handler in a
// freshly-mounted component), causing the Show conditions in that
// component to never re-evaluate. createRoot fixes both.
createRoot(() => {
  createEffect(() => {
    applyTheme();
    try { localStorage.setItem("baluard-theme", theme()); } catch { /* noop */ }
  });
});

if (mql) {
  mql.addEventListener("change", () => {
    if (theme() === "system") applyTheme();
  });
}
