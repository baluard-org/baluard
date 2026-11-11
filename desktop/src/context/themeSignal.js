import { createSignal, createEffect, createRoot } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

const mql = typeof window !== "undefined" && typeof window.matchMedia === "function" ? window.matchMedia("(prefers-color-scheme: light)") : null;

// Reactive mirror of the OS preference so resolvedTheme()-driven UI (icon,
// tooltip) re-renders on scheme flips, not only on stored-theme changes.
const [systemLight, setSystemLight] = createSignal(mql ? mql.matches : false);

function systemIsLight() {
  return systemLight();
}

function resolveEffective(t) {
  return t === "system" ? (systemIsLight() ? "light" : "dark") : t;
}

/** The theme currently displayed: the stored override, or what the OS prefers. */
export function resolvedTheme() {
  return resolveEffective(theme());
}

/**
 * Pure decision behind the two-state toggle: the next stored value for a
 * given stored value and OS preference. The target (opposite of what is on
 * screen) is returned as an override only when it differs from what the OS
 * already provides; otherwise the stored value releases to "system".
 */
export function nextStoredTheme(stored, osIsLight) {
  const systemPref = osIsLight ? "light" : "dark";
  const resolved = stored === "system" ? systemPref : stored;
  const target = resolved === "light" ? "dark" : "light";
  return target === systemPref ? "system" : target;
}

export function toggleTheme() {
  setTheme(nextStoredTheme(theme(), systemIsLight()));
}

export const [theme, setTheme] = createSignal(
  (() => {
    try {
      const stored = localStorage.getItem("baluard-theme");
      return stored || "system";
    } catch { return "system"; }
  })()
);

function applyTheme(themeValue = theme()) {
  const isLight = resolveEffective(themeValue) === "light";
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
  createEffect(
    () => theme(),
    (t) => {
      applyTheme(t);
      try { localStorage.setItem("baluard-theme", t); } catch { /* noop */ }
    },
  );
});

if (mql) {
  mql.addEventListener("change", (e) => setSystemLight(e.matches));
}
