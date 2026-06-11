import { createSignal, createEffect } from "solid-js";

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
  document.body.classList.toggle("light-theme", resolveEffective(theme()) === "light");
}

createEffect(() => {
  applyTheme();
  try { localStorage.setItem("baluard-theme", theme()); } catch { /* noop */ }
});

if (mql) {
  mql.addEventListener("change", () => {
    if (theme() === "system") applyTheme();
  });
}
