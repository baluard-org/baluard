import { createSignal, createEffect } from "solid-js";

export const [theme, setTheme] = createSignal(
  (() => { try { return localStorage.getItem("idtty-theme") || "dark"; } catch { return "dark"; } })()
);

createEffect(() => {
  const t = theme();
  document.body.classList.toggle("light-theme", t === "light");
  try { localStorage.setItem("idtty-theme", t); } catch { /* noop */ }
});
