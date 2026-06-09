import { createSignal, createEffect } from "solid-js";

export const [theme, setTheme] = createSignal(
  (() => { try { return localStorage.getItem("baluard-theme") || "dark"; } catch { return "dark"; } })()
);

createEffect(() => {
  const t = theme();
  document.body.classList.toggle("light-theme", t === "light");
  try { localStorage.setItem("baluard-theme", t); } catch { /* noop */ }
});
