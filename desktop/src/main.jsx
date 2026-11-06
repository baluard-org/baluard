import { render } from "@solidjs/web";
import { I18nProvider } from "./i18n/index.jsx";
import { AuthProvider } from "./context/AuthContext.jsx";
import App from "./App";
import { initRipple } from "./lib/ripple.js";
import "./app.css";

initRipple();

// Disable webview browser context menu (Reload/Inspect Element) outside of text inputs.
// Matches native macOS desktop interaction behavior while preserving text-editing controls.
document.addEventListener("contextmenu", (e) => {
  const isEditable = e.target.closest("input:not([type='checkbox']):not([type='radio']), textarea, [contenteditable='true']");
  if (!isEditable) {
    e.preventDefault();
  }
});

render(() => <I18nProvider><AuthProvider><App /></AuthProvider></I18nProvider>, document.getElementById("root"));
