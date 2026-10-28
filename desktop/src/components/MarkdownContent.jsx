import { createMemo } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { renderMarkdown } from "../lib/markdown.js";
import { openUrl } from "@tauri-apps/plugin-opener";
import { toastError } from "../context/toastSignal.js";

// Renders a note as sanitized markdown HTML (see lib/markdown.js).
// Rendered links are intercepted: Tauri's webview does not route external
// navigation to the system browser, and only browser-safe schemes pass.
export default function MarkdownContent(props) {
  const { t } = useI18n();
  const html = createMemo(() => renderMarkdown(props.text || ""));
  async function handleClick(e) {
    const a = e.target.closest("a");
    if (!a) return;
    e.preventDefault();
    const href = a.getAttribute("href") || "";
    let scheme = "";
    try {
      scheme = new URL(href).protocol;
    } catch {
      // relative or malformed — refuse
    }
    if (scheme !== "https:" && scheme !== "http:" && scheme !== "mailto:") return;
    try {
      await openUrl(href);
    } catch {
      toastError(t("errors.openFailed"));
    }
  }
  return <div class={props.class} innerHTML={html()} onClick={handleClick} onAuxClick={(e) => e.preventDefault()} />;
}
