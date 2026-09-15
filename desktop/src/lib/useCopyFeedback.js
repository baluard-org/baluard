// Shared copy-then-flash feedback (code-health R1).
// One copied signal + auto-reset timer per call site, so every copy button
// in the app flashes the same way for the same duration. The actual write +
// auto-clear policy lives in clipboard.copyToClipboard.
import { createSignal, onCleanup } from "solid-js";
import { copyToClipboard } from "./clipboard.js";

export function useCopyFeedback(resetMs = 1800) {
  const [copied, setCopied] = createSignal(false);
  let timer;
  onCleanup(() => clearTimeout(timer));
  async function copy(value) {
    setCopied(true);
    clearTimeout(timer);
    timer = setTimeout(() => setCopied(false), resetMs);
    await copyToClipboard(value || "");
  }
  return [copied, copy];
}
