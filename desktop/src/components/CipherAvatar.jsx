import { Show } from "solid-js";
import { getCuratedColor, getDomainInitials } from "../lib/utils.js";

/**
 * Colored avatar circle with initials derived from the cipher name.
 * When a `favicon` prop ({ data, mime }) is present — persisted on the Login
 * cipher at add/edit time — it is rendered instead of the colored initials.
 *
 * This component never fetches anything. Favicon retrieval is opt-in
 * (settings.fetch_favicons, default off) and happens only at save time in
 * AddEditCipherForm, so browsing the vault makes zero network calls.
 *
 * D6: the mime is attacker-influenced when the favicon arrived via git sync
 * or import (daemon-fetched ones are validated). Only whitelisted image
 * types reach the data: URI; anything else renders the initials fallback.
 *
 * Sizes: "sm" (row), "lg" (detail header).
 */
const FAVICON_MIME_ALLOWLIST = new Set([
  "image/png",
  "image/jpeg",
  "image/webp",
  "image/x-icon",
  "image/vnd.microsoft.icon",
]);

export default function CipherAvatar(props) {
  const size = props.size || "sm";
  const faviconSrc = () => {
    const f = props.favicon;
    return f && f.data && f.mime && FAVICON_MIME_ALLOWLIST.has(f.mime)
      ? `data:${f.mime};base64,${f.data}`
      : null;
  };

  const containerCls = () => {
    const base = size === "lg"
      ? "w-16 h-16 rounded-2xl overflow-hidden flex items-center justify-center shadow-lg"
      : "w-8 h-8 rounded-lg overflow-hidden flex items-center justify-center shrink-0";
    // Same chip treatment (sidebar bg + border) at both sizes so the list
    // row matches the detail header instead of showing a bare floating icon.
    return faviconSrc()
      ? `${base} bg-[var(--color-sidebar)] border border-[var(--color-border)]`
      : `${base} ${getCuratedColor(props.name)}`;
  };

  return (
    <div class={containerCls()}>
      <Show when={faviconSrc()} fallback={getDomainInitials(props.name)}>
        <img
          src={faviconSrc()}
          alt=""
          class={size === "lg" ? "w-8 h-8 object-contain" : "w-5 h-5 object-contain"}
          draggable={false}
        />
      </Show>
    </div>
  );
}
