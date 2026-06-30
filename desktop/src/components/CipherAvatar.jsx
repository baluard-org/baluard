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
 * Sizes: "sm" (row), "lg" (detail header).
 */
export default function CipherAvatar(props) {
  const size = props.size || "sm";
  const faviconSrc = () => {
    const f = props.favicon;
    return f && f.data && f.mime ? `data:${f.mime};base64,${f.data}` : null;
  };

  const containerCls = () => {
    const base = size === "lg"
      ? "w-16 h-16 rounded-2xl overflow-hidden flex items-center justify-center shadow-lg"
      : "w-8 h-8 rounded-lg overflow-hidden flex items-center justify-center shrink-0";
    return faviconSrc()
      ? (size === "lg" ? `${base} bg-[var(--color-sidebar)] border border-[var(--color-border)]` : base)
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
