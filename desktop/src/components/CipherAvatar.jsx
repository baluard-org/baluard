import { createSignal, createEffect, onCleanup, Show } from "solid-js";
import { getCuratedColor, getDomainInitials } from "../lib/utils.js";
import { daemon } from "../lib/daemon.js";

// Module-level favicon cache: domain -> { data, mime } | null
const faviconCache = new Map();

/**
 * Invalidate cached favicon for a domain (or all if no arg).
 * Call after cipher save to force re-fetch on next render.
 */
export function invalidateFaviconCache(domain) {
  if (domain) {
    faviconCache.delete(extractDomain(domain));
  } else {
    faviconCache.clear();
  }
}

function extractDomain(uri) {
  if (!uri) return "";
  let s = uri.trim();
  s = s.replace(/^https?:\/\//, "");
  s = s.replace(/^www\./, "");
  s = s.split("/")[0];
  s = s.split(":")[0];
  s = s.split("?")[0];
  return s.toLowerCase();
}

/**
 * Colored avatar circle with initials derived from cipher name.
 * When `uri` prop is provided and favicon fetching is enabled,
 * displays the site's favicon instead of colored initials.
 * Sizes: "sm" (row), "lg" (detail header).
 */
export default function CipherAvatar(props) {
  const size = props.size || "sm";
  const [faviconSrc, setFaviconSrc] = createSignal(null);

  createEffect(() => {
    const uri = props.uri;
    const domain = extractDomain(uri);
    if (!domain) { setFaviconSrc(null); return; }

    // Check cache first (unless forced refresh)
    if (!props.refresh && faviconCache.has(domain)) {
      const cached = faviconCache.get(domain);
      if (cached === null) { setFaviconSrc(null); return; }
      setFaviconSrc(`data:${cached.mime};base64,${cached.data}`);
      return;
    }

    // Fetch from daemon
    let active = true;
    (async () => {
      try {
        const resp = await daemon("favicon.get", domain);
        if (!active) return;
        const data = JSON.parse(resp);
        if (data && data.data && data.mime) {
          faviconCache.set(domain, { data: data.data, mime: data.mime });
          if (active) setFaviconSrc(`data:${data.mime};base64,${data.data}`);
        } else {
          faviconCache.set(domain, null);
          if (active) setFaviconSrc(null);
        }
      } catch {
        faviconCache.set(domain, null);
        if (active) setFaviconSrc(null);
      }
    })();
    onCleanup(() => { active = false; });
  });

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
           onError={() => setFaviconSrc(null)}
         />
       </Show>
     </div>
   );
}
