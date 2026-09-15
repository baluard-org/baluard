// Inline autofill content script (in-field dropdown, 1Password/Bitwarden style).
//
// Registered dynamically by the service worker ONLY while the
// `inlineAutofill` setting is on (chrome.scripting.registerContentScripts,
// top-frame only, document_idle). Amends Decision 9's "no inline-field DOM"
// posture WITHOUT weakening its invariants:
//   - No auto-fill on load, ever. Filling requires TWO user gestures on our
//     own UI: icon click -> entry click. The page cannot synthesize either
//     (closed Shadow DOM; page JS cannot reach the inner elements).
//   - Matching is server-side against sender.tab.url (privileged) in the
//     service worker; this script never claims a URL for matching.
//   - Top-frame only: cross-origin login iframes get no icon, no fill.
//   - Fill-time origin re-check before writing to the DOM (same as
//     content.js): if the tab navigated during the IPC round trip, refuse.
//
// The icon shows on focus of username/password fields only — no continuous
// form scanning, no fingerprintable page-load probing.

import { fillLoginForm, isUsernameField, isTotpField, findTotpFields, setNativeValue, isVisible } from "./autofill.js";
import { getSettings, normalizeClearSeconds } from "./settings.js";

// Status mapping for the inline dropdown. Exported for unit tests (the
// esbuild IIFE bundle strips exports from the classic content script).
// Daemon/lock states get actionable one-liners; anything else (including a
// successful but empty match list) stays the plain "no matches" message.
export function statusKeyFor(code) {
  switch (code) {
    case "no-daemon":
      return "appRequired";
    case "locked":
      return "locked";
    case "version-skew":
      return "updateApp";
    case "not-paired":
      return "notPaired";
    default:
      return "noMatches";
  }
}

(() => {
  if (window.__baluardInline) return;
  window.__baluardInline = true;

  // Minimal user-facing strings (same en/es shape as the popup).
  const STRINGS = {
    en: {
      noMatches: "No logins for this site",
      loading: "Loading…",
      codeCopied: "Code copied",
      codeCopyFailed: "Copy failed",
      noCode: "No code available",
      fillFailed: "Couldn't fill this field",
      appRequired: "Open the Baluard app to fill logins",
      locked: "Unlock the Baluard app to fill logins",
      updateApp: "Update the Baluard app to continue",
      notPaired: "Connect this browser to the Baluard app",
    },
    es: {
      noMatches: "No hay inicios de sesión para este sitio",
      loading: "Cargando…",
      codeCopied: "Código copiado",
      codeCopyFailed: "Error al copiar",
      noCode: "Sin código disponible",
      fillFailed: "No se pudo rellenar este campo",
      appRequired: "Abre la app de Baluard para rellenar inicios de sesión",
      locked: "Desbloquea la app de Baluard para rellenar inicios de sesión",
      updateApp: "Actualiza la app de Baluard para continuar",
      notPaired: "Vincula este navegador con la app de Baluard",
    },
  };
  const t = (k) => {
    const locale = (navigator.language || "en").toLowerCase().startsWith("es") ? "es" : "en";
    return (STRINGS[locale] || STRINGS.en)[k] || k;
  };

  // ── Shadow-DOM UI host ──
  // Closed root: the page cannot traverse into our UI, restyle it, or
  // synthesize clicks on its inner elements.
  const host = document.createElement("div");
  host.setAttribute("data-baluard-inline", "");
  const root = host.attachShadow({ mode: "closed" });
  root.innerHTML = `
    <style>
      :host { all: initial; }
      * { box-sizing: border-box; margin: 0; padding: 0; }
      .icon {
        position: fixed;
        width: 22px;
        height: 22px;
        border-radius: 6px;
        background: #0f2022;
        border: 1px solid #1d3a3d;
        display: none;
        align-items: center;
        justify-content: center;
        cursor: pointer;
        z-index: 2147483646;
        box-shadow: 0 1px 4px rgba(0,0,0,0.4);
      }
      .icon:hover { background: #14292c; }
      .icon svg { display: block; }
      .menu {
        position: fixed;
        width: 280px;
        max-height: 260px;
        overflow-y: auto;
        background: #0b1517;
        border: 1px solid #1d3a3d;
        border-radius: 10px;
        box-shadow: 0 8px 24px rgba(0,0,0,0.5);
        z-index: 2147483647;
        display: none;
        font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
        font-size: 13px;
        color: #f3f4f6;
      }
      .menu.open { display: block; }
      .menu-status { padding: 12px; color: #a2b7ba; }
      .entry {
        display: flex;
        flex-direction: column;
        gap: 2px;
        padding: 9px 12px;
        cursor: pointer;
      }
      .entry:hover, .entry:focus-visible { background: #14292c; outline: none; }
      .entry-name { font-weight: 600; }
      .entry-user { color: #a2b7ba; font-size: 12px; word-break: break-all; }
      .status {
        position: fixed;
        display: none;
        padding: 7px 12px;
        background: #0b1517;
        border: 1px solid #1d3a3d;
        border-radius: 8px;
        box-shadow: 0 4px 14px rgba(0,0,0,0.45);
        z-index: 2147483647;
        font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
        font-size: 12px;
        color: #f3f4f6;
        pointer-events: none;
      }
    </style>
    <div class="icon" title="Baluard" part="icon" aria-label="Baluard">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#b3e55c" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    </div>
    <div class="menu" role="listbox" aria-label="Baluard logins"></div>
    <div class="status" role="status" aria-live="polite"></div>
  `;
  const icon = root.querySelector(".icon");
  const menu = root.querySelector(".menu");
  const statusEl = root.querySelector(".status");

  let targetInput = null;
  let menuOpen = false;
  // Capture-race guard: the field the menu was opened on, snapshotted at
  // open time and re-verified at fill time. A hostile page can blur the
  // original field and focus a different one while the menu is open — the
  // code (or password) must go to the field the user actually clicked on.
  let menuField = null;
  let menuFieldType = "";

  // Mount lazily on first qualifying focus so pages without login fields
  // never see the host node at all.
  function ensureMounted() {
    if (!host.isConnected) document.documentElement.appendChild(host);
  }

  // ── Icon positioning ──
  function positionIcon() {
    if (!targetInput || !targetInput.isConnected) return hideIcon();
    const rect = targetInput.getBoundingClientRect();
    const height = targetInput.offsetHeight || rect.height || 22;
    const y = Math.max(4, Math.round(rect.top + (height - 22) / 2));
    const x = Math.max(4, Math.round(rect.right - 26));
    icon.style.left = `${x}px`;
    icon.style.top = `${y}px`;
  }

  function positionMenu() {
    const ir = icon.getBoundingClientRect();
    const below = { top: ir.bottom + 6, left: ir.right - 280 };
    // Flip above the icon when the menu would overflow the viewport bottom.
    if (below.top + 200 > window.innerHeight) {
      below.top = Math.max(4, ir.top - 266);
    }
    menu.style.top = `${Math.round(below.top)}px`;
    menu.style.left = `${Math.round(Math.max(4, below.left))}px`;
  }

  function showIcon(input) {
    targetInput = input;
    ensureMounted();
    icon.style.display = "flex";
    positionIcon();
  }

  function hideIcon() {
    targetInput = null;
    icon.style.display = "none";
    closeMenu();
  }

  // ── Dropdown ──
  function closeMenu() {
    menu.classList.remove("open");
    menuOpen = false;
  }

  async function toggleMenu() {
    if (menuOpen) return closeMenu();
    menuOpen = true;
    // Snapshot the trigger field NOW; requestFill re-verifies before use.
    menuField = targetInput;
    menuFieldType = ((menuField && menuField.type) || "").toLowerCase();
    menu.classList.add("open");
    menu.innerHTML = `<div class="menu-status">${escapeHtml(t("loading"))}</div>`;
    positionMenu();
    try {
      const resp = await chrome.runtime.sendMessage({ action: "inline.matches" });
      if (resp && !resp.ok) {
        // App closed, locked, unpaired, or out of date: say WHY. The empty
        // "no logins" message is only for a real, unlocked, empty match.
        if (!menuOpen) return; // closed while loading
        menu.innerHTML = `<div class="menu-status">${escapeHtml(t(statusKeyFor(resp.code)))}</div>`;
        return;
      }
      const data = resp && resp.ok ? safeParse(resp.payload) : null;
      const matches = (data && data.matches) || [];
      renderEntries(matches);
    } catch {
      // Messaging-level failure (SW died mid-flight): same mapping. A code
      // rarely exists here, so this lands on the plain no-matches message.
      if (!menuOpen) return;
      menu.innerHTML = `<div class="menu-status">${escapeHtml(t("noMatches"))}</div>`;
    }
  }

  function renderEntries(matches) {
    if (!menuOpen) return; // closed while loading
    if (matches.length === 0) {
      menu.innerHTML = `<div class="menu-status">${escapeHtml(t("noMatches"))}</div>`;
      return;
    }
    menu.innerHTML = "";
    for (const m of matches) {
      const item = document.createElement("div");
      item.className = "entry";
      item.setAttribute("role", "option");
      item.tabIndex = 0;
      const name = document.createElement("div");
      name.className = "entry-name";
      name.textContent = m.name || "";
      item.appendChild(name);
      if (m.username) {
        const user = document.createElement("div");
        user.className = "entry-user";
        user.textContent = m.username;
        item.appendChild(user);
      }
      // m.id is chosen from the entries WE rendered — never from the page.
      item.addEventListener("click", () => requestFill(m.id));
      item.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          requestFill(m.id);
        }
      });
      menu.appendChild(item);
    }
  }

  // Ask the SW for the credential and the fill push. mode tells the SW to
  // minimize the pushed payload: "totp" pushes the code ONLY (no username,
  // no password). The SW fetches a code when this page can consume it or
  // when copyTotp is on for an entry that has TOTP (clipboard for step 2).
  async function requestFill(id) {
    // The page may have swapped or removed the trigger field between menu
    // open and entry click. Fail closed.
    if (
      !menuField ||
      !menuField.isConnected ||
      ((menuField.type || "").toLowerCase() !== menuFieldType)
    ) {
      closeMenu();
      return;
    }
    const mode = isTotpField(menuField) ? "totp" : "login";
    const hasTotpField = findTotpFields().length > 0;
    const anchor = menuField;
    closeMenu();
    try {
      const resp = await chrome.runtime.sendMessage({ action: "inline.fill", id, mode, hasTotpField });
      if (resp && !resp.ok) {
        showStatus(t(statusKeyFor(resp.code)), anchor);
      }
    } catch {
      showStatus(t("fillFailed"), anchor);
    }
  }

  // ── Fill push from the SW ──
  chrome.runtime.onMessage.addListener((msg) => {
    if (!msg || msg.type !== "baluard-inline-fill") return;
    // B1: origin compare (scheme+host+port). A hostname-only check would
    // still fill after an https -> http downgrade navigation. Fail closed.
    if (!msg.expectedOrigin || location.origin !== msg.expectedOrigin) {
      // Tab navigated between user click and fill, or expectedOrigin missing. Fail closed.
      console.warn("[baluard] inline fill refused: origin changed during fill");
      return;
    }
    const anchor = menuField && menuField.isConnected ? menuField : targetInput;
    if (msg.kind === "totp") {
      // Code-only fill writes into the EXACT field the menu was opened on —
      // never a fallback. A page that swapped fields mid-flight (SPA
      // re-render: no navigation, so the B1 origin check stays silent)
      // gets an explicit failure, not a code in the wrong box.
      if (!msg.totpCode) {
        showStatus(t("noCode"), anchor);
      } else if (
        menuField &&
        menuField.isConnected &&
        ((menuField.type || "").toLowerCase() === menuFieldType)
      ) {
        setNativeValue(menuField, msg.totpCode);
        reportCopy(msg, menuField, msg.totpCode);
      } else {
        showStatus(t("fillFailed"), anchor);
      }
    } else {
      fillLoginForm(msg.credential);
      if (msg.credential && msg.credential.totpCode) {
        reportCopy(msg, anchor, msg.credential.totpCode);
      }
    }
    closeMenu();
    hideIcon();
  });

  // Copy feedback. The SW already wrote the clipboard via the offscreen doc
  // when msg.copied. Firefox has no offscreen API (msg.clipboardFallback):
  // write directly here — the document still holds user activation from the
  // click a moment ago. copyTotp off => both false => stay quiet.
  function reportCopy(msg, anchor, code) {
    if (msg.copied) {
      showStatus(t("codeCopied"), anchor);
    } else if (msg.clipboardFallback && navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(code).then(
        async () => {
          // Same auto-clear as the SW offscreen path and the popup fallback
          // (clipboardClearSeconds setting; 0 = never). Overwrite with a
          // space so clipboard managers record no captured secret.
          const seconds = normalizeClearSeconds((await getSettings()).clipboardClearSeconds);
          if (seconds > 0) {
            setTimeout(() => navigator.clipboard.writeText(" ").catch(() => {}), seconds * 1000);
          }
          showStatus(t("codeCopied"), anchor);
        },
        () => showStatus(t("codeCopyFailed"), anchor)
      );
    }
  }

  // ── Page events ──
  // focusin bubbles (unlike blur) and sees shadow-piercing composed targets.
  document.addEventListener(
    "focusin",
    (e) => {
      const el = e.target;
      if (
        el &&
        el.tagName === "INPUT" &&
        isVisible(el) &&
        (isUsernameField(el) || isTotpField(el))
      ) {
        showIcon(el);
      } else if (
        menuOpen &&
        el &&
        el.tagName === "INPUT" &&
        !isUsernameField(el) &&
        !isTotpField(el)
      ) {
        closeMenu();
      }
    },
    true
  );

  document.addEventListener(
    "focusin",
    (e) => {
      // Focus left login fields entirely (and is not our own UI) -> hide.
      if (targetInput && e.target !== targetInput && !host.contains(e.target)) {
        if (
          !(
            e.target &&
            e.target.tagName === "INPUT" &&
            (isUsernameField(e.target) || isTotpField(e.target))
          )
        ) {
          hideIcon();
        }
      }
    },
    true
  );

  // Click away closes the menu (the host sits outside the page's DOM tree,
  // so a page click can never land inside it — but clicks on empty space
  // must still close).
  document.addEventListener(
    "click",
    (e) => {
      if (menuOpen && !host.contains(e.target)) closeMenu();
    },
    true
  );

  // Keep the icon glued to its field while the page scrolls/resizes.
  addEventListener("scroll", positionIcon, { capture: true, passive: true });
  addEventListener("resize", positionIcon, { passive: true });

  // mousedown (not click) + preventDefault so clicking the icon does not
  // steal focus from the login field (keeps some pages' focus-styles intact).
  icon.addEventListener("mousedown", (e) => e.preventDefault());
  icon.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    toggleMenu();
  });


  let statusTimer = null;
  function showStatus(text, anchorEl) {
    const anchor = anchorEl || targetInput;
    if (!anchor || !anchor.getBoundingClientRect) return;
    ensureMounted();
    statusEl.textContent = text;
    const rect = anchor.getBoundingClientRect();
    statusEl.style.left = `${Math.max(4, Math.round(rect.right - 170))}px`;
    statusEl.style.top = `${Math.max(4, Math.round(rect.bottom + 6))}px`;
    statusEl.style.display = "block";
    if (statusTimer) clearTimeout(statusTimer);
    statusTimer = setTimeout(() => {
      statusEl.style.display = "none";
    }, 2200);
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[c]);
  }

  function safeParse(raw) {
    try {
      return JSON.parse(typeof raw === "string" ? raw : "{}");
    } catch {
      return {};
    }
  }
})();
