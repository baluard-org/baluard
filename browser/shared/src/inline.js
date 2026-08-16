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

import { fillLoginForm, isUsernameField } from "./autofill.js";

(() => {
  if (window.__baluardInline) return;
  window.__baluardInline = true;

  // Minimal user-facing strings (same en/es shape as the popup).
  const STRINGS = {
    en: { noMatches: "No logins for this site", loading: "Loading…" },
    es: { noMatches: "No hay inicios de sesión para este sitio", loading: "Cargando…" },
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
    </style>
    <div class="icon" title="Baluard" part="icon" aria-label="Baluard">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#b3e55c" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    </div>
    <div class="menu" role="listbox" aria-label="Baluard logins"></div>
  `;
  const icon = root.querySelector(".icon");
  const menu = root.querySelector(".menu");

  let targetInput = null;
  let menuOpen = false;

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
    menu.classList.add("open");
    menu.innerHTML = `<div class="menu-status">${escapeHtml(t("loading"))}</div>`;
    positionMenu();
    try {
      const resp = await chrome.runtime.sendMessage({ action: "inline.matches" });
      const data = resp && resp.ok ? safeParse(resp.payload) : null;
      const matches = (data && data.matches) || [];
      renderEntries(matches);
    } catch {
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

  // Ask the SW for the credential and the fill push. The credential never
  // comes back through this response — the SW pushes it via
  // tabs.sendMessage (baluard-inline-fill) with expectedOrigin derived from
  // the tab's real URL, so a compromised page cannot intercept it here.
  async function requestFill(id) {
    closeMenu();
    try {
      await chrome.runtime.sendMessage({ action: "inline.fill", id });
    } catch {
      // SW unreachable (version skew / daemon down): silently drop. The
      // popup remains the always-works fallback.
    }
  }

  // ── Fill push from the SW ──
  chrome.runtime.onMessage.addListener((msg) => {
    if (!msg || msg.type !== "baluard-inline-fill") return;
    const currentHost = location.hostname.toLowerCase();
    if (msg.expectedOrigin && currentHost !== msg.expectedOrigin) {
      // Tab navigated between user click and fill. Fail closed.
      console.warn("[baluard] inline fill refused: origin changed during fill");
      return;
    }
    fillLoginForm(msg.credential);
    closeMenu();
    hideIcon();
  });

  // ── Page events ──
  // focusin bubbles (unlike blur) and sees shadow-piercing composed targets.
  document.addEventListener(
    "focusin",
    (e) => {
      const el = e.target;
      if (el && el.tagName === "INPUT" && isUsernameField(el) && isVisibleField(el)) {
        showIcon(el);
      } else if (menuOpen && el && el.tagName === "INPUT" && !isUsernameField(el)) {
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
        const stillOnField = e.target === targetInput;
        if (!stillOnField && !(e.target && e.target.tagName === "INPUT" && isUsernameField(e.target))) {
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

  // Local copies of visibility helpers (autofill.js exports them for other
  // bundles; duplicated here in the template only as needed).
  function isVisibleField(el) {
    if (!el || !el.getBoundingClientRect) return false;
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return false;
    const style = window.getComputedStyle(el);
    return style.display !== "none" && style.visibility !== "hidden";
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
