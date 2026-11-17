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

// One TOTP window's ring state, epoch-aligned (now mod period) like the
// daemon rows. The daemon rotates on floor(now/period), so the ring floors
// too: rounding would show a fresh full window for the last half second of
// the dying code. Unusable periods fall back to 30s; the ring flips to
// danger at OTP_EXPIRY_SECONDS and under (Bitwarden parity). The resolved
// period rides the result so callers never re-derive it. Exported for
// unit tests.
export const OTP_EXPIRY_SECONDS = 7;
export function otpRingState(period, nowSec) {
  const p = Number(period) > 0 ? Number(period) : 30;
  const seconds = p - (Math.floor(nowSec) % p);
  return { seconds, expiring: seconds <= OTP_EXPIRY_SECONDS, period: p };
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
      multiVaultNote: "Some logins come from another vault",
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
      multiVaultNote: "Algunos inicios de sesión vienen de otra bóveda",
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
      .menu-note { padding: 8px 12px 0; font-size: 11px; opacity: 0.85; }
      .entry {
        display: flex;
        flex-direction: row;
        align-items: center;
        gap: 10px;
        padding: 9px 12px;
        cursor: pointer;
      }
      .entry:hover, .entry:focus-visible { background: #14292c; outline: none; }
      .entry-text { min-width: 0; display: flex; flex-direction: column; gap: 2px; }
      .entry-name { font-weight: 600; overflow-wrap: anywhere; }
      .entry-user { color: #a2b7ba; font-size: 12px; word-break: break-all; }
      .entry-key { display: flex; align-items: center; flex-shrink: 0; }
      /* Bitwarden-parity countdown ring: inner sweep drains clockwise, the
         remaining seconds sit centered; the whole ring goes danger-red at
         7s and under so the user can wait for a fresh code instead of
         autofilling a stale one. */
      .otp-ring { position: relative; width: 28px; height: 28px; flex-shrink: 0; }
      .otp-ring svg { display: block; width: 100%; height: 100%; transform: rotate(-90deg); }
      .otp-ring circle { fill: none; }
      .otp-ring-track { stroke: #1d3a3d; stroke-width: 1; }
      .otp-ring-sweep { stroke: #b3e55c; stroke-width: 3; stroke-linecap: round; stroke-dasharray: 78.5; }
      .otp-ring-sec {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        font-size: 9px;
        font-weight: 600;
        color: #f3f4f6;
        font-variant-numeric: tabular-nums;
      }
      .otp-ring.expiring .otp-ring-sweep { stroke: #ef4444; }
      .otp-ring.expiring .otp-ring-sec { color: #ef4444; }
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
      <!-- Brand mark from baluard/assets/baluard-lock-only.svg; gradient IDs
           namespaced (bld-*) so page SVGs cannot collide in the shadow root. -->
      <svg width="13" height="13" viewBox="0 0 512 512">
        <defs>
          <linearGradient id="bld-shackle" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#ded8fc" />
            <stop offset="100%" stop-color="#cfc6f9" />
          </linearGradient>
          <linearGradient id="bld-body" x1="20%" y1="0%" x2="80%" y2="100%">
            <stop offset="0%" stop-color="#c5f279" />
            <stop offset="50%" stop-color="#b3e55c" />
            <stop offset="100%" stop-color="#9dce47" />
          </linearGradient>
        </defs>
        <path d="M 172 205 V 150 C 172 103 209 66 256 66 C 303 66 340 103 340 150 V 205 H 294 V 150 C 294 128 277 111 256 111 C 235 111 218 128 218 150 V 205 Z" fill="url(#bld-shackle)" />
        <path d="M 136 205 H 184 V 228 H 228 V 205 H 284 V 228 H 328 V 205 H 376 C 384 205 388 209 388 217 V 405 C 388 424 374 438 355 438 H 157 C 138 438 124 424 124 405 V 217 C 124 209 128 205 136 205 Z" fill="url(#bld-body)" />
        <path d="M317.8351477449456 361.56298600311044Q317.8351477449456 347.19284603421465 304.98911353032656 337.6127527216174L281.6920684292379 320.4121306376361L295.6267496111975 309.5256609642302Q303.02954898911355 303.646967340591 303.02954898911355 294.50233281493Q303.02954898911355 280.56765163297047 288.8771384136858 272.07620528771383Q276.68429237947123 264.89113530326597 262.0964230171073 264.89113530326597Q248.59720062208396 264.89113530326597 226.82426127527214 273.38258164852255Q211.800933125972 279.04354587869364 203.09175738724727 282.3094867807154Q194.38258164852255 285.5754276827372 191.98755832037324 286.01088646967344V291.0186625194401Q205.05132192846034 296.8973561430793 205.05132192846034 315.6220839813375V377.45723172628306Q205.05132192846034 383.9891135303266 199.17262830482113 394.0046656298601L193.51166407465007 403.8024883359254V408.37480559875587Q202.00311041990668 404.67340590979785 204.18040435458786 404.0202177293935Q208.09953343701397 402.27838258164854 216.3732503888025 402.27838258164854Q223.12286158631414 402.27838258164854 237.71073094867805 405.3265940902022Q252.29860031104198 408.37480559875587 259.04821150855366 408.37480559875587Q276.248833592535 408.37480559875587 296.27993779160187 393.78693623639197Q317.8351477449456 377.8926905132193 317.8351477449456 361.56298600311044ZM278.6438569206843 294.50233281493Q278.6438569206843 302.99377916018665 269.71695178849143 311.9206842923795Q264.7091757387247 316.9284603421462 250.3390357698289 325.2021772939347Q244.67807153965785 328.4681181959565 240.3234836702955 331.40746500777607Q235.96889580093313 334.3468118195957 232.92068429237946 336.74183514774495Q232.48522550544322 336.3063763608087 231.61430793157075 336.3063763608087Q231.61430793157075 336.3063763608087 229.43701399688956 336.74183514774495L229.00155520995332 319.5412130637636L228.7838258164852 302.1228615863142Q228.34836702954897 290.58320373250393 238.14618973561429 282.3094867807154Q247.50855365474337 274.68895800933126 259.04821150855366 274.68895800933126Q262.9673405909798 274.68895800933126 266.55987558320373 276.3219284603422Q270.15241057542767 277.95489891135304 272.7651632970451 280.67651632970455Q275.3779160186625 283.398133748056 277.01088646967344 286.99066874027994Q278.6438569206843 290.58320373250393 278.6438569206843 294.50233281493ZM288.4416796267496 372.8849144634526Q288.4416796267496 382.4650077760498 279.29704510108866 389.8678071539658Q269.93468118195955 397.48833592534993 260.57231726283044 397.48833592534993Q244.2426127527216 397.48833592534993 236.18662519440124 383.5536547433904Q229.43701399688956 372.23172628304826 229.43701399688956 354.81337480559876Q229.43701399688956 351.76516329704515 240.5412130637636 344.144634525661Q251.86314152410574 336.74183514774495 255.78227060653188 336.74183514774495Q262.7496111975116 336.74183514774495 275.59564541213064 351.1119751166408Q288.4416796267496 365.6998444790047 288.4416796267496 372.8849144634526Z" fill="#091315" />
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
    // Flip above the icon when the menu would overflow the viewport bottom,
    // using the menu's real height (short lists must hug the icon).
    const h = menu.offsetHeight || 260;
    if (below.top + h > window.innerHeight) {
      below.top = Math.max(4, ir.top - h - 6);
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
    stopOtpTicker();
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
      // Conditional passkey candidates ride the same dropdown (Bitwarden
      // parity): the SW only answers with rows while a conditional
      // WebAuthn request is pending for this tab, and errors stay silent
      // (the browser's own conditional sheet races ours).
      const [resp, pkResp] = await Promise.all([
        chrome.runtime.sendMessage({ action: "inline.matches" }),
        chrome.runtime.sendMessage({ action: "inline.passkeys" }).catch(() => null),
      ]);
      if (resp && !resp.ok) {
        // App closed, locked, unpaired, or out of date: say WHY. The empty
        // "no logins" message is only for a real, unlocked, empty match.
        if (!menuOpen) return; // closed while loading
        menu.innerHTML = `<div class="menu-status">${escapeHtml(t(statusKeyFor(resp.code)))}</div>`;
        return;
      }
      const data = resp && resp.ok ? safeParse(resp.payload) : null;
      const matches = (data && data.matches) || [];
      const passkeys =
        pkResp && pkResp.ok && pkResp.payload ? safeParse(pkResp.payload).rows || [] : [];
      renderEntries(matches, Boolean(data && data.multiVault), passkeys);
    } catch {
      // Messaging-level failure (SW died mid-flight): same mapping. A code
      // rarely exists here, so this lands on the plain no-matches message.
      if (!menuOpen) return;
      menu.innerHTML = `<div class="menu-status">${escapeHtml(t("noMatches"))}</div>`;
    }
  }

  function renderEntries(matches, multiVault = false, passkeys = []) {
    if (!menuOpen) return; // closed while loading
    if (matches.length === 0 && passkeys.length === 0) {
      menu.innerHTML = `<div class="menu-status">${escapeHtml(t("noMatches"))}</div>`;
      return;
    }
    menu.innerHTML = "";
    for (const pk of passkeys) {
      const item = document.createElement("div");
      item.className = "entry";
      item.setAttribute("role", "option");
      item.tabIndex = 0;
      const key = document.createElement("span");
      key.className = "entry-key";
      key.setAttribute("aria-hidden", "true");
      key.innerHTML =
        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#b3e55c" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>';
      item.appendChild(key);
      const text = document.createElement("div");
      text.className = "entry-text";
      const name = document.createElement("div");
      name.className = "entry-name";
      name.textContent = pk.name || "";
      text.appendChild(name);
      if (pk.username) {
        const user = document.createElement("div");
        user.className = "entry-user";
        user.textContent = pk.username;
        text.appendChild(user);
      }
      item.appendChild(text);
      // pk.credential_id comes from rows WE rendered (SW projection) —
      // never from page data. Stashed on the node for the e2e pick seam.
      item.__pkId = pk.credential_id;
      item.addEventListener("click", () => requestPasskeyFill(pk.credential_id));
      item.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          requestPasskeyFill(pk.credential_id);
        }
      });
      menu.appendChild(item);
    }
    if (multiVault) {
      // Neutral merge marker (G24 section 4.5): the page principal learns
      // only that more than one vault contributed - never WHICH vault.
      const note = document.createElement("div");
      note.className = "menu-status menu-note";
      note.textContent = t("multiVaultNote");
      menu.appendChild(note);
    }
    for (const m of matches) {
      const item = document.createElement("div");
      item.className = "entry";
      item.setAttribute("role", "option");
      item.tabIndex = 0;
      if (m.totp && m.totp_period) {
        // The ring takes the row's leading slot, like Bitwarden's inline
        // menu; rows without a code stay text-only.
        const ring = document.createElement("span");
        ring.className = "otp-ring";
        ring.dataset.period = String(m.totp_period);
        ring.setAttribute("aria-hidden", "true");
        ring.innerHTML =
          '<svg viewBox="0 0 29 29"><circle class="otp-ring-track" cx="14.5" cy="14.5" r="14"></circle>' +
          '<circle class="otp-ring-sweep" cx="14.5" cy="14.5" r="12.5"></circle></svg>' +
          '<span class="otp-ring-sec"></span>';
        item.appendChild(ring);
      }
      const text = document.createElement("div");
      text.className = "entry-text";
      const name = document.createElement("div");
      name.className = "entry-name";
      name.textContent = m.name || "";
      text.appendChild(name);
      if (m.username) {
        const user = document.createElement("div");
        user.className = "entry-user";
        user.textContent = m.username;
        text.appendChild(user);
      }
      item.appendChild(text);
      // m.id is chosen from the entries WE rendered — never from the page.
      item.addEventListener("click", () => requestFill(m.id, m.vault_slug));
      item.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          requestFill(m.id, m.vault_slug);
        }
      });
      menu.appendChild(item);
    }
    // The real height is known only after the entries render.
    if (menuOpen) positionMenu();
    // Row ids for the e2e pick seam (node expandos do not survive
    // re-renders reliably).
    window.__pkRowIds = passkeys.map((p) => p.credential_id);
    // Ticker runs only while a ring is on screen; closeMenu stops it.
    if (menu.querySelector(".otp-ring")) startOtpTicker();
  }

  // 1 Hz painter for the on-screen rings, aligned to the second boundary so
  // the displayed second matches the wall clock (a free-running interval
  // drifts and can show a stale 1 after the code already rotated).
  let otpTicker = null;
  function startOtpTicker() {
    if (otpTicker) return;
    const tick = () => {
      tickOtpRings();
      otpTicker = setTimeout(tick, 1000 - (Date.now() % 1000));
    };
    tick();
  }
  function stopOtpTicker() {
    if (otpTicker) {
      clearTimeout(otpTicker);
      otpTicker = null;
    }
  }
  function tickOtpRings() {
    if (!menuOpen) return;
    const now = Date.now() / 1000;
    for (const ring of menu.querySelectorAll(".otp-ring")) {
      const { seconds, expiring, period } = otpRingState(Number(ring.dataset.period), now);
      const sweep = ring.querySelector(".otp-ring-sweep");
      if (sweep) sweep.style.strokeDashoffset = String(((period - seconds) / period) * 78.5);
      const sec = ring.querySelector(".otp-ring-sec");
      if (sec) sec.textContent = String(seconds);
      ring.classList.toggle("expiring", expiring);
    }
  }

  // Conditional passkey pick: the SW resumes the pending WebAuthn request
  // with the chosen credential and pushes the signed assertion to the page.
  // Errors stay silent per conditional-mediation semantics (the browser's
  // native sheet races ours); they surface in the SW trail for diagnosis.
  async function requestPasskeyFill(credentialId) {
    const anchor = menuField && menuField.isConnected ? menuField : targetInput;
    closeMenu();
    // Diagnostics live in the SW trail (storage.session): the host element
    // is light DOM and page-readable, so no pick detail may land on it.
    try {
      const resp = await chrome.runtime.sendMessage({
        action: "inline.pickPasskey",
        credential_id: credentialId,
      });
      if (resp && !resp.ok) showStatus(t("fillFailed"), anchor);
    } catch (e) {
      if (anchor) showStatus(t("fillFailed"), anchor);
    }
  }

  // Ask the SW for the credential and the fill push. mode tells the SW to
  // minimize the pushed payload: "totp" pushes the code ONLY (no username,
  // no password). The SW fetches a code when this page can consume it or
  // when copyTotp is on for an entry that has TOTP (clipboard for step 2).
  async function requestFill(id, vaultSlug) {
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
      const resp = await chrome.runtime.sendMessage({
        action: "inline.fill",
        id,
        vault_slug: vaultSlug || "",
        mode,
        hasTotpField,
      });
      if (resp && !resp.ok) {
        showStatus(t(statusKeyFor(resp.code)), anchor);
      }
    } catch {
      showStatus(t("fillFailed"), anchor);
    }
  }

  // ── Fill push from the SW ──
  chrome.runtime.onMessage.addListener((msg, sender) => {
    // Only our own extension may drive a fill.
    if (sender && sender.id && sender.id !== chrome.runtime.id) return;
    if (!msg) return;
    if (msg.type === "baluard-passkey-pick-result") {
      console.warn("[baluard] passkey pick result: pushed=", msg.pushed);
      return;
    }
    if (msg.type !== "baluard-inline-fill") return;
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
    } else if (msg.copyFailed) {
      // The SW tried and failed (clipboard blocked): say so instead of
      // leaving the user to paste a stale code.
      showStatus(t("codeCopyFailed"), anchor);
    }
  }

  // Test seam for e2e drivers: reports menu state, fires the first rendered
  // row's real click handler. Lives in the isolated world, so pages cannot
  // reach it.
  window.__baluardPasskeyPickFirst = () => {
    const hosts = document.querySelectorAll("[data-baluard-inline]");
    const entries = menu.querySelectorAll(".entry");
    const info = {
      open: menuOpen,
      entries: entries.length,
      hosts: hosts.length,
      mounted: host.isConnected,
      ids: window.__pkRowIds || null,
    };
    const entry = entries[0];
    if (!entry) return info;
    // Bypass the click event: the closed-root row's trusted-click delivery
    // proved flaky under the test harness, and the pipeline under test is
    // the pick handler itself. Id from the last render's row data (node
    // expandos proved unreliable across re-renders).
    requestPasskeyFill((window.__pkRowIds || [])[0]);
    return { ...info, called: true, stamps: [] };
  };

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

  // Keep the icon glued to its field while the page scrolls/resizes,
  // and the open menu glued to the icon.
  const reposition = () => {
    positionIcon();
    if (menuOpen) positionMenu();
  };
  addEventListener("scroll", reposition, { capture: true, passive: true });
  addEventListener("resize", reposition, { passive: true });

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
    // Ceremony routes (inline.passkeys, pick results) send plain objects;
    // daemon-backed routes send JSON strings. Both must survive.
    if (raw && typeof raw === "object") return raw;
    try {
      return JSON.parse(typeof raw === "string" ? raw : "{}");
    } catch {
      return {};
    }
  }
})();
