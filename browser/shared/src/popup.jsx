import { render } from "solid-js/web";
import { createSignal, Show, For, onMount } from "solid-js";
import { getSettings, updateSettings } from "./settings.js";

// Phase 1 popup: first-run welcome -> pairing ceremony -> URL-filtered login
// list + autofill/copy.
//
// States:
//   loading      -> { welcome | not-paired | connecting | ready | no-daemon
//                     | locked | version-skew | error }
//   welcome:     first run (no chrome.storage 'onboarded' flag). One-time.
//   ready:       bridge.match returned matches for the active tab URL.
//   notPaired:   no pairing; show step-by-step Connect guide.
//   connecting:  pair_complete sent, held pending until desktop Approves.
//   locked:      daemon up but active vault locked.
//   noDaemon:    NMH couldn't reach the daemon socket.
//   versionSkew: NMH version < required (background.js hard gate).
//   error:       unexpected / timeout — offer Retry.
//
// Per Decision 2: popup holds NO secrets. The bridge token lives in the NMH.

// i18n. The extension bundles its own strings (review: every error
// code -> friendly actionable message, no hard tech terms). Mirrors the
// desktop's en/es shape so the two can stay in sync.
const STRINGS = {
  en: {
    title: "Baluard",
    loading: "Loading…",
    activeVault: "Vault",
    retry: "Try again",
    openApp: "Open Baluard",
    downloadApp: "Download Baluard",
    // Welcome (first run)
    welcome: "Welcome to Baluard",
    welcomeDesc: "Baluard is a private password manager. This extension fills your saved logins into websites — your passwords never leave your device.",
    haveApp: "I have Baluard installed",
    // Not paired (onboarding guide)
    notPaired: "Connect to Baluard",
    notPairedIntro: "Link this browser to the Baluard app to autofill your passwords.",
    step1: "Open the Baluard app on this computer",
    step2: "In Settings, add a new browser extension",
    step3: "Come back here and connect",
    connectCta: "Connect to Baluard",
    connect: "Waiting for approval",
    connectDesc: "Tap Approve in the Baluard app.",
    // Daemon states
    appRequired: "Open the Baluard app",
    appRequiredDesc: "The Baluard app must be running and unlocked for the extension to work.",
    locked: "Vault locked",
    lockedDesc: "Unlock the Baluard app to fill passwords.",
    versionSkew: "Update required",
    versionSkewDesc: "This extension needs a newer Baluard app. Please update.",
    updateApp: "Update Baluard",
    // Error / timeout
    errorTitle: "Something went wrong",
    errorTimeout: "Couldn't reach the Baluard app. Make sure it's running, then try again.",
    pairExpired: "The connection request expired. Please try again.",
    // Ready
    search: "Search",
    noMatches: "No logins for this site",
    fill: "Fill",
    copyUsername: "Copy username",
    copyPassword: "Copy password",
    copyTotp: "Copy code",
    copied: "Copied",
    refresh: "Refresh",
    // Settings
    settings: "Settings",
    back: "Back",
    inlineAutofillTitle: "Show fill suggestions on login forms",
    inlineAutofillDesc: "Adds a small Baluard button next to login fields. Click it to pick a login and fill the form — no need to open this window. Your passwords still never fill on their own.",
  },
  es: {
    title: "Baluard",
    loading: "Cargando…",
    activeVault: "Caja fuerte",
    retry: "Reintentar",
    openApp: "Abrir Baluard",
    downloadApp: "Descargar Baluard",
    // Welcome (first run)
    welcome: "Te damos la bienvenida a Baluard",
    welcomeDesc: "Baluard es un gestor de contraseñas privado. Esta extensión rellena tus inicios de sesión guardados en los sitios web — tus contraseñas nunca salen de tu dispositivo.",
    haveApp: "Tengo Baluard instalado",
    // Not paired (onboarding guide)
    notPaired: "Conectar a Baluard",
    notPairedIntro: "Vincula este navegador con la app de Baluard para autorrellenar tus contraseñas.",
    step1: "Abre la app de Baluard en este equipo",
    step2: "En Ajustes, añade una nueva extensión del navegador",
    step3: "Vuelve aquí y conecta",
    connectCta: "Conectar a Baluard",
    connect: "Esperando aprobación",
    connectDesc: "Pulsa Aprobar en la app de Baluard.",
    // Daemon states
    appRequired: "Abre la app de Baluard",
    appRequiredDesc: "La app de Baluard debe estar abierta y desbloqueada para que la extensión funcione.",
    locked: "Caja fuerte bloqueada",
    lockedDesc: "Desbloquea la app de Baluard para rellenar contraseñas.",
    versionSkew: "Actualización necesaria",
    versionSkewDesc: "Esta extensión necesita una app de Baluard más reciente. Actualiza, por favor.",
    updateApp: "Actualizar Baluard",
    // Error / timeout
    errorTitle: "Algo salió mal",
    errorTimeout: "No se pudo contactar con la app de Baluard. Asegúrate de que esté abierta e inténtalo de nuevo.",
    pairExpired: "La solicitud de conexión expiró. Vuelve a intentarlo.",
    // Ready
    search: "Buscar",
    noMatches: "No hay inicios de sesión para este sitio",
    fill: "Rellenar",
    copyUsername: "Copiar usuario",
    copyPassword: "Copiar contraseña",
    copyTotp: "Copiar código",
    copied: "Copiado",
    refresh: "Actualizar",
    // Settings
    settings: "Ajustes",
    back: "Volver",
    inlineAutofillTitle: "Mostrar sugerencias en formularios de inicio de sesión",
    inlineAutofillDesc: "Añade un pequeño botón de Baluard junto a los campos de inicio de sesión. Púlsalo para elegir un inicio de sesión y rellenar el formulario — sin abrir esta ventana. Tus contraseñas nunca se rellenan solas.",
  },
};

function detectLocale() {
  const ui = (chrome.i18n?.getUILanguage?.() || navigator.language || "en").toLowerCase();
  return ui.startsWith("es") ? "es" : "en";
}

const [state, setState] = createSignal("loading");
const [matches, setMatches] = createSignal([]);
const [activeVault, setActiveVault] = createSignal("");
const [tabUrl, setTabUrl] = createSignal("");
const [error, setError] = createSignal(null);
const [copied, setCopied] = createSignal("");
// Settings view + inline autofill preference (chrome.storage.local).
const [settingsOpen, setSettingsOpen] = createSignal(false);
const [inlineAutofill, setInlineAutofill] = createSignal(true);

// First-run flag: persisted in chrome.storage.local. Onboarded users skip the
// welcome screen on subsequent opens.
const ONBOARDED_KEY = "onboarded";
// Last-known resting state, so reopening the popup shows something useful
// instantly instead of flashing "Loading…" while we re-probe the SW/NMH.
// Only resting states are cached (not-paired / no-daemon / locked / ready);
// transient states (loading / connecting / welcome) are never cached.
const LAST_STATE_KEY = "last_state";
const CACHEABLE_STATES = new Set(["not-paired", "no-daemon", "locked", "ready", "connecting"]);

// Where to send users who don't have the app yet. Single source of truth.
const DOWNLOAD_URL = "https://baluard.app";

/// Reject after `ms`. Used to race against SW round-trips that may never
/// resolve (MV3 service worker can be GC'd mid-request, orphaning the popup's
/// sendMessage callback — leaving it stuck on "Loading…" forever).
function timeout(ms, label) {
  return new Promise((_resolve, reject) =>
    setTimeout(() => reject(new TimeoutError(label)), ms)
  );
}

class TimeoutError extends Error {
  constructor(label) {
    super(label);
    this.code = "timeout";
  }
}

// Wrap chrome.runtime.sendMessage in a Promise.
function send(action, payload = {}) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ action, payload }, (resp) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (resp && resp.ok) resolve(resp.payload);
      else reject(buildErr(resp));
    });
  });
}

function buildErr(resp) {
  const e = new Error((resp && resp.error) || "unknown");
  e.code = (resp && resp.code) || "proto";
  return e;
}

// Persist resting states so the next popup open shows something useful
// instantly instead of "Loading…". Transient states are never cached.
// Pairing TTL must match the daemon's PENDING_TTL_SECONDS so a cached
// `connecting` state is only resumed while the held ceremony is still live.
function persistState(s) {
  if (CACHEABLE_STATES.has(s)) {
    try {
      chrome.storage.local.set({ [LAST_STATE_KEY]: { state: s, at: Date.now() } });
    } catch {}
  }
}

// set + persist wrapper.
function setStatePersisted(s) {
  setState(s);
  persistState(s);
}

async function refresh(silent = false) {
  console.log("[baluard] refresh silent=", silent);
  // Only show the loading spinner when we have nothing cached to show. When
  // `silent`, we keep the current (cached) resting state on screen while the
  // re-probe runs, so reopening the popup never flashes "Loading…".
  if (!silent) setState("loading");
  setError(null);
  try {
    // Onboarded gate: first-time users see the welcome screen first.
    const onboarded = await getOnboarded();
    if (!onboarded) {
      setState("welcome");
      return;
    }
    // Get the active tab URL for matching.
    const url = await getActiveTabUrl();
    setTabUrl(url);
    if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) {
      // Non-web tab: show ready-but-empty (no autofill context).
      setMatches([]);
      setActiveVault("");
      setStatePersisted("ready");
      return;
    }
    // Race the SW round-trip against a timeout so the popup can never wedge.
    const payload = await Promise.race([
      send("bridge.match", { url }),
      timeout(8000, "timeout"),
    ]);
    const data = JSON.parse(payload || "{}");
    setMatches(data.matches || []);
    setActiveVault(data.active_vault || "");
    setStatePersisted("ready");
  } catch (e) {
    setError(e.message);
    // Map the error code to a popup state.
    if (e.code === "not-paired") setStatePersisted("not-paired");
    else if (e.code === "locked") setStatePersisted("locked");
    else if (e.code === "no-daemon") setStatePersisted("no-daemon");
    else if (e.code === "version-skew") setState("version-skew");
    else if (e.code === "timeout") setState("error");
    else setState("error");
  }
}

function getOnboarded() {
  return new Promise((resolve) => {
    chrome.storage.local.get([ONBOARDED_KEY], (res) => {
      resolve(Boolean(res && res[ONBOARDED_KEY]));
    });
  });
}

function markOnboarded() {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [ONBOARDED_KEY]: true }, () => resolve());
  });
}

function getActiveTabUrl() {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      resolve(tabs[0]?.url || "");
    });
  });
}

async function dismissWelcome() {
  // First run is guaranteed unpaired — skip the bridge.match round-trip
  // (and its loading flash) and go straight to the pair-guide wizard.
  await markOnboarded();
  setStatePersisted("not-paired");
}

async function connect() {
  console.log("[baluard] connect() called");
  setStatePersisted("connecting");
  setError(null);
  try {
    // pair_complete is held pending on the daemon side until the desktop
    // user clicks Approve. This await resolves once approved. Race against
    // the daemon TTL so a never-approved ceremony can't wedge the popup —
    // the user gets a clear expiry instead of an infinite spinner.
    await Promise.race([
      send("bridge.pair_complete", { name: detectBrowser(), browser: detectBrowser() }),
      timeout(PAIR_TTL_MS, "pair-timeout"),
    ]);
    console.log("[baluard] pair_complete resolved OK -> refresh");
    // Paired! Mark onboarded + refresh into the ready state.
    await markOnboarded();
    refresh(true);
  } catch (e) {
    console.log("[baluard] connect failed:", e.code, e.message);
    setError(e.message);
    if (e.code === "pair-timeout") setError((STRINGS[detectLocale()] || STRINGS.en).pairExpired);
    setStatePersisted("not-paired");
  }
}

function detectBrowser() {
  const ua = (navigator.userAgent || "").toLowerCase();
  if (ua.includes("firefox")) return "firefox";
  if (ua.includes("edg/")) return "edge";
  if (ua.includes("chromium")) return "chromium";
  return "chrome";
}

async function fill(entry) {
  try {
    const payload = await send("vault.get", { id: entry.id });
    const cred = JSON.parse(payload || "{}");
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id;
      if (tabId == null) return;
      chrome.scripting.executeScript({
        target: { tabId, frameIds: [0] }, // top-frame only (Decision 9)
        files: ["content.js"],
      }, () => {
        chrome.tabs.sendMessage(tabId, {
          type: "baluard-fill",
          // B1: origin (scheme+host+port), not hostname — blocks the
          // https -> http downgrade fill. content.js compares location.origin.
          expectedOrigin: originOf(tabUrl()),
          credential: {
            username: cred.username || "",
            password: cred.password || "",
          },
        });
        window.close();
      });
    });
  } catch (e) {
    setError(e.message);
  }
}

async function copyField(entry, field) {
  try {
    const payload = await send("vault.get", { id: entry.id });
    const cred = JSON.parse(payload || "{}");
    const val = cred[field] || "";
    await clipboardCopy(val);
    setCopied(`${field}-${entry.id}`);
    setTimeout(() => setCopied(""), 2000);
  } catch (e) {
    setError(e.message);
  }
}

async function copyTotp(entry) {
  try {
    const code = await send("cipher.totp_code", { id: entry.id });
    const parsed = JSON.parse(code || "{}");
    await clipboardCopy(parsed.code || "");
    setCopied(`totp-${entry.id}`);
    setTimeout(() => setCopied(""), 2000);
  } catch (e) {
    setError(e.message);
  }
}

function originOf(url) {
  try {
    return new URL(url).origin;
  } catch {
    return "";
  }
}

// Clipboard via an offscreen document (service worker has no DOM). The
// background.js handles the offscreen lifecycle; here we just post a message.
function clipboardCopy(text) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ action: "clipboard-copy", text }, (resp) => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else if (resp && resp.ok) resolve();
      else reject(new Error("clipboard failed"));
    });
  });
}

// On open: restore the last resting state instantly (no loading flash),
// then re-probe silently so the state refreshes in the background.
function getLastState() {
  return new Promise((resolve) => {
    chrome.storage.local.get([LAST_STATE_KEY], (res) => {
      const v = res && res[LAST_STATE_KEY];
      // Legacy scalar form or missing -> treat as no cached state.
      if (!v || typeof v === "string") return resolve({ state: "", age_ms: Infinity });
      resolve({ state: v.state || "", age_ms: Date.now() - (v.at || 0) });
    });
  });
}

// Pairing ceremony TTL. Must match the daemon's PENDING_TTL_SECONDS so a
// cached `connecting` state is only resumed while the held ceremony is live.
const PAIR_TTL_MS = 120_000;

async function boot() {
  const cached = await getLastState();
  console.log("[baluard] boot cached=", cached);
  if (cached.state) setState(cached.state);
  // Resume an in-flight pairing ceremony ONLY if still within the daemon's
  // TTL window. If the prior attempt expired (user closed the popup and the
  // desktop never approved), fall through to a fresh probe rather than
  // blindly re-issuing a pair_complete that would just time out again.
  if (cached.state === "connecting" && cached.age_ms < PAIR_TTL_MS) {
    // Guard: pairing may have already completed while the popup was closed
    // (the prior pair_complete succeeded but its response died with the
    // closed popup). Probe bridge.match first; if we're no longer
    // not-paired, the ceremony is done — skip reissuing and go straight to
    // refresh (lands on ready/locked). Only reissue if still not-paired.
    const still = await isStillUnpaired();
    console.log("[baluard] isStillUnpaired=", still);
    if (still) {
      connect();
      return;
    }
  }
  // Stale `connecting`: surface the expiry so the user isn't left waiting.
  if (cached.state === "connecting") {
    const strs = STRINGS[detectLocale()] || STRINGS.en;
    setError(strs.pairExpired);
    setStatePersisted("not-paired");
  }
  refresh(true);
}

/// Quick probe: is there still NO pairing? Returns true if the NMH reports
/// not-paired (ceremony not yet completed). Any other outcome (locked, ready,
/// no-daemon, error) means a pairing exists or the daemon is unreachable — in
/// which case we must NOT reissue pair_complete.
async function isStillUnpaired() {
  try {
    await send("bridge.match", { url: "https://example.com" });
    return false; // paired (reached the daemon + matched without error)
  } catch (e) {
    return e.code === "not-paired";
  }
}

onMount(boot);
onMount(async () => {
  const s = await getSettings();
  setInlineAutofill(Boolean(s.inlineAutofill));
});

// Flip the setting. The service worker listens for the storage change and
// registers/unregisters the inline content script (see background.js
// syncInlineScript). Takes effect on the next page load.
async function toggleInlineAutofill() {
  const next = await updateSettings({ inlineAutofill: !inlineAutofill() });
  setInlineAutofill(Boolean(next.inlineAutofill));
}

function App() {
  const t = (k) => (STRINGS[detectLocale()] || STRINGS.en)[k] || k;

  return (
    <div class="baluard-popup">
      {/* Brand styling using modern CSS custom properties and native nesting.
          Dark Mode is the default. Light Mode overrides via prefers-color-scheme media query. */}
      <style>{`
        :root {
          /* Dark Mode (Default) - Deep Forest Teal / Soft Lavender / Lime Accent */
          --color-bg: #091315;
          --color-sidebar: #0f2022;
          --color-list: #14292c;
          --color-detail: #193236;
          --color-card: #0b1517;
          --color-border: #1d3a3d;
          --color-border-focus: #b3e55c;
          --color-text: #f3f4f6;
          --color-muted: #a2b7ba;
          --color-primary: #b3e55c;
          --color-primary-text: #102427;
          --color-primary-hover: #c5f279;
          --color-accent: #cfc6f9;
          --color-danger: #ef4444;
          --color-success: #10b981;
        }

        @media (prefers-color-scheme: light) {
          :root {
            /* Light Mode - Clean White / Slate / Dark Teal Accent */
            --color-bg: #f4f6f6;
            --color-sidebar: #e9ecec;
            --color-list: #ffffff;
            --color-detail: #f8fafc;
            --color-card: #ffffff;
            --color-border: #d1dbdb;
            --color-border-focus: #102427;
            --color-text: #102427;
            --color-muted: #495c5f;
            --color-primary: #102427;
            --color-primary-text: #ffffff;
            --color-primary-hover: #1b383c;
            --color-accent: #7c3aed;
            --color-danger: #ef4444;
            --color-success: #10b981;
          }
        }

        * {
          box-sizing: border-box;
          margin: 0;
          padding: 0;
        }

        body {
          background-color: var(--color-bg);
          color: var(--color-text);
          font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
          font-size: 13px;
          line-height: 1.4;
          width: 350px;
          overflow-x: hidden;
        }

        .baluard-popup {
          padding: 16px;
          display: flex;
          flex-direction: column;
          gap: 16px;
          background-color: var(--color-bg);
          min-height: 150px;
        }

        /* Focus rings for keyboard navigation */
        *:focus-visible {
          outline: 2px solid var(--color-border-focus);
          outline-offset: 2px;
        }

        /* Header area */
        .popup-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          border-bottom: 1px solid var(--color-border);
          padding-bottom: 10px;

          .brand-title {
            font-size: 16px;
            font-weight: 700;
            letter-spacing: -0.02em;
            color: var(--color-text);
          }

          .header-actions {
            display: flex;
            align-items: center;
            gap: 6px;
          }

          .vault-badge {
            font-size: 11px;
            background-color: var(--color-sidebar);
            color: var(--color-muted);
            padding: 2px 8px;
            border-radius: 9999px;
            border: 1px solid var(--color-border);
            font-weight: 500;
          }
        }

        /* Settings view */
        .setting-row {
          display: flex;
          align-items: flex-start;
          justify-content: space-between;
          gap: 12px;
          cursor: pointer;

          .setting-text {
            display: flex;
            flex-direction: column;
            gap: 4px;
            flex: 1;
          }

          .setting-name {
            font-size: 13px;
            font-weight: 600;
            color: var(--color-text);
          }
        }

        .toggle {
          position: relative;
          flex-shrink: 0;
          width: 36px;
          height: 20px;
          border-radius: 9999px;
          background-color: var(--color-border);
          transition: background-color 0.15s ease;
          display: inline-block;

          &.on {
            background-color: var(--color-primary);
          }

          input {
            position: absolute;
            inset: 0;
            opacity: 0;
            cursor: pointer;
            margin: 0;
          }

          .toggle-knob {
            position: absolute;
            top: 2px;
            left: 2px;
            width: 16px;
            height: 16px;
            border-radius: 9999px;
            background-color: #ffffff;
            transition: transform 0.15s ease;
            pointer-events: none;
          }

          &.on .toggle-knob {
            transform: translateX(16px);
          }
        }

        /* UI State Blocks */
        .state-block {
          padding: 12px;
          border-radius: 8px;
          background-color: var(--color-card);
          border: 1px solid var(--color-border);
          display: flex;
          flex-direction: column;
          gap: 6px;

          &.danger {
            border-color: rgba(239, 68, 68, 0.4);
            background-color: rgba(239, 68, 68, 0.05);
          }

          .state-title {
            font-size: 14px;
            font-weight: 600;
            color: var(--color-text);
          }

          .state-desc {
            font-size: 12px;
            color: var(--color-muted);
            line-height: 1.5;
          }
        }

        /* Buttons & Actions */
        .btn-primary {
          background-color: var(--color-primary);
          color: var(--color-primary-text);
          border: none;
          padding: 10px 14px;
          border-radius: 6px;
          font-weight: 600;
          font-size: 13px;
          cursor: pointer;
          width: 100%;
          text-align: center;
          transition: background-color 0.15s ease, transform 0.1s ease;
          display: inline-flex;
          align-items: center;
          justify-content: center;

          &:hover {
            background-color: var(--color-primary-hover);
          }

          &:active {
            transform: scale(0.98);
          }
        }

        .btn-secondary {
          background-color: var(--color-sidebar);
          color: var(--color-text);
          border: 1px solid var(--color-border);
          padding: 9px 14px;
          border-radius: 6px;
          font-weight: 500;
          font-size: 13px;
          cursor: pointer;
          width: 100%;
          text-align: center;
          transition: all 0.15s ease;
          display: inline-flex;
          align-items: center;
          justify-content: center;

          &:hover {
            background-color: var(--color-list);
            border-color: var(--color-border-focus);
          }

          &:active {
            transform: scale(0.98);
          }
        }

        .link-btn {
          text-decoration: none;
        }

        /* Welcome screen list & Connect guide */
        .guide-list {
          padding-left: 20px;
          margin: 4px 0 8px 0;
          display: flex;
          flex-direction: column;
          gap: 6px;

          li {
            font-size: 12px;
            color: var(--color-muted);
            line-height: 1.4;
          }
        }

        /* Matching entries list */
        .matches-list {
          display: flex;
          flex-direction: column;
          gap: 10px;
        }

        .match-card {
          border: 1px solid var(--color-border);
          border-radius: 8px;
          padding: 12px;
          background-color: var(--color-card);
          transition: border-color 0.15s ease, box-shadow 0.15s ease;
          display: flex;
          flex-direction: column;
          gap: 8px;

          &:hover {
            border-color: var(--color-border-focus);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
          }

          .match-info {
            display: flex;
            flex-direction: column;
            gap: 2px;
          }

          .match-name {
            font-size: 13px;
            font-weight: 600;
            color: var(--color-text);
          }

          .match-user {
            font-size: 12px;
            color: var(--color-muted);
            word-break: break-all;
          }

          .match-actions-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-top: 4px;
            border-top: 1px solid rgba(29, 58, 61, 0.3);
            padding-top: 8px;
          }
        }

        .btn-primary-mini {
          background-color: var(--color-primary);
          color: var(--color-primary-text);
          border: none;
          padding: 6px 12px;
          border-radius: 5px;
          font-weight: 600;
          font-size: 12px;
          cursor: pointer;
          transition: background-color 0.15s ease, transform 0.1s ease;
          display: inline-flex;
          align-items: center;
          justify-content: center;

          &:hover {
            background-color: var(--color-primary-hover);
          }

          &:active {
            transform: scale(0.98);
          }
        }

        .match-secondary-actions {
          display: flex;
          align-items: center;
          gap: 4px;
        }

        .btn-icon {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 28px;
          height: 28px;
          border-radius: 6px;
          background-color: var(--color-sidebar);
          color: var(--color-muted);
          border: 1px solid var(--color-border);
          cursor: pointer;
          transition: all 0.12s ease;

          &:hover {
            color: var(--color-text);
            background-color: var(--color-list);
            border-color: var(--color-border-focus);
          }

          &:active {
            transform: scale(0.95);
          }
        }

        .toast-copied {
          font-size: 11px;
          color: var(--color-success);
          font-weight: 500;
          margin-top: 4px;
          display: flex;
          align-items: center;
          gap: 4px;
          animation: fadeIn 0.2s ease-out;
        }

        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(2px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>

      <div class="popup-header">
        <div style="display: flex; align-items: center; gap: 8px;">
          <svg width="18" height="18" viewBox="0 0 512 512" fill="none" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <linearGradient id="pop-shackle" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="#ded8fc" />
                <stop offset="100%" stop-color="#cfc6f9" />
              </linearGradient>
              <linearGradient id="pop-body" x1="20%" y1="0%" x2="80%" y2="100%">
                <stop offset="0%" stop-color="#c5f279" />
                <stop offset="50%" stop-color="#b3e55c" />
                <stop offset="100%" stop-color="#9dce47" />
              </linearGradient>
            </defs>
            <path d="M 172 205 V 150 C 172 103 209 66 256 66 C 303 66 340 103 340 150 V 205 H 294 V 150 C 294 128 277 111 256 111 C 235 111 218 128 218 150 V 205 Z" fill="url(#pop-shackle)" />
            <path d="M 136 205 H 184 V 228 H 228 V 205 H 284 V 228 H 328 V 205 H 376 C 384 205 388 209 388 217 V 405 C 388 424 374 438 355 438 H 157 C 138 438 124 424 124 405 V 217 C 124 209 128 205 136 205 Z" fill="url(#pop-body)" />
            <path d="M317.8351477449456 361.56298600311044Q317.8351477449456 347.19284603421465 304.98911353032656 337.6127527216174L281.6920684292379 320.4121306376361L295.6267496111975 309.5256609642302Q303.02954898911355 303.646967340591 303.02954898911355 294.50233281493Q303.02954898911355 280.56765163297047 288.8771384136858 272.07620528771383Q276.68429237947123 264.89113530326597 262.0964230171073 264.89113530326597Q248.59720062208396 264.89113530326597 226.82426127527214 273.38258164852255Q211.800933125972 279.04354587869364 203.09175738724727 282.3094867807154Q194.38258164852255 285.5754276827372 191.98755832037324 286.01088646967344V291.0186625194401Q205.05132192846034 296.8973561430793 205.05132192846034 315.6220839813375V377.45723172628306Q205.05132192846034 383.9891135303266 199.17262830482113 394.0046656298601L193.51166407465007 403.8024883359254V408.37480559875587Q202.00311041990668 404.67340590979785 204.18040435458786 404.0202177293935Q208.09953343701397 402.27838258164854 216.3732503888025 402.27838258164854Q223.12286158631414 402.27838258164854 237.71073094867805 405.3265940902022Q252.29860031104198 408.37480559875587 259.04821150855366 408.37480559875587Q276.248833592535 408.37480559875587 296.27993779160187 393.78693623639197Q317.8351477449456 377.8926905132193 317.8351477449456 361.56298600311044ZM278.6438569206843 294.50233281493Q278.6438569206843 302.99377916018665 269.71695178849143 311.9206842923795Q264.7091757387247 316.9284603421462 250.3390357698289 325.2021772939347Q244.67807153965785 328.4681181959565 240.3234836702955 331.40746500777607Q235.96889580093313 334.3468118195957 232.92068429237946 336.74183514774495Q232.48522550544322 336.3063763608087 231.61430793157075 336.3063763608087Q231.61430793157075 336.3063763608087 229.43701399688956 336.74183514774495L229.00155520995332 319.5412130637636L228.7838258164852 302.1228615863142Q228.34836702954897 290.58320373250393 238.14618973561429 282.3094867807154Q247.50855365474337 274.68895800933126 259.04821150855366 274.68895800933126Q262.9673405909798 274.68895800933126 266.55987558320373 276.3219284603422Q270.15241057542767 277.95489891135304 272.7651632970451 280.67651632970455Q275.3779160186625 283.398133748056 277.01088646967344 286.99066874027994Q278.6438569206843 290.58320373250393 278.6438569206843 294.50233281493ZM288.4416796267496 372.8849144634526Q288.4416796267496 382.4650077760498 279.29704510108866 389.8678071539658Q269.93468118195955 397.48833592534993 260.57231726283044 397.48833592534993Q244.2426127527216 397.48833592534993 236.18662519440124 383.5536547433904Q229.43701399688956 372.23172628304826 229.43701399688956 354.81337480559876Q229.43701399688956 351.76516329704515 240.5412130637636 344.144634525661Q251.86314152410574 336.74183514774495 255.78227060653188 336.74183514774495Q262.7496111975116 336.74183514774495 275.59564541213064 351.1119751166408Q288.4416796267496 365.6998444790047 288.4416796267496 372.8849144634526Z" fill="#091315" />
          </svg>
          <strong class="brand-title">{t("title")}</strong>
        </div>
        <div class="header-actions">
          <Show when={activeVault()}>
            <span class="vault-badge">{t("activeVault")}: {activeVault()}</span>
          </Show>
          <Show when={!settingsOpen()}>
            <button class="btn-icon" onClick={() => setSettingsOpen(true)} title={t("settings")} aria-label={t("settings")}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="3" />
                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.09a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.09a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.09a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
              </svg>
            </button>
          </Show>
        </div>
      </div>

      {/* Settings view (replaces the state views; gear toggles back) */}
      <Show when={settingsOpen()}>
        <div class="state-block">
          <div class="state-title">{t("settings")}</div>
          <label class="setting-row">
            <div class="setting-text">
              <div class="setting-name">{t("inlineAutofillTitle")}</div>
              <div class="state-desc">{t("inlineAutofillDesc")}</div>
            </div>
            <span class={`toggle ${inlineAutofill() ? "on" : ""}`}>
              <input
                type="checkbox"
                checked={inlineAutofill()}
                onChange={toggleInlineAutofill}
                aria-label={t("inlineAutofillTitle")}
              />
              <span class="toggle-knob" aria-hidden="true"></span>
            </span>
          </label>
        </div>
        <button class="btn-secondary" onClick={() => setSettingsOpen(false)}>{t("back")}</button>
      </Show>

      <Show when={!settingsOpen()}>
      <Show when={state() === "loading"}>
        <div class="state-block">
          <div class="state-desc">{t("loading")}</div>
        </div>
      </Show>

      {/* First-run welcome (one-time) */}
      <Show when={state() === "welcome"}>
        <div class="state-block">
          <div class="state-title">{t("welcome")}</div>
          <div class="state-desc">{t("welcomeDesc")}</div>
        </div>
        <a href={DOWNLOAD_URL} target="_blank" rel="noopener" class="link-btn btn-secondary">{t("downloadApp")}</a>
        <button onClick={dismissWelcome} class="btn-primary">{t("haveApp")}</button>
      </Show>

      {/* Not paired: step-by-step onboarding */}
      <Show when={state() === "not-paired"}>
        <div class="state-block">
          <div class="state-title">{t("notPaired")}</div>
          <div class="state-desc">{t("notPairedIntro")}</div>
          <ol class="guide-list">
            <li>{t("step1")}</li>
            <li>{t("step2")}</li>
            <li>{t("step3")}</li>
          </ol>
        </div>
        <button onClick={connect} class="btn-primary">{t("connectCta")}</button>
      </Show>

      <Show when={state() === "connecting"}>
        <StateBlock title={t("connect")} desc={t("connectDesc")} class="" />
      </Show>

      {/* Daemon states: friendly + actionable */}
      <Show when={state() === "no-daemon"}>
        <StateBlock title={t("appRequired")} desc={t("appRequiredDesc")} class="danger" />
        <button onClick={() => refresh(false)} class="btn-secondary">{t("retry")}</button>
        <a href={DOWNLOAD_URL} target="_blank" rel="noopener" class="link-btn btn-secondary">{t("downloadApp")}</a>
      </Show>

      <Show when={state() === "locked"}>
        <StateBlock title={t("locked")} desc={t("lockedDesc")} class="danger" />
        <button onClick={() => refresh(false)} class="btn-primary">{t("retry")}</button>
      </Show>

      <Show when={state() === "version-skew"}>
        <StateBlock title={t("versionSkew")} desc={t("versionSkewDesc")} class="danger" />
        <a href={DOWNLOAD_URL} target="_blank" rel="noopener" class="link-btn btn-primary">{t("updateApp")}</a>
      </Show>

      <Show when={state() === "ready"}>
        <Show when={matches().length === 0}>
          <div class="state-block">
            <div class="state-desc">{t("noMatches")}</div>
          </div>
        </Show>
        <div class="matches-list">
          <For each={matches()}>
            {(m) => (
              <div class="match-card">
                <div class="match-info">
                  <div class="match-name">{m.name}</div>
                  <Show when={m.username}>
                    <div class="match-user">{m.username}</div>
                  </Show>
                </div>
                <div class="match-actions-row">
                  <button class="btn-primary-mini" onClick={() => fill(m)}>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 4px;">
                      <path d="M14 9V5a3 3 0 0 0-3-3l-4 9v11h11.28a2 2 0 0 0 2-1.7l1.38-9a2 2 0 0 0-2-2.3zM7 22H4a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2h3" />
                    </svg>
                    {t("fill")}
                  </button>
                  <div class="match-secondary-actions">
                    <Show when={m.username}>
                      <button class="btn-icon" onClick={() => copyField(m, "username")} title={t("copyUsername")}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                          <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                          <circle cx="12" cy="7" r="4" />
                        </svg>
                      </button>
                    </Show>
                    <button class="btn-icon" onClick={() => copyField(m, "password")} title={t("copyPassword")}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                      </svg>
                    </button>
                    <button class="btn-icon" onClick={() => copyTotp(m)} title={t("copyTotp")}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="10" />
                        <polyline points="12 6 12 12 16 14" />
                      </svg>
                    </button>
                  </div>
                </div>
                <Show when={copied().startsWith(`username-${m.id}`) || copied().startsWith(`password-${m.id}`) || copied().startsWith(`totp-${m.id}`)}>
                  <div class="toast-copied">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;vertical-align:middle;">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                    <span>{t("copied")}</span>
                  </div>
                </Show>
              </div>
            )}
          </For>
        </div>
        <button class="btn-secondary" onClick={() => refresh(false)}>{t("refresh")}</button>
      </Show>

      <Show when={state() === "error"}>
        {(() => {
          // Keep the raw technical error out of the UI (users see a friendly
          // message) but surface it for debugging so a stale-token / NMH
          // glitch is diagnosable from the console.
          if (error()) console.error("[baluard] popup error:", error());
          return null;
        })()}
        <StateBlock
          title={t("errorTitle")}
          desc={t("errorTimeout")}
          class="danger"
        />
        <button onClick={() => refresh(false)} class="btn-secondary">{t("retry")}</button>
      </Show>
      </Show>
    </div>
  );
}

function StateBlock(props) {
  return (
    <div class={`state-block ${props.class || ""}`}>
      <div class="state-title">{props.title}</div>
      <div class="state-desc">{props.desc}</div>
    </div>
  );
}

render(() => <App />, document.body);

