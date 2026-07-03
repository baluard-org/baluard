import { render } from "solid-js/web";
import { createSignal, Show, For, onMount } from "solid-js";

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

// i18n. The extension bundles its own strings (review sonnet B-5: every error
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
          expectedOrigin: hostnameOf(tabUrl()),
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

function hostnameOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
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

function App() {
  const t = (k) => (STRINGS[detectLocale()] || STRINGS.en)[k] || k;

  return (
    <div style={{ width: "340px", "font-family": "system-ui, sans-serif", padding: "12px" }}>
      {/* CSS vars + dark-mode handling. The popup is a standalone doc (no
          access to the desktop app's stylesheet), so we define the small
          palette here and honor the browser's color-scheme preference. */}
      <style>{`
        :root {
          --baluard-text: #1a1a1a;
          --baluard-muted: #666;
          --baluard-surface: #fff;
          --baluard-border: #ccc;
          --baluard-primary: #2563eb;
          --baluard-primary-text: #fff;
          --baluard-danger: #c00;
        }
        @media (prefers-color-scheme: dark) {
          :root {
            --baluard-text: #e8e8e8;
            --baluard-muted: #9a9a9a;
            --baluard-surface: #1e1e1e;
            --baluard-border: #3a3a3a;
            --baluard-primary: #4d8bff;
            --baluard-primary-text: #fff;
            --baluard-danger: #ff6b6b;
          }
        }
        .baluard-primary-btn {
          padding: 8px 12px; font-size: 13px; cursor: pointer; width: 100%;
          border: none; border-radius: 5px;
          background: var(--baluard-primary); color: var(--baluard-primary-text);
        }
        .baluard-link {
          padding: 8px 12px; font-size: 13px; color: var(--baluard-primary);
          text-decoration: none; border: 1px solid var(--baluard-border);
          border-radius: 5px; background: var(--baluard-surface);
          display: block; text-align: center;
        }
      `}</style>
      <div style={{ display: "flex", "align-items": "center", "justify-content": "space-between", "margin-bottom": "10px" }}>
        <strong style={{ "font-size": "15px" }}>{t("title")}</strong>
        <Show when={activeVault()}>
          <span style={{ "font-size": "11px", color: "var(--baluard-muted)" }}>{t("activeVault")}: {activeVault()}</span>
        </Show>
      </div>

      <Show when={state() === "loading"}>
        <div style={{ "font-size": "13px", color: "var(--baluard-muted)" }}>{t("loading")}</div>
      </Show>

      {/* First-run welcome (one-time) */}
      <Show when={state() === "welcome"}>
        <div style={{ "font-size": "15px", "font-weight": "bold", "margin-bottom": "8px" }}>{t("welcome")}</div>
        <div style={{ "font-size": "12px", color: "var(--baluard-muted)", "margin-bottom": "12px", "line-height": "1.5" }}>{t("welcomeDesc")}</div>
        <a href={DOWNLOAD_URL} target="_blank" rel="noopener" class="baluard-link" style={{ "margin-bottom": "6px" }}>{t("downloadApp")}</a>
        <button onClick={dismissWelcome} class="baluard-primary-btn">{t("haveApp")}</button>
      </Show>

      {/* Not paired: step-by-step onboarding */}
      <Show when={state() === "not-paired"}>
        <div style={{ "font-size": "14px", "font-weight": "bold", "margin-bottom": "4px" }}>{t("notPaired")}</div>
        <div style={{ "font-size": "12px", color: "var(--baluard-muted)", "margin-bottom": "12px" }}>{t("notPairedIntro")}</div>
        <ol style={{ "font-size": "12px", color: "var(--baluard-text)", "padding-left": "20px", "margin-bottom": "14px", "line-height": "1.7" }}>
          <li>{t("step1")}</li>
          <li>{t("step2")}</li>
          <li>{t("step3")}</li>
        </ol>
        <button onClick={connect} class="baluard-primary-btn">{t("connectCta")}</button>
      </Show>

      <Show when={state() === "connecting"}>
        <StateBlock title={t("connect")} desc={t("connectDesc")} color="var(--baluard-muted)" />
      </Show>

      {/* Daemon states: friendly + actionable */}
      <Show when={state() === "no-daemon"}>
        <StateBlock title={t("appRequired")} desc={t("appRequiredDesc")} color="var(--baluard-danger)" />
        <button onClick={() => refresh(false)} style={{ ...btnStyle(), "margin-bottom": "6px" }}>{t("retry")}</button>
        <a href={DOWNLOAD_URL} target="_blank" rel="noopener" class="baluard-link">{t("downloadApp")}</a>
      </Show>
      <Show when={state() === "locked"}>
        <StateBlock title={t("locked")} desc={t("lockedDesc")} color="var(--baluard-danger)" />
        <button onClick={() => refresh(false)} style={btnStyle()}>{t("retry")}</button>
      </Show>
      <Show when={state() === "version-skew"}>
        <StateBlock title={t("versionSkew")} desc={t("versionSkewDesc")} color="var(--baluard-danger)" />
        <a href={DOWNLOAD_URL} target="_blank" rel="noopener" class="baluard-link">{t("updateApp")}</a>
      </Show>

      <Show when={state() === "ready"}>
        <Show when={matches().length === 0}>
          <div style={{ "font-size": "13px", color: "var(--baluard-muted)", "margin-bottom": "8px" }}>{t("noMatches")}</div>
        </Show>
        <For each={matches()}>
          {(m) => (
            <div style={{ border: "1px solid var(--baluard-border)", "border-radius": "6px", padding: "8px", "margin-bottom": "6px", background: "var(--baluard-surface)" }}>
              <div style={{ "font-size": "13px", "font-weight": "bold", color: "var(--baluard-text)" }}>{m.name}</div>
              <Show when={m.username}>
                <div style={{ "font-size": "12px", color: "var(--baluard-muted)" }}>{m.username}</div>
              </Show>
              <div style={{ display: "flex", gap: "6px", "margin-top": "6px", "flex-wrap": "wrap" }}>
                <button style={miniBtn()} onClick={() => fill(m)}>{t("fill")}</button>
                <Show when={m.username}>
                  <button style={miniBtn()} onClick={() => copyField(m, "username")}>{t("copyUsername")}</button>
                </Show>
                <button style={miniBtn()} onClick={() => copyField(m, "password")}>{t("copyPassword")}</button>
                <button style={miniBtn()} onClick={() => copyTotp(m)}>{t("copyTotp")}</button>
              </div>
              <Show when={copied().startsWith(`username-${m.id}`) || copied().startsWith(`password-${m.id}`) || copied().startsWith(`totp-${m.id}`)}>
                <div style={{ "font-size": "11px", color: "#080", "margin-top": "4px" }}>{t("copied")}</div>
              </Show>
            </div>
          )}
        </For>
        <button style={{ ...btnStyle(), "margin-top": "8px" }} onClick={() => refresh(false)}>{t("refresh")}</button>
      </Show>

      <Show when={state() === "error"}>
        <StateBlock
          title={t("errorTitle")}
          desc={error() && error().includes("timeout") ? t("errorTimeout") : (error() || t("errorTimeout"))}
          color="var(--baluard-danger)"
        />
        <button onClick={() => refresh(false)} style={btnStyle()}>{t("retry")}</button>
      </Show>
    </div>
  );
}

function StateBlock(props) {
  return (
    <div style={{ "margin-bottom": "10px" }}>
      <div style={{ "font-size": "14px", "font-weight": "bold", color: props.color || "var(--baluard-text)" }}>{props.title}</div>
      <div style={{ "font-size": "12px", color: "var(--baluard-muted)", "margin-top": "3px", "line-height": "1.5" }}>{props.desc}</div>
    </div>
  );
}

function btnStyle() {
  return { padding: "7px 11px", "font-size": "13px", cursor: "pointer", width: "100%", border: "1px solid var(--baluard-border)", "border-radius": "5px", background: "var(--baluard-surface)", color: "var(--baluard-text)" };
}
function miniBtn() {
  return { padding: "4px 7px", "font-size": "11px", cursor: "pointer", border: "1px solid var(--baluard-border)", "border-radius": "4px", background: "var(--baluard-surface)", color: "var(--baluard-text)" };
}

render(() => <App />, document.body);
