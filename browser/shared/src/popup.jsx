import { render } from "solid-js/web";
import { createSignal, Show, For, onMount, onCleanup } from "solid-js";
import { getSettings, updateSettings, normalizeClearSeconds } from "./settings.js";
import { originOf } from "./url.js";
// ?inline gives the raw CSS string. It is rendered as a DYNAMIC <style>
// child on purpose: Solid bakes STATIC template children into an HTML
// string and entity-escapes them, which turned every "&" nesting selector
// into "&amp;" and silently killed .toggle.on, :hover, :active and .danger
// rules in real Chrome (text-node insertion never escapes). Keep it dynamic.
import popupCss from "./popup.css?inline";

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
    downloadApp: "Download the Baluard app",
    // Welcome (first run)
    welcome: "Welcome to Baluard",
    welcomeDesc: "Baluard is a private password manager. This extension fills your saved logins into websites — your passwords never leave your device.",
    haveApp: "I have Baluard installed",
    // Not paired (onboarding guide)
    notPaired: "Connect to Baluard",
    notPairedIntro: "Link this browser to the Baluard app to autofill your passwords.",
    step1: "Open the Baluard app on this computer",
    step2: "In Settings, add a new browser extension",
    step3: "Type the pairing code shown in the app, then connect",
    pairCodeLabel: "Pairing code",
    pairCodePlaceholder: "8-character code",
    wrongCode: "That code does not match. Check the Baluard app and try again.",
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
    updateApp: "Update the Baluard app",
    // Error / timeout
    errorTitle: "Something went wrong",
    errorTimeout: "Couldn't reach the Baluard app. Make sure it's running, then try again.",
    pairExpired: "The connection request expired. Please try again.",
    // Ready
    noMatches: "No logins for this site",
    fill: "Fill",
    copyUsername: "Copy username",
    copyPassword: "Copy password",
    copyTotp: "Copy code",
    viewInApp: "View in Baluard app",
    copied: "Copied",
    refresh: "Refresh",
    // G24 merged surfaces
    lockedChip: "is locked. Open Baluard.",
    spaceRemoved: "You may no longer have access to this space.",
    askUnlock: "Click to ask the Baluard app to unlock this vault",
    unlockRequested: "Unlock requested.",
    // Settings
    settings: "Settings",
    back: "Back",
    inlineAutofillTitle: "Show fill suggestions on login forms",
    inlineAutofillDesc: "Adds a small Baluard button next to login fields. Click it to pick a login and fill the form — no need to open this window. Your passwords still never fill on their own.",
    copyTotpTitle: "Copy verification codes when filling",
    copyTotpDesc: "After filling a login that has a verification code, the code is copied too, so you can paste it on the next screen. Cleared shortly after.",
    clipboardClearTitle: "Clear clipboard after",
    clipboardClearDesc: "Copied passwords and codes are wiped from the clipboard after this time.",
    clear10: "10 seconds",
    clear30: "30 seconds",
    clear60: "1 minute",
    clear120: "2 minutes",
    clearNever: "Never",
  },
  es: {
    title: "Baluard",
    loading: "Cargando…",
    activeVault: "Caja fuerte",
    retry: "Reintentar",
    downloadApp: "Descargar la app de Baluard",
    // Welcome (first run)
    welcome: "Te damos la bienvenida a Baluard",
    welcomeDesc: "Baluard es un gestor de contraseñas privado. Esta extensión rellena tus inicios de sesión guardados en los sitios web — tus contraseñas nunca salen de tu dispositivo.",
    haveApp: "Tengo Baluard instalado",
    // Not paired (onboarding guide)
    notPaired: "Conectar a Baluard",
    notPairedIntro: "Vincula este navegador con la app de Baluard para autorrellenar tus contraseñas.",
    step1: "Abre la app de Baluard en este equipo",
    step2: "En Ajustes, añade una nueva extensión del navegador",
    step3: "Escribe el código que muestra la app y conecta",
    pairCodeLabel: "Código de emparejamiento",
    pairCodePlaceholder: "Código de 8 caracteres",
    wrongCode: "El código no coincide. Revisa la app de Baluard e inténtalo de nuevo.",
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
    updateApp: "Actualizar la app de Baluard",
    // Error / timeout
    errorTitle: "Algo salió mal",
    errorTimeout: "No se pudo contactar con la app de Baluard. Asegúrate de que esté abierta e inténtalo de nuevo.",
    pairExpired: "La solicitud de conexión expiró. Vuelve a intentarlo.",
    // Ready
    noMatches: "No hay inicios de sesión para este sitio",
    fill: "Rellenar",
    copyUsername: "Copiar usuario",
    copyPassword: "Copiar contraseña",
    copyTotp: "Copiar código",
    viewInApp: "Ver en la app de Baluard",
    copied: "Copiado",
    refresh: "Actualizar",
    lockedChip: "está bloqueada. Abre Baluard.",
    spaceRemoved: "Puede que ya no tengas acceso a este espacio.",
    askUnlock: "Pulsa para pedir a la app de Baluard que la desbloquee",
    unlockRequested: "Desbloqueo solicitado.",
    // Settings
    settings: "Ajustes",
    back: "Volver",
    inlineAutofillTitle: "Mostrar sugerencias en formularios de inicio de sesión",
    inlineAutofillDesc: "Añade un pequeño botón de Baluard junto a los campos de inicio de sesión. Púlsalo para elegir un inicio de sesión y rellenar el formulario — sin abrir esta ventana. Tus contraseñas nunca se rellenan solas.",
    copyTotpTitle: "Copiar códigos de verificación al rellenar",
    copyTotpDesc: "Tras rellenar un inicio de sesión con código de verificación, el código se copia también, para pegarlo en la siguiente pantalla. Se borra poco después.",
    clipboardClearTitle: "Vaciar el portapapeles después de",
    clipboardClearDesc: "Las contraseñas y códigos copiados se borran del portapapeles después de este tiempo.",
    clear10: "10 segundos",
    clear30: "30 segundos",
    clear60: "1 minuto",
    clear120: "2 minutos",
    clearNever: "Nunca",
  },
  pt: {
    title: "Baluard",
    loading: "Carregando…",
    activeVault: "Cofre",
    retry: "Tentar novamente",
    downloadApp: "Baixar o app Baluard",
    // Welcome (first run)
    welcome: "Boas-vindas ao Baluard",
    welcomeDesc: "Baluard é um gerenciador de senhas privado. Esta extensão preenche seus logins salvos em sites — suas senhas nunca saem do seu dispositivo.",
    haveApp: "Já tenho o Baluard instalado",
    // Not paired (onboarding guide)
    notPaired: "Conectar ao Baluard",
    notPairedIntro: "Vincule este navegador ao app Baluard para preencher suas senhas automaticamente.",
    step1: "Abra o app Baluard neste computador",
    step2: "Em Configurações, adicione uma nova extensão do navegador",
    step3: "Digite o código exibido no app e conecte",
    pairCodeLabel: "Código de pareamento",
    pairCodePlaceholder: "Código de 8 caracteres",
    wrongCode: "Esse código não corresponde. Verifique o app Baluard e tente novamente.",
    connectCta: "Conectar ao Baluard",
    connect: "Aguardando aprovação",
    connectDesc: "Toque em Aprovar no app Baluard.",
    // Daemon states
    appRequired: "Abra o app Baluard",
    appRequiredDesc: "O app Baluard precisa estar aberto e desbloqueado para a extensão funcionar.",
    locked: "Cofre bloqueado",
    lockedDesc: "Desbloqueie o app Baluard para preencher senhas.",
    versionSkew: "Atualização necessária",
    versionSkewDesc: "Esta extensão precisa de um app Baluard mais recente. Atualize, por favor.",
    updateApp: "Atualizar o app Baluard",
    // Error / timeout
    errorTitle: "Algo deu errado",
    errorTimeout: "Não foi possível contatar o app Baluard. Verifique se ele está aberto e tente novamente.",
    pairExpired: "A solicitação de conexão expirou. Tente novamente.",
    // Ready
    noMatches: "Nenhum login para este site",
    fill: "Preencher",
    copyUsername: "Copiar usuário",
    copyPassword: "Copiar senha",
    copyTotp: "Copiar código",
    viewInApp: "Ver en la app de Baluard",
    copied: "Copiado",
    refresh: "Atualizar",
    // G24 merged surfaces
    lockedChip: "está bloqueado. Abra o Baluard.",
    spaceRemoved: "Pode ser que você não tenha mais acesso a este espaço.",
    askUnlock: "Toque para pedir ao app Baluard para desbloquear este cofre",
    unlockRequested: "Desbloqueio solicitado.",
    // Settings
    settings: "Configurações",
    back: "Voltar",
    inlineAutofillTitle: "Mostrar sugestões de preenchimento em formulários de login",
    inlineAutofillDesc: "Adiciona um pequeno botão Baluard ao lado dos campos de login. Clique nele para escolher um login e preencher o formulário — sem precisar abrir esta janela. Suas senhas nunca são preenchidas sozinhas.",
    copyTotpTitle: "Copiar códigos de verificação ao preencher",
    copyTotpDesc: "Após preencher um login que tem código de verificação, o código também é copiado, para você colar na próxima tela. É apagado pouco depois.",
    clipboardClearTitle: "Limpar a área de transferência após",
    clipboardClearDesc: "Senhas e códigos copiados são apagados da área de transferência após esse tempo.",
    clear10: "10 segundos",
    clear30: "30 segundos",
    clear60: "1 minuto",
    clear120: "2 minutos",
    clearNever: "Nunca",
  },
};

function detectLocale() {
  const ui = (chrome.i18n?.getUILanguage?.() || navigator.language || "en").toLowerCase();
  if (ui.startsWith("es")) return "es";
  if (ui.startsWith("pt")) return "pt";
  return "en";
}

const [state, setState] = createSignal("loading");
const [matches, setMatches] = createSignal([]);
const [activeVault, setActiveVault] = createSignal("");
const [tabUrl, setTabUrl] = createSignal("");
// G24: eligible-vault rows for the locked/removal chips (popup-owned page,
// so display names are fine here - they never cross to the page principal).
const [vaultChips, setVaultChips] = createSignal([]);
const [error, setError] = createSignal(null);
const [copied, setCopied] = createSignal("");
// Settings view + inline autofill preference (chrome.storage.local).
const [settingsOpen, setSettingsOpen] = createSignal(false);
const [inlineAutofill, setInlineAutofill] = createSignal(true);
const [copyTotpEnabled, setCopyTotpEnabled] = createSignal(true);
const [clipboardClear, setClipboardClear] = createSignal(60);
// Live TOTP ring clock. Windows are epoch-aligned, so the drained fraction
// is just now mod the row's period — no code is ever fetched for display.
const [nowSec, setNowSec] = createSignal(Date.now() / 1000);
// G24 section 4.11: vault attribution renders only when two or more
// eligible vaults contribute, so a single-vault user never sees merge UI.
function multiVault() {
  return new Set(matches().map((m) => m.vault_slug).filter(Boolean)).size > 1;
}

// Locked-space chips ask the desktop to unlock (bridge.request_unlock,
// section 4.7 v2). No unlock route ever accepts a password here: the
// desktop shows the ask and its approval IS the unlock.
const [unlockRequested, setUnlockRequested] = createSignal(new Set());

async function askUnlock(c) {
  if (unlockRequested().has(c.slug)) return;
  try {
    await send("bridge.request_unlock", { slug: c.slug });
    const next = new Set(unlockRequested());
    next.add(c.slug);
    setUnlockRequested(next);
  } catch (e) {
    // Lifecycle errors must move the popup, not vanish into a signal the
    // ready view never renders.
    if (e.code === "locked" || e.code === "no-daemon" || e.code === "version-skew") {
      setStatePersisted(e.code);
    } else {
      setError(e.message);
    }
  }
}

// Pairing code typed by the user (audit C13): proves the pair_complete
// comes from the person watching the desktop ceremony panel.
const [pairCode, setPairCode] = createSignal("");

// First-run flag: persisted in chrome.storage.local. Onboarded users skip the
// welcome screen on subsequent opens.
const ONBOARDED_KEY = "onboarded";
// Last-known resting state, so reopening the popup shows something useful
// instantly instead of flashing "Loading…" while we re-probe the SW/NMH.
// Resting states are cached; "connecting" is cached too but only resumed
// within the pairing TTL (see boot()). "loading" / "welcome" are never.
const LAST_STATE_KEY = "last_state";
const CACHEABLE_STATES = new Set(["not-paired", "no-daemon", "locked", "ready", "connecting"]);

// Where to send users who don't have the app yet. Single source of truth.
const DOWNLOAD_URL = "https://baluard.app";

/// Reject after `ms`. Used to race against SW round-trips that may never
/// resolve (MV3 service worker can be GC'd mid-request, orphaning the popup's
/// sendMessage callback — leaving it stuck on "Loading…" forever).
function timeout(ms, label) {
  let timerId;
  const p = new Promise((_resolve, reject) => {
    timerId = setTimeout(() => reject(new TimeoutError(label)), ms);
  });
  // Losing racers must not leave their timers in the event loop.
  p.finally(() => clearTimeout(timerId)).catch(() => {});
  return p;
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
      setVaultChips([]);
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
    setVaultChips(data.vaults || []);
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
  const code = pairCode().trim();
  const browser = detectBrowser();
  if (!code) return;
  setStatePersisted("connecting");
  setError(null);
  try {
    // pair_complete carries the pairing code (audit C13). The daemon
    // verifies it before registering this caller as the ceremony waiter,
    // so a same-user process cannot silently win the pairing race. The
    // request is then held pending until the desktop user clicks Approve.
    // Race against the daemon TTL so a never-approved ceremony can't wedge
    // the popup — the user gets a clear expiry instead of a spinner.
    await Promise.race([
      send("bridge.pair_complete", { name: browser, browser, code }),
      timeout(PAIR_TTL_MS, "pair-timeout"),
    ]);
    // Paired! Mark onboarded + refresh into the ready state.
    await markOnboarded();
    refresh(true);
  } catch (e) {
    const strings = STRINGS[detectLocale()] || STRINGS.en;
    if (e.code === "pair-timeout") setError(strings.pairExpired);
    else if (/pair code/i.test(e.message || "")) setError(strings.wrongCode);
    else setError(e.message);
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
    // Slug-scoped reads always carry the tab URL: the daemon enforces the
    // URI match server-side even for a foreign (merge-eligible) vault.
    const payload = await send("vault.get", {
      id: entry.id,
      url: tabUrl(),
      vault_slug: entry.vault_slug || "",
    });
    const cred = JSON.parse(payload || "{}");
    // Fetch the fresh code when the entry has TOTP configured (cred.totp is
    // only a presence flag here — the seed itself is never read or stored).
    // content.js fills it only when a TOTP field exists on the page.
    let totpCode = "";
    if (cred.totp) {
      try {
        const t = await send("cipher.totp_code", {
          id: entry.id,
          url: tabUrl(),
          vault_slug: entry.vault_slug || "",
        });
        const raw = typeof t === "string" ? t : (t && t.payload) || "{}";
        totpCode = JSON.parse(raw).code || "";
      } catch {
        totpCode = "";
      }
      if (totpCode && copyTotpEnabled()) {
        clipboardCopy(totpCode).catch(() => {});
      }
    }
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id;
      if (tabId == null) return;
      chrome.scripting.executeScript({
        target: { tabId, frameIds: [0] }, // top-frame only (Decision 9)
        files: ["content.js"],
      }, () => {
        chrome.tabs.sendMessage(
          tabId,
          {
            type: "baluard-fill",
            // B1: origin (scheme+host+port), not hostname — blocks the
            // https -> http downgrade fill. content.js compares location.origin.
            expectedOrigin: originOf(tabUrl()),
            credential: {
              username: cred.username || "",
              password: cred.password || "",
              totpCode,
            },
          },
          { frameId: 0 }
        );
        window.close();
      });
    });
  } catch (e) {
    // Lifecycle errors must move the popup, not vanish into a signal the
    // ready view never renders.
    if (e.code === "locked" || e.code === "no-daemon" || e.code === "version-skew") {
      setStatePersisted(e.code);
    } else {
      setError(e.message);
    }
  }
}

function viewInApp(entry) {
  // Opens baluard://entry/<slug>/<id>; the OS hands it to the desktop app,
  // which navigates to the entry (asking for unlock first when locked).
  if (!entry?.id || !entry?.vault_slug) return;
  chrome.tabs.create({ url: `baluard://entry/${entry.vault_slug}/${entry.id}` });
}

async function copyField(entry, field) {
  try {
    const payload = await send("vault.get", {
      id: entry.id,
      url: tabUrl(),
      vault_slug: entry.vault_slug || "",
    });
    const cred = JSON.parse(payload || "{}");
    const val = cred[field] || "";
    await clipboardCopy(val);
    setCopied(`${field}-${entry.id}`);
    setTimeout(() => setCopied(""), 2000);
  } catch (e) {
    // Lifecycle errors must move the popup, not vanish into a signal the
    // ready view never renders.
    if (e.code === "locked" || e.code === "no-daemon" || e.code === "version-skew") {
      setStatePersisted(e.code);
    } else {
      setError(e.message);
    }
  }
}

// Degrees of border already drained (clockwise from 12 o'clock), empty
// when the row carries no usable period.
function totpSweepDeg(m) {
  if (!m.totp_period) return "";
  const periodMs = m.totp_period * 1000;
  const elapsed = ((nowSec() * 1000) % periodMs + periodMs) % periodMs;
  return `${((elapsed / periodMs) * 360).toFixed(2)}deg`;
}

async function copyTotp(entry) {
  try {
    const code = await send("cipher.totp_code", {
      id: entry.id,
      url: tabUrl(),
      vault_slug: entry.vault_slug || "",
    });
    const parsed = JSON.parse(code || "{}");
    await clipboardCopy(parsed.code || "");
    setCopied(`totp-${entry.id}`);
    setTimeout(() => setCopied(""), 2000);
  } catch (e) {
    // Lifecycle errors must move the popup, not vanish into a signal the
    // ready view never renders.
    if (e.code === "locked" || e.code === "no-daemon" || e.code === "version-skew") {
      setStatePersisted(e.code);
    } else {
      setError(e.message);
    }
  }
}



// Clipboard via an offscreen document (service worker has no DOM). The
// background.js handles the offscreen lifecycle; here we just post a message.
// B8: Firefox has no offscreen API — the SW signals {fallback: true} and
// the copy happens HERE, where the user gesture and document focus satisfy
// navigator.clipboard. Best-effort 20s auto-clear while the popup is open
// (mirrors the offscreen clear on Chrome; the timer dies with the popup).
function clipboardCopy(text) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ action: "clipboard-copy", text }, (resp) => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else if (resp && resp.ok && resp.fallback) {
        navigator.clipboard
          .writeText(text)
          .then(async () => {
            const seconds = normalizeClearSeconds((await getSettings()).clipboardClearSeconds);
            // Overwrite with a space (matches the offscreen clear):
            // clipboard managers record a space, not a captured secret.
            if (seconds > 0) {
              setTimeout(
                () => navigator.clipboard.writeText(" ").catch(() => {}),
                seconds * 1000
              );
            }
            resolve();
          })
          .catch(() => reject(new Error("clipboard failed")));
      } else if (resp && resp.ok) resolve();
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

onMount(() => {
  const iv = setInterval(() => setNowSec(Date.now() / 1000), 500);
  onCleanup(() => clearInterval(iv));
});
onMount(boot);
onMount(async () => {
  const s = await getSettings();
  setInlineAutofill(Boolean(s.inlineAutofill));
  setCopyTotpEnabled(Boolean(s.copyTotp));
  setClipboardClear(normalizeClearSeconds(s.clipboardClearSeconds));
});

// Flip the setting. The service worker listens for the storage change and
// registers/unregisters the inline content script (see background.js
// syncInlineScript). Takes effect on the next page load.
async function toggleInlineAutofill() {
  const next = await updateSettings({ inlineAutofill: !inlineAutofill() });
  setInlineAutofill(Boolean(next.inlineAutofill));
}

// Flip the clipboard-after-fill preference. Read by the service worker at
// fill time (background.js settingEnabled("copyTotp")).
async function toggleCopyTotp() {
  const next = await updateSettings({ copyTotp: !copyTotpEnabled() });
  setCopyTotpEnabled(Boolean(next.copyTotp));
}

// Change the clipboard auto-clear choice (select). Honored by the SW
// offscreen copy, this popup's Firefox fallback, and the inline fallback.
function changeClipboardClear(ev) {
  const seconds = normalizeClearSeconds(ev.currentTarget.value);
  updateSettings({ clipboardClearSeconds: seconds }).then((next) =>
    setClipboardClear(normalizeClearSeconds(next.clipboardClearSeconds))
  );
}

function App() {
  const t = (k) => (STRINGS[detectLocale()] || STRINGS.en)[k] || k;

  return (
    <div class="baluard-popup">
      {/* Brand styling using modern CSS custom properties and native nesting.
          Dark Mode is the default. Light Mode overrides via prefers-color-scheme media query. */}
      <style>{popupCss}</style>

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
          <label class="setting-row">
            <div class="setting-text">
              <div class="setting-name">{t("copyTotpTitle")}</div>
              <div class="state-desc">{t("copyTotpDesc")}</div>
            </div>
            <span class={`toggle ${copyTotpEnabled() ? "on" : ""}`}>
              <input
                type="checkbox"
                checked={copyTotpEnabled()}
                onChange={toggleCopyTotp}
                aria-label={t("copyTotpTitle")}
              />
              <span class="toggle-knob" aria-hidden="true"></span>
            </span>
          </label>
          <label class="setting-row">
            <div class="setting-text">
              <div class="setting-name">{t("clipboardClearTitle")}</div>
              <div class="state-desc">{t("clipboardClearDesc")}</div>
            </div>
            <select
              class="setting-select"
              value={clipboardClear()}
              onChange={changeClipboardClear}
              aria-label={t("clipboardClearTitle")}
            >
              <option value="10">{t("clear10")}</option>
              <option value="30">{t("clear30")}</option>
              <option value="60">{t("clear60")}</option>
              <option value="120">{t("clear120")}</option>
              <option value="0">{t("clearNever")}</option>
            </select>
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
          <label class="pair-code-label" for="pair-code-input">{t("pairCodeLabel")}</label>
          <input
            id="pair-code-input"
            class="pair-code-input"
            type="text"
            autocomplete="off"
            autocorrect="off"
            spellcheck="false"
            maxlength="8"
            placeholder={t("pairCodePlaceholder")}
            value={pairCode()}
            onInput={(e) =>
              setPairCode(e.currentTarget.value.toUpperCase().replace(/[^A-Z0-9]/g, ""))
            }
          />
        </div>
        <button onClick={connect} class="btn-primary" disabled={!pairCode()}>{t("connectCta")}</button>
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
        <button
          class="btn-secondary"
          onClick={async () => {
            // A ping is the only verb allowed to reconnect a skewed port;
            // after the desktop app updates, the handshake clears the skew.
            try { await send("ping", {}); } catch {}
            setState("loading");
            await boot();
          }}
        >
          {t("retry")}
        </button>
      </Show>

      <Show when={state() === "ready"}>
        <Show when={vaultChips().some((c) => !c.unlocked)}>
          <div class="vault-chips">
            <For each={vaultChips().filter((c) => !c.unlocked)}>
              {(c) => (
                <div
                  class={`vault-chip ${c.removed ? "danger" : "clickable"}`}
                  role={c.removed ? undefined : "button"}
                  title={c.removed ? undefined : t("askUnlock")}
                  onClick={c.removed ? undefined : () => askUnlock(c)}
                >
                  {c.removed
                    ? t("spaceRemoved")
                    : `${c.display_name} ${t("lockedChip")}${
                        unlockRequested().has(c.slug) ? ` ${t("unlockRequested")}` : ""
                      }`}
                </div>
              )}
            </For>
          </div>
        </Show>
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
                  <Show when={multiVault() && m.vault_name}>
                    <div class="match-vault">{m.vault_name}</div>
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
                    <button
                      class="btn-icon"
                      classList={{ "totp-ring": Boolean(m.totp && m.totp_period) }}
                      style={{ "--totp-sweep": totpSweepDeg(m) }}
                      onClick={() => copyTotp(m)}
                      title={t("copyTotp")}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="10" />
                        <polyline points="12 6 12 12 16 14" />
                      </svg>
                    </button>
                    <button class="btn-icon btn-icon--view" onClick={() => viewInApp(m)} title={t("viewInApp")}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                        <circle cx="12" cy="12" r="3" />
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

