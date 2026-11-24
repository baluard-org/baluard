import { render } from "solid-js/web";
import { createSignal, Show, For, onMount, onCleanup, createEffect } from "solid-js";
import { getSettings, updateSettings, normalizeClearSeconds } from "./settings.js";
import { originOf } from "./url.js";
import { probePasskeyPageState } from "./passkey-probe.js";
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
    // Passkey popout (WebAuthn ceremonies)
    passkeyBadge: "Passkey",
    passkeySaveTitle: "Save this passkey?",
    passkeySaveDesc: "Baluard stores a passkey for this site in your vault.",
    passkeySaveInto: "Add to an existing entry",
    passkeyNewEntry: "Create a new entry",
    passkeyPickTitle: "Sign in with Baluard?",
    passkeyPickDesc: "Choose the passkey to use for this site.",
    passkeyNotFoundTitle: "No passkey for this site",
    passkeyNotFoundDesc: "Baluard has no stored passkey for this site. Try another sign-in method.",
    passkeyExcludedTitle: "You already have a passkey here",
    passkeyExcludedDesc: "This site already has a passkey in your vault. Use it to sign in.",
    passkeyLockedTitle: "Unlock Baluard first",
    passkeyLockedDesc: "Open the Baluard app and unlock your vault, then try again.",
    passkeyRetry: "Retry",
    passkeyCancel: "Use another method",
    passkeyDone: "You can return to the site.",
    // Settings
    passkeysTitle: "Offer passkeys",
    passkeysDesc: "Baluard fills sign-in requests with passkeys stored in your vault. Requires the Baluard app.",
    passkeysUnsupported: "This browser cannot offer passkeys.",
    pkDiagOk: "Intercepting passkeys on this tab",
    pkDiagShadow: "Another password manager is claiming passkeys on this tab",
    pkDiagInactive: "Not intercepting on this tab yet — reload the page",
    pkDiagNoTab: "Open a website tab to check interception",
    pkDiagScripts: "passkey scripts registered",
    pkDiagTrail: "Recent passkey activity",
    defaultMgrTitle: "Make Baluard the default password manager",
    defaultMgrDesc: "Turns off the browser's offer to save passwords, so only Baluard asks to save your logins.",
  },
  es: {
    title: "Baluard",
    loading: "Cargando…",
    activeVault: "Bóveda",
    retry: "Reintentar",
    downloadApp: "Descargar la app de Baluard",
    // Welcome (first run)
    welcome: "Te damos la bienvenida a Baluard",
    welcomeDesc: "Baluard es un gestor de contraseñas privado. Esta extensión rellena tus accesos guardados en los sitios web. Tus contraseñas nunca salen de tu dispositivo.",
    haveApp: "Tengo Baluard instalado",
    // Not paired (onboarding guide)
    notPaired: "Conectar a Baluard",
    notPairedIntro: "Vincula este navegador con la app de Baluard para autocompletar tus contraseñas.",
    step1: "Abre la app de Baluard en este equipo",
    step2: 'En Ajustes, abre la pestaña "Extensiones de navegador" y haz clic en "Agregar extensión de navegador"',
    step3: "Escribe el código que muestra la app y conecta",
    pairCodeLabel: "Código de emparejamiento",
    pairCodePlaceholder: "Código de 8 caracteres",
    wrongCode: "El código no coincide. Revisa la app de Baluard e inténtalo de nuevo.",
    connectCta: "Conectar a Baluard",
    connect: "Esperando aprobación",
    connectDesc: "Haz clic en Aprobar en la app de Baluard.",
    // Daemon states
    appRequired: "Abre la app de Baluard",
    appRequiredDesc: "La app de Baluard debe estar abierta y desbloqueada para que la extensión funcione.",
    locked: "Bóveda bloqueada",
    lockedDesc: "Desbloquea la app de Baluard para rellenar contraseñas.",
    versionSkew: "Actualización necesaria",
    versionSkewDesc: "Esta extensión necesita una versión más reciente de Baluard. Por favor, actualiza la app.",
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
    spaceRemoved: "Es posible que ya no tengas acceso a este espacio.",
    askUnlock: "Haz clic para pedirle a Baluard que desbloquee esta bóveda",
    unlockRequested: "Desbloqueo solicitado.",
    // Settings
    settings: "Ajustes",
    back: "Volver",
    inlineAutofillTitle: "Mostrar sugerencias en formularios de inicio de sesión",
    inlineAutofillDesc: "Agrega un pequeño botón de Baluard junto a los campos de inicio de sesión. Haz clic en él para elegir una cuenta y rellenar el formulario sin abrir esta ventana. Tus contraseñas nunca se rellenan solas.",
    copyTotpTitle: "Copiar códigos de verificación al rellenar",
    copyTotpDesc: "Al rellenar un inicio de sesión que tiene código de verificación, también se copia el código para que puedas pegarlo en el siguiente paso. Se borra poco después.",
    clipboardClearTitle: "Vaciar el portapapeles después de",
    clipboardClearDesc: "Las contraseñas y códigos copiados se borran del portapapeles después de este tiempo.",
    clear10: "10 segundos",
    clear30: "30 segundos",
    clear60: "1 minuto",
    clear120: "2 minutos",
    clearNever: "Nunca",
    // Passkey popout (ceremonias WebAuthn)
    passkeyBadge: "Clave de acceso",
    passkeySaveTitle: "¿Guardar esta clave de acceso?",
    passkeySaveDesc: "Baluard guardará una clave de acceso para este sitio en tu bóveda.",
    passkeySaveInto: "Agregar a una entrada existente",
    passkeyNewEntry: "Crear una entrada nueva",
    passkeyPickTitle: "¿Iniciar sesión con Baluard?",
    passkeyPickDesc: "Elige la clave de acceso para este sitio.",
    passkeyNotFoundTitle: "No hay clave de acceso para este sitio",
    passkeyNotFoundDesc: "Baluard no tiene una clave de acceso guardada para este sitio. Prueba otro método para iniciar sesión.",
    passkeyExcludedTitle: "Ya tienes una clave de acceso aquí",
    passkeyExcludedDesc: "Este sitio ya tiene una clave de acceso en tu bóveda. Úsala para iniciar sesión.",
    passkeyLockedTitle: "Desbloquea Baluard primero",
    passkeyLockedDesc: "Abre la app de Baluard y desbloquea tu bóveda; después inténtalo de nuevo.",
    passkeyRetry: "Reintentar",
    passkeyCancel: "Usar otro método",
    passkeyDone: "Puedes volver al sitio.",
    // Ajustes
    passkeysTitle: "Ofrecer claves de acceso",
    passkeysDesc: "Baluard completa inicios de sesión con claves de acceso guardadas en tu bóveda. Requiere la app de Baluard.",
    passkeysUnsupported: "Este navegador no puede ofrecer claves de acceso.",
    pkDiagOk: "Interceptando claves de acceso en esta pestaña",
    pkDiagShadow: "Otro gestor de contraseñas está reclamando las claves de acceso en esta pestaña",
    pkDiagInactive: "Aún no intercepta en esta pestaña — recarga la página",
    pkDiagNoTab: "Abre una pestaña web para comprobar la intercepción",
    pkDiagScripts: "scripts de claves de acceso registrados",
    pkDiagTrail: "Actividad reciente de claves de acceso",
    defaultMgrTitle: "Usar Baluard como gestor de contraseñas predeterminado",
    defaultMgrDesc: "Desactiva el aviso del navegador para guardar contraseñas, de modo que solo Baluard te pregunte si quieres guardarlas.",
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
    step2: 'Em Configurações, abra a aba "Extensões do navegador" e clique em "Adicionar extensão"',
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
    viewInApp: "Ver no app Baluard",
    copied: "Copiado",
    refresh: "Atualizar",
    // G24 merged surfaces
    lockedChip: "está bloqueado. Abra o Baluard.",
    spaceRemoved: "Pode ser que você não tenha mais acesso a este espaço.",
    askUnlock: "Clique para pedir ao app Baluard para desbloquear este cofre",
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
    // Pop-up de passkey (cerimônias WebAuthn)
    passkeyBadge: "Chave de acesso",
    passkeySaveTitle: "Salvar esta chave de acesso?",
    passkeySaveDesc: "O Baluard guardará uma chave de acesso para este site no seu cofre.",
    passkeySaveInto: "Adicionar a uma entrada existente",
    passkeyNewEntry: "Criar uma nova entrada",
    passkeyPickTitle: "Entrar com o Baluard?",
    passkeyPickDesc: "Escolha a chave de acesso para este site.",
    passkeyNotFoundTitle: "Sem chave para este site",
    passkeyNotFoundDesc: "O Baluard não tem uma chave de acesso guardada para este site. Tente outro método de login.",
    passkeyExcludedTitle: "Você já tem uma chave aqui",
    passkeyExcludedDesc: "Este site já tem uma chave de acesso no seu cofre. Use-a para entrar.",
    passkeyLockedTitle: "Desbloqueie o Baluard antes",
    passkeyLockedDesc: "Abra o app Baluard e desbloqueie seu cofre, depois tente novamente.",
    passkeyRetry: "Tentar novamente",
    passkeyCancel: "Usar outro método",
    passkeyDone: "Você pode voltar ao site.",
    // Configurações
    passkeysTitle: "Oferecer chaves de acesso",
    passkeysDesc: "O Baluard completa logins com chaves de acesso guardadas no seu cofre. Requer o app Baluard.",
    passkeysUnsupported: "Este navegador não pode oferecer chaves de acesso.",
    pkDiagOk: "Interceptando chaves de acesso nesta aba",
    pkDiagShadow: "Outro gerenciador de senhas está reivindicando as chaves de acesso nesta aba",
    pkDiagInactive: "Ainda não intercepta nesta aba — recarregue a página",
    pkDiagNoTab: "Abra uma aba de site para verificar a interceptação",
    pkDiagScripts: "scripts de chaves de acesso registrados",
    pkDiagTrail: "Atividade recente de chaves de acesso",
    defaultMgrTitle: "Usar o Baluard como gerenciador de senhas padrão",
    defaultMgrDesc: "Desativa o aviso do navegador para salvar senhas, para que apenas o Baluard peça para salvar seus logins.",
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
const [defaultMgrEnabled, setDefaultMgrEnabled] = createSignal(false);
// Row renders only where the browser ships the control (Chrome-family and
// Firefox do; the guard keeps honest UI on anything else).
const defaultMgrAvailable = Boolean(
  chrome.privacy?.services?.passwordSavingEnabled
);
const [clipboardClear, setClipboardClear] = createSignal(60);
const [passkeysEnabled, setPasskeysEnabled] = createSignal(false);
const [passkeysSupported, setPasskeysSupported] = createSignal(true);
// Diagnostics (settings view): SW-side facts + the active tab's MAIN-world
// probe. Loaded when the settings view opens with passkeys on.
const [pkDiag, setPkDiag] = createSignal(null);
const [pkProbe, setPkProbe] = createSignal(null);

async function refreshPasskeyDiagnostics() {
  if (!passkeysEnabled() || !passkeysSupported()) return;
  // Reset first: a probe that cannot run (no http tab) must not keep the
  // previous tab's verdict on screen.
  setPkProbe(null);
  setPkDiag(null);
  try {
    // send() resolves with the payload itself.
    const payload = await send("passkey.diagnostics");
    if (payload) setPkDiag(payload);
  } catch {}
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.id && /^https?:/i.test(tab.url || "")) {
      const frames = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: "MAIN",
        func: probePasskeyPageState,
      });
      if (frames && frames[0] && frames[0].result) setPkProbe(frames[0].result);
    }
  } catch {}
}
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
        // Same surfacing as copyField: a silent copy failure would leave the
        // user pasting nothing at the 2FA step.
        clipboardCopy(totpCode).catch((e) => setError(e.message));
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
  setPasskeysEnabled(Boolean(s.enablePasskeys));
  setDefaultMgrEnabled(Boolean(s.defaultPasswordManager));
  // Support = the SW never recorded a failed MAIN-world registration (old
  // Firefox) and the scripting API exists. Read straight from storage so
  // no extra message route is needed.
  const flags = await Promise.resolve(
    chrome.storage.local.get(["passkeysWorldUnsupported"])
  ).catch(() => ({}));
  setPasskeysSupported(
    !flags.passkeysWorldUnsupported &&
      typeof chrome.scripting?.registerContentScripts === "function"
  );
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

async function togglePasskeys() {
  const next = await updateSettings({ enablePasskeys: !passkeysEnabled() });
  setPasskeysEnabled(Boolean(next.enablePasskeys));
  // The SW reverts the flag itself when registration fails (Firefox < 128);
  // re-read so the hint appears on the next render tick.
  setTimeout(async () => {
    const r = await chrome.storage.local.get(["passkeysWorldUnsupported"]);
    setPasskeysSupported(!r.passkeysWorldUnsupported);
    const cur = await getSettings();
    setPasskeysEnabled(Boolean(cur.enablePasskeys));
  }, 400);
}

// Flip the default-manager control. The service worker listens for the
// storage change and applies chrome.privacy (see background.js
// applyDefaultPasswordManager). Takes effect immediately.
async function toggleDefaultMgr() {
  const next = await updateSettings({ defaultPasswordManager: !defaultMgrEnabled() });
  setDefaultMgrEnabled(Boolean(next.defaultPasswordManager));
}

function App() {
  const t = (k) => (STRINGS[detectLocale()] || STRINGS.en)[k] || k;
  // Reads all three gates so boot-order and toggle flips re-probe.
  createEffect(() => {
    const open = settingsOpen();
    const enabled = passkeysEnabled();
    const supported = passkeysSupported();
    if (open && enabled && supported) void refreshPasskeyDiagnostics();
  });

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
              <div class="setting-name">{t("passkeysTitle")}</div>
              <div class="state-desc">
                {passkeysSupported() ? t("passkeysDesc") : t("passkeysUnsupported")}
              </div>
            </div>
            <span class={`toggle ${passkeysEnabled() ? "on" : ""}`}>
              <input
                type="checkbox"
                checked={passkeysEnabled()}
                disabled={!passkeysSupported()}
                onChange={togglePasskeys}
                aria-label={t("passkeysTitle")}
              />
              <span class="toggle-knob" aria-hidden="true"></span>
            </span>
          </label>
          <Show when={passkeysEnabled() && passkeysSupported()}>
            <div class="pk-diag">
              <div
                class={`pk-diag-status ${
                  pkProbe()
                    ? pkProbe().shadow
                      ? "pk-diag-warn"
                      : pkProbe().wrap
                        ? "pk-diag-ok"
                        : ""
                    : ""
                }`}
              >
                {pkProbe()
                  ? pkProbe().shadow
                    ? `⚠ ${t("pkDiagShadow")}`
                    : pkProbe().wrap
                      ? `✓ ${t("pkDiagOk")}`
                      : t("pkDiagInactive")
                  : t("pkDiagNoTab")}
              </div>
              <Show when={pkDiag()}>
                <div class="pk-diag-meta">
                  {pkDiag().registered.length}/2 {t("pkDiagScripts")} — v{""}
                  {pkDiag().versions.extension ?? "—"}, NMH {pkDiag().versions.nmh ?? "—"}
                  {pkDiag().versions.proto ? `, proto ${pkDiag().versions.proto}` : ""}
                </div>
                <Show when={pkDiag().pkTrail.length > 0}>
                  <details class="pk-diag-trail">
                    <summary>{t("pkDiagTrail")}</summary>
                    <For each={pkDiag().pkTrail}>
                      {(entry) => <div class="pk-diag-trail-row">{entry}</div>}
                    </For>
                  </details>
                </Show>
              </Show>
            </div>
          </Show>
          <Show when={defaultMgrAvailable}>
            <label class="setting-row">
              <div class="setting-text">
                <div class="setting-name">{t("defaultMgrTitle")}</div>
                <div class="state-desc">{t("defaultMgrDesc")}</div>
              </div>
              <span class={`toggle ${defaultMgrEnabled() ? "on" : ""}`}>
                <input
                  type="checkbox"
                  checked={defaultMgrEnabled()}
                  onChange={toggleDefaultMgr}
                  aria-label={t("defaultMgrTitle")}
                />
                <span class="toggle-knob" aria-hidden="true"></span>
              </span>
            </label>
          </Show>
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
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" stroke="none">
                        <path d="M2,17h20v2H2V17z M3.15,12.95L4,11.47l0.85,1.48l1.3-0.75L5.3,10.72H7v-1.5H5.3l0.85-1.47L4.85,7L4,8.47L3.15,7l-1.3,0.75L2.7,9.22H1v1.5h1.7L1.85,12.2L3.15,12.95z M9.85,12.2l1.3,0.75L12,11.47l0.85,1.48l1.3-0.75l-0.85-1.48H15v-1.5h-1.7l0.85-1.47L12.85,7L12,8.47L11.15,7l-1.3,0.75l0.85,1.47H9v1.5h1.7L9.85,12.2z M23,9.22h-1.7l0.85-1.47L20.85,7L20,8.47L19.15,7l-1.3,0.75l0.85,1.47H17v1.5h1.7l-0.85,1.48l1.3,0.75L20,11.47l0.85,1.48l1.3-0.75l-0.85-1.48H23V9.22z" />
                      </svg>
                    </button>
                    {/* A row without the flag comes from a daemon older than 0.1.7. */}
                    <button
                      class="btn-icon"
                      classList={{ "totp-ring": Boolean(m.totp && m.totp_period) }}
                      style={{ "--totp-sweep": totpSweepDeg(m) }}
                      onClick={() => copyTotp(m)}
                      disabled={m.totp === false}
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
                  <button class="btn-primary-mini" onClick={() => fill(m)}>
                    <svg version="1.1" xmlns="http://www.w3.org/2000/svg" style="display: block; margin-right: 4px;" viewBox="398 241 1210 1186" width="12" height="12" fill="currentColor" aria-hidden="true">
                      <path fill-rule="evenodd" d="M 1122.13 596.276 C 1165.63 593.389 1180.97 627.138 1210.25 652.948 C 1218.84 660.529 1225.32 672.212 1227.69 683.437 C 1234.94 717.702 1215.22 733.967 1193.57 755.648 L 1153.64 795.602 L 1001.65 947.544 L 693.63 1255.53 L 593.963 1355.23 C 576.65 1372.55 559.163 1390.32 541.54 1407.32 C 533.773 1414.81 523.021 1418.82 512.584 1421.01 C 499.334 1421.92 480.812 1420.85 470.686 1411.27 C 449.043 1390.77 409.712 1361.26 403.906 1331.16 C 397.263 1296.71 424.914 1276.08 446.213 1254.75 L 496.249 1204.71 L 672.873 1028.09 L 953.028 747.921 L 1044.14 656.732 C 1059.82 641.056 1075.75 624.734 1091.82 609.474 C 1099.99 601.726 1111.19 598.066 1122.13 596.276 z M 1127.27 639.072 C 1130.08 639.359 1133.73 639.84 1136.09 641.516 C 1147.37 649.832 1155.79 661.024 1166.09 670.677 C 1173.19 677.334 1186.13 687.382 1185.86 697.879 C 1185.8 700.277 1179.44 708.003 1177.59 709.874 C 1135.59 752.344 1093.09 794.372 1050.88 836.621 C 1049.09 838.417 1049.71 837.984 1047.35 837.845 L 985.97 776.392 L 1077.24 685.135 C 1086.67 675.699 1117.43 642.611 1127.27 639.072 z" />
                      <path d="M 1396.34 246.061 C 1415.58 246.131 1417.04 267.793 1423.37 283.05 C 1433.88 308.337 1449 331.449 1467.97 351.207 C 1484.69 368.486 1504.13 382.909 1525.52 393.902 C 1535.33 398.917 1545.99 403.599 1556.82 406.98 C 1567.33 410.259 1583.55 416.818 1577.67 431.392 C 1573.25 442.334 1548.59 447.505 1537.14 452.668 C 1489.67 473.505 1451.21 510.625 1428.71 557.328 C 1423.12 568.834 1419.72 578.606 1415.42 590.607 C 1411.95 600.283 1410.44 602.096 1401.67 606.028 C 1383.08 606.308 1381.62 588.551 1376.13 574.016 C 1356.57 523.317 1318.83 481.721 1270.27 457.338 C 1256.26 450.31 1243.65 446.262 1229.2 440.652 C 1224.83 438.87 1220.84 435.445 1219.51 430.754 C 1213.7 410.268 1246.45 405.824 1261.4 399.009 C 1272.22 394.141 1282.64 388.429 1292.56 381.926 C 1327.75 358.649 1355.49 325.73 1372.47 287.106 C 1377.15 276.688 1379.78 265.978 1384.54 255.72 C 1387.43 249.495 1390.14 248.121 1396.34 246.061 z" />
                      <path d="M 1337.16 766.908 C 1351.53 767.512 1351.28 780.746 1356.01 792.027 C 1362.89 808.446 1370.98 820.144 1382.33 833.568 C 1402.14 856.993 1427.55 867.761 1455.04 878.907 C 1458.61 880.359 1460.32 886.912 1458.83 890.343 C 1455.95 897.015 1442.66 900.7 1436.09 903.349 C 1403.1 916.286 1376.12 941.046 1360.4 972.801 C 1353.71 986.005 1352.51 1001.22 1342.05 1007.1 C 1327.26 1006.14 1328.21 993.532 1323.02 981.558 C 1307.57 945.944 1278.88 916.167 1241.95 902.994 C 1235.95 900.855 1225.79 897.004 1221.34 892.277 C 1218.39 887.574 1220.12 880.606 1225.55 878.335 C 1248.52 868.717 1267.98 861.436 1286.92 843.905 C 1296.9 834.558 1305.58 823.907 1312.71 812.241 C 1321.39 797.951 1325.03 785.518 1332.22 770.727 C 1332.71 769.731 1336.01 767.613 1337.16 766.908 z" />
                      <path d="M 1521.99 624.782 C 1530.47 625.43 1532.59 633.197 1535.51 640.719 C 1544.59 664.175 1562 681.179 1584.91 691.266 C 1590.95 693.927 1599.44 695.162 1602.53 700.814 C 1600.99 709.141 1583.39 713.098 1575.66 717.526 C 1558.01 727.634 1546 740.866 1537.31 759.266 C 1534.2 765.849 1531.8 772.851 1528.22 779.067 L 1522.97 778.678 C 1516.44 774.937 1510.35 752.637 1503.81 744.321 C 1494.74 732.791 1491.08 729.246 1479.01 720.892 C 1469.47 714.297 1451.97 711.31 1447.99 702.843 C 1448.21 701.136 1448.54 697.681 1450.46 696.979 C 1478.98 686.558 1503.73 669.648 1514.23 639.736 C 1515.7 635.557 1518.83 628.333 1521.99 624.782 z" />
                    </svg>
                    {t("fill")}
                  </button>
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

// ── Passkey popout (WebAuthn ceremony UI) ──
// The service worker opens this page as a small popup window
// (popup.html#/passkey/<sessionId>) whenever a ceremony needs a decision:
// registration save-target, assertion pick, not-found/excluded notices, or
// the unlock-and-retry prompt. All decisions ride runtime messaging back to
// the SW (passkey.ui.*); the SW closes the window after acting.
function BaluardLogo(props) {
  const id = props.id || "pop";
  return (
    <svg width="18" height="18" viewBox="0 0 512 512" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <defs>
        <linearGradient id={`${id}-shackle`} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#ded8fc" />
          <stop offset="100%" stop-color="#cfc6f9" />
        </linearGradient>
        <linearGradient id={`${id}-body`} x1="20%" y1="0%" x2="80%" y2="100%">
          <stop offset="0%" stop-color="#c5f279" />
          <stop offset="50%" stop-color="#b3e55c" />
          <stop offset="100%" stop-color="#9dce47" />
        </linearGradient>
      </defs>
      <path d="M 172 205 V 150 C 172 103 209 66 256 66 C 303 66 340 103 340 150 V 205 H 294 V 150 C 294 128 277 111 256 111 C 235 111 218 128 218 150 V 205 Z" fill={`url(#${id}-shackle)`} />
      <path d="M 136 205 H 184 V 228 H 228 V 205 H 284 V 228 H 328 V 205 H 376 C 384 205 388 209 388 217 V 405 C 388 424 374 438 355 438 H 157 C 138 438 124 424 124 405 V 217 C 124 209 128 205 136 205 Z" fill={`url(#${id}-body)`} />
      <path d="M317.8351477449456 361.56298600311044Q317.8351477449456 347.19284603421465 304.98911353032656 337.6127527216174L281.6920684292379 320.4121306376361L295.6267496111975 309.5256609642302Q303.02954898911355 303.646967340591 303.02954898911355 294.50233281493Q303.02954898911355 280.56765163297047 288.8771384136858 272.07620528771383Q276.68429237947123 264.89113530326597 262.0964230171073 264.89113530326597Q248.59720062208396 264.89113530326597 226.82426127527214 273.38258164852255Q211.800933125972 279.04354587869364 203.09175738724727 282.3094867807154Q194.38258164852255 285.5754276827372 191.98755832037324 286.01088646967344V291.0186625194401Q205.05132192846034 296.8973561430793 205.05132192846034 315.6220839813375V377.45723172628306Q205.05132192846034 383.9891135303266 199.17262830482113 394.0046656298601L193.51166407465007 403.8024883359254V408.37480559875587Q202.00311041990668 404.67340590979785 204.18040435458786 404.0202177293935Q208.09953343701397 402.27838258164854 216.3732503888025 402.27838258164854Q223.12286158631414 402.27838258164854 237.71073094867805 405.3265940902022Q252.29860031104198 408.37480559875587 259.04821150855366 408.37480559875587Q276.248833592535 408.37480559875587 296.27993779160187 393.78693623639197Q317.8351477449456 377.8926905132193 317.8351477449456 361.56298600311044ZM278.6438569206843 294.50233281493Q278.6438569206843 302.99377916018665 269.71695178849143 311.9206842923795Q264.7091757387247 316.9284603421462 250.3390357698289 325.2021772939347Q244.67807153965785 328.4681181959565 240.3234836702955 331.40746500777607Q235.96889580093313 334.3468118195957 232.92068429237946 336.74183514774495Q232.48522550544322 336.3063763608087 231.61430793157075 336.3063763608087Q231.61430793157075 336.3063763608087 229.43701399688956 336.74183514774495L229.00155520995332 319.5412130637636L228.7838258164852 302.1228615863142Q228.34836702954897 290.58320373250393 238.14618973561429 282.3094867807154Q247.50855365474337 274.68895800933126 259.04821150855366 274.68895800933126Q262.9673405909798 274.68895800933126 266.55987558320373 276.3219284603422Q270.15241057542767 277.95489891135304 272.7651632970451 280.67651632970455Q275.3779160186625 283.398133748056 277.01088646967344 286.99066874027994Q278.6438569206843 290.58320373250393 278.6438569206843 294.50233281493ZM288.4416796267496 372.8849144634526Q288.4416796267496 382.4650077760498 279.29704510108866 389.8678071539658Q269.93468118195955 397.48833592534993 260.57231726283044 397.48833592534993Q244.2426127527216 397.48833592534993 236.18662519440124 383.5536547433904Q229.43701399688956 372.23172628304826 229.43701399688956 354.81337480559876Q229.43701399688956 351.76516329704515 240.5412130637636 344.144634525661Q251.86314152410574 336.74183514774495 255.78227060653188 336.74183514774495Q262.7496111975116 336.74183514774495 275.59564541213064 351.1119751166408Q288.4416796267496 365.6998444790047 288.4416796267496 372.8849144634526Z" fill="#091315" />
    </svg>
  );
}

function PasskeyPopout(props) {
  const t = (k) => (STRINGS[detectLocale()] || STRINGS.en)[k] || k;
  const [view, setView] = createSignal(null); // uiState payload or {gone}
  const [busy, setBusy] = createSignal(false);

  async function pull() {
    const r = await chrome.runtime
      .sendMessage({ action: "passkey.ui.state", sessionId: props.sessionId })
      .catch(() => null);
    if (!r || !r.ok) {
      setView({ gone: true });
      return;
    }
    setView(r.payload);
    if (r.payload.gone) setTimeout(() => window.close(), 400);
  }

  async function decide(decision) {
    // One decision per ceremony: a rapid double Enter/click must not push
    // the assertion twice to the service worker.
    if (busy()) return;
    setBusy(true);
    const r = await chrome.runtime
      .sendMessage({ action: "passkey.ui.decide", sessionId: props.sessionId, decision })
      .catch(() => null);
    setBusy(false);
    if (!r || !r.ok) {
      setView({ gone: true });
      setTimeout(() => window.close(), 400);
      return;
    }
    // Decisions either finish the ceremony (window closes server-side) or
    // return fresh state (retry loops).
    await pull();
  }

  onMount(() => {
    document.body.classList.add("is-popout");
    void pull();
  });
  onCleanup(() => {
    document.body.classList.remove("is-popout");
  });

  const v = () => view() || {};
  const show = (kind) => v().kind === kind;

  const PasskeyKeyIcon = (iconProps) => (
    <svg width={iconProps.size || 16} height={iconProps.size || 16} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
    </svg>
  );

  const GlobeIcon = () => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="10" />
      <line x1="2" y1="12" x2="22" y2="12" />
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
  );

  const ChevronIcon = () => (
    <svg class="pk-option-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <polyline points="9 18 15 12 9 6" />
    </svg>
  );

  return (
    <div class="baluard-popup is-popout">
      <style>{popupCss}</style>
      <div class="popup-header">
        <div style="display: flex; align-items: center; gap: 8px;">
          <BaluardLogo id="pk" />
          <strong class="brand-title">{t("title")}</strong>
        </div>
        <span class="pk-badge">
          <PasskeyKeyIcon size={11} />
          {t("passkeyBadge")}
        </span>
      </div>
      <Show when={!v().gone} fallback={
        <div class="pk-status-card">
          <div class="pk-status-icon">
            <PasskeyKeyIcon size={16} />
          </div>
          <div class="pk-status-body">
            <div class="state-desc">{t("passkeyDone")}</div>
          </div>
        </div>
      }>
        <Show when={show("confirmRegister")}>
          <div class="pk-hero">
            <div class="pk-title">{t("passkeySaveTitle")}</div>
            <div class="pk-desc">{t("passkeySaveDesc")}</div>
            {/* The rpId is the daemon-validated site identity; the page-supplied rp.name is never displayed. */}
            <div class="pk-site-row">
              <span class="pk-site-pill">
                <GlobeIcon />
                {v().rpId}
              </span>
              <Show when={v().userName}>
                <span class="pk-user-pill">{v().userName}</span>
              </Show>
            </div>
          </div>
          <Show when={(v().siteRows || []).length > 0}>
            <div class="pk-section-label">{t("passkeySaveInto")}</div>
            <div class="matches-list">
              <For each={v().siteRows}>
                {(row) => (
                  <div
                    class="match-card pk-option"
                    role="button"
                    tabIndex={0}
                    aria-disabled={busy()}
                    onClick={() => !busy() && decide({ kind: "confirmRegister", cipher_id: row.cipher_id, vault_slug: row.vault_slug })}
                    onKeyDown={(e) => e.key === "Enter" && decide({ kind: "confirmRegister", cipher_id: row.cipher_id, vault_slug: row.vault_slug })}
                  >
                    <div class="pk-option-icon">
                      <PasskeyKeyIcon size={17} />
                    </div>
                    <div class="match-info">
                      <div class="match-name">{row.name}</div>
                      <Show when={row.username}>
                        <div class="match-user">{row.username}</div>
                      </Show>
                    </div>
                    <ChevronIcon />
                  </div>
                )}
              </For>
            </div>
          </Show>
          <div class="pk-footer">
            <button
              class="btn-primary"
              disabled={busy()}
              onClick={() => decide({ kind: "confirmRegister", new_login: { name: v().rpName, username: v().userName || undefined } })}
            >
              {t("passkeyNewEntry")}
            </button>
          </div>
        </Show>
        <Show when={show("pickAssertion")}>
          <div class="pk-hero">
            <div class="pk-title">{t("passkeyPickTitle")}</div>
            <div class="pk-desc">{t("passkeyPickDesc")}</div>
            <div class="pk-site-row">
              <span class="pk-site-pill">
                <GlobeIcon />
                {v().rpId}
              </span>
            </div>
          </div>
          <div class="matches-list">
            <For each={v().rows || []}>
              {(row) => (
                <div
                  class="match-card pk-option"
                  role="button"
                  tabIndex={0}
                  aria-disabled={busy()}
                  onClick={() => !busy() && decide({ kind: "pickAssertion", credential_id: row.credential_id })}
                  onKeyDown={(e) => e.key === "Enter" && decide({ kind: "pickAssertion", credential_id: row.credential_id })}
                >
                  <div class="pk-option-icon">
                    <PasskeyKeyIcon size={17} />
                  </div>
                  <div class="match-info">
                    <div class="match-name">{row.name}</div>
                    <Show when={row.username}>
                      <div class="match-user">{row.username}</div>
                    </Show>
                  </div>
                  <ChevronIcon />
                </div>
              )}
            </For>
          </div>
          <div class="pk-footer">
            <button class="btn-ghost" disabled={busy()} onClick={() => decide({ kind: "cancel" })}>
              {t("passkeyCancel")}
            </button>
          </div>
        </Show>
        <Show when={show("notFound")}>
          <div class="pk-status-card">
            <div class="pk-status-icon">
              <PasskeyKeyIcon size={17} />
            </div>
            <div class="pk-status-body">
              <div class="state-title">{t("passkeyNotFoundTitle")}</div>
              <div class="state-desc">{t("passkeyNotFoundDesc")}</div>
            </div>
          </div>
          <div class="pk-footer">
            <button class="btn-secondary" onClick={() => decide({ kind: "dismiss" })}>
              {t("passkeyCancel")}
            </button>
          </div>
        </Show>
        <Show when={show("excluded")}>
          <div class="pk-status-card">
            <div class="pk-status-icon">
              <PasskeyKeyIcon size={17} />
            </div>
            <div class="pk-status-body">
              <div class="state-title">{t("passkeyExcludedTitle")}</div>
              <div class="state-desc">{t("passkeyExcludedDesc")}</div>
            </div>
          </div>
          <div class="pk-footer">
            <button class="btn-secondary" onClick={() => decide({ kind: "dismiss" })}>
              {t("passkeyCancel")}
            </button>
          </div>
        </Show>
        <Show when={show("locked")}>
          <div class="pk-status-card danger">
            <div class="pk-status-icon">
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
            </div>
            <div class="pk-status-body">
              <div class="state-title">{t("passkeyLockedTitle")}</div>
              <div class="state-desc">{t("passkeyLockedDesc")}</div>
            </div>
          </div>
          <div class="pk-footer">
            <button class="btn-primary" disabled={busy()} onClick={() => decide({ kind: "retryUnlock" })}>
              {t("passkeyRetry")}
            </button>
            <button class="btn-ghost" disabled={busy()} onClick={() => decide({ kind: "cancel" })}>
              {t("passkeyCancel")}
            </button>
          </div>
        </Show>
      </Show>
    </div>
  );
}

// Route: the popup doubles as the passkey ceremony popout via the hash
// (popup.html#/passkey/<sessionId>) that the service worker appends when it
// opens the window.
const passkeySession = (location.hash || "").match(/^#\/passkey\/(.+)$/);
render(
  () =>
    passkeySession ? (
      <PasskeyPopout sessionId={decodeURIComponent(passkeySession[1])} />
    ) : (
      <App />
    ),
  document.body
);

