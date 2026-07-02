import { render } from "solid-js/web";
import { createSignal, Show, For, onMount } from "solid-js";

// Phase 1 popup: pairing ceremony + URL-filtered login list + autofill/copy.
//
// States: loading -> { not-paired | version-skew | locked | ready | no-daemon }
//   ready:     bridge.match returned matches for the active tab URL; show list.
//   notPaired: extension has no pairing; show Connect (triggers pair_complete,
//              held pending until the desktop user Approves).
//   locked:    daemon up but active vault locked; prompt to open the app.
//   noDaemon:  NMH couldn't reach the daemon socket.
//   versionSkew: NMH version < required; extension refuses (background.js gate).
//
// Per Decision 2: popup holds NO secrets. The bridge token lives in the NMH.

// Minimal i18n. The extension bundles its own strings (review sonnet B-5:
// every error code -> friendly actionable message, no hard tech terms).
// Mirrors the desktop's en/es shape so the two can stay in sync.
const STRINGS = {
  en: {
    title: "Baluard",
    loading: "Loading...",
    activeVault: "Vault",
    appRequired: "Open the Baluard app",
    appRequiredDesc: "The Baluard desktop app must be running and unlocked.",
    locked: "Vault locked",
    lockedDesc: "Unlock the Baluard app to fill passwords.",
    notPaired: "Connect to Baluard",
    notPairedDesc: "Open the Baluard app, go to Settings > Browser extensions, and add one.",
    connect: "Waiting for approval",
    connectDesc: "Tap Approve in the Baluard app.",
    versionSkew: "Update required",
    versionSkewDesc: "Update the Baluard desktop app.",
    search: "Search",
    noMatches: "No logins for this site",
    fill: "Fill",
    copyUser: "Copy username",
    copyPass: "Copy password",
    copyTotp: "Copy code",
    copied: "Copied",
    refresh: "Refresh",
  },
  es: {
    title: "Baluard",
    loading: "Cargando...",
    activeVault: "Caja fuerte",
    appRequired: "Abre la app de Baluard",
    appRequiredDesc: "La app de escritorio de Baluard debe estar abierta y desbloqueada.",
    locked: "Caja fuerte bloqueada",
    lockedDesc: "Desbloquea la app de Baluard para rellenar contraseñas.",
    notPaired: "Conectar a Baluard",
    notPairedDesc: "Abre la app de Baluard, ve a Ajustes > Extensiones, y añade una.",
    connect: "Esperando aprobación",
    connectDesc: "Pulsa Aprobar en la app de Baluard.",
    versionSkew: "Actualización necesaria",
    versionSkewDesc: "Actualiza la app de escritorio de Baluard.",
    search: "Buscar",
    noMatches: "No hay inicios de sesión para este sitio",
    fill: "Rellenar",
    copyUser: "Copiar usuario",
    copyPass: "Copiar contraseña",
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

async function refresh() {
  setState("loading");
  setError(null);
  try {
    // Get the active tab URL for matching.
    const url = await getActiveTabUrl();
    setTabUrl(url);
    if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) {
      // Non-web tab: show ready-but-empty (no autofill context).
      setMatches([]);
      setActiveVault("");
      setState("ready");
      return;
    }
    const payload = await send("bridge.match", { url });
    const data = JSON.parse(payload || "{}");
    setMatches(data.matches || []);
    // Active vault name comes back with the match response if available.
    setActiveVault(data.active_vault || "");
    setState("ready");
  } catch (e) {
    setError(e.message);
    // Map the NMH error code to a popup state.
    if (e.code === "not-paired") setState("not-paired");
    else if (e.code === "locked") setState("locked");
    else if (e.code === "no-daemon") setState("no-daemon");
    else if (e.code === "version-skew") setState("version-skew");
    else setState("error");
  }
}

function getActiveTabUrl() {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      resolve(tabs[0]?.url || "");
    });
  });
}

async function connect() {
  setState("connecting");
  setError(null);
  try {
    // pair_complete is held pending on the daemon side until the desktop
    // user clicks Approve. This await resolves once approved.
    await send("bridge.pair_complete", { name: detectBrowser(), browser: detectBrowser() });
    // Paired! Refresh into the ready state.
    refresh();
  } catch (e) {
    setError(e.message);
    setState("not-paired");
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
    // Send the credential to the content script in the active tab for fill.
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
    // totp_code returns a JSON blob like {"code":"123456","period":30}
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

onMount(refresh);

function App() {
  const t = (k) => (STRINGS[detectLocale()] || STRINGS.en)[k] || k;

  return (
    <div style={{ width: "320px", "font-family": "system-ui, sans-serif", padding: "12px" }}>
      <div style={{ display: "flex", "align-items": "center", "justify-content": "space-between", "margin-bottom": "10px" }}>
        <strong style={{ "font-size": "14px" }}>{t("title")}</strong>
        <Show when={activeVault()}>
          <span style={{ "font-size": "10px", color: "#888" }}>{t("activeVault")}: {activeVault()}</span>
        </Show>
      </div>

      <Show when={state() === "loading"}>
        <div style={{ "font-size": "12px", color: "#666" }}>{t("loading")}</div>
      </Show>

      <Show when={state() === "no-daemon"}>
        <StateBlock title={t("appRequired")} desc={t("appRequiredDesc")} color="#c00" />
      </Show>
      <Show when={state() === "locked"}>
        <StateBlock title={t("locked")} desc={t("lockedDesc")} color="#c00" />
      </Show>
      <Show when={state() === "version-skew"}>
        <StateBlock title={t("versionSkew")} desc={t("versionSkewDesc")} color="#c00" />
      </Show>

      <Show when={state() === "not-paired"}>
        <StateBlock title={t("notPaired")} desc={t("notPairedDesc")} color="#666" />
        <button onClick={connect} style={btnStyle()}>{t("connect")}</button>
      </Show>

      <Show when={state() === "connecting"}>
        <StateBlock title={t("connect")} desc={t("connectDesc")} color="#666" />
      </Show>

      <Show when={state() === "ready"}>
        <Show when={matches().length === 0}>
          <div style={{ "font-size": "12px", color: "#666", "margin-bottom": "8px" }}>{t("noMatches")}</div>
        </Show>
        <For each={matches()}>
          {(m) => (
            <div style={{ border: "1px solid #e5e5e5", "border-radius": "6px", padding: "8px", "margin-bottom": "6px" }}>
              <div style={{ "font-size": "12px", "font-weight": "bold" }}>{m.name}</div>
              <Show when={m.username}>
                <div style={{ "font-size": "11px", color: "#666" }}>{m.username}</div>
              </Show>
              <div style={{ display: "flex", gap: "6px", "margin-top": "6px" }}>
                <button style={miniBtn()} onClick={() => fill(m)}>{t("fill")}</button>
                <Show when={m.username}>
                  <button style={miniBtn()} onClick={() => copyField(m, "username")}>{t("copyUser")}</button>
                </Show>
                <button style={miniBtn()} onClick={() => copyField(m, "password")}>{t("copyPass")}</button>
                <button style={miniBtn()} onClick={() => copyTotp(m)}>{t("copyTotp")}</button>
              </div>
              <Show when={copied().startsWith(`username-${m.id}`) || copied().startsWith(`password-${m.id}`) || copied().startsWith(`totp-${m.id}`)}>
                <div style={{ "font-size": "10px", color: "#080", "margin-top": "4px" }}>{t("copied")}</div>
              </Show>
            </div>
          )}
        </For>
        <button style={{ ...btnStyle(), "margin-top": "8px" }} onClick={refresh}>{t("refresh")}</button>
      </Show>

      <Show when={state() === "error" && error()}>
        <div style={{ "font-size": "11px", color: "#c00", "margin-top": "8px" }}>{error()}</div>
      </Show>
    </div>
  );
}

function StateBlock(props) {
  return (
    <div style={{ "margin-bottom": "10px" }}>
      <div style={{ "font-size": "13px", "font-weight": "bold", color: props.color || "#333" }}>{props.title}</div>
      <div style={{ "font-size": "11px", color: "#666", "margin-top": "2px" }}>{props.desc}</div>
    </div>
  );
}

function btnStyle() {
  return { padding: "6px 10px", "font-size": "12px", cursor: "pointer", width: "100%", border: "1px solid #ccc", "border-radius": "4px", background: "#f5f5f5" };
}
function miniBtn() {
  return { padding: "3px 6px", "font-size": "10px", cursor: "pointer", border: "1px solid #ddd", "border-radius": "3px", background: "#fafafa" };
}

render(() => <App />, document.body);
