import { createSignal, Show, For, onSettled, onCleanup } from "solid-js";
import { useAuth } from "../context/AuthContext.jsx";
import { useI18n } from "../i18n/index.jsx";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import { daemon } from "../lib/daemon.js";
import { providerLabel } from "../lib/providers.js";
import { createProviderConnect } from "../lib/providerConnect.js";
import { sanitizeError } from "../lib/utils.js";
import { startVaultPrefetch } from "../lib/vaultPrefetch.js";
import { IconRefresh, IconGitHub, IconGitLab, IconCodeberg, IconSpinner, IconCheck } from "./Icon.jsx";
import ThemeToggleFloating from "./ThemeToggleFloating.jsx";
import FocusTrap from "./FocusTrap.jsx";
import ExternalLink from "./ExternalLink.jsx";
import CopyButton from "./CopyButton.jsx";

const PROVIDERS = [
  { key: "github", label: "providerGitHub", Icon: IconGitHub },
  { key: "gitlab", label: "providerGitLab", Icon: IconGitLab },
  { key: "codeberg", label: "providerCodeberg", Icon: IconCodeberg },
];



export default function SetupScreen() {
  const auth = useAuth();
  const { t, locale } = useI18n();
  let cardRef;

  // Sync flow state
  const [phase, setPhase] = createSignal("idle"); // idle | authenticating | connected | synced
  const [subState, setSubState] = createSignal("idle"); // idle | creating | error
  const [selectedProvider, setSelectedProvider] = createSignal(null);
  const [authSession, setAuthSession] = createSignal(null);
  const [webOAuthUrl, setWebOAuthUrl] = createSignal(null);
  const [providerInfo, setProviderInfo] = createSignal(null); // { key, username }
  const [error, setError] = createSignal(null);
  const [repoName, setRepoName] = createSignal("");

  // Prepare vault (unlock + defaults) transparently on mount. The vault was
  // created in step 2 and is already active + token-filed in the daemon, so
  // sync operations below are valid. We apply the system theme + locale
  // defaults here; the profile display name was already persisted from the
  // vault name by the daemon during `vault.create`.
  let prepared = false;
  async function prepare() {
    if (prepared) return;
    const pw = auth.createPassword();
    if (pw) {
      try {
        await daemon("vault.open");
        await daemon("vault.unlock", pw);
      } catch (e) {
        toastError(sanitizeError(e, t));
        auth.setStatus("locked");
        return;
      }
    }
    try {
      await daemon("settings.set", JSON.stringify({ theme: "system", lang: locale() }));
      await daemon("locale.save", locale());
    } catch { /* non-fatal */ }
    prepared = true;
  }
  onSettled(() => {
    void prepare();
  });

  const conn = createProviderConnect({
    t,
    onUpdate: (info) => {
      if (info.phase === "device-flow" && info.session) setAuthSession(info.session);
      else if (info.phase === "web-oauth") setWebOAuthUrl(info.url);
    },
  });
  onCleanup(() => conn.dispose());

  function reset() {
    conn.dispose();
    setSelectedProvider(null);
    setAuthSession(null);
    setWebOAuthUrl(null);
    setError(null);
    setPhase("idle");
    setSubState("idle");
  }

  async function connectProvider(key) {
    setSelectedProvider(key);
    setPhase("authenticating");
    setError(null);
    setAuthSession(null);
    setWebOAuthUrl(null);
    try {
      const result = await conn.connect(key);
      setProviderInfo({ key, username: result.username || "" });
      setPhase("connected");
      // Default repo name to the slug-prefixed convention.
      setRepoName("baluard-vault");
      toastSuccess(t("sync.connectedAs", { username: result.username || "" }));
    } catch (e) {
      setError(sanitizeError(e, t));
      setSubState("error");
      setAuthSession(null);
      setWebOAuthUrl(null);
      conn.dispose();
    }
  }

  async function enableSync() {
    setSubState("creating");
    setError(null);
    const provider = providerInfo()?.key;
    if (!provider) { setError(t("sync.errorAuthFailed")); setSubState("error"); return; }
    try {
      let name = repoName().trim() || "baluard-vault";
      let cloneUrl = null;
      try {
        const createRaw = await daemon("provider.create_repo", JSON.stringify({ provider, name }));
        cloneUrl = JSON.parse(createRaw)?.clone_url ?? null;
      } catch (createErr) {
        const msg = sanitizeError(createErr, t).toLowerCase();
        if (!msg.includes("already exists") && !msg.includes("422")) throw createErr;
      }
      const setupPayload = { provider, repo_name: name };
      if (cloneUrl) setupPayload.clone_url = cloneUrl;
      await daemon("vault.setup_sync", JSON.stringify(setupPayload));
      setPhase("synced");
      setSubState("idle");
    } catch (e) {
      setError(sanitizeError(e, t));
      setSubState("error");
    }
  }

  function finish() {
    // D3: the password has served its purpose (prepare() unlocked with it at
    // mount). It must not outlive onboarding in webview heap for the app's
    // entire uptime.
    auth.setCreatePassword("");
    startVaultPrefetch();
    auth.setStatus("unlocked");
  }

  return (
    <div class="flex items-center justify-center h-full bg-radial from-[var(--color-detail)] to-[var(--color-bg)] px-4 relative overflow-y-auto py-8">
      <ThemeToggleFloating />
      <div class="flex items-center justify-center min-h-full w-full">
        <FocusTrap containerRef={() => cardRef} />
        <div ref={cardRef} class="w-full max-w-lg p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative overflow-hidden transition-all-fast">

          <div class="text-center mb-6">
            <div class="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center shadow-lg">
              <IconRefresh class="w-8 h-8 text-white" />
            </div>
            <h1 class="text-2xl font-bold tracking-tight text-[var(--color-text)]">{t("setup.title")}</h1>
            <p class="text-sm text-[var(--color-muted)] mt-1">{t("setup.subtitle")}</p>
          </div>

          {/* Explanation */}
          <div class="mb-5 p-4 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)]">
            <p class="text-xs text-[var(--color-text)] leading-relaxed mb-2">{t("setup.whatIsSync")}</p>
            <p class="text-xs text-[var(--color-muted)] leading-relaxed">{t("setup.benefits")}</p>
          </div>

          {/* Sync section */}
          <Show when={phase() === "idle"}>
            <div class="mb-6">
              <label class="block text-xs font-semibold text-[var(--color-muted)] uppercase tracking-wider mb-3">
                {t("setup.connectProvider")}
              </label>
              <div class="grid grid-cols-3 gap-3">
                <For each={PROVIDERS}>
                  {(p) => (
                    <button
                      type="button"
                      onClick={() => connectProvider(p.key)}
                      class="flex flex-col items-center gap-2 py-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-bg)] hover:border-[var(--color-primary)] transition-all cursor-pointer"
                    >
                      <p.Icon class="w-6 h-6 text-[var(--color-text)]" />
                      <span class="text-xs font-medium text-[var(--color-text)]">{providerLabel(t, p.key)}</span>
                    </button>
                  )}
                </For>
              </div>
            </div>
          </Show>

          {/* Authenticating: device flow */}
          <Show when={phase() === "authenticating" && authSession()}>
            <div class="mb-6 p-4 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] space-y-3">
              <h5 class="text-sm font-bold text-[var(--color-text)]">{t("sync.deviceFlowTitle", { provider: providerLabel(t, selectedProvider()) })}</h5>
              <p class="text-xs text-[var(--color-muted)]">{t("sync.deviceFlowInstructions")}</p>
              <div class="flex items-center justify-center gap-2 py-2">
                <span class="text-lg font-mono font-bold text-[var(--color-primary)] tracking-widest">{authSession().user_code}</span>
                <CopyButton value={authSession().user_code?.replace(/-/g, "")} />
              </div>
              <div class="flex justify-center">
                <ExternalLink href={authSession().verification_uri} class="px-4 py-2 rounded-xl bg-[var(--color-primary)] text-[var(--color-primary-text)] text-xs font-bold hover:bg-[var(--color-primary-hover)] transition-all">
                  {t("sync.deviceFlowOpenLink", { provider: providerLabel(t, selectedProvider()) })}
                </ExternalLink>
              </div>
              <div class="flex items-center justify-center gap-2 text-xs text-[var(--color-muted)]">
                <IconSpinner class="w-3 h-3" />
                {t("sync.deviceFlowPolling")}
              </div>
              <button type="button" onClick={reset} class="w-full text-xs text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer">
                {t("entry.cancel")}
              </button>
            </div>
          </Show>

          {/* Authenticating: web-oauth */}
          <Show when={phase() === "authenticating" && webOAuthUrl()}>
            <div class="mb-6 p-4 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] space-y-3">
              <h5 class="text-sm font-bold text-[var(--color-text)]">{t("sync.webOAuthTitle", { provider: providerLabel(t, selectedProvider()) })}</h5>
              <p class="text-xs text-[var(--color-muted)]">{t("sync.webOAuthInstructions")}</p>
              <Show when={selectedProvider() === "codeberg"}>
                <p class="text-[11px] text-yellow-300 leading-relaxed">{t("sync.codebergFullAccessWarning")}</p>
              </Show>
              <div class="flex justify-center">
                <ExternalLink href={webOAuthUrl()} class="px-4 py-2 rounded-xl bg-[var(--color-primary)] text-[var(--color-primary-text)] text-xs font-bold hover:bg-[var(--color-primary-hover)] transition-all">
                  {t("sync.webOAuthOpenLink", { provider: providerLabel(t, selectedProvider()) })}
                </ExternalLink>
              </div>
              <div class="flex items-center justify-center gap-2 text-xs text-[var(--color-muted)]">
                <IconSpinner class="w-3 h-3" />
                {t("sync.webOAuthWaiting")}
              </div>
              <button type="button" onClick={reset} class="w-full text-xs text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer">
                {t("entry.cancel")}
              </button>
            </div>
          </Show>

          {/* Connected: repo setup */}
          <Show when={phase() === "connected"}>
            <div class="mb-6 space-y-3">
              <div class="p-3 rounded-xl bg-green-950/20 border border-green-900/30">
                <p class="text-xs text-green-400 font-bold">
                  {t("sync.connectedAs", { username: providerInfo()?.username || "" })}
                  {" · "}{providerLabel(t, providerInfo()?.key)}
                </p>
              </div>
              <Show when={subState() !== "creating"}>
                <div>
                  <label class="text-xs font-semibold text-[var(--color-muted)] uppercase tracking-wider">{t("setup.repoNameLabel")}</label>
                  <input
                    type="text"
                    value={repoName()}
                    onInput={e => setRepoName(e.target.value)}
                    placeholder={t("sync.repoNamePlaceholder")}
                    class="w-full mt-1 px-4 py-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
                  />
                </div>
                <button
                  type="button"
                  onClick={enableSync}
                  class="w-full py-3 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-sm font-semibold transition-all cursor-pointer shadow-md"
                >
                  {t("setup.enableSync")}
                </button>
              </Show>
              <Show when={subState() === "creating"}>
                <div class="flex items-center justify-center gap-2 py-4">
                  <IconSpinner class="w-4 h-4 text-[var(--color-primary)]" />
                  <span class="text-sm text-[var(--color-muted)]">{t("sync.settingUp")}</span>
                </div>
              </Show>
            </div>
          </Show>

          {/* Synced: success */}
          <Show when={phase() === "synced"}>
            <div class="mb-6 p-4 rounded-xl bg-green-950/20 border border-green-900/30 flex items-center gap-3">
              <IconCheck class="w-5 h-5 text-green-400 shrink-0" />
              <p class="text-sm text-green-400 font-medium">{t("setup.synced")}</p>
            </div>
          </Show>

          {/* Error */}
          <Show when={error()}>
            <div class="mb-6 p-3 rounded-xl bg-red-950/20 border border-red-900/30 flex items-start gap-2">
              <span class="text-xs text-red-300 leading-relaxed">{error()}</span>
            </div>
            <Show when={phase() !== "connected"}>
              <button type="button" onClick={reset} class="mb-6 text-xs text-[var(--color-primary)] hover:underline cursor-pointer">
                {t("entry.cancel")}
              </button>
            </Show>
          </Show>

          {/* Actions */}
          <div class="space-y-3">
            <button
              type="button"
              onClick={finish}
              class="w-full py-3.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-semibold transition-all shadow-lg active:scale-[0.99] cursor-pointer"
            >
              {phase() === "synced" ? t("setup.finish") : t("setup.skip")}
            </button>
            <p class="text-xs text-[var(--color-muted)] text-center">{t("setup.skipHint")}</p>
          </div>
        </div>
      </div>
    </div>
  );
}
