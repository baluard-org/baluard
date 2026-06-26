import { createSignal, Show, For, onMount, onCleanup } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { createProviderConnect } from "../lib/providerConnect.js";
import { sanitizeError } from "../lib/utils.js";
import { toastSuccess } from "../context/toastSignal.js";
import { IconUpload, IconDownload, IconRefresh, IconAlert, IconSpinner } from "./Icon.jsx";
import FocusTrap from "./FocusTrap.jsx";
import ExternalLink from "./ExternalLink.jsx";

const PROVIDER_STYLES = {
  github: { bg: "bg-gray-800", border: "border-gray-600", text: "text-white" },
  gitlab: { bg: "bg-orange-900/30", border: "border-orange-700/50", text: "text-orange-300" },
  codeberg: { bg: "bg-teal-900/30", border: "border-teal-700/50", text: "text-teal-300" },
};

const PROVIDER_KEYS = ["github", "gitlab", "codeberg"];

export default function SyncTab() {
  const { t } = useI18n();

  const [topState, setTopState] = createSignal("A");
  const [subState, setSubState] = createSignal("idle");
  const [error, setError] = createSignal(null);
  const [loading, setLoading] = createSignal(true);
  const [syncStatus, setSyncStatus] = createSignal(null);
  const [providerList, setProviderList] = createSignal(null);

  const [authSession, setAuthSession] = createSignal(null);
  const [selectedProvider, setSelectedProvider] = createSignal(null);
  const [repoName, setRepoName] = createSignal("baluard-vault");
  const [showDisconnectModal, setShowDisconnectModal] = createSignal(false);
  const [revokeToken, setRevokeToken] = createSignal(false);
  // Advanced Options: power users override the OAuth client_id (independence
  // from Baluard's app) or point at a self-hosted instance. Blank = defaults.
  const [showAdvanced, setShowAdvanced] = createSignal(false);
  const [advClientId, setAdvClientId] = createSignal("");
  const [advInstanceUrl, setAdvInstanceUrl] = createSignal("");
  const [advPat, setAdvPat] = createSignal("");
  // Web-OAuth (Codeberg PKCE): auth URL opened in browser, status polled.
  const [webOAuthUrl, setWebOAuthUrl] = createSignal(null);

  let disconnectDialogRef;

  // Provider auth flow (device-flow / web-oauth / PAT) shared with the
  // download-from-provider wizard. onUpdate mirrors the phase into the
  // signals the JSX already binds to (authSession for the device code,
  // webOAuthUrl for the browser link).
  const conn = createProviderConnect({
    t,
    onUpdate: (info) => {
      if (info.phase === "device-flow" && info.session) setAuthSession(info.session);
      else if (info.phase === "web-oauth") setWebOAuthUrl(info.url);
    },
  });
  onCleanup(() => conn.dispose());

  onMount(loadState);

  // ── State Detection ──

  async function loadState() {
    setLoading(true);
    setError(null);
    try {
      const [statusRaw, providersRaw] = await Promise.all([
        daemon("sync.status_json"),
        daemon("provider.list"),
      ]);
      const status = JSON.parse(statusRaw);
      const providers = JSON.parse(providersRaw);
      setSyncStatus(status);
      setProviderList(providers);

      if (status.has_remote) {
        const inferredProvider = status.provider;
        const pinfo = inferredProvider ? providers[inferredProvider] : null;
        if (pinfo?.connected) {
          // Connected provider matches remote — but verify provider isn't a different account
          // by checking that the remote URL provider matches any connected provider
          setTopState("C");
        } else {
          // Check if a DIFFERENT provider is connected than the remote expects
          const anyOtherConnected = Object.entries(providers).some(([key, val]) =>
            val.connected && key !== inferredProvider
          );
          if (anyOtherConnected) {
            // Connected to a different provider than the remote uses
            setError(t("sync.warningDescription"));
            setTopState("D");
          } else {
            setTopState("D");
          }
        }
      } else {
        const any = Object.values(providers).some((p) => p.connected);
        setTopState(any ? "B" : "A");
      }
    } catch (e) {
      const msg = sanitizeError(e, t);
      if (msg.includes("not available") || msg.includes("not enabled")) {
        setTopState("unavailable");
      } else {
        setError(msg);
      }
    } finally {
      setLoading(false);
    }
  }

  // ── Provider connect (device-flow / web-oauth / PAT) ──
  // Consolidated in lib/providerConnect.js. This maps the flow's phase into
  // the signals the JSX binds to and mirrors the old per-method success/error
  // handling (reset advanced fields, reload, toast on success; error on reject).

  async function connectProvider(provider) {
    setSelectedProvider(provider);
    setSubState("authenticating");
    setError(null);
    setAuthSession(null);
    setWebOAuthUrl(null);
    try {
      const advanced = {};
      if (advClientId().trim()) advanced.client_id = advClientId().trim();
      if (advInstanceUrl().trim()) advanced.instance_url = advInstanceUrl().trim();
      const result = await conn.connect(provider, {
        pat: advPat().trim() || undefined,
        advanced,
      });
      // Success: reset advanced fields, reload state, toast (mirrors old flows).
      setSubState("idle");
      setAuthSession(null);
      setWebOAuthUrl(null);
      setSelectedProvider(null);
      setAdvClientId("");
      setAdvInstanceUrl("");
      setAdvPat("");
      setShowAdvanced(false);
      await loadState();
      toastSuccess(t("sync.connectedAs", { username: result.username || "" }));
    } catch (e) {
      setError(sanitizeError(e, t));
      setSubState("error");
      setAuthSession(null);
      setWebOAuthUrl(null);
      conn.dispose();
    }
  }

  function cancelAuth() {
    conn.dispose();
    setAuthSession(null);
    setSelectedProvider(null);
    setSubState("idle");
    setError(null);
    setAdvClientId("");
    setAdvInstanceUrl("");
    setAdvPat("");
    setShowAdvanced(false);
    setWebOAuthUrl(null);
  }

  // ── Repo Setup ──

  function detectConnectedProvider() {
    const providers = providerList();
    if (!providers) return null;
    for (const key of PROVIDER_KEYS) {
      if (providers[key]?.connected) return key;
    }
    return null;
  }

  // Auth method for a provider key, derived from provider.list ("device-flow" | "pat").
  function authMethodFor(key) {
    return providerList()?.[key]?.auth_method || "pat";
  }

  async function createAndSetupRepo() {
    setSubState("creating");
    setError(null);
    const provider = detectConnectedProvider();
    if (!provider) { setError(t("sync.errorAuthFailed")); setSubState("error"); return; }

    // M3: Verify provider token is still valid before creating repo
    try {
      const statusRaw = await daemon("provider.status", JSON.stringify({ provider }));
      const statusResult = JSON.parse(statusRaw);
      if (!statusResult.valid && !statusResult.connected) {
        setError(t("sync.errorAuthFailed"));
        setSubState("error");
        await loadState();
        return;
      }
    } catch (e) {
      // Token validation failed — refresh state and bail
      await loadState();
      return;
    }

    try {
      // Try creating the repo. If it already exists (partial failure), skip to setup.
      let repoNameUsed = repoName() || "baluard-vault";
      let repoCreated = false;
      let cloneUrl = null;
      try {
        const createRaw = await daemon("provider.create_repo", JSON.stringify({ provider, name: repoNameUsed }));
        repoCreated = true;
        // Pass the clone_url to setup_sync so it skips the redundant
        // (and now-conflicting) repo creation step.
        try { cloneUrl = JSON.parse(createRaw)?.clone_url ?? null; } catch { /* keep null */ }
      } catch (createErr) {
        const msg = sanitizeError(createErr, t).toLowerCase();
        if (msg.includes("already exists") || msg.includes("already") || msg.includes("422")) {
          // Repo exists from a prior partial attempt — proceed to setup_sync
          // (setup_sync will create-or-reuse by name)
        } else {
          throw createErr;
        }
      }

      try {
        const setupPayload = { provider, repo_name: repoNameUsed };
        if (cloneUrl) setupPayload.clone_url = cloneUrl;
        await daemon("vault.setup_sync", JSON.stringify(setupPayload));
        setSubState("idle");
        await loadState();
        toastSuccess(t("sync.statusActive"));
      } catch (setupErr) {
        // M1: if we created the repo but setup_sync failed, it's orphaned on
        // the provider. Surface that so the user can clean it up manually.
        if (repoCreated) {
          setError(`${sanitizeError(setupErr, t)} ${t("sync.errorRepoCreatePartial", { provider: providerLabel(provider) })}`);
        } else {
          setError(sanitizeError(setupErr, t));
        }
        setSubState("error");
      }
    } catch (e) {
      setError(sanitizeError(e, t));
      setSubState("error");
    }
  }

  // ── Push / Pull ──

  async function doPush() {
    setSubState("syncing");
    setError(null);
    try {
      await daemon("sync.push");
      toastSuccess(t("sync.push"));
      await loadState();
      setSubState("idle");
    } catch (e) {
      setError(classifySyncError(e));
      setSubState("error");
    }
  }

  async function doPull() {
    setSubState("syncing");
    setError(null);
    try {
      await daemon("sync.pull");
      toastSuccess(t("sync.pull"));
      await loadState();
      setSubState("idle");
    } catch (e) {
      setError(classifySyncError(e));
      setSubState("error");
    }
  }

  function classifySyncError(e) {
    const msg = sanitizeError(e, t).toLowerCase();
    if (msg.includes("signature") || msg.includes("integrity") || msg.includes("verify")) {
      return t("sync.errorIntegrityFailure");
    }
    if (msg.includes("conflict")) {
      return t("sync.errorMergeConflict");
    }
    return t("sync.errorSyncFailed") + " " + sanitizeError(e, t);
  }

  // ── Disconnect ──

  async function confirmDisconnect() {
    setSubState("creating");
    setError(null);
    try {
      await daemon("sync.disconnect");
      if (revokeToken()) {
        const provider = syncStatus()?.provider;
        if (provider) {
          try { await daemon("provider.disconnect", JSON.stringify({ provider })); } catch {}
        }
      }
      setShowDisconnectModal(false);
      setRevokeToken(false);
      setSubState("idle");
      await loadState();
      toastSuccess(t("sync.disconnect"));
    } catch (e) {
      setError(sanitizeError(e, t));
      setSubState("error");
      setShowDisconnectModal(false);
    }
  }

  function getConnectedProviderInfo() {
    const providers = providerList();
    if (!providers) return null;
    for (const key of PROVIDER_KEYS) {
      if (providers[key]?.connected) return { key, ...providers[key] };
    }
    return null;
  }

  function providerLabel(key) {
    const map = {
      github: "providerGitHub",
      gitlab: "providerGitLab",
      codeberg: "providerCodeberg",
    };
    return t(`sync.${map[key] || key}`);
  }

  // ── Render ──

  return (
    <div class="space-y-6">
      {/* Unavailable */}
      <Show when={topState() === "unavailable"}>
        <div class="text-center py-8">
          <p class="text-sm text-[var(--color-muted)]">{t("settings.syncNotAvailable")}</p>
        </div>
      </Show>

      <Show when={topState() !== "unavailable"}>
        {/* Loading */}
        <Show when={loading()}>
          <div class="flex items-center justify-center py-8">
            <IconSpinner class="w-5 h-5 text-[var(--color-muted)]" />
          </div>
        </Show>

        <Show when={!loading()}>
          {/* ── State A: Not Connected ── */}
          <Show when={topState() === "A"}>
            <div class="space-y-4">
              <div>
                <h4 class="text-xs font-bold text-[var(--color-text)]">{t("sync.title")}</h4>
                <p class="text-[10px] text-[var(--color-muted)] mt-0.5">{t("sync.description")}</p>
              </div>

              {/* Provider picker (idle) */}
              <Show when={subState() === "idle"}>
                <div class="grid grid-cols-1 gap-3">
                  <For each={PROVIDER_KEYS}>
                    {(key) => {
                      const style = PROVIDER_STYLES[key];
                      const info = providerList()?.[key];
                      return (
                        <button
                          onClick={() => {
                            // M5: guard double-submit while a flow is in flight.
                            if (subState() !== "idle") return;
                            connectProvider(key);
                          }}
                          class={`flex items-center gap-3 p-4 rounded-xl border transition-all cursor-pointer ${style.bg} ${style.border} hover:opacity-80`}
                        >
                          <span class={`text-sm font-bold ${style.text}`}>{providerLabel(key)}</span>
                          <span class="text-[10px] text-[var(--color-muted)] ml-auto">
                            {(() => {
                              const m = info?.auth_method;
                              if (m === "device-flow") return t("sync.authMethodDeviceFlow");
                              if (m === "web-oauth") return t("sync.authMethodWebOAuth");
                              return t("sync.authMethodPat");
                            })()}
                          </span>
                        </button>
                      );
                    }}
                  </For>
                </div>

                {/* Advanced Options: override client_id (independence) or instance (self-hosted). */}
                <div class="border-t border-[var(--color-border)] pt-3 space-y-2">
                  <button
                    type="button"
                    onClick={() => setShowAdvanced(!showAdvanced())}
                    class="flex items-center gap-1 text-[10px] text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer"
                  >
                    <span class="text-[8px]">{showAdvanced() ? "\u25BE" : "\u25B8"}</span>
                    {t("sync.advancedOptions")}
                  </button>
                  <Show when={showAdvanced()}>
                    <p class="text-[10px] text-[var(--color-muted)] leading-relaxed">{t("sync.advancedOptionsHint")}</p>
                    <div>
                      <label class="text-[10px] text-[var(--color-muted)]">{t("sync.advancedClientId")}</label>
                      <input
                        type="text"
                        value={advClientId()}
                        onInput={(e) => setAdvClientId(e.target.value)}
                        placeholder={t("sync.advancedClientIdPlaceholder")}
                        class="w-full mt-1 px-3 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
                      />
                    </div>
                    <div>
                      <label class="text-[10px] text-[var(--color-muted)]">{t("sync.advancedInstanceUrl")}</label>
                      <input
                        type="text"
                        value={advInstanceUrl()}
                        onInput={(e) => setAdvInstanceUrl(e.target.value)}
                        placeholder={t("sync.advancedInstanceUrlPlaceholder")}
                        class="w-full mt-1 px-3 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
                      />
                    </div>
                    <div>
                      <label class="text-[10px] text-[var(--color-muted)]">{t("sync.advancedPat")}</label>
                      <input
                        type="password"
                        value={advPat()}
                        onInput={(e) => setAdvPat(e.target.value)}
                        placeholder={t("sync.advancedPatPlaceholder")}
                        class="w-full mt-1 px-3 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
                      />
                      <p class="text-[9px] text-[var(--color-muted)] mt-1">{t("sync.advancedPatHint")}</p>
                    </div>
                  </Show>
                </div>
              </Show>

              {/* Device Flow (GitHub, GitLab) */}
              <Show when={subState() === "authenticating" && selectedProvider() && authMethodFor(selectedProvider()) === "device-flow" && authSession()}>
                <div class="p-4 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] space-y-3">
                  <h5 class="text-xs font-bold text-[var(--color-text)]">{t("sync.deviceFlowTitle", { provider: providerLabel(selectedProvider()) })}</h5>
                  <p class="text-[10px] text-[var(--color-muted)]">{t("sync.deviceFlowInstructions")}</p>
                  <div class="text-center py-2">
                    <span class="text-lg font-mono font-bold text-[var(--color-primary)] tracking-widest">{authSession().user_code}</span>
                  </div>
                  <div class="flex justify-center">
                    <ExternalLink
                      href={authSession().verification_uri}
                      class="px-4 py-2 rounded-xl bg-[var(--color-primary)] text-[var(--color-primary-text)] text-xs font-bold hover:bg-[var(--color-primary-hover)] transition-all"
                    >
                      {t("sync.deviceFlowOpenLink", { provider: providerLabel(selectedProvider()) })}
                    </ExternalLink>
                  </div>
                  <div class="flex items-center justify-center gap-2 text-[10px] text-[var(--color-muted)]">
                    <IconSpinner class="w-3 h-3" />
                    {t("sync.deviceFlowPolling")}
                  </div>
                  <button onClick={cancelAuth} class="w-full text-[10px] text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer">
                    {t("entry.cancel")}
                  </button>
                </div>
              </Show>

              {/* Web-OAuth (Codeberg PKCE) */}
              <Show when={subState() === "authenticating" && selectedProvider() && authMethodFor(selectedProvider()) === "web-oauth" && webOAuthUrl()}>
                <div class="p-4 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] space-y-3">
                  <h5 class="text-xs font-bold text-[var(--color-text)]">{t("sync.webOAuthTitle", { provider: providerLabel(selectedProvider()) })}</h5>
                  <p class="text-[10px] text-[var(--color-muted)]">{t("sync.webOAuthInstructions")}</p>
                  <Show when={selectedProvider() === "codeberg"}>
                    <div class="p-2 rounded-lg bg-yellow-950/20 border border-yellow-900/30">
                      <p class="text-[10px] text-yellow-300 leading-relaxed">{t("sync.codebergFullAccessWarning")}</p>
                    </div>
                  </Show>
                  <div class="flex justify-center">
                    <ExternalLink
                      href={webOAuthUrl()}
                      class="px-4 py-2 rounded-xl bg-[var(--color-primary)] text-[var(--color-primary-text)] text-xs font-bold hover:bg-[var(--color-primary-hover)] transition-all"
                    >
                      {t("sync.webOAuthOpenLink", { provider: providerLabel(selectedProvider()) })}
                    </ExternalLink>
                  </div>
                  <div class="flex items-center justify-center gap-2 text-[10px] text-[var(--color-muted)]">
                    <IconSpinner class="w-3 h-3" />
                    {t("sync.webOAuthWaiting")}
                  </div>
                  <button onClick={cancelAuth} class="w-full text-[10px] text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer">
                    {t("entry.cancel")}
                  </button>
                </div>
              </Show>

            </div>
          </Show>

          {/* ── State B: Provider Connected, No Remote ── */}
          <Show when={topState() === "B"}>
            <div class="space-y-4">
              <div>
                <h4 class="text-xs font-bold text-[var(--color-text)]">{t("sync.title")}</h4>
                <p class="text-[10px] text-[var(--color-muted)] mt-0.5">{t("sync.description")}</p>
              </div>

              <Show when={getConnectedProviderInfo()}>
                <div class="p-3 rounded-xl bg-green-950/20 border border-green-900/30">
                  <p class="text-xs text-green-400 font-bold">{t("sync.connectedAs", { username: getConnectedProviderInfo().username || "" })}</p>
                </div>
              </Show>

              <Show when={subState() === "idle"}>
                <div class="space-y-3">
                  <div>
                    <label class="text-[10px] font-bold text-[var(--color-muted)] uppercase tracking-wider">{t("sync.repoName")}</label>
                    <input
                      type="text"
                      value={repoName()}
                      onInput={(e) => setRepoName(e.target.value)}
                      placeholder={t("sync.repoNamePlaceholder")}
                      class="w-full mt-1 px-3 py-2 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
                    />
                  </div>
                  <button
                    onClick={createAndSetupRepo}
                    class="w-full py-2.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-xs font-bold transition-all cursor-pointer shadow-md"
                  >
                    {t("sync.createRepo")}
                  </button>
                </div>
              </Show>

              <Show when={subState() === "creating"}>
                <div class="flex items-center justify-center gap-2 py-6">
                  <IconSpinner class="w-4 h-4 text-[var(--color-primary)]" />
                  <span class="text-xs text-[var(--color-muted)]">{t("sync.settingUp")}</span>
                </div>
              </Show>
            </div>
          </Show>

          {/* ── State C: Sync Active ── */}
          <Show when={topState() === "C"}>
            <div class="space-y-4">
              <div class="flex items-center justify-between">
                <div>
                  <h4 class="text-xs font-bold text-[var(--color-text)]">{t("sync.title")}</h4>
                  <p class="text-[10px] text-[var(--color-muted)] mt-0.5">
                    <Show when={getConnectedProviderInfo()} fallback={syncStatus()?.provider || ""}>
                      {t("sync.connectedAs", { username: getConnectedProviderInfo().username || "" })}
                    </Show>
                  </p>
                </div>
                <div class="px-2.5 py-1 rounded-lg bg-green-950/20 text-green-400 text-[10px] font-bold border border-green-900/30">
                  {t("sync.statusActive")}
                </div>
              </div>

              {/* Status card */}
              <Show when={syncStatus()}>
                <div class="p-3 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] space-y-2">
                  <div class="flex items-center justify-between text-[10px]">
                    <span class="text-[var(--color-muted)]">{t("sync.workingTree")}</span>
                    <span class={syncStatus().dirty ? "text-yellow-400 font-bold" : "text-green-400"}>
                      {syncStatus().dirty ? t("sync.dirty") : t("sync.clean")}
                    </span>
                  </div>
                  <Show when={syncStatus().last_commit}>
                    <div class="flex items-center justify-between text-[10px]">
                      <span class="text-[var(--color-muted)]">{t("sync.lastCommit")}</span>
                      <span class="text-[var(--color-text)] font-mono">{syncStatus().last_commit.id?.substring(0, 7)}</span>
                    </div>
                  </Show>
                  <Show when={!syncStatus().last_commit}>
                    <p class="text-[10px] text-[var(--color-muted)]">{t("sync.noCommits")}</p>
                  </Show>
                </div>
              </Show>

              {/* Push / Pull */}
              <Show when={subState() !== "syncing"}>
                <div class="grid grid-cols-2 gap-3">
                  <button onClick={doPush} class="flex items-center justify-center gap-2 p-3 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-xs font-bold text-[var(--color-text)] transition-all cursor-pointer">
                    <IconUpload class="w-4 h-4 text-[var(--color-muted)]" />
                    {t("sync.push")}
                  </button>
                  <button onClick={doPull} class="flex items-center justify-center gap-2 p-3 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-xs font-bold text-[var(--color-text)] transition-all cursor-pointer">
                    <IconDownload class="w-4 h-4 text-[var(--color-muted)]" />
                    {t("sync.pull")}
                  </button>
                </div>
              </Show>

              <Show when={subState() === "syncing"}>
                <div class="flex items-center justify-center gap-2 py-4">
                  <IconSpinner class="w-4 h-4 text-[var(--color-primary)]" />
                  <span class="text-xs text-[var(--color-muted)]">{t("sync.syncInProgress")}</span>
                </div>
              </Show>

              <button
                onClick={() => setShowDisconnectModal(true)}
                class="w-full py-2 rounded-xl border border-red-900/30 text-xs font-bold text-red-400 hover:bg-red-950/20 transition-all cursor-pointer"
              >
                {t("sync.disconnect")}
              </button>
            </div>
          </Show>

          {/* ── State D: Remote Only ── */}
          <Show when={topState() === "D"}>
            <div class="space-y-4">
              <div class="p-4 rounded-xl bg-yellow-950/20 border border-yellow-900/30 space-y-2">
                <div class="flex items-center gap-2">
                  <IconAlert class="w-4 h-4 text-yellow-400" />
                  <h5 class="text-xs font-bold text-yellow-400">{t("sync.warningTitle")}</h5>
                </div>
                <p class="text-[10px] text-yellow-300">{t("sync.warningDescription")}</p>
                <Show when={syncStatus()?.remote_url}>
                  <p class="text-[10px] text-[var(--color-muted)] font-mono break-all">{syncStatus().remote_url}</p>
                </Show>
              </div>

              <div class="grid grid-cols-2 gap-3">
                <button
                  onClick={() => { setTopState("A"); setSubState("idle"); setError(null); }}
                  class="py-2.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-xs font-bold cursor-pointer"
                >
                  {t("sync.reconnect")}
                </button>
                <button
                  onClick={() => setShowDisconnectModal(true)}
                  class="py-2.5 rounded-xl border border-red-900/30 text-red-400 text-xs font-bold hover:bg-red-950/20 cursor-pointer"
                >
                  {t("sync.removeRemote")}
                </button>
              </div>
            </div>
          </Show>

          {/* ── Error ── */}
          <Show when={error()}>
            <div class="p-3 rounded-xl bg-red-950/20 border border-red-900/30 flex items-start gap-2">
              <IconAlert class="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <p class="text-[10px] text-red-300 leading-relaxed">{error()}</p>
            </div>
            <button
              onClick={() => { setError(null); setSubState("idle"); }}
              class="text-[10px] text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer"
            >
              {t("entry.cancel")}
            </button>
          </Show>

          {/* ── Disconnect Modal ── */}
          <Show when={showDisconnectModal()}>
            <div
              ref={disconnectDialogRef}
              role="dialog"
              aria-modal="true"
              aria-labelledby="sync-disconnect-title"
              class="fixed inset-0 bg-black/40 flex items-center justify-center z-[200]"
              onClick={() => setShowDisconnectModal(false)}
            >
              <FocusTrap containerRef={disconnectDialogRef} onEscape={() => { setShowDisconnectModal(false); setRevokeToken(false); }} />
              <div class="bg-[var(--color-card)] border border-[var(--color-border)] rounded-2xl shadow-2xl w-[380px] p-6 space-y-4" onClick={(e) => e.stopPropagation()}>
                <h4 id="sync-disconnect-title" class="text-sm font-bold text-[var(--color-text)]">{t("sync.disconnectConfirmTitle")}</h4>
                <p class="text-xs text-[var(--color-muted)]">{t("sync.disconnectConfirm")}</p>
                <label class="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={revokeToken()}
                    onChange={(e) => setRevokeToken(e.target.checked)}
                    class="accent-red-500"
                  />
                  <span class="text-[10px] text-red-300">{t("sync.disconnectRevokeToken")}</span>
                </label>
                <div class="flex items-center gap-3 pt-2">
                  <button
                    onClick={confirmDisconnect}
                    disabled={subState() === "creating"}
                    class="flex-1 py-2 rounded-xl bg-red-600 hover:bg-red-700 text-white text-xs font-bold cursor-pointer disabled:opacity-50"
                  >
                    {subState() === "creating" ? t("sync.disconnecting") : t("sync.disconnect")}
                  </button>
                  <button
                    onClick={() => { setShowDisconnectModal(false); setRevokeToken(false); }}
                    disabled={subState() === "creating"}
                    class="flex-1 py-2 rounded-xl border border-[var(--color-border)] text-xs font-bold text-[var(--color-muted)] cursor-pointer disabled:opacity-50"
                  >
                    {t("entry.cancel")}
                  </button>
                </div>
              </div>
            </div>
          </Show>
        </Show>
      </Show>
    </div>
  );
}
