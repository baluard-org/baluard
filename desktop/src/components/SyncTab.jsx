import { createSignal, Show, For, onMount, onCleanup } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastSuccess } from "../context/toastSignal.js";
import { IconUpload, IconDownload, IconRefresh, IconAlert } from "./Icon.jsx";
import FocusTrap from "./FocusTrap.jsx";

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
  const [patToken, setPatToken] = createSignal("");
  const [repoName, setRepoName] = createSignal("baluard-vault");
  const [showDisconnectModal, setShowDisconnectModal] = createSignal(false);
  const [revokeToken, setRevokeToken] = createSignal(false);

  let pollTimer = null;
  let disconnectDialogRef;

  onCleanup(() => {
    if (pollTimer) clearTimeout(pollTimer);
  });

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

  // ── GitHub Device Flow ──

  async function startDeviceFlow(provider) {
    setSelectedProvider(provider);
    setSubState("authenticating");
    setError(null);
    try {
      const raw = await daemon("provider.connect_start", JSON.stringify({ provider }));
      const session = JSON.parse(raw);
      setAuthSession(session);
      schedulePoll(session);
    } catch (e) {
      setError(sanitizeError(e, t));
      setSubState("error");
    }
  }

  function schedulePoll(session) {
    const delay = (session.interval_secs || 5) * 1000;
    pollTimer = setTimeout(() => pollDeviceFlow(session), delay);
  }

  async function pollDeviceFlow(session) {
    pollTimer = null;
    try {
      const raw = await daemon("provider.connect_poll", JSON.stringify(session));
      const result = JSON.parse(raw);

      if (result.status === "pending") {
        schedulePoll(session);
      } else if (result.status === "slow_down") {
        session.interval_secs = result.interval_secs;
        setAuthSession({ ...session });
        schedulePoll(session);
      } else if (result.status === "expired") {
        setError(t("sync.deviceFlowExpired"));
        setSubState("error");
      } else if (result.status === "success") {
        cancelPoll();
        setSubState("idle");
        setAuthSession(null);
        await loadState();
        toastSuccess(t("sync.connectedAs", { username: result.username || "" }));
      }
    } catch (e) {
      setError(sanitizeError(e, t));
      setSubState("error");
      cancelPoll();
    }
  }

  function cancelPoll() {
    if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
  }

  function cancelAuth() {
    cancelPoll();
    setAuthSession(null);
    setSelectedProvider(null);
    setSubState("idle");
    setError(null);
  }

  // ── PAT Auth ──

  async function submitPat(provider) {
    if (!patToken().trim()) return;
    setSelectedProvider(provider);
    setSubState("authenticating");
    setError(null);
    try {
      const raw = await daemon(
        "provider.connect_pat",
        JSON.stringify({ provider, token: patToken().trim() })
      );
      const result = JSON.parse(raw);
      if (result.status === "success") {
        setPatToken("");
        setSubState("idle");
        setSelectedProvider(null);
        await loadState();
        toastSuccess(t("sync.connectedAs", { username: result.username || "" }));
      }
    } catch (e) {
      setError(sanitizeError(e, t));
      setSubState("error");
    }
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
      try {
        await daemon("provider.create_repo", JSON.stringify({ provider, name: repoNameUsed }));
      } catch (createErr) {
        const msg = sanitizeError(createErr, t).toLowerCase();
        if (msg.includes("already exists") || msg.includes("already") || msg.includes("422")) {
          // Repo exists from a prior partial attempt — proceed to setup_sync
        } else {
          throw createErr;
        }
      }

      await daemon("vault.setup_sync", JSON.stringify({ provider, repo_name: repoNameUsed }));
      setSubState("idle");
      await loadState();
      toastSuccess(t("sync.statusActive"));
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
    return t(`sync.provider${key.charAt(0).toUpperCase() + key.slice(1)}`);
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
            <IconRefresh class="w-5 h-5 text-[var(--color-muted)] animate-spin" />
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
                            if (key === "github") startDeviceFlow(key);
                            else { setSelectedProvider(key); setSubState("authenticating"); }
                          }}
                          class={`flex items-center gap-3 p-4 rounded-xl border transition-all cursor-pointer ${style.bg} ${style.border} hover:opacity-80`}
                        >
                          <span class={`text-sm font-bold ${style.text}`}>{providerLabel(key)}</span>
                          <span class="text-[10px] text-[var(--color-muted)] ml-auto">
                            {info?.auth_method === "device-flow" ? t("sync.authMethodDeviceFlow") : t("sync.authMethodPat")}
                          </span>
                        </button>
                      );
                    }}
                  </For>
                </div>
              </Show>

              {/* GitHub Device Flow */}
              <Show when={subState() === "authenticating" && selectedProvider() === "github" && authSession()}>
                <div class="p-4 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] space-y-3">
                  <h5 class="text-xs font-bold text-[var(--color-text)]">{t("sync.deviceFlowTitle")}</h5>
                  <p class="text-[10px] text-[var(--color-muted)]">{t("sync.deviceFlowInstructions")}</p>
                  <div class="text-center py-2">
                    <span class="text-lg font-mono font-bold text-[var(--color-primary)] tracking-widest">{authSession().user_code}</span>
                  </div>
                  <div class="flex justify-center">
                    <a
                      href={authSession().verification_uri}
                      target="_blank"
                      rel="noopener noreferrer"
                      class="px-4 py-2 rounded-xl bg-[var(--color-primary)] text-[var(--color-primary-text)] text-xs font-bold hover:bg-[var(--color-primary-hover)] transition-all"
                    >
                      {t("sync.deviceFlowOpenLink")}
                    </a>
                  </div>
                  <div class="flex items-center justify-center gap-2 text-[10px] text-[var(--color-muted)]">
                    <IconRefresh class="w-3 h-3 animate-spin" />
                    {t("sync.deviceFlowPolling")}
                  </div>
                  <button onClick={cancelAuth} class="w-full text-[10px] text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer">
                    {t("entry.cancel")}
                  </button>
                </div>
              </Show>

              {/* PAT Input (GitLab/Codeberg) */}
              <Show when={subState() === "authenticating" && selectedProvider() && selectedProvider() !== "github"}>
                <div class="p-4 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] space-y-3">
                  <h5 class="text-xs font-bold text-[var(--color-text)]">{t("sync.patTitle", { provider: providerLabel(selectedProvider()) })}</h5>
                  <p class="text-[10px] text-[var(--color-muted)]">{t("sync.patInstructions")}</p>
                  <div class="flex items-center gap-2">
                    <input
                      type="password"
                      placeholder={t("sync.patPlaceholder")}
                      value={patToken()}
                      onInput={(e) => setPatToken(e.target.value)}
                      onKeyDown={(e) => { if (e.key === "Enter") submitPat(selectedProvider()); }}
                      class="flex-1 px-3 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
                      autofocus
                    />
                    <button
                      onClick={() => submitPat(selectedProvider())}
                      disabled={!patToken().trim()}
                      class="px-4 py-2 rounded-lg bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-xs font-bold cursor-pointer disabled:opacity-40"
                    >
                      {t("sync.connect")}
                    </button>
                    <button onClick={cancelAuth} class="px-2 py-2 text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer text-xs">
                      {t("entry.cancel")}
                    </button>
                  </div>
                  <Show when={selectedProvider() === "gitlab" || selectedProvider() === "codeberg"}>
                    <a
                      href={selectedProvider() === "gitlab" ? "https://gitlab.com/-/user_settings/personal_access_tokens" : "https://codeberg.org/user/settings/applications"}
                      target="_blank"
                      rel="noopener noreferrer"
                      class="text-[10px] text-[var(--color-primary)] hover:underline"
                    >
                      {t("sync.patGenerateToken")}
                    </a>
                  </Show>
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
                  <IconRefresh class="w-4 h-4 text-[var(--color-primary)] animate-spin" />
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
                  <IconRefresh class="w-4 h-4 text-[var(--color-primary)] animate-spin" />
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
