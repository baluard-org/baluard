import { createSignal, Show, For, onSettled, onCleanup, createEffect } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { useVaultSwitcher } from "../context/VaultSwitcherContext.jsx";
import { daemon } from "../lib/daemon.js";
import { createProviderConnect } from "../lib/providerConnect.js";
import { providerLabel as providerLabelT } from "../lib/providers.js";
import { sanitizeError } from "../lib/utils.js";
import { toastSuccess, toastWarning } from "../context/toastSignal.js";
import GitExplainerModal from "./GitExplainerModal.jsx";
import { normalizeSlug } from "../lib/slug.js";
import { IconUpload, IconDownload, IconRefresh, IconAlert, IconSpinner } from "./Icon.jsx";
import FocusTrap from "./FocusTrap.jsx";
import ExternalLink from "./ExternalLink.jsx";
import { Button } from "./Primitives.jsx";
import CopyButton from "./CopyButton.jsx";

const PROVIDER_STYLES = {
  github: { bg: "bg-gray-800", border: "border-gray-600", text: "text-white" },
  gitlab: { bg: "bg-orange-900/30", border: "border-orange-700/50", text: "text-orange-300" },
  codeberg: { bg: "bg-teal-900/30", border: "border-teal-700/50", text: "text-teal-300" },
};

const PROVIDER_KEYS = ["github", "gitlab", "codeberg"];

export default function SyncTab() {
  const { t } = useI18n();
  const switcher = useVaultSwitcher();

  const [topState, setTopState] = createSignal("A");
  const [subState, setSubState] = createSignal("idle");
  const [error, setError] = createSignal(null);
  const [loading, setLoading] = createSignal(true);
  const [syncStatus, setSyncStatus] = createSignal(null);
  const [providerList, setProviderList] = createSignal(null);
  // Session-scoped provider state. The global providers.json / keyring is
  // shared across all vaults by design (Phase 3), so "is anything connected?"
  // can leak another vault's identity into this vault's SyncTab. These two
  // signals track only what happened in THIS mount for THIS active vault:
  //   authedThisSession      -> gate state B (avoid the leak)
  //   justConnectedProvider  -> which provider was picked, so create-repo and
  //                             the "Connected as" line use THAT provider, not
  //                             whichever happens to be first in PROVIDER_KEYS.
  const [authedThisSession, setAuthedThisSession] = createSignal(false);
  const [justConnectedProvider, setJustConnectedProvider] = createSignal(null);

  const [authSession, setAuthSession] = createSignal(null);
  const [selectedProvider, setSelectedProvider] = createSignal(null);
  const [repoName, setRepoName] = createSignal("baluard-vault");
  const [showDisconnectModal, setShowDisconnectModal] = createSignal(false);
  const [revokeToken, setRevokeToken] = createSignal(false);
  const [deleteRemote, setDeleteRemote] = createSignal(false);
  const [confirmDeleteRemote, setConfirmDeleteRemote] = createSignal(false);
  const [showGitHelp, setShowGitHelp] = createSignal(false);
  // Advanced Options: power users override the OAuth client_id (independence
  // from Baluard's app) or point at a self-hosted instance. Blank = defaults.
  const [showAdvanced, setShowAdvanced] = createSignal(false);
  const [advClientId, setAdvClientId] = createSignal("");
  const [advInstanceUrl, setAdvInstanceUrl] = createSignal("");
  const [advPat, setAdvPat] = createSignal("");
  // Web-OAuth (Codeberg PKCE): auth URL opened in browser, status polled.
  const [webOAuthUrl, setWebOAuthUrl] = createSignal(null);
  // State C: collapsible git-power-user panel (status + directional push/pull).
  const [showAdvancedPanel, setShowAdvancedPanel] = createSignal(false);

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

  // SyncTab mounts once and is NOT remounted on a vault switch (pointer-flip
  // model). Reset every session-scoped bit when the active slug changes so
  // vault B does not inherit vault A's in-flight auth flow, open disconnect
  // modal, or "just connected" state — all of which would act on the wrong
  // vault (e.g. a device-flow timer resolving against vault C, or
  // sync.disconnect firing on the wrong remote). Mirrors VaultView's pattern.
  // Lives after `conn` + all signals so every referenced binding is in scope.
  let lastSlug = switcher.activeSlug();
  createEffect(
    () => switcher.activeSlug(),
    (slug) => {
    if (slug === lastSlug) return;
    lastSlug = slug;
    // Abort any in-flight auth flow so its poll can't resolve into the new vault.
    conn.dispose();
    setSubState("idle");
    setSelectedProvider(null);
    setAuthSession(null);
    setWebOAuthUrl(null);
    setError(null);
    setShowDisconnectModal(false);
    setRevokeToken(false);
    setDeleteRemote(false);
    setConfirmDeleteRemote(false);
    // Clear user-typed advanced/repo fields so vault A's inputs don't prefill vault B.
    setRepoName("baluard-vault");
    setShowAdvanced(false);
    setAdvClientId("");
    setAdvInstanceUrl("");
    setAdvPat("");
    setShowAdvancedPanel(false);
    setAuthedThisSession(false);
    setJustConnectedProvider(null);
    // Refresh from the now-active vault so the tab doesn't show stale remote
    // URL / status / sync badge from the previous vault.
    loadState();
    },
  );

  onSettled(() => {
    void loadState();
  });

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
        // State B (create-repo) only after a connect done IN THIS session.
        // A cold-mounted vault with no remote must show the picker (A) even
        // if another vault left a global provider token, otherwise switching
        // vaults leaks the prior vault's identity as "Connected as @user"
        // and hides the provider picker (locking the vault to that provider).
        setTopState(authedThisSession() ? "B" : "A");
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
      setAuthedThisSession(true);
      setJustConnectedProvider(provider);
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
    // In state B (no remote) the only source of truth for WHICH provider to
    // create the repo under is the one the user just picked here; the global
    // "first connected" would be wrong if two providers are authed.
    const just = justConnectedProvider();
    if (just) return just;
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
      const repoNameUsed = normalizeSlug(repoName() || "baluard-vault");
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

  // Primary one-click sync: pull remote changes in first, then push local
  // changes up. Bidirectional, handles the common "edited on two devices"
  // case. Conflicts surface as an error the user can resolve from Advanced.
  async function doSync() {
    setSubState("syncing");
    setError(null);
    try {
      await daemon("sync.pull");
      await daemon("sync.push");
      toastSuccess(t("sync.statusActive"));
      await loadState();
      setSubState("idle");
    } catch (e) {
      setError(classifySyncError(e));
      setSubState("error");
    }
  }

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
      const raw = await daemon("sync.disconnect", JSON.stringify({ delete_remote: deleteRemote() }));
      if (revokeToken()) {
        const provider = syncStatus()?.provider;
        if (provider) {
          try { await daemon("provider.disconnect", JSON.stringify({ provider })); } catch {}
        }
      }
      setShowDisconnectModal(false);
      setRevokeToken(false);
      setDeleteRemote(false);
      setConfirmDeleteRemote(false);
      setSubState("idle");
      // Reset session flags so the post-disconnect view lands on the picker
      // (state A), not a stale "Connected as @user" (state B), and never
      // references a provider whose token was just revoked.
      setAuthedThisSession(false);
      setJustConnectedProvider(null);
      await loadState();
      // Best-effort delete: the disconnect always succeeds, but the remote
      // delete may have failed (403/no delete scope, network). Warn the user
      // with a persistent toast + the manual-delete URL so they can finish.
      let result = {};
      try { result = JSON.parse(raw) || {}; } catch { /* legacy string response */ }
      if (deleteRemote() && result.remote_deleted === false) {
        toastWarning(
          result.repo_web_url
            ? t("sync.disconnectDeleteFailedWithUrl", { url: result.repo_web_url })
            : t("sync.disconnectDeleteFailed"),
          { duration: 0, manual: true }
        );
      } else {
        toastSuccess(t("sync.disconnect"));
      }
    } catch (e) {
      setError(sanitizeError(e, t));
      setSubState("error");
      setShowDisconnectModal(false);
      setDeleteRemote(false);
      setConfirmDeleteRemote(false);
    }
  }

  function getConnectedProviderInfo() {
    const providers = providerList();
    if (!providers) return null;
    // Provider priority for display:
    //   1. justConnectedProvider — what the user picked THIS session (state B)
    //   2. syncStatus().provider — the per-vault remote's provider (states C/D;
    //      the authoritative source when the vault already has a remote)
    //   3. first globally connected — last resort; only correct when exactly
    //      one provider is authed. Without #2, a vault with a GitLab remote
    //      plus a stored GitHub token would show the GitHub username.
    const key =
      justConnectedProvider() ??
      syncStatus()?.provider ??
      PROVIDER_KEYS.find((k) => providers[k]?.connected);
    if (!key || !providers[key]) return null;
    return { key, ...providers[key] };
  }

  const providerLabel = (key) => providerLabelT(t, key);

  // Human "X ago" for a Unix-seconds timestamp. Returns a key the i18n
  // lastSynced template interpolates. Uses relative units, never a raw hash
  // or git jargon.
  function timeAgo(unixSec) {
    if (!unixSec) return null;
    const diff = Math.max(0, Math.floor(Date.now() / 1000) - unixSec);
    if (diff < 60) return t("relative.justNow");
    if (diff < 3600) return t("relative.minutes", { n: Math.floor(diff / 60) });
    if (diff < 86400) return t("relative.hours", { n: Math.floor(diff / 3600) });
    return t("relative.days", { n: Math.floor(diff / 86400) });
  }

  // Convert a git remote URL (SSH or HTTPS) to a browser URL.
  // SSH:  git@github.com:owner/name.git -> https://github.com/owner/name
  // HTTPS: https://gitlab.com/owner/name.git -> https://gitlab.com/owner/name
  // Returns null for unparseable forms.
  function repoWebUrl(remoteUrl) {
    if (!remoteUrl) return null;
    const cleaned = remoteUrl.replace(/\.git$/, "");
    // SSH form: git@host:path
    const ssh = cleaned.match(/^git@([^:]+):(.+)$/);
    if (ssh) return `https://${ssh[1]}/${ssh[2]}`;
    // HTTPS form (already a URL, drop credentials if present)
    if (/^https?:\/\//.test(cleaned)) return cleaned.replace(/^[^@]+@/, "");
    return null;
  }

  // owner/name from a git remote URL, for display.
  function repoOwnerName(remoteUrl) {
    const web = repoWebUrl(remoteUrl);
    if (!web) return null;
    const m = web.match(/^https?:\/\/[^/]+\/(.+)$/);
    return m ? m[1].replace(/^\/+|\/+$/g, "") : null;
  }

  // ── Render ──

  return (
    <div class="space-y-6">
      {/* Plain-words explainer for the storage backbone (non-technical users). */}
      <div class="flex justify-end">
        <button
          onClick={() => setShowGitHelp(true)}
          class="text-[10px] font-semibold text-[var(--color-muted)] hover:text-[var(--color-text)] underline underline-offset-2 cursor-pointer bg-transparent border-0 p-0"
        >
          {t("gitWhat.link")}
        </button>
      </div>
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
                  <div class="flex items-center justify-center gap-2 py-2">
                    <span class="text-lg font-mono font-bold text-[var(--color-primary)] tracking-widest">{authSession().user_code}</span>
                    <CopyButton value={authSession().user_code?.replace(/-/g, "")} />
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
                  <p class="text-xs text-green-400 font-bold">
                    {t("sync.connectedAs", { username: getConnectedProviderInfo().username || "" })}{getConnectedProviderInfo().key ? ` \u00B7 ${providerLabel(getConnectedProviderInfo().key)}` : ""}
                  </p>
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
              {/* Friendly status header: connected account + simple pill */}
              <div class="flex items-center justify-between">
                <div class="min-w-0">
                  <h4 class="text-xs font-bold text-[var(--color-text)]">{t("sync.title")}</h4>
                  <p class="text-[10px] text-[var(--color-muted)] mt-0.5 truncate">
                    <Show when={getConnectedProviderInfo()} fallback={syncStatus()?.provider || ""}>
                      {t("sync.connectedAs", { username: getConnectedProviderInfo().username || "" })}{syncStatus()?.provider ? ` \u00B7 ${providerLabel(syncStatus().provider)}` : ""}
                    </Show>
                  </p>
                  <Show when={repoWebUrl(syncStatus()?.remote_url)}>
                    <ExternalLink
                      href={repoWebUrl(syncStatus().remote_url)}
                      class="inline-flex items-center gap-1 text-[10px] text-[var(--color-primary)] hover:underline mt-0.5"
                    >
                      {repoOwnerName(syncStatus().remote_url)}
                    </ExternalLink>
                  </Show>
                </div>
                <Show when={syncStatus()} fallback={
                  <span class="px-2.5 py-1 rounded-lg text-[10px] font-bold border badge-green">{t("sync.statusUpToDate")}</span>
                }>
                  <span class={`px-2.5 py-1 rounded-lg text-[10px] font-bold border ${
                    subState() === "syncing"
                      ? "badge-blue"
                      : syncStatus().dirty
                        ? "badge-yellow"
                        : "badge-green"
                  }`}>
                    {subState() === "syncing"
                      ? t("sync.syncing")
                      : syncStatus().dirty
                        ? t("sync.statusChangesPending")
                        : t("sync.statusUpToDate")}
                  </span>
                </Show>
              </div>

              {/* Friendly status line: last synced time, no git jargon */}
              <Show when={syncStatus()}>
                <p class="text-[10px] text-[var(--color-muted)] text-center">
                  {syncStatus().last_synced
                    ? t("sync.lastSynced", { ago: timeAgo(syncStatus().last_synced) })
                    : t("sync.lastSyncedNever")}
                </p>
              </Show>

              {/* Primary action: one-click bidirectional sync */}
              <Show when={subState() !== "syncing"}>
                <button
                  onClick={doSync}
                  disabled={subState() === "syncing"}
                  class="w-full py-3.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-sm font-bold transition-all cursor-pointer shadow-md disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                >
                  <IconRefresh class="w-4 h-4" />
                  {t("sync.syncNow")}
                </button>
              </Show>

              <Show when={subState() === "syncing"}>
                <div class="flex items-center justify-center gap-2 py-3.5 rounded-xl bg-[var(--color-primary)]/10">
                  <IconSpinner class="w-4 h-4 text-[var(--color-primary)]" />
                  <span class="text-sm text-[var(--color-primary)] font-bold">{t("sync.syncInProgress")}</span>
                </div>
              </Show>

              {/* Advanced: git status + directional push/pull for power users */}
              <div class="border-t border-[var(--color-border)] pt-3 space-y-2">
                <button
                  type="button"
                  onClick={() => setShowAdvancedPanel(!showAdvancedPanel())}
                  class="flex items-center gap-1 text-[10px] text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer w-full"
                >
                  <span class="text-[8px]">{showAdvancedPanel() ? "\u25BE" : "\u25B8"}</span>
                  {t("sync.advancedSection")}
                </button>
                <Show when={showAdvancedPanel()}>
                  <div class="space-y-3">
                    <Show when={syncStatus()}>
                      <div class="p-3 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] space-y-2">
                        <div class="flex items-center justify-between text-[10px]">
                          <span class="text-[var(--color-muted)]">{t("sync.workingTree")}</span>
                          <span class={syncStatus().dirty ? "text-status-yellow font-bold" : "text-status-green"}>
                            {syncStatus().dirty ? t("sync.dirty") : t("sync.clean")}
                          </span>
                        </div>
                        <Show when={syncStatus().last_commit}>
                          <div class="flex items-center justify-between text-[10px]">
                            <span class="text-[var(--color-muted)]">{t("sync.lastCommit")}</span>
                            <span class="text-[var(--color-text)] font-mono">{syncStatus().last_commit.id?.substring(0, 7)}</span>
                          </div>
                        </Show>
                        <Show when={syncStatus().remote_url}>
                          <div class="text-[10px]">
                            <span class="text-[var(--color-muted)]">{t("sync.advancedRemoteUrl")}</span>
                            <p class="text-[var(--color-text)] font-mono break-all mt-0.5">{syncStatus().remote_url}</p>
                          </div>
                        </Show>
                        <Show when={!syncStatus().last_commit}>
                          <p class="text-[10px] text-[var(--color-muted)]">{t("sync.noCommits")}</p>
                        </Show>
                      </div>
                    </Show>
                    <div class="grid grid-cols-2 gap-3">
                      <button onClick={doPush} disabled={subState() === "syncing"} class="flex items-center justify-center gap-2 p-2.5 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-[10px] font-bold text-[var(--color-text)] transition-all cursor-pointer disabled:opacity-50">
                        <IconUpload class="w-3.5 h-3.5 text-[var(--color-muted)]" />
                        {t("sync.push")}
                      </button>
                      <button onClick={doPull} disabled={subState() === "syncing"} class="flex items-center justify-center gap-2 p-2.5 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-[10px] font-bold text-[var(--color-text)] transition-all cursor-pointer disabled:opacity-50">
                        <IconDownload class="w-3.5 h-3.5 text-[var(--color-muted)]" />
                        {t("sync.pull")}
                      </button>
                    </div>
                  </div>
                </Show>
              </div>

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
                  onClick={() => { setTopState("A"); setSubState("idle"); setError(null); setJustConnectedProvider(null); }}
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
              aria-describedby="sync-disconnect-desc"
              class="fixed inset-0 bg-black/50 flex items-center justify-center z-[200]"
              onClick={() => { setShowDisconnectModal(false); setRevokeToken(false); setDeleteRemote(false); setConfirmDeleteRemote(false); }}
            >
              <FocusTrap containerRef={disconnectDialogRef} onEscape={() => { setShowDisconnectModal(false); setRevokeToken(false); setDeleteRemote(false); setConfirmDeleteRemote(false); }} />
              <div
                class="bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-2xl shadow-2xl w-[380px] p-6 space-y-5 animate-in fade-in zoom-in-95 duration-150"
                onClick={(e) => e.stopPropagation()}
              >
                <div>
                  <h3 id="sync-disconnect-title" class="text-lg font-bold text-[var(--color-text)] mb-2">
                    {t("sync.disconnectConfirmTitle")}
                  </h3>
                  <p id="sync-disconnect-desc" class="text-sm text-[var(--color-muted)] leading-relaxed">
                    {t("sync.disconnectConfirm")}
                  </p>
                </div>

                <div class="space-y-3">
                  <label class="p-3 bg-[var(--color-bg)] border border-[var(--color-border)] rounded-xl flex items-center gap-3 cursor-pointer select-none hover:bg-black/10 transition-all">
                    <input
                      type="checkbox"
                      checked={revokeToken()}
                      onChange={(e) => setRevokeToken(e.target.checked)}
                      class="w-4 h-4 rounded border-[var(--color-border)] text-[var(--color-danger)] focus:ring-[var(--color-danger)] cursor-pointer accent-[var(--color-danger)] shrink-0"
                    />
                    <span class="text-xs font-semibold text-[var(--color-text)] leading-tight">
                      {t("sync.disconnectRevokeToken")}
                    </span>
                  </label>

                  <label class="p-3 bg-[var(--color-bg)] border border-[var(--color-border)] rounded-xl flex items-center gap-3 cursor-pointer select-none hover:bg-black/10 transition-all">
                    <input
                      type="checkbox"
                      checked={deleteRemote()}
                      onChange={(e) => {
                        setDeleteRemote(e.target.checked);
                        if (!e.target.checked) setConfirmDeleteRemote(false);
                      }}
                      class="w-4 h-4 rounded border-[var(--color-border)] text-[var(--color-danger)] focus:ring-[var(--color-danger)] cursor-pointer accent-[var(--color-danger)] shrink-0"
                    />
                    <span class="text-xs font-semibold text-[var(--color-text)] leading-tight">
                      {t("sync.disconnectDeleteRemote")}
                    </span>
                  </label>

                  <Show when={deleteRemote()}>
                    <label class="p-3 border rounded-xl flex items-start gap-3 cursor-pointer select-none transition-all animate-in fade-in slide-in-from-top-2 duration-150 box-danger-warning">
                      <input
                        type="checkbox"
                        checked={confirmDeleteRemote()}
                        onChange={(e) => setConfirmDeleteRemote(e.target.checked)}
                        class="w-4 h-4 rounded text-[var(--color-danger)] focus:ring-[var(--color-danger)] cursor-pointer accent-[var(--color-danger)] mt-0.5 shrink-0"
                      />
                      <div class="flex flex-col gap-0.5">
                        <span class="text-xs font-semibold leading-tight text-warning-title">
                          {t("sync.disconnectConfirmDeleteRemote")}
                        </span>
                        <span class="text-[10px] leading-tight text-warning-desc">
                          {t("sync.disconnectConfirmDeleteRemoteDesc")}
                        </span>
                      </div>
                    </label>
                  </Show>
                </div>

                <div class="flex items-center gap-3 pt-1">
                  <Button
                    onClick={() => { setShowDisconnectModal(false); setRevokeToken(false); setDeleteRemote(false); setConfirmDeleteRemote(false); }}
                    disabled={subState() === "creating"}
                    class="flex-1 py-2.5"
                  >
                    {t("entry.cancel")}
                  </Button>
                  <Button
                    onClick={confirmDisconnect}
                    disabled={subState() === "creating" || (deleteRemote() && !confirmDeleteRemote())}
                    variant="danger"
                    class="flex-1 py-2.5"
                  >
                    {subState() === "creating" ? t("sync.disconnecting") : t("sync.disconnect")}
                  </Button>
                </div>
              </div>
            </div>
          </Show>
        </Show>
      </Show>
      <GitExplainerModal open={showGitHelp()} onClose={() => setShowGitHelp(false)} />
    </div>
  );
}
