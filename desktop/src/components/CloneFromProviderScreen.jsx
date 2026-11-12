import { createSignal, For, onCleanup, Show } from "solid-js";
import { useAuth } from "../context/AuthContext.jsx";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import { useI18n } from "../i18n/index.jsx";
import {
  discardOrphanVault,
  parseCloneClash,
  registerLocalVault,
  startClone,
} from "../lib/cloneFlow.js";
import { daemon } from "../lib/daemon.js";
import { providerLabel as providerLabelT } from "../lib/providers.js";
import { createProviderConnect } from "../lib/providerConnect.js";
import { sanitizeError } from "../lib/utils.js";
import CopyButton from "./CopyButton.jsx";
import ExternalLink from "./ExternalLink.jsx";
import FocusTrap from "./FocusTrap.jsx";
import { Button } from "./Primitives.jsx";
import {
  IconAlert,
  IconArrowLeft,
  IconDownload,
  IconLock,
  IconGitHub,
  IconGitLab,
  IconCodeberg,
} from "./Icon.jsx";

const PROVIDERS = [{ key: "github" }, { key: "gitlab" }, { key: "codeberg" }];

const WARNED_KEY = "baluard.clone2faDismissed";

// Phase 4 "Download from provider" flow:
// pick -> authenticate (if needed) -> vault repo list -> clone (progress) ->
// master password -> unlock. Reachable from WelcomeScreen.
export default function CloneFromProviderScreen(props) {
  const { t } = useI18n();
  const auth = useAuth();

  const [step, setStep] = createSignal("pick"); // pick | auth | repos | cloning | unlock
  const [provider, setProvider] = createSignal(null);
  const [repos, setRepos] = createSignal([]);
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal(null);
  const [authInfo, setAuthInfo] = createSignal(null); // { user_code, verification_uri, url }
  const [progress, setProgress] = createSignal({
    pct: 0,
    objects: 0,
    bytes: 0,
  });
  const [chosenRepo, setChosenRepo] = createSignal(null);
  // Clone-clash dialog: the daemon refused because this slug already exists.
  // kind "registered" = live registry entry (open it, or delete it and pull
  // the fresh copy); kind "orphan" = unregistered folder on disk (adopt it,
  // or delete it). Deletion is credential-free: the user controls the
  // machine, and the folder is a plain directory they could remove in a
  // file manager.
  const [clash, setClash] = createSignal(null);
  const [clashPath, setClashPath] = createSignal(null);
  const [clashError, setClashError] = createSignal(null);
  const [clashBusy, setClashBusy] = createSignal(false);
  let dialogRef;
  let passwordRef;
  let phraseRef;

  const conn = createProviderConnect({
    t,
    onUpdate: (info) => setAuthInfo(info),
  });
  onCleanup(() => conn.dispose());

  // 2FA warning banner: dismissible, shown once per provider.
  const dismissed = () => {
    try {
      const raw = localStorage.getItem(WARNED_KEY);
      return raw ? JSON.parse(raw) : {};
    } catch {
      return {};
    }
  };
  const [warnHidden, setWarnHidden] = createSignal(dismissed());
  function dismissWarn() {
    const next = { ...warnHidden(), [provider() || "any"]: true };
    setWarnHidden(next);
    try {
      localStorage.setItem(WARNED_KEY, JSON.stringify(next));
    } catch {}
  }

  function back() {
    props?.onCancel?.();
  }

  // Step 1 -> 2: user picked a provider. Start auth if needed, then list repos.
  async function pickProvider(key) {
    setProvider(key);
    setError(null);
    setLoading(true);
    setStep("auth");
    try {
      await conn.connect(key);
      await listRepos(key);
    } catch (e) {
      setError(sanitizeError(e, t));
      setLoading(false);
    }
  }

  async function listRepos(key) {
    setLoading(true);
    setError(null);
    try {
      const raw = await daemon(
        "provider.vault_repos",
        JSON.stringify({ provider: key }),
      );
      const list = JSON.parse(raw);
      if (!Array.isArray(list) || list.length === 0) {
        setError(t("clone.noVaultRepos"));
        setStep("pick");
        setLoading(false);
        return;
      }
      setRepos(list);
      setStep("repos");
    } catch (e) {
      setError(sanitizeError(e, t));
      setStep("pick");
    } finally {
      setLoading(false);
    }
  }

  // Step 3 -> 4: user picked a repo. Clone it.
  async function pickRepo(repo) {
    setChosenRepo(repo);
    setStep("cloning");
    setError(null);
    setProgress({ pct: 0, objects: 0, bytes: 0 });
    try {
      await startClone(
        {
          clone_url: repo.clone_url,
          provider: provider(),
          slug: repo.vault_slug || repo.name,
          display_name: repo.name,
        },
        { onProgress: (p) => setProgress(p), t },
      );
      toastSuccess(t("clone.cloned"));
      setStep("unlock");
    } catch (e) {
      const parsed = parseCloneClash(String(e?.message ?? e));
      if (parsed) {
        setClash(parsed);
        setClashPath(null);
        setClashError(null);
        if (parsed.kind === "registered") {
          // Surface the folder the wipe would delete, wherever it was
          // registered from (imported folders need not live in the
          // default vaults directory).
          daemon("vaults.list", "")
            .then((raw) => JSON.parse(raw))
            .then((rows) => {
              const row = Array.isArray(rows)
                ? rows.find((r) => r.slug === parsed.slug)
                : null;
              if (row?.path) setClashPath(row.path);
            })
            .catch(() => {});
        }
      } else {
        setError(sanitizeError(e, t));
      }
      setStep("repos");
    }
  }

  function clashDismiss() {
    if (clashBusy()) return;
    setClash(null);
    setClashPath(null);
    setClashError(null);
  }

  // Adopt an unregistered leftover folder and drop into the unlock flow.
  async function clashAdoptFolder() {
    const c = clash();
    if (!c?.path) return;
    setClashBusy(true);
    try {
      const { slug } = await registerLocalVault(c.path);
      setClashBusy(false);
      clashDismiss();
      try {
        await auth.refreshActiveVault();
        auth.setSwitchTarget(slug);
        auth.setStatus("locked");
      } catch (e) {
        toastError(sanitizeError(e, t));
      }
    } catch (e) {
      setClashBusy(false);
      setClashError(String(e?.message ?? e));
    }
  }

  // Destructive arm: delete the local copy — registered vault or orphan
  // alike — and re-download the selected vault in place. Credential-free:
  // the user controls the machine, and the daemon's marker check prevents
  // wrong-target deletes.
  async function clashDiscardFolder() {
    const c = clash();
    const repo = chosenRepo();
    if (!c?.slug || !repo) return;
    setClashError(null);
    setClashBusy(true);
    try {
      await discardOrphanVault(c.slug);
      setClashBusy(false);
      setClash(null);
      setClashPath(null);
      setClashError(null);
      await pickRepo(repo);
    } catch (e) {
      setClashBusy(false);
      setClashError(String(e?.message ?? e));
    }
  }

  // Cancel exits the whole clone wizard back to the start screen, not
  // just back to the repo list.
  function clashExitToStart() {
    if (clashBusy()) return;
    if (props?.onCancel) {
      props.onCancel();
      return;
    }
    clashDismiss();
  }

  // Arm (b): keep the local copy, drop into the normal unlock flow for it.
  async function clashOpenExisting() {
    const slug = clash()?.slug;
    if (!slug) return;
    setClash(null);
    setClashPath(null);
    setClashError(null);
    try {
      await auth.refreshActiveVault();
      auth.setSwitchTarget(slug);
      auth.setStatus("locked");
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  // Step 5: unlock the freshly cloned vault.
  async function doUnlock() {
    const password = passwordRef?.value;
    if (!password) return;
    const phrase = phraseRef?.value || "";
    if (!phrase.trim()) return;
    const slug = chosenRepo()?.vault_slug || chosenRepo()?.name;
    try {
      await daemon("vault.open", "", slug);
      // A downloaded vault never carries the device-private key (it is
      // gitignored inside the vault and never syncs), so the master
      // password alone can never open it — the phrase recovers the
      // root key and the password seals this device's fresh key.
      await daemon(
        "vault.enroll_with_phrase",
        JSON.stringify({
          slug,
          phrase: phrase.trim(),
          master_password: password,
        }),
        slug,
      );
      // Do not leave the master password live in the DOM after unlock.
      if (passwordRef) passwordRef.value = "";
      if (phraseRef) phraseRef.value = "";
      const infoStr = await daemon(
        "vault.unlock",
        JSON.stringify({ slug, password }),
        slug,
      );
      try {
        auth.setVaultInfo(JSON.parse(infoStr));
      } catch {}
      auth.setStatus("unlocked");
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  const providerLabel = (key) => providerLabelT(t, key);

  return (
    <div class="clone-screen flex justify-center h-full overflow-y-auto bg-radial from-[var(--color-detail)] to-[var(--color-bg)] px-4 py-8">
      <div class="clone-screen__card w-full max-w-lg my-auto p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl motion-fade-up">
        <div class="flex items-center gap-3 mb-6">
          <button
            type="button"
            onClick={back}
            class="clone-screen__back text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer"
            aria-label={t("common.back")}
          >
            <IconArrowLeft class="w-5 h-5" />
          </button>
          <IconDownload class="w-6 h-6 text-[var(--color-primary)]" />
          <h1 class="text-xl font-bold text-[var(--color-text)]">
            {t("clone.title")}
          </h1>
        </div>

        <Show when={error()}>
          <div class="clone-screen__error mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-sm text-red-400 flex items-start gap-2">
            <IconAlert class="w-4 h-4 mt-0.5 shrink-0" />
            <span>{error()}</span>
          </div>
        </Show>

        {/* Step: pick provider */}
        <Show when={step() !== "cloning" && step() !== "unlock"}>
          {/* 2FA warning banner (shown once per provider, dismissible) */}
          <Show
            when={provider() && !warnHidden()[provider()] && step() === "pick"}
          >
            <div class="clone-screen__warn mb-4 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-xs text-amber-300">
              <div class="flex items-start gap-2">
                <IconAlert class="w-4 h-4 mt-0.5 shrink-0" />
                <div class="flex-1">
                  <p>{t("clone.twoFaWarning")}</p>
                </div>
                <button
                  type="button"
                  onClick={dismissWarn}
                  class="text-amber-300/70 hover:text-amber-200 cursor-pointer shrink-0"
                  aria-label={t("common.dismiss")}
                >
                  ×
                </button>
              </div>
            </div>
          </Show>

          {/* Provider picker */}
          <Show when={step() === "pick"}>
            <p class="text-sm text-[var(--color-muted)] mb-4">
              {t("clone.pickProvider")}
            </p>
            <div class="flex flex-col gap-2">
              <For each={PROVIDERS}>
                {(p) => (
                  <button
                    type="button"
                    onClick={() => pickProvider(p.key)}
                    class="clone-screen__provider w-full px-4 py-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-bg)] hover:border-[var(--color-primary)] text-left font-medium text-[var(--color-text)] transition-all cursor-pointer flex items-center gap-3"
                  >
                    <Show when={p.key === "github"}>
                      <IconGitHub class="w-5 h-5 opacity-90 shrink-0" />
                    </Show>
                    <Show when={p.key === "gitlab"}>
                      <IconGitLab class="w-5 h-5 opacity-90 shrink-0" />
                    </Show>
                    <Show when={p.key === "codeberg"}>
                      <IconCodeberg class="w-5 h-5 opacity-90 shrink-0" />
                    </Show>
                    <span>{providerLabel(p.key)}</span>
                  </button>
                )}
              </For>
            </div>
          </Show>

          {/* Authenticating (device flow / web oauth) */}
          <Show when={step() === "auth" && loading()}>
            <div class="text-center py-6">
              <Show
                when={
                  authInfo()?.method === "device-flow" && authInfo()?.session
                }
              >
                <p class="text-sm text-[var(--color-text)] mb-2">
                  {t("sync.deviceFlowInstructions")}
                </p>
                <div class="flex items-center justify-center gap-2 my-3">
                  <p class="text-2xl font-mono font-bold tracking-widest text-[var(--color-primary)]">
                    {authInfo().session.user_code}
                  </p>
                  <CopyButton
                    value={authInfo().session.user_code?.replace(/-/g, "")}
                    title={t("sync.copyCode")}
                  />
                </div>
                <ExternalLink
                  href={authInfo().session.verification_uri}
                  class="text-sm text-[var(--color-primary)] underline"
                >
                  {authInfo().session.verification_uri}
                </ExternalLink>
                <p class="text-xs text-[var(--color-muted)] mt-3">
                  {t("sync.deviceFlowPolling")}
                </p>
              </Show>
              <Show when={authInfo()?.method === "web-oauth"}>
                <p class="text-sm text-[var(--color-text)] mb-2">
                  {t("clone.webOAuthOpened")}
                </p>
                <Show when={authInfo()?.url}>
                  <ExternalLink
                    href={authInfo().url}
                    class="text-sm text-[var(--color-primary)] underline"
                  >
                    {t("clone.webOAuthRelink")}
                  </ExternalLink>
                </Show>
                <p class="text-xs text-[var(--color-muted)] mt-3">
                  {t("sync.deviceFlowPolling")}
                </p>
              </Show>
              <Show when={!authInfo()?.method}>
                <p class="text-sm text-[var(--color-muted)]">
                  {t("sync.connecting")}
                </p>
              </Show>
            </div>
          </Show>

          {/* Repo list */}
          <Show when={step() === "repos"}>
            <p class="text-sm text-[var(--color-muted)] mb-4">
              {t("clone.pickRepo")}
            </p>
            <div class="flex flex-col gap-2 max-h-72 overflow-y-auto">
              <For each={repos()}>
                {(repo) => (
                  <button
                    type="button"
                    onClick={() => pickRepo(repo)}
                    class="clone-screen__repo w-full px-4 py-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-bg)] hover:border-[var(--color-primary)] text-left transition-all cursor-pointer"
                  >
                    <div class="font-medium text-[var(--color-text)]">
                      {repo.full_name || repo.name}
                    </div>
                    <Show when={repo.vault_slug}>
                      <div class="text-xs text-[var(--color-muted)] mt-0.5">
                        {repo.vault_slug}
                      </div>
                    </Show>
                  </button>
                )}
              </For>
            </div>
          </Show>
        </Show>

        {/* Step: cloning (progress bar) */}
        <Show when={step() === "cloning"}>
          <div class="py-6">
            <p class="text-sm text-[var(--color-text)] mb-3">
              {t("clone.cloning")}
            </p>
            <div class="w-full h-2 rounded-full bg-[var(--color-bg)] overflow-hidden">
              <div
                class="h-full bg-[var(--color-primary)] transition-all"
                style={{
                  width: `${Math.min(100, Math.max(2, progress().pct))}%`,
                }}
              />
            </div>
            <p class="text-xs text-[var(--color-muted)] mt-2">
              {progress().pct}% &middot; {progress().objects}{" "}
              {t("clone.objects")}
            </p>
          </div>
        </Show>

        {/* Step: unlock with master password */}
        <Show when={step() === "unlock"}>
          <div class="py-2">
            <div class="flex items-center gap-2 mb-4 text-[var(--color-text)]">
              <IconLock class="w-5 h-5 text-[var(--color-primary)]" />
              <p class="text-sm">{t("clone.enrollBody")}</p>
            </div>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                doUnlock();
              }}
              class="space-y-4"
            >
              <input
                ref={(el) => {
                  passwordRef = el;
                }}
                type="password"
                autocomplete="current-password"
                placeholder={t("login.passwordPlaceholder")}
                autofocus
                class="w-full px-4 py-3.5 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] focus:ring-1 focus:ring-[var(--color-primary)]"
              />
              <textarea
                ref={(el) => {
                  phraseRef = el;
                }}
                rows={3}
                autocomplete="off"
                spellcheck={false}
                placeholder={t("clone.phrasePlaceholder")}
                class="w-full px-4 py-3.5 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] focus:ring-1 focus:ring-[var(--color-primary)] resize-none text-sm"
              />
              <button
                type="submit"
                class="w-full py-3.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-semibold cursor-pointer"
              >
                {t("login.enrollAction")}
              </button>
            </form>
          </div>
        </Show>
      </div>

      {/* Clone-clash dialog: this vault already exists on this device. */}
      <Show when={clash()}>
        <div
          ref={dialogRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby="clone-clash-title"
          aria-describedby="clone-clash-desc"
          class="clone-screen__clash fixed inset-0 bg-black/50 flex items-center justify-center z-50"
        >
          {/* Escape dismisses back to the repo list; only the Cancel
						button exits the whole wizard to the start screen — the
						lighter gesture gets the lighter undo. */}
          <FocusTrap containerRef={dialogRef} onEscape={clashDismiss} />
          <div class="bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-2xl p-6 max-w-md w-full mx-4 shadow-2xl">
            <h3
              id="clone-clash-title"
              class="text-lg font-bold text-[var(--color-text)] mb-2"
            >
              {t("clone.clashTitle")}
            </h3>
            <p
              id="clone-clash-desc"
              class="text-sm text-[var(--color-muted)] mb-2"
            >
              {clash()?.kind === "orphan"
                ? t("clone.clashOrphanBody", { slug: clash()?.slug })
                : t("clone.clashBody", { slug: clash()?.slug })}
            </p>
            <Show when={clashPath()}>
              <p class="text-[10px] font-mono text-[var(--color-muted)] mb-3 break-all">
                {clashPath()}
              </p>
            </Show>

            <Show
              when={clash()?.kind === "registered"}
              fallback={
                <div class="flex flex-col gap-2">
                  <Button
                    onClick={clashAdoptFolder}
                    disabled={clashBusy()}
                    class="w-full py-2.5"
                  >
                    {t("clone.clashUseExisting")}
                  </Button>
                  <Button
                    onClick={clashDiscardFolder}
                    disabled={clashBusy()}
                    variant="danger"
                    class="w-full py-2.5"
                  >
                    {clashBusy()
                      ? t("vault.vaultSwitcher.working")
                      : t("clone.clashReimport")}
                  </Button>
                  <Button onClick={clashExitToStart} class="w-full py-2.5">
                    {t("common.cancel")}
                  </Button>
                </div>
              }
            >
              <div class="flex flex-col gap-2">
                <Button onClick={clashOpenExisting} class="w-full py-2.5">
                  {t("clone.clashOpenExisting")}
                </Button>
                <Button
                  onClick={clashDiscardFolder}
                  disabled={clashBusy()}
                  variant="danger"
                  class="w-full py-2.5"
                >
                  {clashBusy()
                    ? t("vault.vaultSwitcher.working")
                    : t("clone.clashReimport")}
                </Button>
                <Button onClick={clashDismiss} class="w-full py-2.5">
                  {t("common.cancel")}
                </Button>
              </div>
              <Show when={clashError()}>
                <p class="text-sm text-[var(--color-danger)] mt-3">
                  {clashError()}
                </p>
              </Show>
            </Show>
            <Show when={clash()?.kind === "orphan" && clashError()}>
              <p class="text-sm text-[var(--color-danger)] mt-3">
                {clashError()}
              </p>
            </Show>
          </div>
        </div>
      </Show>
    </div>
  );
}
