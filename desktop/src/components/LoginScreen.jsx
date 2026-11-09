import { Show, createSignal, createEffect, onCleanup, untrack } from "solid-js";
import { useAuth } from "../context/AuthContext.jsx";
import { useI18n } from "../i18n/index.jsx";
import BridgeUnlockBanner from "./BridgeUnlockBanner.jsx";
import { useVaultSwitcher } from "../context/VaultSwitcherContext.jsx";
import { daemon, getRenderState } from "../lib/daemon.js";
import { biometryAvailable, biometryPrompt } from "../lib/biometry.js";
import { toastError } from "../context/toastSignal.js";
import { sanitizeError, isHardwareError } from "../lib/utils.js";
import { IconLock, IconFingerprint, IconSpinner, IconBaluardLogo } from "./Icon.jsx";
import ThemeToggleFloating from "./ThemeToggleFloating.jsx";
import VaultSwitcher from "./VaultSwitcher.jsx";
import CopyButton from "./CopyButton.jsx";
import OpenSharedModal from "./OpenSharedModal.jsx";
import LegacyContactOpen from "./LegacyContactOpen.jsx";

export default function LoginScreen() {
  const auth = useAuth();
  const switcher = useVaultSwitcher();
  const { t } = useI18n();
  let passwordRef;

  const [wrongPassword, setWrongPassword] = createSignal(false);

  // Linux compatible-rendering recovery notice. The backend enables the
  // WebKitGTK workaround for THIS session when the previous run died
  // uncleanly (blank-window force-quit signature). One best-effort probe on
  // mount; silent no-op off Linux.
  const [renderRecovery, setRenderRecovery] = createSignal(false);
  getRenderState()
    .then(rs => {
      if (rs.linux && rs.recovery) setRenderRecovery(true);
    })
    .catch(() => {});

  // Plugin truth: the daemon reports per-vault Quick Unlock state, but only
  // this plugin can actually show a prompt (Linux holds keyring escrow with
  // no platform biometry, so the daemon says enabled while a prompt is
  // impossible). One probe per mount gates both the button and the prompt.
  const [pluginBiometryOk, setPluginBiometryOk] = createSignal(false);
  biometryAvailable()
    .then(ok => setPluginBiometryOk(ok))
    .catch(() => setPluginBiometryOk(false));

  // Re-query Quick Unlock status whenever the effective target vault changes.
  // Post-QU fix the keychain entry is per-vault, so the button must reflect
  // the currently-targeted vault, not a global flag.
  //
  // The effective slug is switchTarget (explicit pick) falling back to the
  // switcher's activeSlug (the daemon-active vault). Tracking activeSlug here
  // is what fixes the cold-start race: the effect fires on mount before the
  // daemon is reachable (activeSlug still null), so it skips; once vaults.list
  // resolves and activeSlug populates, the effect re-fires and probes the
  // right slug. Skip entirely when there is no target yet so we never fire a
  // no-slug probe that errors and logs at WARN.
  createEffect(
    () => auth.switchTarget() ?? switcher.activeSlug(),
    (target) => {
      if (!target) return;
      auth.refreshBiometric(target);
      // Session PIN escrow is also per-vault (in-memory). Re-query alongside.
      auth.refreshPin(target);
    },
  );
  const [bruteLock, setBruteLock] = createSignal(false);

  // One Quick Unlock at a time; the auto-prompt and the button share it so a
  // click cannot stack a second prompt on top of the running one. Tauri
  // invokes reject plugin errors as PLAIN STRINGS (the biometry plugin
  // serializes its error enum), so the cancel check must read the rejection
  // itself, not e.message.
  const [quBusy, setQuBusy] = createSignal(false);
  const runQuickUnlock = async (slug) => {
    if (bruteLock() || quBusy()) return;
    setQuBusy(true);
    try {
      await biometryPrompt();
      const infoStr = await daemon("vault.open", "", slug);
      await daemon("vault.biometric_unlock", "", slug);
      auth.finishQuickUnlock(infoStr);
    } catch (e) {
      const msg = typeof e === "string" ? e : e?.message || "";
      if (!/cancelled|canceled|user cancel/i.test(msg)) {
        toastError(sanitizeError(e, t));
      }
    } finally {
      setQuBusy(false);
    }
  };

  const [pinValue, setPinValue] = createSignal("");
  const [pinBusy, setPinBusy] = createSignal(false);

  // §4.8-2: join-side flow. The joiner cloned the shared vault (existing
  // clone flow), picked their OWN password, and waits for the admin's
  // approval. The password lives only in these signals and is wiped as
  // soon as the unlock attempt runs.
  const [joinMode, setJoinMode] = createSignal(false);
  const [joinState, setJoinState] = createSignal("form"); // form | waiting
  const [joinCode, setJoinCode] = createSignal("");
  const [joinPassword, setJoinPassword] = createSignal("");
  const [joinConfirm, setJoinConfirm] = createSignal("");
  const [joinDeviceName, setJoinDeviceName] = createSignal("");

  // 1Password/Bitwarden parity: present the platform biometric prompt as
  // soon as Quick Unlock is available on this screen instead of waiting
  // for the button. Cancel drops the user on the password form and the
  // button retries. One shot per resolved target so a cancel cannot loop.
  const [autoPromptedSlug, setAutoPromptedSlug] = createSignal(null);
  createEffect(
    () => [auth.biometricAvailable(), pluginBiometryOk(), auth.switchTarget() ?? switcher.activeSlug(), joinMode()],
    ([available, pluginOk, slug, joining]) => {
      // Guard reads are deliberately untracked: they gate this run only.
      if (untrack(() => !available || !pluginOk || !slug || joining || bruteLock() || quBusy())) return;
      // Never prompt while a password unlock is already in flight, nor
      // after the vault unlocked underneath us mid-batch.
      if (untrack(() => auth.status() !== "locked")) return;
      if (untrack(() => autoPromptedSlug() === slug)) return;
      setAutoPromptedSlug(slug);
      runQuickUnlock(slug);
    },
  );
  const [joinEmail, setJoinEmail] = createSignal("");
  const [introCode, setIntroCode] = createSignal("");
  const [joinBusy, setJoinBusy] = createSignal(false);
  // Slug captured at introduction time: polling must never float to
  // another vault if the user switches the active vault mid-wait.
  const [joinSlug, setJoinSlug] = createSignal("");
  const [showOpenShared, setShowOpenShared] = createSignal(false);
  const [showLegacyOpen, setShowLegacyOpen] = createSignal(false);
  let joinTimer;
  let pollInFlight = false;

  function stopJoinPolling() {
    if (joinTimer) clearInterval(joinTimer);
    joinTimer = undefined;
  }

  function exitJoinMode() {
    stopJoinPolling();
    setJoinMode(false);
    setJoinState("form");
    setJoinCode("");
    setJoinPassword("");
    setJoinConfirm("");
    setIntroCode("");
    setJoinSlug("");
  }

  function effectiveSlug() {
    return auth.switchTarget() ?? switcher.activeSlug();
  }

  async function doIntroduce(e) {
    e.preventDefault();
    const slug = effectiveSlug();
    if (!slug) {
      toastError(t("join.noVault"));
      return;
    }
    if (joinPassword().length < 8) {
      toastError(t("join.passwordShort"));
      return;
    }
    if (joinPassword() !== joinConfirm()) {
      toastError(t("join.passwordMismatch"));
      return;
    }
    setJoinBusy(true);
    try {
      const res = JSON.parse(
        await daemon("join.introduce", {
          slug,
          code: joinCode().trim(),
          password: joinPassword(),
          device_name: joinDeviceName().trim() || "My device",
          email: joinEmail().trim() || null,
        }),
      );
      setIntroCode(res.intro_code);
      setJoinSlug(slug);
      setJoinState("waiting");
      stopJoinPolling();
      pollApproval();
      joinTimer = setInterval(pollApproval, 10000);
    } catch (err) {
      toastError(sanitizeError(err, t));
    } finally {
      setJoinBusy(false);
    }
  }

  async function pollApproval() {
    if (pollInFlight) return;
    const slug = joinSlug();
    if (!slug) return;
    pollInFlight = true;
    try {
      const res = JSON.parse(await daemon("join.poll", { slug }));
      if (res.approved) {
        stopJoinPolling();
        // Reuse the standard unlock path: feed the chosen password into
        // the login field and run the normal machinery (canary-override
        // member unlock). The signal copies are wiped immediately. On
        // failure the join UI closes — the user lands on the normal
        // login form and can unlock with their password.
        if (passwordRef) passwordRef.value = joinPassword();
        setJoinPassword("");
        setJoinConfirm("");
        setJoinMode(false);
        const ok = await auth.unlock(t);
        if (!ok) toastError(t("join.unlockFailed"));
      }
    } catch {
      // Offline or transient: keep waiting.
    } finally {
      pollInFlight = false;
    }
  }

  onCleanup(() => stopJoinPolling());

  async function handleUnlock() {
    if (bruteLock() || auth.status() === "unlocking") return;
    const success = await auth.unlock(t);
    if (!success) {
      // A hardware-seal failure is not a wrong password: no red shake,
      // no lockout timer. The toast from unlock() explains the chip.
      if (isHardwareError(auth.lastUnlockError())) return;
      setWrongPassword(true);
      setBruteLock(true);
      setTimeout(() => {
        setWrongPassword(false);
      }, 500);
      setTimeout(() => {
        setBruteLock(false);
        passwordRef?.focus();
      }, 2000);
    }
  }

  return (
    <div class="login-screen flex items-center justify-center h-full bg-radial from-[var(--color-detail)] to-[var(--color-bg)] px-4 relative">
      <ThemeToggleFloating />

      <div class="login-screen__card w-full max-w-md p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative overflow-hidden transition-all-fast motion-fade-up">
        {/* Static gradient accents (contained glow, replaces expensive blur-3xl for GPU performance) */}
        <div class="login-screen__glow-top absolute -top-10 -left-10 w-40 h-40 rounded-full opacity-10 pointer-events-none" style={{"background": "radial-gradient(circle, var(--color-primary) 0%, transparent 70%)"}}></div>
        <div class="login-screen__glow-bottom absolute -bottom-10 -right-10 w-40 h-40 rounded-full opacity-10 pointer-events-none" style={{"background": "radial-gradient(circle, var(--color-accent) 0%, transparent 70%)"}}></div>

        <div class="login-screen__header text-center mb-8">
          <div class="login-screen__logo-container w-24 h-24 mx-auto mb-4 flex items-center justify-center">
            <IconBaluardLogo class="w-24 h-24 object-contain logo-shadow" />
          </div>
          <h1 class="text-2xl font-bold tracking-tight text-[var(--color-text)] font-logo">{t("login.title")}</h1>
          <p class="text-sm text-[var(--color-muted)] mt-1">{t("login.subtitle")}</p>
          <BridgeUnlockBanner onUnlock={async (row) => {
            // Same handoff as picking a locked vault in the switcher:
            // move the pre-unlock pointer and show that vault's unlock.
            await switcher.switchTo(row.slug);
            auth.setSwitchTarget(row.slug);
            auth.refreshActiveVault();
          }} />
          <Show when={switcher.vaults().length > 1} fallback={
            <Show when={auth.activeVault()}>
              <p class="text-xs text-[var(--color-primary)] mt-2 font-medium">{auth.activeVault().display_name}</p>
            </Show>
          }>
            <div class="w-full mt-4 text-left">
              <VaultSwitcher onLockedTarget={async (row) => {
                // Pre-unlock: moving the active pointer is safe (nothing is
                // unlocked yet) and is what makes the pick visibly change the
                // selection. Contrast with the unlocked view, where the
                // pointer must NOT move until the target actually unlocks.
                await switcher.switchTo(row.slug);
                auth.setSwitchTarget(row.slug);
                auth.refreshActiveVault();
              }} />
            </div>
          </Show>
        </div>

        <Show when={!joinMode()}>
        <form onSubmit={(e) => { e.preventDefault(); handleUnlock(); }} class="login-screen__form space-y-4">
          <div>
            <input
              ref={(el) => { passwordRef = el; auth.setLoginPasswordRef(el); }}
              type="password"
              data-testid="login-password"
              autocomplete="current-password"
              autocorrect="off"
              autocapitalize="off"
              spellcheck="false"
              placeholder={t("login.passwordPlaceholder")}
              class={`login-screen__input w-full px-4 py-3.5 rounded-xl bg-[var(--color-bg)] border text-[var(--color-text)] outline-none transition-all-fast ${
                wrongPassword()
                  ? "animate-shake border-red-500 ring-1 ring-red-500 text-red-500 focus:border-red-500 focus:ring-red-500"
                  : "border-[var(--color-border)] focus:border-[var(--color-primary)] focus:ring-1 focus:ring-[var(--color-primary)]"
              }`}
              disabled={auth.status() === "unlocking" || bruteLock()}
              autofocus
            />
          </div>

          <button
            type="submit"
            data-testid="login-unlock"
            disabled={auth.status() === "unlocking" || bruteLock()}
            class="login-screen__submit-btn w-full py-3.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-semibold transition-all shadow-lg shadow-black/10 active:scale-[0.99] disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer flex items-center justify-center gap-2"
          >
            <Show when={auth.status() === "unlocking"}>
              <IconSpinner class="w-4 h-4" />
            </Show>
            {auth.status() === "unlocking" ? t("login.unlocking") : t("login.unlock")}
          </button>

          {/* Quick Unlock (Biometric) */}
          <Show when={auth.biometricAvailable() && pluginBiometryOk()}>
            <button
              type="button"
              onClick={() => runQuickUnlock(auth.switchTarget() ?? switcher.activeSlug())}
              disabled={bruteLock() || quBusy()}
              class="login-screen__quick-unlock-btn w-full mt-2 py-3 rounded-xl border border-[var(--color-border)] text-[var(--color-muted)] hover:text-[var(--color-text)] hover:border-[var(--color-primary)] font-semibold transition-all cursor-pointer flex items-center justify-center gap-2 disabled:opacity-50"
            >
              <IconFingerprint class="w-4 h-4" />
              {t("login.quickUnlock")}
            </button>
          </Show>

          {/* Missing system keyring: print the fix, never run it */}
          <Show when={auth.keyringHint()}>
            <div class="w-full mt-3 text-center text-[11px] text-[var(--color-muted)] leading-relaxed">
              {t("common.keyringMissing")}{" "}
              <code class="font-mono text-[10px] bg-[var(--color-sidebar)] border border-[var(--color-border)] px-1.5 py-0.5 rounded">{auth.keyringHint()}</code>
            </div>
          </Show>

          {/* Quick Unlock (Session PIN) */}
          <Show when={auth.pinAvailable()}>
            <div class="login-screen__pin-wrap w-full mt-2">
              <input
                type="password"
                inputmode="numeric"
                pattern="[0-9]*"
                autocomplete="off"
                maxlength="6"
                placeholder={t("login.pinPlaceholder")}
                value={pinValue()}
                onInput={(e) => setPinValue(e.currentTarget.value.replace(/\D/g, "").slice(0, 6))}
                aria-label={t("login.pinPlaceholder")}
                disabled={pinBusy() || bruteLock()}
                class="login-screen__pin-input w-full py-3 px-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)] text-[var(--color-text)] text-center tracking-[0.5em] font-semibold outline-none focus:border-[var(--color-primary)] disabled:opacity-50"
              />
              <button
                type="button"
                onClick={async () => {
                  const pin = pinValue();
                  if (pin.length !== 6 || pinBusy() || bruteLock()) return;
                  setPinBusy(true);
                  try {
                    const target = auth.switchTarget();
                    await daemon("vault.open", "", target);
                    await daemon(
                      "vault.pin_unlock",
                      JSON.stringify({ pin }),
                      target,
                    );
                    setPinValue("");
                    auth.finishQuickUnlock();
                  } catch (e) {
                    toastError(sanitizeError(e, t));
                    setPinValue("");
                    // Escrow may have been nuked (5 wrong PINs): re-query.
                    auth.refreshPin(auth.switchTarget());
                  } finally {
                    setPinBusy(false);
                  }
                }}
                disabled={pinValue().length !== 6 || pinBusy() || bruteLock()}
                class="login-screen__pin-btn w-full mt-2 py-2.5 rounded-xl border border-[var(--color-border)] text-[var(--color-muted)] hover:text-[var(--color-text)] hover:border-[var(--color-primary)] font-semibold transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {pinBusy() ? t("login.unlocking") : t("login.pinUnlock")}
              </button>
            </div>
          </Show>
        </form>
        </Show>

        {/* §4.8-2: join-side flow — invite code in, intro code back, wait
            for the admin's approval, then unlock with the chosen password. */}
        <Show when={joinMode()}>
          <Show
            when={joinState() === "waiting"}
            fallback={
              <form onSubmit={doIntroduce} class="login-screen__form space-y-4">
                <div>
                  <label class="text-[10px] font-bold text-[var(--color-muted)] uppercase tracking-wide">{t("join.codeLabel")}</label>
                  <textarea
                    value={joinCode()}
                    onInput={(e) => setJoinCode(e.currentTarget.value)}
                    rows="3"
                    class="w-full mt-1 px-3 py-2.5 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-xs text-[var(--color-text)] font-mono outline-none focus:border-[var(--color-primary)] resize-none"
                    placeholder={t("join.codePlaceholder")}
                  />
                </div>
                <div>
                  <label class="text-[10px] font-bold text-[var(--color-muted)] uppercase tracking-wide">{t("join.passwordLabel")}</label>
                  <input
                    type="password"
                    value={joinPassword()}
                    onInput={(e) => setJoinPassword(e.currentTarget.value)}
                    autocomplete="new-password"
                    class="w-full mt-1 px-4 py-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
                  />
                </div>
                <div>
                  <label class="text-[10px] font-bold text-[var(--color-muted)] uppercase tracking-wide">{t("join.passwordConfirmLabel")}</label>
                  <input
                    type="password"
                    value={joinConfirm()}
                    onInput={(e) => setJoinConfirm(e.currentTarget.value)}
                    autocomplete="new-password"
                    class="w-full mt-1 px-4 py-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
                  />
                </div>
                <div>
                  <label class="text-[10px] font-bold text-[var(--color-muted)] uppercase tracking-wide">{t("join.nameLabel")}</label>
                  <input
                    value={joinDeviceName()}
                    onInput={(e) => setJoinDeviceName(e.currentTarget.value)}
                    maxlength="64"
                    class="w-full mt-1 px-4 py-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
                    placeholder={t("join.namePlaceholder")}
                  />
                </div>
                <div>
                  <label class="text-[10px] font-bold text-[var(--color-muted)] uppercase tracking-wide">{t("join.emailLabel")}</label>
                  <input
                    value={joinEmail()}
                    onInput={(e) => setJoinEmail(e.currentTarget.value)}
                    maxlength="254"
                    class="w-full mt-1 px-4 py-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
                    placeholder={t("join.emailPlaceholder")}
                  />
                </div>
                <button
                  type="submit"
                  disabled={joinBusy() || !joinCode().trim()}
                  class="w-full py-3.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-semibold transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer flex items-center justify-center gap-2"
                >
                  <Show when={joinBusy()}>
                    <IconSpinner class="w-4 h-4" />
                  </Show>
                  {t("join.sendRequest")}
                </button>
              </form>
            }
          >
            <div class="text-center space-y-4">
              <IconSpinner class="w-8 h-8 mx-auto text-[var(--color-primary)]" />
              <div>
                <p class="text-sm font-bold text-[var(--color-text)]">{t("join.waitingTitle")}</p>
                <p class="text-xs text-[var(--color-muted)] mt-1">{t("join.waitingHint")}</p>
              </div>
              <div class="p-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-left">
                <p class="text-[10px] text-[var(--color-muted)] mb-1">{t("join.introHint")}</p>
                <div class="flex items-center gap-2">
                  <code class="text-[10px] text-[var(--color-text)] break-all flex-1 font-mono">
                    {introCode()}
                  </code>
                  <CopyButton value={introCode()} />
                </div>
              </div>
            </div>
          </Show>
        </Show>

        <div class="mt-6 text-center border-t border-[var(--color-border)] pt-4 space-y-2">
          <Show when={renderRecovery()}>
            <p class="text-[11px] text-[var(--color-muted)] leading-relaxed">
              {t("login.renderRecoveryNotice")}
            </p>
          </Show>
          <button
            onClick={() => (joinMode() ? exitJoinMode() : setJoinMode(true))}
            class="block w-full text-sm font-medium text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
          >
            {joinMode() ? t("join.backToLogin") : t("join.joinLink")}
          </button>
          <button
            onClick={() => auth.setStatus("welcome")}
            class="login-screen__create-btn block w-full text-sm font-medium text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
          >
            {t("login.useDifferent")}
          </button>
          <button
            onClick={() => setShowOpenShared(true)}
            class="login-screen__create-btn block w-full text-sm font-medium text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
          >
            {t("share.guestLink")}
          </button>
          <button
            onClick={() => setShowLegacyOpen(true)}
            class="login-screen__create-btn block w-full text-sm font-medium text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
            data-testid="login-legacy-open"
          >
            {t("legacy.openKit")}
          </button>
        </div>
        <Show when={showOpenShared()}>
          <OpenSharedModal guest onClose={() => setShowOpenShared(false)} />
        </Show>
        <Show when={showLegacyOpen()}>
          <LegacyContactOpen onClose={() => setShowLegacyOpen(false)} />
        </Show>
      </div>
    </div>
  );
}
