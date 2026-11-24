import { createSignal, onCleanup, onSettled, Show, For, useContext } from "solid-js";
import { useAuth } from "../context/AuthContext.jsx";
import { VaultSwitcherContext } from "../context/VaultSwitcherContext.jsx";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { toastSuccess, toastError } from "../context/toastSignal.js";
import { sanitizeError } from "../lib/utils.js";
import { open } from "@tauri-apps/plugin-dialog";
import { registerLocalVault } from "../lib/cloneFlow.js";
import {
	IconSpinner,
	IconBaluardLogo,
	IconFolder,
	IconKey,
} from "./Icon.jsx";
import ThemeToggleFloating from "./ThemeToggleFloating.jsx";

/**
 * Forgot-password recovery: the vault is re-opened from the 24-word
 * recovery phrase alone. The daemon unwraps the Root Key from the vault's
 * recovery kit, binds this device a fresh member row, and sets the
 * password typed here as this device's master password — the old password
 * is never asked and never needed. Works only on a fresh install for this
 * vault (the daemon's brick guard refuses a device that already holds
 * keys), so it lives beside the login/welcome screens, never inside the
 * unlocked app.
 */
export default function RecoverVaultScreen() {
	const { t } = useI18n();
	const auth = useAuth();
	const switcher = useContext(VaultSwitcherContext);

	const [vaults, setVaults] = createSignal([]);
	const [slug, setSlug] = createSignal("");
	const [phrase, setPhrase] = createSignal("");
	const [password, setPassword] = createSignal("");
	const [confirm, setConfirm] = createSignal("");
	const [deviceName, setDeviceName] = createSignal(defaultDeviceName());
	const [busy, setBusy] = createSignal(false);
	const [loading, setLoading] = createSignal(true);

	onSettled(() => {
		void loadVaults();
	});

	async function loadVaults() {
		try {
			const data = JSON.parse(await daemon("vaults.list", ""));
			const list = Array.isArray(data.vaults) ? data.vaults : [];
			setVaults(list);
			// The vault whose password was forgotten: whatever the switcher
			// had selected, else the only registered vault.
			const target = auth.switchTarget();
			const pre = list.find((v) => v.slug === target) || list[0];
			if (pre) setSlug(pre.slug);
		} catch {
			setVaults([]);
		} finally {
			setLoading(false);
		}
	}

	function phraseWords() {
		return phrase().trim().split(/\s+/).filter(Boolean);
	}

	async function addLocal() {
		try {
			const selected = await open({ directory: true, multiple: false });
			if (!selected) return;
			const { slug: added } = await registerLocalVault(selected);
			await loadVaults();
			setSlug(added);
			toastSuccess(t("welcome.openLocal"));
		} catch (e) {
			toastError(sanitizeError(e, t));
		}
	}

	async function submit(e) {
		e.preventDefault();
		if (busy()) return;
		if (!slug()) {
			toastError(t("recover.pickVault"));
			return;
		}
		if (phraseWords().length !== 24) {
			toastError(t("recover.badPhrase"));
			return;
		}
		if (password().length < 8) {
			toastError(t("recover.shortPassword"));
			return;
		}
		if (password() !== confirm()) {
			toastError(t("recover.passwordMismatch"));
			return;
		}
		if (!deviceName().trim()) {
			toastError(t("recover.deviceNameRequired"));
			return;
		}
		setBusy(true);
		try {
			await daemon("vault.recover_kit", {
				slug: slug(),
				phrase: phraseWords()
					.map((w) => w.trim().toLowerCase())
					.join(" "),
				password: password(),
				device_name: deviceName().trim(),
			});
			passwordSignalCleanup();
			toastSuccess(t("recover.done"));
			if (switcher) await switcher.refresh();
			auth.setSwitchTarget(slug());
			// Back to the unlock screen: the user signs in with the NEW
			// password they just chose.
			auth.setStatus("locked");
		} catch (err) {
			toastError(sanitizeError(err, t));
		} finally {
			setBusy(false);
		}
	}

	function passwordSignalCleanup() {
		setPassword("");
		setConfirm("");
		setPhrase("");
	}

	// Review N6: the phrase and password must not outlive the screen.
	onCleanup(() => {
		passwordSignalCleanup();
		setDeviceName("");
	});

	return (
		<div class="welcome-screen flex justify-center h-full overflow-y-auto bg-radial from-[var(--color-detail)] to-[var(--color-bg)] px-4 py-8">
			<div class="welcome-screen__card w-full max-w-md my-auto p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl motion-fade-up">
				<div class="welcome-screen__header text-center mb-6">
					<div class="w-16 h-16 mx-auto mb-3 flex items-center justify-center">
						<IconBaluardLogo class="w-16 h-16 object-contain logo-shadow" />
					</div>
					<h1 class="text-xl font-bold tracking-tight text-[var(--color-text)]">
						{t("recover.title")}
					</h1>
					<p class="text-sm text-[var(--color-muted)] mt-1">
						{t("recover.subtitle")}
					</p>
				</div>

				<Show
					when={!loading() && vaults().length > 0}
					fallback={
						<div class="text-center space-y-4">
							<p class="text-sm text-[var(--color-muted)]">
								{t("recover.noVaults")}
							</p>
							<button
								type="button"
								onClick={addLocal}
								class="w-full px-4 py-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-bg)] hover:border-[var(--color-primary)] text-sm text-[var(--color-text)] font-medium transition-all flex items-center justify-center gap-2 cursor-pointer"
							>
								<IconFolder class="w-5 h-5" />
								<span>{t("welcome.openLocal")}</span>
							</button>
							<p class="text-xs text-[var(--color-muted)]">
								{t("recover.cloneHint")}
							</p>
						</div>
					}
				>
					<form onSubmit={submit} class="space-y-4" data-testid="recover-form">
						<div>
							<label class="block text-xs font-semibold text-[var(--color-muted)] mb-1" for="recover-vault">
								{t("recover.vault")}
							</label>
							<select
								id="recover-vault"
								value={slug()}
								onChange={(e) => setSlug(e.currentTarget.value)}
								class="w-full px-3 py-2.5 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-sm text-[var(--color-text)] cursor-pointer"
							>
								<For each={vaults()}>
									{(v) => (
										<option value={v.slug}>{v.display_name || v.slug}</option>
									)}
								</For>
							</select>
						</div>

						<div>
							<label class="block text-xs font-semibold text-[var(--color-muted)] mb-1" for="recover-phrase">
								{t("recover.phrase")}
							</label>
							<textarea
								id="recover-phrase"
								value={phrase()}
								onInput={(e) => setPhrase(e.currentTarget.value)}
								rows={3}
								autocomplete="off"
								spellcheck={false}
								placeholder={t("recover.phrasePlaceholder")}
								class="w-full px-3 py-2.5 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-sm text-[var(--color-text)] font-mono resize-none"
							/>
							<Show when={phrase().trim() && phraseWords().length !== 24}>
								<p class="text-xs text-[var(--color-danger-strong)] mt-1">
									{t("recover.badPhrase")}
								</p>
							</Show>
						</div>

						<div>
							<label class="block text-xs font-semibold text-[var(--color-muted)] mb-1" for="recover-password">
								{t("recover.newPassword")}
							</label>
							<input
								id="recover-password"
								type="password"
								value={password()}
								onInput={(e) => setPassword(e.currentTarget.value)}
								autocomplete="new-password"
								class="w-full px-3 py-2.5 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-sm text-[var(--color-text)]"
							/>
						</div>

						<div>
							<label class="block text-xs font-semibold text-[var(--color-muted)] mb-1" for="recover-confirm">
								{t("recover.confirm")}
							</label>
							<input
								id="recover-confirm"
								type="password"
								value={confirm()}
								onInput={(e) => setConfirm(e.currentTarget.value)}
								autocomplete="new-password"
								class="w-full px-3 py-2.5 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-sm text-[var(--color-text)]"
							/>
						</div>

						<div>
							<label class="block text-xs font-semibold text-[var(--color-muted)] mb-1" for="recover-device">
								{t("recover.deviceName")}
							</label>
							<input
								id="recover-device"
								type="text"
								value={deviceName()}
								onInput={(e) => setDeviceName(e.currentTarget.value)}
								class="w-full px-3 py-2.5 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-sm text-[var(--color-text)]"
							/>
						</div>

						<p class="text-xs text-[var(--color-muted)] flex items-start gap-2">
							<IconKey class="w-4 h-4 shrink-0 mt-0.5 text-[var(--color-muted)]" />
							<span>{t("recover.freshInstallNote")}</span>
						</p>

						<button
							type="submit"
							disabled={busy()}
							class="w-full py-3 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-semibold transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer flex items-center justify-center gap-2"
							data-testid="recover-submit"
						>
							<Show when={busy()}>
								<IconSpinner class="w-4 h-4" />
							</Show>
							{t("recover.submit")}
						</button>
					</form>
				</Show>

				<div class="mt-6 text-center border-t border-[var(--color-border)] pt-4">
					<button
						type="button"
						onClick={() =>
							auth.setStatus(vaults().length > 0 || loading() ? "locked" : "welcome")
						}
						class="text-sm font-medium text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
					>
						{t("recover.back")}
					</button>
				</div>
			</div>
			<ThemeToggleFloating />
		</div>
	);
}

function defaultDeviceName() {
	const ua = navigator.userAgent;
	if (ua.includes("Windows")) return "Windows PC";
	if (ua.includes("Mac")) return "Mac";
	if (ua.includes("Linux")) return "Linux PC";
	return "Baluard device";
}
