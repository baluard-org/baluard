import { open } from "@tauri-apps/plugin-dialog";
import { createSignal, Show } from "solid-js";
import { useAuth } from "../context/AuthContext.jsx";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import { useI18n } from "../i18n/index.jsx";
import { registerLocalVault } from "../lib/cloneFlow.js";
import { sanitizeError } from "../lib/utils.js";
import CloneFromProviderScreen from "./CloneFromProviderScreen.jsx";
import { IconDownload, IconFolder, IconLock, IconPlus } from "./Icon.jsx";

// Phase 4 wizard first screen: three entry points.
//   New vault            -> existing create flow (status "init")
//   Open local vault     -> native dir picker -> vaults.register_local -> login
//   Download from provider -> CloneFromProviderScreen (clone + unlock)
export default function WelcomeScreen() {
	const { t } = useI18n();
	const auth = useAuth();
	const [view, setView] = createSignal("menu"); // menu | clone

	async function openLocal() {
		try {
			const selected = await open({ directory: true, multiple: false });
			if (!selected) return;
			const { slug } = await registerLocalVault(selected);
			toastSuccess(t("welcome.openLocal"));
			// Refresh the active-vault signal so the login screen shows it, then
			// drop into the normal unlock flow.
			await auth.refreshActiveVault();
			auth.setSwitchTarget(slug);
			auth.setStatus("locked");
		} catch (e) {
			toastError(sanitizeError(e, t));
		}
	}

	return (
		<Show
			when={view() === "clone"}
			fallback={
				<div class="welcome-screen flex items-center justify-center h-full bg-radial from-[var(--color-detail)] to-[var(--color-bg)] px-4">
					<div class="welcome-screen__card w-full max-w-md p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl animate-fade-in-up">
						<div class="welcome-screen__header text-center mb-8">
							<div class="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-tr from-[var(--color-sidebar)] to-[var(--color-border)] border border-[var(--color-border)] flex items-center justify-center shadow-lg">
								<IconLock class="w-8 h-8 text-[var(--color-primary)]" />
							</div>
							<h1 class="text-2xl font-bold tracking-tight text-[var(--color-text)]">
								{t("welcome.title")}
							</h1>
							<p class="text-sm text-[var(--color-muted)] mt-1">
								{t("welcome.subtitle")}
							</p>
						</div>

						<div class="flex flex-col gap-3">
							<button
								type="button"
								onClick={() => auth.setStatus("init")}
								class="welcome-screen__btn-new w-full px-4 py-4 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-semibold transition-all shadow-lg flex items-center gap-3 cursor-pointer"
							>
								<IconPlus class="w-5 h-5" />
								<span>{t("welcome.newVault")}</span>
							</button>

							<button
								type="button"
								onClick={openLocal}
								class="welcome-screen__btn-open w-full px-4 py-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-bg)] hover:border-[var(--color-primary)] text-[var(--color-text)] font-medium transition-all flex items-center gap-3 cursor-pointer"
							>
								<IconFolder class="w-5 h-5" />
								<span>{t("welcome.openLocal")}</span>
							</button>

							<button
								type="button"
								onClick={() => setView("clone")}
								class="welcome-screen__btn-download w-full px-4 py-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-bg)] hover:border-[var(--color-primary)] text-[var(--color-text)] font-medium transition-all flex items-center gap-3 cursor-pointer"
							>
								<IconDownload class="w-5 h-5" />
								<span>{t("welcome.downloadFromProvider")}</span>
							</button>
						</div>

						<Show when={auth.activeVault()}>
							<div class="mt-6 text-center border-t border-[var(--color-border)] pt-4">
								<button
									type="button"
									onClick={() => auth.setStatus("locked")}
									class="text-sm font-medium text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
								>
									{t("login.title")}
								</button>
							</div>
						</Show>
					</div>
				</div>
			}
		>
			<CloneFromProviderScreen onCancel={() => setView("menu")} />
		</Show>
	);
}
