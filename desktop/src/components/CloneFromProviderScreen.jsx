import { createSignal, For, onCleanup, Show } from "solid-js";
import { useAuth } from "../context/AuthContext.jsx";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import { useI18n } from "../i18n/index.jsx";
import { startClone } from "../lib/cloneFlow.js";
import { daemon } from "../lib/daemon.js";
import { createProviderConnect } from "../lib/providerConnect.js";
import { sanitizeError } from "../lib/utils.js";
import CopyButton from "./CopyButton.jsx";
import ExternalLink from "./ExternalLink.jsx";
import { IconAlert, IconArrowLeft, IconDownload, IconLock, IconGitHub, IconGitLab, IconCodeberg } from "./Icon.jsx";

const PROVIDERS = [
	{ key: "github" },
	{ key: "gitlab" },
	{ key: "codeberg" },
];

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
	let passwordRef;

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
			setError(sanitizeError(e, t));
			setStep("repos");
		}
	}

	// Step 5: unlock the freshly cloned vault.
	async function doUnlock() {
		const password = passwordRef?.value;
		if (!password) return;
		const slug = chosenRepo()?.vault_slug || chosenRepo()?.name;
		try {
			await daemon("vault.open", "", slug);
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

	const providerLabel = (key) =>
		key ? key.charAt(0).toUpperCase() + key.slice(1) : "";

	return (
		<div class="clone-screen flex items-center justify-center h-full bg-radial from-[var(--color-detail)] to-[var(--color-bg)] px-4">
			<div class="clone-screen__card w-full max-w-lg p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl animate-fade-in-up">
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
										value={authInfo().session.user_code}
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
							<p class="text-sm">{t("clone.enterPassword")}</p>
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
							<button
								type="submit"
								class="w-full py-3.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-semibold cursor-pointer"
							>
								{t("login.unlock")}
							</button>
						</form>
					</div>
				</Show>
			</div>
		</div>
	);
}
