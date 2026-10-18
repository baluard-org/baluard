// Reusable provider connection flow for the desktop.
//
// Runs the appropriate auth method for a provider (GitHub/GitLab = device flow,
// Codeberg = web-OAuth PKCE, any = PAT override) to completion, calling
// `onUpdate` with human-readable phase changes. Extracted from SyncTab so the
// Phase 4 "download from provider" flow can reuse the exact same wiring.
//
// Usage:
//   const conn = createProviderConnect({ t, onUpdate });
//   await conn.connect("github");           // resolves { username } on success
//   conn.dispose();                         // clears any pending timers

import { openUrl } from "@tauri-apps/plugin-opener";
import { daemon } from "./daemon.js";
import { sanitizeError } from "./utils.js";

function buildOverrides(opts) {
	const o = {};
	if (opts?.client_id) o.client_id = opts.client_id;
	if (opts?.instance_url) o.instance_url = opts.instance_url;
	return o;
}

export function createProviderConnect({ t, onUpdate }) {
	let deviceTimer = null;
	let webTimer = null;

	function dispose() {
		if (deviceTimer) {
			clearTimeout(deviceTimer);
			deviceTimer = null;
		}
		if (webTimer) {
			clearTimeout(webTimer);
			webTimer = null;
		}
	}

	// Resolve a provider's auth method ("device-flow" | "web-oauth" | "pat")
	// from provider.list, falling back per-provider if unknown.
	async function resolveMethod(provider) {
		// Desktop prefers the browser sign-in for GitHub (mobile parity): the
		// daemon route serves it and PAT stays available via the PAT field.
		if (provider === "github") return "web-oauth";
		try {
			const providers = JSON.parse(await daemon("provider.list"));
			const m = providers?.[provider]?.auth_method;
			if (m === "device-flow" || m === "web-oauth" || m === "pat") return m;
		} catch {}
		// Fallbacks match the daemon's primary auth per provider.
		if (provider === "gitlab") return "device-flow";
		if (provider === "codeberg") return "web-oauth";
		return "pat";
	}

	function openInBrowser(url) {
		// Tauri 2.x: openUrl from @tauri-apps/plugin-opener launches the
		// system browser for external URLs. The old `window.__TAURI__.shell.open`
		// API was Tauri 1.x and no longer works in 2.x.
		openUrl(url);
	}

	// ── Device flow (GitHub / GitLab) ──
	function runDeviceFlow(provider, overrides) {
		return new Promise((resolve, reject) => {
			let session = null;
			(async () => {
				try {
					onUpdate?.({ phase: "authenticating", method: "device-flow" });
					const raw = await daemon(
						"provider.connect_start",
						JSON.stringify({ provider, ...overrides }),
					);
					session = JSON.parse(raw);
					onUpdate?.({ phase: "device-flow", method: "device-flow", session });
					schedulePoll();
				} catch (e) {
					reject(new Error(sanitizeError(e, t)));
				}
			})();

			function schedulePoll() {
				const delay = (session.interval_secs || 5) * 1000;
				deviceTimer = setTimeout(poll, delay);
			}

			async function poll() {
				deviceTimer = null;
				try {
					const raw = await daemon(
						"provider.connect_poll",
						JSON.stringify(session),
					);
					const result = JSON.parse(raw);
					if (result.status === "pending") {
						schedulePoll();
					} else if (result.status === "slow_down") {
						session.interval_secs = result.interval_secs;
						schedulePoll();
					} else if (result.status === "expired") {
						reject(new Error(t("sync.deviceFlowExpired")));
					} else if (result.status === "success") {
						dispose();
						resolve({ username: result.username || "" });
					}
				} catch (e) {
					dispose();
					reject(new Error(sanitizeError(e, t)));
				}
			}
		});
	}

	// ── Web-OAuth PKCE (Codeberg) ──
	function runWebOAuth(provider, overrides) {
		return new Promise((resolve, reject) => {
			(async () => {
				try {
					onUpdate?.({ phase: "authenticating", method: "web-oauth" });
					const raw = await daemon(
						"provider.oauth_start_web",
						JSON.stringify({ provider, ...overrides }),
					);
					const result = JSON.parse(raw);
					onUpdate?.({ phase: "web-oauth", url: result.auth_url });
					openInBrowser(result.auth_url);
					schedulePoll();
				} catch (e) {
					reject(new Error(sanitizeError(e, t)));
				}
			})();

			function schedulePoll() {
				webTimer = setTimeout(poll, 2000);
			}

			async function poll() {
				webTimer = null;
				try {
					const raw = await daemon("provider.oauth_status_web");
					const result = JSON.parse(raw);
					if (result.status === "pending") {
						schedulePoll();
					} else if (result.status === "success") {
						dispose();
						resolve({ username: result.username || "" });
					} else if (result.status === "error") {
						dispose();
						reject(
							new Error(
								`${t("sync.webOAuthError")} ${result.error || ""}`.trim(),
							),
						);
					}
				} catch (e) {
					dispose();
					reject(new Error(sanitizeError(e, t)));
				}
			}
		});
	}

	// ── PAT ──
	async function runPat(provider, token, overrides) {
		onUpdate?.({ phase: "authenticating", method: "pat" });
		const raw = await daemon(
			"provider.connect_pat",
			JSON.stringify({ provider, token, ...overrides }),
		);
		const result = JSON.parse(raw);
		if (result.status === "success") return { username: result.username || "" };
		throw new Error(t("sync.errorAuthFailed"));
	}

	// ── Public: connect a provider. Skips auth if already connected. ──
	async function connect(provider, { pat, advanced } = {}) {
		// Already connected? provider.status validates the stored token.
		try {
			const statusRaw = await daemon(
				"provider.status",
				JSON.stringify({ provider }),
			);
			const s = JSON.parse(statusRaw);
			if (s.connected && s.valid) return { username: s.username || "" };
		} catch {
			// Not connected yet — proceed to auth below.
		}

		const overrides = buildOverrides(advanced);

		if (pat?.trim()) return runPat(provider, pat.trim(), overrides);

		const method = await resolveMethod(provider);
		if (method === "device-flow") return runDeviceFlow(provider, overrides);
		if (method === "web-oauth") return runWebOAuth(provider, overrides);
		// No automatic flow available + no PAT supplied.
		throw new Error(t("sync.errorAuthFailed"));
	}

	return { connect, dispose };
}
