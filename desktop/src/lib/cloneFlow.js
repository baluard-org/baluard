// Phase 4 remote vault clone flow (desktop side of vault.clone_*).
//
// startClone() kicks off the daemon job and polls transfer_progress until the
// job is done/failed, then finalize returns { slug, path }. `onProgress` fires
// on each poll with { pct, objects, bytes, phase } for a live progress bar.

import { daemon } from "./daemon.js";
import { sanitizeError } from "./utils.js";

const POLL_INTERVAL_MS = 500;
const DEADLINE_MS = 10 * 60 * 1000; // 10 minutes

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Clone a remote vault. Resolves { slug, path, objects, bytes } on success.
export async function startClone(
	{ clone_url, provider, slug, display_name },
	{ onProgress, t } = {},
) {
	const startPayload = JSON.stringify({
		clone_url,
		provider,
		slug,
		display_name,
	});
	const startResp = JSON.parse(await daemon("vault.clone_start", startPayload));
	const jobId = startResp.job_id;
	if (!jobId) throw new Error("daemon returned no job_id");

	const deadline = Date.now() + DEADLINE_MS;
	let lastPct = -1;
	for (;;) {
		if (Date.now() > deadline)
			throw new Error(t ? t("clone.timeout") : "clone timed out");
		await sleep(POLL_INTERVAL_MS);
		const p = JSON.parse(
			await daemon("vault.clone_progress", JSON.stringify({ job_id: jobId })),
		);
		const pct = typeof p.pct === "number" ? p.pct : 0;
		if (pct !== lastPct || p.phase === "done" || p.phase === "failed") {
			lastPct = pct;
			onProgress?.({
				pct,
				objects: p.objects_received || 0,
				total: p.total_objects || 0,
				bytes: p.bytes_received || 0,
				phase: p.phase,
			});
		}
		if (p.done || p.phase === "done") break;
		if (p.phase === "failed") {
			throw new Error(p.error || (t ? t("clone.failed") : "clone failed"));
		}
	}

	const result = JSON.parse(
		await daemon("vault.clone_finalize", JSON.stringify({ job_id: jobId })),
	);
	return {
		slug: result.slug,
		path: result.path,
		objects: result.objects || 0,
		bytes: result.bytes || 0,
	};
}

// The daemon refuses a clone whose target slug already exists on disk or in
// the registry. The clone dialog turns that refusal into a choice: wipe the
// local copy and re-import, or open the existing vault.
export function isCloneClashError(message) {
	const m = String(message ?? "");
	return (
		m.includes("Target directory already exists") ||
		/A vault '.+' is already registered/.test(m)
	);
}

// Delete a local vault copy. The daemon re-verifies the master password
// against the KEK canary and rate-limits wrong answers; this call is intent,
// not the security boundary.
export async function wipeLocalVault(slug, password) {
	await daemon(
		"vaults.detach",
		JSON.stringify({
			slug,
			delete_from_disk: true,
			force: true,
			confirm: { kind: "password", value: password },
		}),
	);
}

// Register an existing local vault directory (no copy). Resolves { slug }.
export async function registerLocalVault(path) {
	const result = JSON.parse(
		await daemon("vaults.register_local", JSON.stringify({ path })),
	);
	return { slug: result.slug };
}

// Re-export for components that need raw error text.
export { sanitizeError };
