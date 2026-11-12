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
// the registry. The refusal text carries which: "Target directory already
// exists: <path>" means an unregistered folder (safe detach leftover), while
// "A vault '<slug>' is already registered" means a live registry entry. The
// dialog branches on it because the two shapes support different arms.
export function isCloneClashError(message) {
	return parseCloneClash(message) !== null;
}

export function parseCloneClash(message) {
	const m = String(message ?? "");
	const reg = m.match(/A vault '([^']+)' is already registered/);
	if (reg) return { kind: "registered", slug: reg[1], path: null };
	// Greedy capture anchored on the trailing sentence: vault paths contain
	// dots (~/.local/share) so a lazy match would truncate at the first one,
	// and Windows paths use backslashes throughout.
	const dir = m.match(/Target directory already exists: (.+)\. Pick a different/);
	if (dir) {
		const path = dir[1];
		const slug = path.split(/[\\/]/).filter(Boolean).pop() ?? path;
		return { kind: "orphan", slug, path };
	}
	return null;
}

// Delete a local vault folder blocking a clone target — registered vault or
// orphan alike. The daemon derives the path from the slug and requires a
// matching .baluard marker, so only a genuine Baluard vault copy can be
// removed. Credential-free by design: local folder deletion is machine-level
// control the user already has.
export async function discardOrphanVault(slug) {
	const result = JSON.parse(
		await daemon("vaults.discard_orphan", JSON.stringify({ slug })),
	);
	return { discarded: result.discarded === true };
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
