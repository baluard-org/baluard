import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock the daemon IPC client so we can drive the clone poll loop without Tauri.
const calls = [];
let responses = {}; // action -> value (string payload) or Error
vi.mock("../lib/daemon.js", () => ({
	daemon: async (action, payload = "") => {
		calls.push({ action, payload });
		const r = responses[action];
		if (r instanceof Error) throw r;
		if (typeof r === "function") return r();
		return r ?? "";
	},
}));

import {
	parseCloneClash,
	registerLocalVault,
	startClone,
	discardOrphanVault,
} from "../lib/cloneFlow.js";

const t = (k) => k; // pass-through translator

function seq(values) {
	let i = 0;
	return () => values[Math.min(i++, values.length - 1)];
}

beforeEach(() => {
	calls.length = 0;
	responses = {};
});

describe("startClone", () => {
	it("starts, polls to done, and finalizes", async () => {
		responses["vault.clone_start"] = JSON.stringify({ job_id: "J1" });
		responses["vault.clone_progress"] = seq([
			JSON.stringify({
				phase: "cloning",
				pct: 50,
				objects_received: 2,
				total_objects: 4,
				bytes_received: 128,
				done: false,
			}),
			JSON.stringify({
				phase: "done",
				pct: 100,
				objects_received: 4,
				total_objects: 4,
				bytes_received: 256,
				done: true,
			}),
		]);
		responses["vault.clone_finalize"] = JSON.stringify({
			slug: "my-vault",
			path: "/data/vaults/my-vault",
			objects: 4,
			bytes: 256,
		});

		const result = await startClone(
			{
				clone_url: "https://github.com/u/v.git",
				provider: "github",
				slug: "my-vault",
				display_name: "my-vault",
			},
			{ t },
		);

		expect(result.slug).toBe("my-vault");
		expect(result.path).toBe("/data/vaults/my-vault");
		expect(result.objects).toBe(4);

		// start -> at least one progress poll -> finalize
		const actions = calls.map((c) => c.action);
		expect(actions[0]).toBe("vault.clone_start");
		expect(actions).toContain("vault.clone_progress");
		expect(actions[actions.length - 1]).toBe("vault.clone_finalize");
	});

	it("reports progress via onProgress", async () => {
		responses["vault.clone_start"] = JSON.stringify({ job_id: "J2" });
		responses["vault.clone_progress"] = seq([
			JSON.stringify({
				phase: "cloning",
				pct: 25,
				objects_received: 1,
				total_objects: 4,
				bytes_received: 64,
				done: false,
			}),
			JSON.stringify({
				phase: "done",
				pct: 100,
				objects_received: 4,
				total_objects: 4,
				bytes_received: 256,
				done: true,
			}),
		]);
		responses["vault.clone_finalize"] = JSON.stringify({
			slug: "v",
			path: "/p",
			objects: 4,
			bytes: 256,
		});

		const seen = [];
		await startClone(
			{ clone_url: "u", provider: "github", slug: "v", display_name: "v" },
			{ onProgress: (p) => seen.push(p), t },
		);
		expect(seen.length).toBeGreaterThanOrEqual(1);
		expect(seen.some((p) => p.pct === 100)).toBe(true);
	});

	it("rejects when the daemon marks the job failed (orphan path surfaces error)", async () => {
		responses["vault.clone_start"] = JSON.stringify({ job_id: "J3" });
		responses["vault.clone_progress"] = JSON.stringify({
			phase: "failed",
			pct: 0,
			objects_received: 0,
			total_objects: 0,
			bytes_received: 0,
			error: "not a baluard vault",
			done: false,
		});

		await expect(
			startClone(
				{ clone_url: "u", provider: "github", slug: "v", display_name: "v" },
				{ t },
			),
		).rejects.toThrow(/baluard vault/i);
	});

	it("rejects when clone_start returns no job_id", async () => {
		responses["vault.clone_start"] = JSON.stringify({});
		await expect(
			startClone(
				{ clone_url: "u", provider: "github", slug: "v", display_name: "v" },
				{ t },
			),
		).rejects.toThrow(/job_id/i);
	});
});

describe("registerLocalVault", () => {
	it("posts the path and returns the slug", async () => {
		responses["vaults.register_local"] = JSON.stringify({
			slug: "local",
			vault_id: "abc",
		});
		const result = await registerLocalVault("/home/me/vault");
		expect(result.slug).toBe("local");
		const last = calls[calls.length - 1];
		expect(last.action).toBe("vaults.register_local");
		expect(JSON.parse(last.payload).path).toBe("/home/me/vault");
	});
});

describe("parseCloneClash", () => {
	const REGISTERED =
		"A vault 'my-vault' is already registered. Remove it first.";
	const ORPHAN =
		"Target directory already exists: /data/vaults/my-vault. Pick a different slug or remove it.";

	it("classifies the registered refusal and captures the slug", () => {
		expect(parseCloneClash(REGISTERED)).toEqual({
			kind: "registered",
			slug: "my-vault",
			path: null,
		});
	});

	it("classifies the orphan-directory refusal and captures the path", () => {
		expect(parseCloneClash(ORPHAN)).toEqual({
			kind: "orphan",
			slug: "my-vault",
			path: "/data/vaults/my-vault",
		});
	});

	it("isCloneClashError wraps the classifier", async () => {
		const { isCloneClashError } = await import("../lib/cloneFlow.js");
		expect(isCloneClashError(REGISTERED)).toBe(true);
		expect(isCloneClashError(ORPHAN)).toBe(true);
		expect(isCloneClashError("network unreachable")).toBe(false);
		expect(
			isCloneClashError("Cloned repository has no .baluard marker"),
		).toBe(false);
		expect(isCloneClashError(undefined)).toBe(false);
	});

	it("rejects unrelated errors", () => {
		expect(parseCloneClash("network unreachable")).toBeNull();
		expect(parseCloneClash(undefined)).toBeNull();
	});
});

describe("discardOrphanVault", () => {
	it("posts the slug with no credential", async () => {
		responses["vaults.discard_orphan"] = JSON.stringify({ discarded: true });
		const r = await discardOrphanVault("my-vault");
		const last = calls[calls.length - 1];
		expect(last.action).toBe("vaults.discard_orphan");
		expect(JSON.parse(last.payload)).toEqual({ slug: "my-vault" });
		expect(r).toEqual({ discarded: true });
	});

	it("propagates the daemon refusal", async () => {
		responses["vaults.discard_orphan"] = new Error(
			"The folder at this path has no .baluard marker",
		);
		await expect(discardOrphanVault("my-vault")).rejects.toThrow(
			/baluard marker/,
		);
	});
});

describe("parseCloneClash real-world paths (review blocker B1)", () => {
	// The daemon's refusal is `Target directory already exists: <path>. Pick
	// a different slug or remove it.` — real data dirs contain dots
	// (~/.local/share) or backslashes (Windows), so the capture must anchor
	// on the trailing sentence, not the first period.
	const LINUX = "Target directory already exists: /home/u/.local/share/baluard/vaults/baluard-x. Pick a different slug or remove it.";
	const LINUX_DOT_USER = "Target directory already exists: /home/john.doe/Library/Application Support/baluard/vaults/my-vault. Pick a different slug or remove it.";
	const WINDOWS = "Target directory already exists: C:\\Users\\u\\AppData\\Local\\baluard\\vaults\\baluard-x. Pick a different slug or remove it.";

	it("parses a dotted Linux path without truncating at the first dot", () => {
		expect(parseCloneClash(LINUX)).toEqual({
			kind: "orphan",
			slug: "baluard-x",
			path: "/home/u/.local/share/baluard/vaults/baluard-x",
		});
	});

	it("parses a path whose username contains a dot", () => {
		expect(parseCloneClash(LINUX_DOT_USER)).toEqual({
			kind: "orphan",
			slug: "my-vault",
			path: "/home/john.doe/Library/Application Support/baluard/vaults/my-vault",
		});
	});

	it("parses a Windows backslash path", () => {
		expect(parseCloneClash(WINDOWS)).toEqual({
			kind: "orphan",
			slug: "baluard-x",
			path: "C:\\Users\\u\\AppData\\Local\\baluard\\vaults\\baluard-x",
		});
	});
});
