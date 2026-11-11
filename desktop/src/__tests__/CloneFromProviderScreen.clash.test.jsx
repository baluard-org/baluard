import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, waitFor } from "@solidjs/testing-library";

// Module-scope mock state; the vi.mock factories close over these bindings.
const calls = [];
let responses = {}; // action -> string payload | Error
const authSpies = {
	refreshActiveVault: vi.fn(async () => {}),
	setSwitchTarget: vi.fn(),
	setStatus: vi.fn(),
	setVaultInfo: vi.fn(),
};

vi.mock("../lib/daemon.js", () => ({
	daemon: async (action, payload = "") => {
		calls.push({ action, payload });
		const r = responses[action];
		if (r instanceof Error) throw r;
		return r ?? "";
	},
}));

vi.mock("../i18n/index.jsx", () => ({
	useI18n: () => ({ t: (k) => k }),
}));

vi.mock("../context/toastSignal.js", () => ({
	toastError: vi.fn(),
	toastSuccess: vi.fn(),
}));

vi.mock("../lib/providerConnect.js", () => ({
	createProviderConnect: () => ({
		connect: async () => ({}),
		dispose: () => {},
	}),
}));

vi.mock("../context/AuthContext.jsx", () => ({
	useAuth: () => authSpies,
}));

// ExternalLink pulls the opener plugin; CopyButton pulls clipboard feedback.
vi.mock("../components/ExternalLink.jsx", () => ({
	default: (props) => <a href={props.href}>{props.children}</a>,
}));
vi.mock("../components/CopyButton.jsx", () => ({
	default: () => <button type="button" />,
}));

import CloneFromProviderScreen from "../components/CloneFromProviderScreen.jsx";

const REPO = {
	full_name: "esteban/baluard-vault",
	name: "baluard-vault",
	clone_url: "https://github.com/esteban/baluard-vault.git",
	vault_slug: "baluard-vault",
};

const CLASH_ERR = new Error(
	"A vault 'baluard-vault' is already registered. Remove it first.",
);
const ORPHAN_ERR = new Error(
	"Target directory already exists: /data/vaults/baluard-vault. Pick a different slug or remove it.",
);

beforeEach(() => {
	calls.length = 0;
	responses = {};
	vi.clearAllMocks();
	responses["provider.vault_repos"] = JSON.stringify([REPO]);
	responses["vaults.list"] = JSON.stringify([
		{
			slug: "baluard-vault",
			display_name: "baluard-vault",
			path: "/home/me/custom/baluard-vault",
			presence: "closed",
		},
	]);
});

afterEach(() => {
	cleanup();
});

async function renderToRepoList() {
	const { getByText, container } = render(() => (
		<CloneFromProviderScreen onCancel={() => {}} />
	));
	fireEvent.click(container.querySelector(".clone-screen__provider"));
	await waitFor(() =>
		expect(
			container.querySelector(".clone-screen__repo"),
		).not.toBeNull(),
	);
	return { getByText, container };
}

describe("CloneFromProviderScreen clone-clash dialog", () => {
	it("shows the clash dialog instead of the raw error", async () => {
		responses["vault.clone_start"] = CLASH_ERR;
		const { getByText, container } = await renderToRepoList();

		fireEvent.click(container.querySelector(".clone-screen__repo"));
		await waitFor(() =>
			expect(container.querySelector(".clone-screen__clash")).not.toBeNull(),
		);
		expect(getByText("clone.clashTitle")).toBeTruthy();
		// The registered vault's on-disk path is shown before a destructive arm.
		await waitFor(() =>
			expect(container.textContent).toContain(
				"/home/me/custom/baluard-vault",
			),
		);
		// The raw refusal must not leak into the inline error box.
		expect(container.textContent).not.toContain("already registered");
	});

	it("open-existing routes to the unlock flow for the existing slug", async () => {
		responses["vault.clone_start"] = CLASH_ERR;
		const { getByText, container } = await renderToRepoList();

		fireEvent.click(container.querySelector(".clone-screen__repo"));
		await waitFor(() =>
			expect(container.querySelector(".clone-screen__clash")).not.toBeNull(),
		);
		fireEvent.click(getByText("clone.clashOpenExisting"));
		await waitFor(() =>
			expect(authSpies.setSwitchTarget).toHaveBeenCalledWith("baluard-vault"),
		);
		expect(authSpies.setStatus).toHaveBeenCalledWith("locked");
	});

	it("wipe arm detaches with the password, then re-runs the clone", async () => {
		responses["vault.clone_start"] = CLASH_ERR;
		const { getByText, container } = await renderToRepoList();

		fireEvent.click(container.querySelector(".clone-screen__repo"));
		await waitFor(() =>
			expect(container.querySelector(".clone-screen__clash")).not.toBeNull(),
		);
		fireEvent.click(getByText("clone.clashReimport"));
		await waitFor(() =>
			expect(
				container.querySelector(".clone-screen__clash input[type=password]"),
			).not.toBeNull(),
		);

		const input = container.querySelector(
			".clone-screen__clash input[type=password]",
		);
		fireEvent.input(input, { target: { value: "master-pw" } });
		fireEvent.click(getByText("clone.clashWipeConfirm"));
		await Promise.resolve();
		await waitFor(() => {
			const detach = calls.find((c) => c.action === "vaults.detach");
			expect(detach).toBeTruthy();
			expect(JSON.parse(detach.payload)).toEqual({
				slug: "baluard-vault",
				delete_from_disk: true,
				force: true,
				confirm: { kind: "password", value: "master-pw" },
			});
		});
		// The clone re-runs: two clone_start calls (refused, then the retry).
		await waitFor(() => {
			const starts = calls.filter((c) => c.action === "vault.clone_start");
			expect(starts.length).toBe(2);
		});
	});

	it("unrelated clone errors keep the plain inline error box", async () => {
		responses["vault.clone_start"] = new Error("network unreachable");
		const { container } = await renderToRepoList();

		fireEvent.click(container.querySelector(".clone-screen__repo"));
		await waitFor(() =>
			expect(container.querySelector(".clone-screen__error")).not.toBeNull(),
		);
		expect(container.querySelector(".clone-screen__clash")).toBeNull();
	});

	it("orphan-directory clash offers adopt, not the password arm", async () => {
		responses["vault.clone_start"] = ORPHAN_ERR;
		const { getByText, container } = await renderToRepoList();

		fireEvent.click(container.querySelector(".clone-screen__repo"));
		await waitFor(() =>
			expect(container.querySelector(".clone-screen__clash")).not.toBeNull(),
		);
		expect(getByText("clone.clashOrphanBody")).toBeTruthy();
		expect(getByText("clone.clashUseExisting")).toBeTruthy();
		// Nothing registered to delete: no destructive arm in this mode.
		expect(container.querySelector("input[type=password]")).toBeNull();

		fireEvent.click(getByText("clone.clashUseExisting"));
		await waitFor(() => {
			const reg = calls.find((c) => c.action === "vaults.register_local");
			expect(reg).toBeTruthy();
			expect(JSON.parse(reg.payload).path).toBe(
				"/data/vaults/baluard-vault",
			);
		});
	});

	it("wipe refusal keeps the dialog open and surfaces the error", async () => {
		responses["vault.clone_start"] = CLASH_ERR;
		responses["vaults.detach"] = new Error(
			"verification failed: master password incorrect",
		);
		const { getByText, container } = await renderToRepoList();

		fireEvent.click(container.querySelector(".clone-screen__repo"));
		await waitFor(() =>
			expect(container.querySelector(".clone-screen__clash")).not.toBeNull(),
		);
		fireEvent.click(getByText("clone.clashReimport"));
		await waitFor(() =>
			expect(
				container.querySelector(".clone-screen__clash input[type=password]"),
			).not.toBeNull(),
		);
		const input = container.querySelector(
			".clone-screen__clash input[type=password]",
		);
		fireEvent.input(input, { target: { value: "wrong" } });
		fireEvent.click(getByText("clone.clashWipeConfirm"));

		await waitFor(() =>
			expect(container.textContent).toContain(
				"verification failed: master password incorrect",
			),
		);
		// The dialog stays open so the user can retry.
		expect(container.querySelector(".clone-screen__clash")).not.toBeNull();
	});

	it("cancel dismisses the dialog and clears the password", async () => {
		responses["vault.clone_start"] = CLASH_ERR;
		const { getByText, container } = await renderToRepoList();

		fireEvent.click(container.querySelector(".clone-screen__repo"));
		await waitFor(() =>
			expect(container.querySelector(".clone-screen__clash")).not.toBeNull(),
		);
		fireEvent.click(getByText("clone.clashReimport"));
		await waitFor(() =>
			expect(
				container.querySelector(".clone-screen__clash input[type=password]"),
			).not.toBeNull(),
		);
		fireEvent.input(
			container.querySelector(".clone-screen__clash input[type=password]"),
			{ target: { value: "typed" } },
		);
		fireEvent.click(getByText("common.cancel").closest("button"));
		await waitFor(() =>
			expect(container.querySelector(".clone-screen__clash")).toBeNull(),
		);

		// Re-trigger the clash: the fresh dialog must not carry the old text.
		fireEvent.click(container.querySelector(".clone-screen__repo"));
		await waitFor(() =>
			expect(container.querySelector(".clone-screen__clash")).not.toBeNull(),
		);
		expect(
			container.querySelector(".clone-screen__clash input[type=password]"),
		).toBeNull();
	});
});

