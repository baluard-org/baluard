import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, cleanup } from "@solidjs/testing-library";

const { daemonMock, clipboardMock, toastMock } = vi.hoisted(() => ({
  daemonMock: vi.fn(),
  clipboardMock: vi.fn().mockResolvedValue(undefined),
  toastMock: vi.fn(),
}));

vi.mock("../lib/daemon.js", () => ({ daemon: (...a) => daemonMock(...a) }));
vi.mock("../lib/clipboard.js", () => ({ copyToClipboard: (...a) => clipboardMock(...a) }));
vi.mock("../context/toastSignal.js", () => ({ toastSuccess: toastMock }));
vi.mock("../i18n/index.jsx", () => ({ useI18n: () => ({ t: (k, vars) => k }) }));
vi.mock("../lib/utils.js", () => ({ sanitizeError: (e) => String(e) }));
vi.mock("../context/VaultSwitcherContext.jsx", () => ({
  useVaultSwitcher: () => ({ activeSlug: () => "personal" }),
}));
vi.mock("./Primitives.jsx", () => ({
  Button: (props) => <button onClick={props.onClick} class={props.class}>{props.children}</button>,
}));

const SNAPSHOT = {
  verdict: "behind",
  vaultId: "0f0e-aaaa",
  deviceId: "dev1",
  autosync: { active: true, state: "Idle", last_sync: 1700000000, pending: 0, conflicts_resolved: 0, access_denied_streak: 0 },
  hasRemote: true,
  remoteHost: "github.com",
  headOid: "a".repeat(40),
  headAt: 1700000100,
  upstreamOid: "b".repeat(40),
  ahead: 0,
  behind: 3,
  staged: 0,
  unstaged: 0,
  commits: [],
  entries: 12,
  folders: 2,
  tags: 0,
  totp: 1,
  archived: 0,
  trashed: 0,
  report: "Baluard diagnostic report\nhead: aaaaaaa\n",
};

import VaultDiagnostics from "../components/VaultDiagnostics.jsx";

describe("VaultDiagnostics", () => {
  beforeEach(() => {
    daemonMock.mockReset().mockResolvedValue(JSON.stringify(SNAPSHOT));
    clipboardMock.mockClear();
    toastMock.mockClear();
    cleanup();
  });

  it("renders the verdict and the behind count", async () => {
    const { container, findByText } = render(() => <VaultDiagnostics />);
    await findByText("diag.verdict.behind");
    expect(container.textContent).toContain("diag.verdict.behind");
    expect(container.textContent).toContain("aaaaaaa");
    // The slug rides the daemon payload untouched (a JSON.stringify would
    // double-quote it and the daemon would name the vault '"personal"').
    expect(daemonMock).toHaveBeenCalledWith("sync.diagnostics", "personal");
    expect(container.textContent).toContain("diag.behindCount");
  });

  it("no-remote vaults skip the remote rows", async () => {
    daemonMock.mockResolvedValue(JSON.stringify({ ...SNAPSHOT, verdict: "no_remote", hasRemote: false, headOid: null, behind: 0, ahead: 0 }));
    const { findByText, queryByText } = render(() => <VaultDiagnostics />);
    await findByText("diag.verdict.noRemote");
    expect(queryByText("diag.head")).toBeNull();
    expect(queryByText("diag.remoteState")).toBeNull();
  });

  it("copies the daemon-composed report verbatim", async () => {
    const { findByText } = render(() => <VaultDiagnostics />);
    const btn = await findByText("diag.copy");
    btn.click();
    await vi.waitFor(() => expect(clipboardMock).toHaveBeenCalled());
    expect(clipboardMock.mock.calls[0][0]).toBe(SNAPSHOT.report);
    expect(toastMock).toHaveBeenCalledWith("diag.copied");
  });
});
