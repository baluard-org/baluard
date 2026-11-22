import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, cleanup } from "@solidjs/testing-library";

const { daemonMock, clipboardMock, toastMock, setSlug, slugSignal } = await vi.hoisted(async () => {
  const solid = await import("solid-js");
  const [slug, setSlug] = solid.createSignal("personal");
  return {
    daemonMock: vi.fn(),
    clipboardMock: vi.fn().mockResolvedValue(undefined),
    toastMock: vi.fn(),
    setSlug,
    slugSignal: slug,
  };
});

vi.mock("../lib/daemon.js", () => ({ daemon: (...a) => daemonMock(...a) }));
vi.mock("../lib/clipboard.js", () => ({ copyToClipboard: (...a) => clipboardMock(...a) }));
vi.mock("../context/toastSignal.js", () => ({ toastSuccess: toastMock }));
vi.mock("../i18n/index.jsx", () => ({ useI18n: () => ({ t: (k, vars) => (vars?.n != null ? `${k}:${vars.n}` : k) }) }));
vi.mock("../lib/utils.js", () => ({ sanitizeError: (e) => String(e) }));
vi.mock("../context/VaultSwitcherContext.jsx", () => ({
  useVaultSwitcher: () => ({ activeSlug: () => slugSignal() }),
}));
vi.mock("../components/Primitives.jsx", () => ({
  Button: (props) => <button onClick={props.onClick} disabled={props.disabled} class={props.class}>{props.children}</button>,
}));

const SNAPSHOT = {
  verdict: "behind",
  vaultId: "0f0e-aaaa",
  deviceId: "dev1abcdef",
  branch: "main",
  autosync: { active: true, state: "idle", last_sync: 1700000000, pending: 0, conflicts_resolved: 0, access_denied_streak: 0 },
  hasRemote: true,
  remoteHost: "github.com",
  headOid: "a".repeat(40),
  headAt: 1700000100,
  upstreamOid: "b".repeat(40),
  upstreamAt: 1700000050,
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
    // The vault routes via daemon()'s third argument; the payload stays
    // empty (the report never carries user-typed text).
    expect(daemonMock).toHaveBeenCalledWith("sync.diagnostics", "", "personal");
    expect(container.textContent).toContain("diag.behindCount:3");
  });

  it("diverged vaults show behind and ahead together", async () => {
    daemonMock.mockResolvedValue(JSON.stringify({ ...SNAPSHOT, ahead: 2, behind: 3 }));
    const { container, findByText } = render(() => <VaultDiagnostics />);
    await findByText("diag.verdict.behind");
    expect(container.textContent).toContain("diag.behindCount:3");
    expect(container.textContent).toContain("diag.aheadCount:2");
  });

  it("unfetched vaults show a never-fetched remote row", async () => {
    daemonMock.mockResolvedValue(
      JSON.stringify({ ...SNAPSHOT, verdict: "unfetched", upstreamOid: null, upstreamAt: null, behind: null, ahead: null }),
    );
    const { container, findByText, queryByText } = render(() => <VaultDiagnostics />);
    await findByText("diag.verdict.unfetched");
    expect(container.textContent).toContain("diag.remoteState");
    expect(container.textContent).toContain("diag.never");
    expect(queryByText("diag.upstream")).toBeNull();
  });

  it("no-remote vaults skip the remote rows", async () => {
    daemonMock.mockResolvedValue(JSON.stringify({ ...SNAPSHOT, verdict: "no_remote", hasRemote: false, headOid: null, behind: 0, ahead: 0 }));
    const { findByText, queryByText } = render(() => <VaultDiagnostics />);
    await findByText("diag.verdict.noRemote");
    expect(queryByText("diag.head")).toBeNull();
    expect(queryByText("diag.remoteState")).toBeNull();
    expect(queryByText("diag.upstream")).toBeNull();
  });

  it("copies the daemon-composed report verbatim", async () => {
    const { findByText } = render(() => <VaultDiagnostics />);
    const btn = await findByText("diag.copy");
    btn.click();
    await vi.waitFor(() => expect(clipboardMock).toHaveBeenCalled());
    expect(clipboardMock.mock.calls[0][0]).toBe(SNAPSHOT.report);
    expect(toastMock).toHaveBeenCalledWith("diag.copied");
  });

  it("a stale response from a superseded request never lands", async () => {
    // Load 1 hangs; a slug switch starts load 2 which wins. When load 1
    // finally resolves with a different vault's data, it must be dropped.
    let release;
    const slow = new Promise((resolve) => { release = resolve; });
    daemonMock.mockImplementationOnce(() => slow);
    const { findByText, queryByText } = render(() => <VaultDiagnostics />);
    daemonMock.mockResolvedValueOnce(JSON.stringify({ ...SNAPSHOT, verdict: "up_to_date", behind: 0 }));
    setSlug("work");
    await vi.waitFor(() => expect(daemonMock).toHaveBeenCalledTimes(2));
    expect(daemonMock).toHaveBeenNthCalledWith(2, "sync.diagnostics", "", "work");
    await findByText("diag.verdict.upToDate");
    release(JSON.stringify({ ...SNAPSHOT, verdict: "failing", behind: 0 }));
    await new Promise((r) => setTimeout(r, 20));
    expect(queryByText("diag.verdict.failing")).toBeNull();
  });
});
