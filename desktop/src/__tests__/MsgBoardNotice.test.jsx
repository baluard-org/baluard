import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, cleanup, waitFor } from "@solidjs/testing-library";

// MsgBoardNotice: classify the shared message board and surface a
// compaction rewrite. The daemon call is mocked at the IPC boundary,
// returning the RAW transport shape (a JSON string), since a
// parsed-object mock would hide a missing JSON.parse exactly like the
// settings-payload defect did.

vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({
    t: (k, vars) => (vars ? `${k}(${JSON.stringify(vars)})` : k),
    locale: () => "en",
  }),
  I18nProvider: (props) => props.children,
}));

vi.mock("../lib/utils.js", () => ({
  sanitizeError: (e) => String(e?.message ?? e),
}));

const daemonMock = vi.fn();
vi.mock("../lib/daemon.js", () => ({ daemon: (...args) => daemonMock(...args) }));

const toasts = { error: vi.fn() };
vi.mock("../context/toastSignal.js", () => ({
  toastError: (...a) => toasts.error(...a),
}));

import MsgBoardNotice from "../components/MsgBoardNotice.jsx";

beforeEach(() => {
  cleanup();
  daemonMock.mockReset();
  toasts.error.mockReset();
});

describe("MsgBoardNotice", () => {
  it("renders nothing on a clean status", async () => {
    daemonMock.mockResolvedValue(
      JSON.stringify({ tip: "a".repeat(64), rewritten: false, foreign: false }),
    );
    render(() => <MsgBoardNotice />);
    await waitFor(() => expect(daemonMock).toHaveBeenCalled());
    expect(screen.queryByTestId("msg-notice")).toBeNull();
  });

  it("renders the verified compaction notice with details and acks the tip", async () => {
    const STATUS = JSON.stringify({
      tip: "b".repeat(64),
      rewritten: true,
      foreign: false,
      rewrite_signed: true,
      compaction: { device_id: "12345678abcdef90", at: 1, compacted_entries: 4 },
    });
    daemonMock.mockImplementation((action, payload) => {
      if (action === "vault.msg_status") return Promise.resolve(STATUS);
      if (action === "vault.msg_ack")
        return Promise.resolve(JSON.stringify({ acknowledged: true }));
      throw new Error(`unexpected action ${action}`);
    });
    render(() => <MsgBoardNotice />);
    const notice = await waitFor(() => screen.getByTestId("msg-notice"));
    expect(notice.textContent).toContain("sync.msgCleaned");
    // Details carry the device prefix and the removed count.
    expect(notice.textContent).toContain('"device":"12345678"');
    expect(notice.textContent).toContain('"count":4');
    fireEvent.click(screen.getByTestId("msg-accept-btn"));
    await waitFor(() => expect(screen.queryByTestId("msg-notice")).toBeNull());
    expect(daemonMock).toHaveBeenCalledWith("vault.msg_ack", {
      tip: "b".repeat(64),
    });
  });

  it("shows the verified hint when the rewrite has no details payload", async () => {
    const STATUS = JSON.stringify({
      tip: "e".repeat(64),
      rewritten: true,
      foreign: false,
      rewrite_signed: true,
      compaction: null,
    });
    daemonMock.mockResolvedValue(STATUS);
    render(() => <MsgBoardNotice />);
    const notice = await waitFor(() => screen.getByTestId("msg-notice"));
    expect(notice.textContent).toContain("sync.msgCleanedVerifiedHint");
    expect(notice.textContent).not.toContain("msgCleanedDetails");
  });

  it("shows the foreign arm without an accept button", async () => {
    daemonMock.mockResolvedValue(
      JSON.stringify({ tip: "c".repeat(64), rewritten: true, foreign: true }),
    );
    render(() => <MsgBoardNotice />);
    const notice = await waitFor(() => screen.getByTestId("msg-notice"));
    expect(notice.textContent).toContain("sync.msgForeign");
    expect(screen.queryByTestId("msg-accept-btn")).toBeNull();
  });

  it("surfaces a stale accept through the mapped toast and keeps the notice", async () => {
    const STATUS = JSON.stringify({
      tip: "d".repeat(64),
      rewritten: true,
      foreign: false,
      rewrite_signed: true,
      compaction: { device_id: "12345678abcdef90", at: 1, compacted_entries: 4 },
    });
    daemonMock.mockImplementation((action) => {
      if (action === "vault.msg_status") return Promise.resolve(STATUS);
      if (action === "vault.msg_ack")
        return Promise.reject(new Error("The message board changed again while you were reviewing. Check once more."));
      throw new Error(`unexpected action ${action}`);
    });
    render(() => <MsgBoardNotice />);
    await waitFor(() => screen.getByTestId("msg-notice"));
    fireEvent.click(screen.getByTestId("msg-accept-btn"));
    await waitFor(() => expect(toasts.error).toHaveBeenCalled());
    // The notice stays open so the user can re-check.
    expect(screen.getByTestId("msg-notice")).toBeTruthy();
  });
});
