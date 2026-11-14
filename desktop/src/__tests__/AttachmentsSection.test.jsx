import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, cleanup, waitFor } from "@solidjs/testing-library";

// AttachmentsSection: run the line compaction, render the daemon's
// report, and surface failures through the mapped toast. The daemon call
// is mocked at the IPC boundary, returning the RAW transport shape (a
// JSON string), since a parsed-object mock would hide a missing
// JSON.parse exactly like the settings-payload defect did.

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

import AttachmentsSection from "../components/AttachmentsSection.jsx";

const REPORT = JSON.stringify({ reclaimed: 3, reclaimed_bytes: 5 * 1024 * 1024, kept: 12 });

beforeEach(() => {
  cleanup();
  daemonMock.mockReset();
  toasts.error.mockReset();
});

describe("AttachmentsSection", () => {
  it("renders idle with no report", () => {
    render(() => <AttachmentsSection />);
    expect(screen.getByTestId("attachments-section")).toBeTruthy();
    expect(screen.getByTestId("attach-compact-btn").textContent).toContain(
      "sync.attachCompact"
    );
    expect(screen.queryByTestId("attach-result")).toBeNull();
  });

  it("parses the raw JSON payload and renders the report", async () => {
    daemonMock.mockResolvedValue(REPORT);
    render(() => <AttachmentsSection />);
    fireEvent.click(screen.getByTestId("attach-compact-btn"));
    await waitFor(() => expect(screen.getByTestId("attach-result")).toBeTruthy());
    expect(daemonMock).toHaveBeenCalledWith("vault.attach_compact");
    const text = screen.getByTestId("attach-result").textContent;
    expect(text).toContain("sync.attachResult");
    // Interpolated vars carry the daemon's numbers and the formatted size.
    expect(text).toContain('"reclaimed":3');
    expect(text).toContain('"bytes":"5.0 MB"');
    expect(text).toContain('"kept":12');
  });

  it("shows the cleanup notice and clears it through attach_ack", async () => {
    const STATUS = JSON.stringify({
      tip: "a".repeat(64),
      rewritten: true,
      foreign: false,
    });
    daemonMock.mockImplementation((action, payload) => {
      if (action === "vault.attach_status") return Promise.resolve(STATUS);
      if (action === "vault.attach_ack")
        return Promise.resolve(JSON.stringify({ acknowledged: true }));
      return Promise.resolve(REPORT);
    });
    render(() => <AttachmentsSection />);
    const notice = await waitFor(() =>
      screen.getByTestId("attach-notice")
    );
    expect(notice.textContent).toContain("sync.attachCleaned");
    fireEvent.click(screen.getByTestId("attach-accept-btn"));
    await waitFor(() =>
      expect(screen.queryByTestId("attach-notice")).toBeNull()
    );
    expect(daemonMock).toHaveBeenCalledWith("vault.attach_ack", {
      tip: "a".repeat(64),
    });
  });

  it("attributes a verified rewrite in the cleanup notice", async () => {
    const STATUS = JSON.stringify({
      tip: "d".repeat(64),
      rewritten: true,
      foreign: false,
      rewrite_signed: true,
    });
    daemonMock.mockImplementation((action) =>
      action === "vault.attach_status"
        ? Promise.resolve(STATUS)
        : Promise.resolve(REPORT)
    );
    render(() => <AttachmentsSection />);
    const notice = await waitFor(() => screen.getByTestId("attach-notice"));
    expect(notice.textContent).toContain("sync.attachCleaned");
    expect(notice.textContent).toContain("sync.attachCleanedVerifiedHint");
    expect(notice.textContent).not.toContain("sync.attachCleanedHint");
  });

  it("shows the verified cleanup details in the notice", async () => {
    const STATUS = JSON.stringify({
      tip: "e".repeat(64),
      rewritten: true,
      foreign: false,
      rewrite_signed: true,
      compaction: {
        device_id: "12345678-1234-1234-1234-123456789abc",
        at: 1731600000,
        reclaimed: 3,
        reclaimed_bytes: 5242880,
        kept: 12,
      },
    });
    daemonMock.mockImplementation((action) =>
      action === "vault.attach_status"
        ? Promise.resolve(STATUS)
        : Promise.resolve(REPORT)
    );
    render(() => <AttachmentsSection />);
    const notice = await waitFor(() => screen.getByTestId("attach-notice"));
    expect(notice.textContent).toContain("sync.attachCleanedDetails");
    expect(notice.textContent).toContain("12345678");
    expect(notice.textContent).toContain("3");
    expect(notice.textContent).toContain("5.0 MB");
  });

  it("shows the foreign-storage notice without an accept button", async () => {
    const STATUS = JSON.stringify({
      tip: "b".repeat(64),
      rewritten: true,
      foreign: true,
    });
    daemonMock.mockImplementation((action) =>
      action === "vault.attach_status"
        ? Promise.resolve(STATUS)
        : Promise.resolve(REPORT)
    );
    render(() => <AttachmentsSection />);
    const notice = await waitFor(() =>
      screen.getByTestId("attach-notice")
    );
    expect(notice.textContent).toContain("sync.attachForeign");
    expect(screen.queryByTestId("attach-accept-btn")).toBeNull();
  });

  it("shows no notice when the line matches the acknowledged tip", async () => {
    const STATUS = JSON.stringify({
      tip: "c".repeat(64),
      rewritten: false,
      foreign: false,
    });
    daemonMock.mockImplementation((action) =>
      action === "vault.attach_status"
        ? Promise.resolve(STATUS)
        : Promise.resolve(REPORT)
    );
    render(() => <AttachmentsSection />);
    await waitFor(() => expect(daemonMock).toHaveBeenCalled());
    expect(screen.queryByTestId("attach-notice")).toBeNull();
  });

  it("maps a daemon refusal to the sanitized toast and keeps the section usable", async () => {
    daemonMock.mockRejectedValue(
      new Error("some files have not finished syncing to the vault yet")
    );
    render(() => <AttachmentsSection />);
    fireEvent.click(screen.getByTestId("attach-compact-btn"));
    await waitFor(() =>
      expect(toasts.error).toHaveBeenCalledWith(
        "some files have not finished syncing to the vault yet"
      )
    );
    expect(screen.queryByTestId("attach-result")).toBeNull();
    // The button re-enables after the failure so the user can retry.
    await waitFor(() =>
      expect(screen.getByTestId("attach-compact-btn").disabled).toBe(false)
    );
  });
});
