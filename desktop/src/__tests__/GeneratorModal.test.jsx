// Tests for desktop/src/components/GeneratorModal.jsx — password /
// passphrase generator modal. Heavy on auto-generation effects;
// we test the user-facing interaction points (mode tabs, charset
// toggles, copy, history) and don't try to assert the random output
// value (it's random; we just confirm SOMETHING is rendered).

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, fireEvent, waitFor, cleanup } from "@solidjs/testing-library";

// ── Mocks (hoisted) ───────────────────────────────────────────

vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({ t: (k, vars) => (vars ? `${k}(${JSON.stringify(vars)})` : k), locale: () => "en", setLocale: vi.fn() }),
  I18nProvider: (props) => props.children,
}));

const daemonMock = vi.fn();
vi.mock("../lib/daemon.js", () => ({ daemon: (...args) => daemonMock(...args) }));

vi.mock("../lib/clipboard.js", () => ({ copyToClipboard: vi.fn().mockResolvedValue(undefined) }));

vi.mock("../context/toastSignal.js", () => ({
  toast: vi.fn(),
  toastSuccess: vi.fn(),
  toastError: vi.fn(),
  toasts: { length: 0 },
}));

vi.mock("../components/FocusTrap.jsx", () => ({ default: () => null }));

import { copyToClipboard } from "../lib/clipboard.js";
import GeneratorModal from "../components/GeneratorModal.jsx";

describe("GeneratorModal", () => {
  beforeEach(() => {
    daemonMock.mockReset();
    vi.mocked(copyToClipboard).mockClear();
    // Default: history_list returns empty
    daemonMock.mockImplementation((action) => {
      if (action === "generator.history_list") return Promise.resolve("[]");
      return Promise.resolve("[]");
    });
  });

  it("does not render when showGenerator=false", () => {
    const { queryByRole } = render(() => (
      <GeneratorModal showGenerator={false} setShowGenerator={vi.fn()} />
    ));
    expect(queryByRole("dialog")).toBeNull();
  });

  it("renders the dialog when showGenerator=true", () => {
    const { getByRole } = render(() => (
      <GeneratorModal showGenerator={true} setShowGenerator={vi.fn()} />
    ));
    expect(getByRole("dialog")).toBeTruthy();
  });

  it("renders mode tabs (Password + Passphrase)", () => {
    const { getByText } = render(() => (
      <GeneratorModal showGenerator={true} setShowGenerator={vi.fn()} />
    ));
    expect(getByText("generator.passwordTab")).toBeTruthy();
    expect(getByText("generator.passphraseTab")).toBeTruthy();
  });

  it("default mode is Password (length slider present)", () => {
    const { getByText } = render(() => (
      <GeneratorModal showGenerator={true} setShowGenerator={vi.fn()} />
    ));
    // "generator.length": <strong>16</strong>
    expect(getByText("generator.length", { exact: false })).toBeTruthy();
  });

  it("clicking Passphrase tab shows word-count slider", () => {
    const { getByText } = render(() => (
      <GeneratorModal showGenerator={true} setShowGenerator={vi.fn()} />
    ));
    fireEvent.click(getByText("generator.passphraseTab"));
    expect(getByText("generator.words", { exact: false })).toBeTruthy();
  });

  it("clicking close (✕) calls setShowGenerator(false)", () => {
    const setShow = vi.fn();
    const { container } = render(() => (
      <GeneratorModal showGenerator={true} setShowGenerator={setShow} />
    ));
    // The close button is the bare ✕ in the header.
    const closeBtn = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent.trim() === "✕"
    );
    expect(closeBtn).toBeTruthy();
    fireEvent.click(closeBtn);
    expect(setShow).toHaveBeenCalledWith(false);
  });

  it("Regenerate button calls daemon generator.history_add", async () => {
    const { getByText } = render(() => (
      <GeneratorModal showGenerator={true} setShowGenerator={vi.fn()} />
    ));
    // The regenerate button is the one with the IconRefresh — find by
    // aria/title. It uses t("generator.regenerate") as label.
    const regenBtn = getByText("generator.regenerate");
    fireEvent.click(regenBtn);
    await waitFor(() => expect(daemonMock).toHaveBeenCalledWith("generator.history_add", expect.any(String)));
  });

  it("opening the history panel calls daemon generator.history_list", async () => {
    daemonMock.mockImplementation((action) => {
      if (action === "generator.history_list") {
        return Promise.resolve(JSON.stringify([
          { value: "old-pass-1", kind: "password", created_at: 1700000000 },
        ]));
      }
      return Promise.resolve("[]");
    });
    const { getByText } = render(() => (
      <GeneratorModal showGenerator={true} setShowGenerator={vi.fn()} />
    ));
    // The history toggle is t("generator.history") — find it.
    const historyBtn = getByText("generator.history");
    fireEvent.click(historyBtn);
    await waitFor(() => expect(daemonMock).toHaveBeenCalledWith("generator.history_list"));
  });
});