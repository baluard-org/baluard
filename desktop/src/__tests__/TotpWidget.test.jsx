import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, fireEvent, waitFor, cleanup } from "@solidjs/testing-library";

vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({ t: (k) => k, locale: () => "en" }),
  I18nProvider: (props) => props.children,
}));

const daemonMock = vi.fn();
vi.mock("../lib/daemon.js", () => ({ daemon: (...args) => daemonMock(...args) }));

const clipboardMock = vi.fn().mockResolvedValue(undefined);
vi.mock("../lib/clipboard.js", () => ({ copyToClipboard: (...a) => clipboardMock(...a) }));

import TotpWidget, { totpSeedOf } from "../components/TotpWidget.jsx";

const CODE = { code: "123456", period_seconds: 30, expires_at: Math.floor(Date.now() / 1000) + 30 };

function mockSuccess() {
  daemonMock.mockImplementation((action) => {
    if (action === "cipher.totp_code") return Promise.resolve(JSON.stringify(CODE));
    return Promise.resolve("{}");
  });
}

describe("totpSeedOf", () => {
  it("reads the flattened daemon shape", () => {
    expect(totpSeedOf({ totp: "ABC" })).toBe("ABC");
  });
  it("reads the edit-form flat shape", () => {
    expect(totpSeedOf({ totp_uri: "ABC" })).toBe("ABC");
  });
  it("reads the nested kind shape when no flat field exists", () => {
    expect(totpSeedOf({ totp: null, kind: { data: { totp_uri: "ABC" } } })).toBe("ABC");
  });
  it("rejects missing, empty, and blank seeds", () => {
    expect(totpSeedOf({})).toBeNull();
    expect(totpSeedOf({ totp: null, kind: { data: { totp_uri: null } } })).toBeNull();
    expect(totpSeedOf({ totp: "   " })).toBeNull();
  });
});

describe("TotpWidget", () => {
  beforeEach(() => {
    daemonMock.mockReset();
    clipboardMock.mockClear();
    cleanup();
  });

  it("shows the generated code for a bare-secret seed at top level", async () => {
    mockSuccess();
    const { container } = render(() => <TotpWidget cipher={{ id: "u1", totp: "JBSWY3DPEHPK3PXP" }} />);
    await waitFor(() => expect(container.textContent).toContain("123 456"), { timeout: 3000 });
    expect(daemonMock).toHaveBeenCalledWith("cipher.totp_code", "u1", null);
  });

  it("shows the generated code when the seed only exists nested under kind.data", async () => {
    mockSuccess();
    const cipher = { id: "u2", totp: null, kind: { data: { totp_uri: "JBSWY3DPEHPK3PXP" } } };
    const { container } = render(() => <TotpWidget cipher={cipher} />);
    await waitFor(() => expect(container.textContent).toContain("123 456"), { timeout: 3000 });
  });

  it("renders the countdown and a depleting progress bar", async () => {
    mockSuccess();
    const { container } = render(() => <TotpWidget cipher={{ id: "u3", totp: "ABC" }} />);
    await waitFor(() => expect(container.textContent).toContain("123 456"), { timeout: 3000 });
    expect(container.querySelector("[data-testid='totp-seconds']").textContent).toMatch(/\d+s/);
    const bar = container.querySelector("[data-testid='totp-bar']");
    expect(bar).toBeTruthy();
    expect(bar.style.width).toMatch(/%/);
  });

  it("copies the code from the copy button", async () => {
    mockSuccess();
    const { container } = render(() => <TotpWidget cipher={{ id: "u4", totp: "ABC" }} />);
    await waitFor(() => expect(container.textContent).toContain("123 456"), { timeout: 3000 });
    fireEvent.click(container.querySelector("[data-testid='totp-copy']"));
    expect(clipboardMock).toHaveBeenCalledWith("123456");
  });

  it("shows an error with a retry instead of hiding when the fetch fails", async () => {
    daemonMock.mockImplementation(() => Promise.reject(new Error("boom")));
    const { container } = render(() => <TotpWidget cipher={{ id: "u5", totp: "ABC" }} />);
    await waitFor(() => expect(container.querySelector("[data-testid='totp-retry']")).toBeTruthy(), { timeout: 3000 });
    expect(container.textContent).toContain("entry.totpUnavailable");
    mockSuccess();
    fireEvent.click(container.querySelector("[data-testid='totp-retry']"));
    await waitFor(() => expect(container.textContent).toContain("123 456"), { timeout: 3000 });
  });
});
