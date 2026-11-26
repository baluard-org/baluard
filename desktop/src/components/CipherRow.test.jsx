// CipherRow indicators: a row shows a paperclip when the item carries at
// least one attachment and a fingerprint when it has an associated passkey.
// The list payload carries both arrays, so this is presentation only.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, cleanup } from "@solidjs/testing-library";

vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({ t: (k) => k, locale: () => "en", setLocale: vi.fn() }),
}));

vi.mock("./CipherAvatar.jsx", () => ({ default: () => <div data-testid="avatar" /> }));

import CipherRow from "./CipherRow.jsx";

const base = { id: "c1", type: "login", name: "Alpha", username: "u" };

describe("CipherRow item indicators", () => {
  beforeEach(cleanup);

  it("a plain item shows no indicator", () => {
    render(() => <CipherRow cipher={base} />);
    expect(screen.queryByTestId("row-attachment-indicator")).toBeNull();
    expect(screen.queryByTestId("row-passkey-indicator")).toBeNull();
    expect(screen.queryByTestId("row-totp-indicator")).toBeNull();
  });

  it("an item with at least one attachment shows the attachment indicator", () => {
    render(() => <CipherRow cipher={{ ...base, attachments: [{ id: "a1" }] }} />);
    expect(screen.getByTestId("row-attachment-indicator")).toBeTruthy();
    expect(screen.getByTestId("row-attachment-indicator").getAttribute("title")).toBe(
      "entry.hasAttachments",
    );
    expect(screen.queryByTestId("row-passkey-indicator")).toBeNull();
  });

  it("an item with a passkey shows the passkey indicator", () => {
    render(() => (
      <CipherRow cipher={{ ...base, fido2_credentials: [{ credential_id: "pk1" }] }} />
    ));
    expect(screen.getByTestId("row-passkey-indicator")).toBeTruthy();
    expect(screen.getByTestId("row-passkey-indicator").getAttribute("title")).toBe(
      "entry.hasPasskey",
    );
    expect(screen.queryByTestId("row-attachment-indicator")).toBeNull();
  });

  it("an item with a TOTP seed shows the TOTP indicator", () => {
    render(() => (
      <CipherRow
        cipher={{ ...base, totp: "otpauth://totp/Alpha?secret=ABC" }}
      />
    ));
    expect(screen.getByTestId("row-totp-indicator")).toBeTruthy();
    expect(screen.getByTestId("row-totp-indicator").getAttribute("title")).toBe(
      "entry.hasTotp",
    );
    expect(screen.queryByTestId("row-attachment-indicator")).toBeNull();
    expect(screen.queryByTestId("row-passkey-indicator")).toBeNull();
  });

  it("an empty TOTP string shows nothing", () => {
    render(() => <CipherRow cipher={{ ...base, totp: "" }} />);
    expect(screen.queryByTestId("row-totp-indicator")).toBeNull();
  });

  it("an item can carry all three indicators at once", () => {
    render(() => (
      <CipherRow
        cipher={{
          ...base,
          attachments: [{ id: "a1" }],
          fido2_credentials: [{ credential_id: "pk1" }],
          totp: "otpauth://totp/Alpha?secret=ABC",
        }}
      />
    ));
    expect(screen.getByTestId("row-attachment-indicator")).toBeTruthy();
    expect(screen.getByTestId("row-passkey-indicator")).toBeTruthy();
    expect(screen.getByTestId("row-totp-indicator")).toBeTruthy();
  });

  it("empty arrays show nothing", () => {
    render(() => (
      <CipherRow cipher={{ ...base, attachments: [], fido2_credentials: [] }} />
    ));
    expect(screen.queryByTestId("row-attachment-indicator")).toBeNull();
    expect(screen.queryByTestId("row-passkey-indicator")).toBeNull();
    expect(screen.queryByTestId("row-totp-indicator")).toBeNull();
  });
});
