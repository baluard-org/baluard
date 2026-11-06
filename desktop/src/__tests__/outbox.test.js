import { describe, expect, it } from "vitest";
import { recipientOutboxPath } from "../lib/outbox.js";

const ana = {
  display_name: "Ana",
  identity_signing_pubkey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
};
const other = {
  display_name: "Ana",
  identity_signing_pubkey: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
};

describe("recipientOutboxPath", () => {
  it("creates a distinct safe subfolder for each recipient", () => {
    const first = recipientOutboxPath("/tmp/shared", ana);
    const second = recipientOutboxPath("/tmp/shared", other);
    expect(first).toBe("/tmp/shared/ana-aaaaaaaaaaaa");
    expect(second).toBe("/tmp/shared/ana-bbbbbbbbbbbb");
    expect(first).not.toBe(second);
  });

  it("normalizes names and preserves filesystem roots", () => {
    expect(recipientOutboxPath("/", { ...ana, display_name: "Ána / Work" })).toBe("/ana-work-aaaaaaaaaaaa");
    expect(recipientOutboxPath("C:\\shared\\", ana)).toBe("C:/shared/ana-aaaaaaaaaaaa");
  });
});
