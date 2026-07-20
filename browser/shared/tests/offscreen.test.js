// Unit tests for offscreen.js (clipboard bridge).
//
// Covers the message router: only `target: "offscreen"` messages are handled,
// offscreen-copy delegates to navigator.clipboard.writeText, offscreen-clear
// writes a single space (per design — overwrite, not empty string, to avoid
// some clipboard managers capturing an empty history entry).

import { describe, it, expect, beforeEach, vi } from "vitest";
import { handleOffscreenMessage } from "../src/offscreen.js";

describe("offscreen message router", () => {
  let writeText;
  beforeEach(() => {
    writeText = vi.fn().mockResolvedValue(undefined);
    globalThis.navigator.clipboard.writeText = writeText;
  });

  it("ignores messages without target=offscreen", () => {
    const sendResponse = vi.fn();
    const result = handleOffscreenMessage({ action: "offscreen-copy", text: "x" }, {}, sendResponse);
    expect(result).toBeUndefined();
    expect(sendResponse).not.toHaveBeenCalled();
    expect(writeText).not.toHaveBeenCalled();
  });

  it("routes offscreen-copy to navigator.clipboard.writeText", async () => {
    const sendResponse = vi.fn();
    const result = handleOffscreenMessage(
      { target: "offscreen", action: "offscreen-copy", text: "secret" },
      {},
      sendResponse
    );
    expect(result).toBe(true); // signals async response
    // Drain the microtask queue so writeText().then(sendResponse) settles.
    await new Promise((r) => setTimeout(r, 0));
    expect(writeText).toHaveBeenCalledWith("secret");
    expect(sendResponse).toHaveBeenCalledWith({ ok: true });
  });

  it("defaults the copy payload to empty string when text is missing", async () => {
    const sendResponse = vi.fn();
    handleOffscreenMessage(
      { target: "offscreen", action: "offscreen-copy" },
      {},
      sendResponse
    );
    await new Promise((r) => setTimeout(r, 0));
    expect(writeText).toHaveBeenCalledWith("");
  });

  it("surfaces clipboard write errors as a failed response", async () => {
    writeText.mockRejectedValueOnce(new Error("permission denied"));
    const sendResponse = vi.fn();
    handleOffscreenMessage(
      { target: "offscreen", action: "offscreen-copy", text: "x" },
      {},
      sendResponse
    );
    await new Promise((r) => setTimeout(r, 0));
    expect(sendResponse).toHaveBeenCalledWith({ ok: false, error: "Error: permission denied" });
  });

  it("offscreen-clear overwrites with a single space (not empty)", async () => {
    const sendResponse = vi.fn();
    handleOffscreenMessage({ target: "offscreen", action: "offscreen-clear" }, {}, sendResponse);
    await new Promise((r) => setTimeout(r, 0));
    expect(writeText).toHaveBeenCalledWith(" ");
    expect(sendResponse).toHaveBeenCalledWith({ ok: true });
  });

  it("ignores unknown actions under target=offscreen", () => {
    const sendResponse = vi.fn();
    const result = handleOffscreenMessage(
      { target: "offscreen", action: "offscreen-frobnicate" },
      {},
      sendResponse
    );
    expect(result).toBeUndefined();
    expect(writeText).not.toHaveBeenCalled();
    expect(sendResponse).not.toHaveBeenCalled();
  });
});