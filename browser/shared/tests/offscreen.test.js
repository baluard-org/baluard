// Unit tests for offscreen.js (clipboard bridge).
//
// Covers the message router: only `target: "offscreen"` messages are handled,
// offscreen-copy delegates to navigator.clipboard.writeText, offscreen-clear
// writes a single space (per design — overwrite, not empty string, to avoid
// some clipboard managers capturing an empty history entry).

import { describe, it, expect, beforeEach, vi } from "vitest";
import { handleOffscreenMessage } from "../src/offscreen.js";

// The extension's own sender shape (background service worker: no tab).
const SENDER = { id: "test-extension-id" };

describe("offscreen message router", () => {
  let writeText;
  beforeEach(() => {
    writeText = vi.fn().mockResolvedValue(undefined);
    globalThis.navigator.clipboard.writeText = writeText;
  });


  it("rejects senders from another extension id", () => {
    const sendResponse = vi.fn();
    const result = handleOffscreenMessage(
      { target: "offscreen", action: "offscreen-copy", text: "x" },
      { id: "other-extension" },
      sendResponse
    );
    expect(result).toBeUndefined();
    expect(writeText).not.toHaveBeenCalled();
  });

  it("rejects tab senders (content scripts)", () => {
    const sendResponse = vi.fn();
    const result = handleOffscreenMessage(
      { target: "offscreen", action: "offscreen-copy", text: "x" },
      { id: "test-extension-id", tab: { id: 1 } },
      sendResponse
    );
    expect(result).toBeUndefined();
    expect(writeText).not.toHaveBeenCalled();
  });

  it("ignores messages without target=offscreen", () => {
    const sendResponse = vi.fn();
    const result = handleOffscreenMessage({ action: "offscreen-copy", text: "x" }, SENDER, sendResponse);
    expect(result).toBeUndefined();
    expect(sendResponse).not.toHaveBeenCalled();
    expect(writeText).not.toHaveBeenCalled();
  });

  it("routes offscreen-copy to navigator.clipboard.writeText", async () => {
    const sendResponse = vi.fn();
    const result = handleOffscreenMessage(
      { target: "offscreen", action: "offscreen-copy", text: "secret" },
      SENDER,
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
      SENDER,
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
      SENDER,
      sendResponse
    );
    await new Promise((r) => setTimeout(r, 0));
    expect(sendResponse).toHaveBeenCalledWith({ ok: false, error: "Error: permission denied" });
  });

  it("offscreen-clear overwrites with a single space (not empty)", async () => {
    const sendResponse = vi.fn();
    handleOffscreenMessage({ target: "offscreen", action: "offscreen-clear" }, SENDER, sendResponse);
    await new Promise((r) => setTimeout(r, 0));
    expect(writeText).toHaveBeenCalledWith(" ");
    expect(sendResponse).toHaveBeenCalledWith({ ok: true });
  });

  it("ignores unknown actions under target=offscreen", () => {
    const sendResponse = vi.fn();
    const result = handleOffscreenMessage(
      { target: "offscreen", action: "offscreen-frobnicate" },
      SENDER,
      sendResponse
    );
    expect(result).toBeUndefined();
    expect(writeText).not.toHaveBeenCalled();
    expect(sendResponse).not.toHaveBeenCalled();
  });
});

// ── Auto-clear timer (offscreen doc owns it; SW alarms clamp at 30s) ──

describe("offscreen-copy clearSeconds", () => {
  let writeText;

  beforeEach(() => {
    writeText = vi.fn().mockResolvedValue(undefined);
    globalThis.navigator.clipboard.writeText = writeText;
  });

  it("overwrites with a space after clearSeconds", async () => {
    vi.useFakeTimers();
    try {
      const sendResponse = vi.fn();
      handleOffscreenMessage(
        { target: "offscreen", action: "offscreen-copy", text: "secret", clearSeconds: 10 },
        { id: chrome.runtime.id },
        sendResponse
      );
      await vi.advanceTimersByTimeAsync(0); // settle the write microtask
      expect(writeText).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(10000);
      expect(writeText).toHaveBeenCalledTimes(2);
      expect(writeText).toHaveBeenLastCalledWith(" ");
    } finally {
      vi.useRealTimers();
    }
  });

  it("clearSeconds=0 never schedules a clear", async () => {
    vi.useFakeTimers();
    try {
      handleOffscreenMessage(
        { target: "offscreen", action: "offscreen-copy", text: "secret", clearSeconds: 0 },
        { id: chrome.runtime.id },
        vi.fn()
      );
      await vi.advanceTimersByTimeAsync(0);
      await vi.advanceTimersByTimeAsync(600000);
      expect(writeText).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("a fresh copy cancels the previous pending clear", async () => {
    vi.useFakeTimers();
    try {
      const sender = { id: chrome.runtime.id };
      handleOffscreenMessage(
        { target: "offscreen", action: "offscreen-copy", text: "first", clearSeconds: 10 },
        sender,
        vi.fn()
      );
      await vi.advanceTimersByTimeAsync(0);
      handleOffscreenMessage(
        { target: "offscreen", action: "offscreen-copy", text: "second", clearSeconds: 10 },
        sender,
        vi.fn()
      );
      await vi.advanceTimersByTimeAsync(0);
      expect(writeText).toHaveBeenCalledTimes(2); // both writes, no clear yet
      await vi.advanceTimersByTimeAsync(10000);
      expect(writeText).toHaveBeenCalledTimes(3); // exactly one clear
      expect(writeText).toHaveBeenLastCalledWith(" ");
    } finally {
      vi.useRealTimers();
    }
  });
});