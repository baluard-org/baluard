// Unit tests for offscreen.js (clipboard bridge).
//
// Covers the message router: only `target: "offscreen"` messages are handled,
// offscreen-copy delegates to navigator.clipboard.writeText, offscreen-clear
// writes a single space (per design — overwrite, not empty string, to avoid
// some clipboard managers capturing an empty history entry).

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { handleOffscreenMessage } from "../src/offscreen.js";

// The extension's own sender shape (background service worker: no tab).
const SENDER = { id: "test-extension-id" };

describe("offscreen message router", () => {
  let writeText;
  beforeEach(() => {
    // jsdom reports the document unfocused, which would skip the writeText
    // fast path; these tests exercise it explicitly.
    document.hasFocus = () => true;
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
    // The async API failed, so the execCommand fallback ran; with no
    // execCommand support the copy is reported as failed.
    expect(sendResponse).toHaveBeenCalledWith({
      ok: false,
      error: "Error: clipboard write failed: permission denied",
    });
  });

  // Chromium 109-156: navigator.clipboard.writeText() rejects in an
  // offscreen document ("Document is not focused."). The execCommand
  // fallback is the only write that works from an unfocused document.
  it("falls back to execCommand when the async clipboard API refuses", async () => {
    writeText.mockRejectedValueOnce(new Error("Document is not focused."));
    document.execCommand = vi.fn(() => true);
    const sendResponse = vi.fn();
    handleOffscreenMessage(
      { target: "offscreen", action: "offscreen-copy", text: "secret" },
      SENDER,
      sendResponse
    );
    await new Promise((r) => setTimeout(r, 0));
    expect(document.execCommand).toHaveBeenCalledWith("copy");
    expect(sendResponse).toHaveBeenCalledWith({ ok: true });
    delete document.execCommand;
  });

  it("copies the secret through a hidden textarea on the execCommand path", async () => {
    writeText.mockRejectedValueOnce(new Error("Document is not focused."));
    let copied = null;
    document.execCommand = vi.fn(() => {
      copied = document.activeElement?.value ?? null;
      return true;
    });
    handleOffscreenMessage(
      { target: "offscreen", action: "offscreen-copy", text: "secret" },
      SENDER,
      vi.fn()
    );
    await new Promise((r) => setTimeout(r, 0));
    expect(copied).toBe("secret");
    // The textarea must not stay behind in the page.
    expect(document.querySelectorAll("textarea")).toHaveLength(0);
    delete document.execCommand;
  });

  it("uses execCommand when the async clipboard API is missing", async () => {
    const saved = globalThis.navigator.clipboard;
    globalThis.navigator.clipboard = undefined;
    document.execCommand = vi.fn(() => true);
    const sendResponse = vi.fn();
    handleOffscreenMessage(
      { target: "offscreen", action: "offscreen-copy", text: "secret" },
      SENDER,
      sendResponse
    );
    await new Promise((r) => setTimeout(r, 0));
    expect(document.execCommand).toHaveBeenCalledWith("copy");
    expect(sendResponse).toHaveBeenCalledWith({ ok: true });
    globalThis.navigator.clipboard = saved;
    delete document.execCommand;
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
describe("offscreen writeClipboard fallback (unfocused document)", () => {
  let writeText;
  let execCommand;
  let lastCopiedValue;
  beforeEach(() => {
    vi.useFakeTimers();
    // Focused document: writeText is tried first and rejects below.
    document.hasFocus = () => true;
    writeText = vi.fn().mockRejectedValue(new Error("NotAllowedError: Document is not focused"));
    globalThis.navigator.clipboard.writeText = writeText;
    lastCopiedValue = null;
    execCommand = vi.fn(() => {
      lastCopiedValue = document.querySelector("textarea")?.value ?? null;
      return true;
    });
    document.execCommand = execCommand;
  });
  afterEach(() => {
    vi.useRealTimers();
    delete document.execCommand;
  });

  it("falls back to execCommand('copy') when writeText rejects, and reports ok", async () => {
    const sendResponse = vi.fn();
    handleOffscreenMessage(
      { target: "offscreen", action: "offscreen-copy", text: "secret", clearSeconds: 0 },
      { id: chrome.runtime.id },
      sendResponse
    );
    await vi.advanceTimersByTimeAsync(0);
    expect(writeText).toHaveBeenCalledWith("secret");
    expect(execCommand).toHaveBeenCalledWith("copy");
    expect(lastCopiedValue).toBe("secret");
    expect(sendResponse).toHaveBeenCalledWith({ ok: true });
    // The hidden textarea never survives the copy.
    expect(document.querySelectorAll("textarea")).toHaveLength(0);
  });

  it("skips writeText entirely when the document is unfocused", async () => {
    document.hasFocus = () => true; // overridden below
    document.hasFocus = () => false;
    const sendResponse = vi.fn();
    handleOffscreenMessage(
      { target: "offscreen", action: "offscreen-copy", text: "secret", clearSeconds: 0 },
      { id: chrome.runtime.id },
      sendResponse
    );
    await vi.advanceTimersByTimeAsync(0);
    expect(writeText).not.toHaveBeenCalled();
    expect(execCommand).toHaveBeenCalledWith("copy");
    expect(sendResponse).toHaveBeenCalledWith({ ok: true });
  });

  it("routes the auto-clear through the same fallback", async () => {
    const sendResponse = vi.fn();
    handleOffscreenMessage(
      { target: "offscreen", action: "offscreen-copy", text: "secret", clearSeconds: 10 },
      { id: chrome.runtime.id },
      sendResponse
    );
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(10000);
    expect(execCommand).toHaveBeenCalledTimes(2);
    // Second write is the clear overwrite.
    expect(lastCopiedValue).toBe(" ");
    expect(sendResponse).toHaveBeenCalledTimes(1);
  });
});
