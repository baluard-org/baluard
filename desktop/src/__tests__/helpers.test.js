// Tests for desktop/src/lib/helpers.js + clipboard.js.
// Pure helpers + a small navigator.clipboard-mocked test for the
// auto-clear timer.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { stripDigits, handleCardInput } from "../lib/helpers.js";
import { formatCardNumber } from "../lib/utils.js";
import { copyToClipboard } from "../lib/clipboard.js";


describe("stripDigits", () => {
  it("removes all non-digit characters", () => {
    expect(stripDigits("4111-1111-1111-1111")).toBe("4111111111111111");
    expect(stripDigits("4111 1111 1111 1111")).toBe("4111111111111111");
    expect(stripDigits("abc123def456")).toBe("123456");
  });

  it("returns empty for null/undefined/empty", () => {
    expect(stripDigits(null)).toBe("");
    expect(stripDigits(undefined)).toBe("");
    expect(stripDigits("")).toBe("");
  });
});

describe("formatCardNumber + stripDigits", () => {
  it("formats 16-digit card as 4-4-4-4", () => {
    expect(formatCardNumber("4111111111111111")).toBe("4111 1111 1111 1111");
  });

  it("does not crash on short input", () => {
    expect(formatCardNumber("4111")).toBe("4111");
  });
});

describe("handleCardInput", () => {
  it("strips + reformats on input event", () => {
    const update = vi.fn();
    const handler = handleCardInput(update);
    const target = document.createElement("input");
    target.value = "4111-1111";
    // selectionStart 5 is right after the dash; the handler should
    // preserve the cursor position past the new space-or-dash placement.
    target.setSelectionRange(5, 5);
    const event = { target };
    handler(event);
    expect(update).toHaveBeenCalledWith("cardNumber", "41111111");
    expect(event.target.value).toBe("4111 1111");
  });
});

// ── clipboard.js with mocked navigator.clipboard ────────────────

describe("copyToClipboard", () => {
  let writeText;
  let readText;
  beforeEach(() => {
    writeText = vi.fn().mockResolvedValue(undefined);
    readText = vi.fn().mockResolvedValue(""); // assume clipboard changed
    // Replace the global navigator.clipboard mock for this test.
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText, readText },
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("writes the value to the clipboard", async () => {
    await copyToClipboard("secret-xyz", { autoClearMs: 0 });
    expect(writeText).toHaveBeenCalledWith("secret-xyz");
  });

  it("does not schedule clear when autoClearMs=0", async () => {
    vi.useFakeTimers();
    await copyToClipboard("secret-xyz", { autoClearMs: 0 });
    vi.advanceTimersByTime(60_000);
    // Only the initial writeText call; no clear attempt.
    expect(writeText).toHaveBeenCalledTimes(1);
  });

  it("schedules a clear timer when autoClearMs > 0", async () => {
    vi.useFakeTimers();
    await copyToClipboard("secret-xyz", { autoClearMs: 1000 });
    // Initial writeText happened, no clear yet.
    expect(writeText).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(1500);
    // readText is called inside the timer; allow it to resolve.
    await vi.runAllTimersAsync();
    // After the timer fires, the clear path runs readText + maybe writeText("").
    expect(readText).toHaveBeenCalled();
  });
});