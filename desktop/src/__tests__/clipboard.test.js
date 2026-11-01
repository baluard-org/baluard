import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { copyToClipboard } from "../lib/clipboard.js";

describe("clipboard auto-clear default", () => {
  let writeText;
  let readText;

  beforeEach(() => {
    vi.useFakeTimers();
    writeText = vi.fn().mockResolvedValue(undefined);
    readText = vi.fn().mockResolvedValue("secret");
    navigator.clipboard = { writeText, readText };
    vi.doMock("@tauri-apps/api/core", () => ({
      invoke: vi.fn().mockRejectedValue(new Error("not under tauri")),
    }));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.doUnmock("@tauri-apps/api/core");
    vi.restoreAllMocks();
  });

  it("clears at sixty seconds by default, not before", async () => {
    const pending = copyToClipboard("secret");
    await pending;

    await vi.advanceTimersByTimeAsync(59_000);
    const clearsBefore = writeText.mock.calls.filter(
      (c) => c[0] === "",
    ).length;
    expect(clearsBefore).toBe(0);

    await vi.advanceTimersByTimeAsync(1_000);
    expect(writeText).toHaveBeenCalledWith("");
  });
});
