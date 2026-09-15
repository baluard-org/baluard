// Tests for desktop/src/lib/disableAutofill.js + lib/daemon.js.
// disableAutofill is a DOM-sweep helper; the daemon wrapper is a thin
// Tauri invoke call that dispatches a window event for mutation actions.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── disableAutofill.js ───────────────────────────────────────────

import { disableAutofill } from "../lib/disableAutofill.js";

describe("disableAutofill", () => {
  let disconnect;

  afterEach(() => {
    if (typeof disconnect === "function") disconnect();
    // Remove any install marker so each test starts fresh.
    document.documentElement.removeAttribute("data-baluard-autofill-installed");
  });

  it("sets the suppress attrs on plain inputs", () => {
    const input = document.createElement("input");
    input.type = "text";
    document.body.appendChild(input);

    disconnect = disableAutofill();

    expect(input.getAttribute("autocomplete")).toBe("off");
    expect(input.getAttribute("autocorrect")).toBe("off");
    expect(input.getAttribute("autocapitalize")).toBe("off");
    expect(input.getAttribute("spellcheck")).toBe("false");
    expect(input.getAttribute("data-baluard-autofill")).toBe("1");
  });

  it("does not touch inputs that opt in via data-autofill=on", () => {
    const input = document.createElement("input");
    input.type = "text";
    input.setAttribute("data-autofill", "on");
    document.body.appendChild(input);

    disconnect = disableAutofill();

    expect(input.hasAttribute("data-baluard-autofill")).toBe(false);
    expect(input.getAttribute("autocomplete")).toBeNull();
  });

  it("is idempotent (second install returns a no-op disposer)", () => {
    const d1 = disableAutofill();
    const d2 = disableAutofill();
    expect(typeof d1).toBe("function");
    expect(typeof d2).toBe("function");
    d1();
    d2();
  });

  it("covers inputs added after install (MutationObserver)", async () => {
    disconnect = disableAutofill();
    const input = document.createElement("input");
    input.type = "email";
    document.body.appendChild(input);
    // MutationObserver fires asynchronously; flush microtasks.
    await new Promise((r) => setTimeout(r, 0));
    expect(input.getAttribute("data-baluard-autofill")).toBe("1");
  });

  it("covers textareas and selects", () => {
    const ta = document.createElement("textarea");
    const sel = document.createElement("select");
    document.body.appendChild(ta);
    document.body.appendChild(sel);

    disconnect = disableAutofill();

    expect(ta.getAttribute("data-baluard-autofill")).toBe("1");
    expect(sel.getAttribute("data-baluard-autofill")).toBe("1");
  });
});

// ── lib/daemon.js (Tauri invoke wrapper) ─────────────────────────

// Mock the Tauri invoke API so we can test the wrapper's dispatch + event
// emission without a real Tauri runtime.
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

import { invoke } from "@tauri-apps/api/core";
import { daemon, showWindow } from "../lib/daemon.js";

describe("daemon wrapper", () => {
  beforeEach(() => {
    vi.mocked(invoke).mockReset();
    // jsdom default: no window CustomEvent -> wire it up if missing.
    if (typeof window.CustomEvent !== "function") {
      window.CustomEvent = class CustomEvent {
        constructor(type, init) {
          this.type = type;
          this.detail = init?.detail;
        }
      };
    }
  });

  it("calls invoke with the daemon_request command + action/payload", async () => {
    vi.mocked(invoke).mockResolvedValue({ success: true, payload: "ok" });
    const result = await daemon("vault.list", "ignored");
    expect(invoke).toHaveBeenCalledWith("daemon_request", {
      action: "vault.list",
      payload: "ignored",
    });
    expect(result).toBe("ok");
  });

  it("passes slug override when provided", async () => {
    vi.mocked(invoke).mockResolvedValue({ success: true, payload: "" });
    await daemon("vault.get", "{}", "personal");
    expect(invoke).toHaveBeenCalledWith("daemon_request", {
      action: "vault.get",
      payload: "{}",
      slug: "personal",
    });
  });

  it("omits slug when not provided", async () => {
    vi.mocked(invoke).mockResolvedValue({ success: true, payload: "" });
    await daemon("vault.list", "");
    const call = vi.mocked(invoke).mock.calls[0][1];
    expect(call).not.toHaveProperty("slug");
  });

  it("throws on daemon error response", async () => {
    vi.mocked(invoke).mockResolvedValue({
      success: false,
      error: "vault locked",
      payload: "",
    });
    await expect(daemon("vault.list", "")).rejects.toThrow("vault locked");
  });

  it("dispatches baluard:local-mutation on mutation action success", async () => {
    vi.mocked(invoke).mockResolvedValue({ success: true, payload: "" });
    let captured = null;
    const listener = (e) => {
      captured = e.type;
    };
    window.addEventListener("baluard:local-mutation", listener);
    try {
      await daemon("vault.add", JSON.stringify({ name: "X" }));
      expect(captured).toBe("baluard:local-mutation");
    } finally {
      window.removeEventListener("baluard:local-mutation", listener);
    }
  });

  it("does NOT dispatch the event for non-mutation actions", async () => {
    vi.mocked(invoke).mockResolvedValue({ success: true, payload: "" });
    let fired = false;
    const listener = () => {
      fired = true;
    };
    window.addEventListener("baluard:local-mutation", listener);
    try {
      await daemon("vault.list", "");
      expect(fired).toBe(false);
    } finally {
      window.removeEventListener("baluard:local-mutation", listener);
    }
  });

  it("does NOT dispatch the event on failed mutation", async () => {
    vi.mocked(invoke).mockResolvedValue({
      success: false,
      error: "nope",
      payload: "",
    });
    let fired = false;
    const listener = () => {
      fired = true;
    };
    window.addEventListener("baluard:local-mutation", listener);
    try {
      await expect(daemon("vault.add", "{}")).rejects.toThrow();
      expect(fired).toBe(false);
    } finally {
      window.removeEventListener("baluard:local-mutation", listener);
    }
  });
});

describe("showWindow", () => {
  beforeEach(() => {
    vi.mocked(invoke).mockReset();
  });

  it("showWindow calls the dedicated Tauri command", async () => {
    vi.mocked(invoke).mockResolvedValue(undefined);
    await showWindow();
    expect(invoke).toHaveBeenCalledWith("show_window");
  });
});