import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@solidjs/testing-library";
import { I18nProvider } from "../i18n/index.jsx";

// The final phrase check: the second, we-are-not-joking confirmation shown
// after the user already confirmed storage once. Decline keeps the words on
// screen; confirm is the only path forward.
import FinalPhraseCheckDialog from "../components/FinalPhraseCheckDialog.jsx";

describe("FinalPhraseCheckDialog", () => {
  beforeEach(() => {
    cleanup();
    // The vitest node env has no localStorage; the i18n module reads the
    // global at call time, so a stub drives both boot and persistence.
    const store = new Map();
    globalThis.localStorage = {
      getItem: (k) => store.get(k) ?? null,
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: (k) => store.delete(k),
      clear: () => store.clear(),
    };
    localStorage.setItem("baluard-locale", "en");
  });

  const mount = (onDecline, onConfirm) =>
    render(() => (
      <I18nProvider>
        <FinalPhraseCheckDialog open={true} onDecline={onDecline} onConfirm={onConfirm} />
      </I18nProvider>
    ));

  it("shows the we-are-not-joking copy with decline and confirm actions", () => {
    mount(vi.fn(), vi.fn());
    expect(screen.getByText("One last check")).toBeTruthy();
    expect(screen.getByText(/no way for anyone, including us/)).toBeTruthy();
    expect(screen.getByText("No, I haven't yet")).toBeTruthy();
    expect(screen.getByText("Yes, they are stored safely")).toBeTruthy();
  });

  it("keeps the words on screen when the user declines", () => {
    const onDecline = vi.fn();
    const onConfirm = vi.fn();
    mount(onDecline, onConfirm);
    fireEvent.click(screen.getByText("No, I haven't yet"));
    expect(onDecline).toHaveBeenCalledTimes(1);
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("proceeds only through the explicit confirm action", () => {
    const onDecline = vi.fn();
    const onConfirm = vi.fn();
    mount(onDecline, onConfirm);
    fireEvent.click(screen.getByText("Yes, they are stored safely"));
    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onDecline).not.toHaveBeenCalled();
  });
});
