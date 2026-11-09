import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@solidjs/testing-library";
import { I18nProvider } from "../i18n/index.jsx";
import { holdPhrase, takeHeldPhrase, clearHeldPhrase } from "../lib/heldPhrase.js";
import RecoveryPhraseCard from "../components/RecoveryPhraseCard.jsx";

// The rotation ceremony must not close on the first confirmation: Done now
// opens the final we-are-not-joking check, and the phrase only clears once
// that second dialog is explicitly confirmed.
const PHRASE =
  "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic act absorb absurd abuse access accident";

describe("RecoveryPhraseCard final check", () => {
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
    clearHeldPhrase("recovery");
    holdPhrase("recovery", PHRASE);
  });

  const mount = async () => {
    render(() => (
      <I18nProvider>
        <RecoveryPhraseCard />
      </I18nProvider>
    ));
    await Promise.resolve();
    expect(screen.getAllByText("abandon")[0]).toBeTruthy();
  };

  const confirmStored = async () => {
    fireEvent.click(screen.getByLabelText("I stored my new phrase somewhere safe"));
    await Promise.resolve();
  };

  it("opens the final check instead of closing on Done", async () => {
    await mount();
    await confirmStored();
    fireEvent.click(screen.getByText("Done"));
    await Promise.resolve();
    expect(screen.getByText("One last check")).toBeTruthy();
  });

  it("declining keeps the ceremony open with the phrase visible", async () => {
    await mount();
    await confirmStored();
    fireEvent.click(screen.getByText("Done"));
    await Promise.resolve();
    fireEvent.click(screen.getByText("No, I haven't yet"));
    await Promise.resolve();
    expect(screen.queryByText("One last check")).toBeNull();
    expect(screen.getByText("Your new recovery phrase")).toBeTruthy();
    expect(screen.getAllByText("abandon").length).toBeGreaterThan(0);
  });

  it("confirming the final check clears the phrase and closes the ceremony", async () => {
    await mount();
    await confirmStored();
    fireEvent.click(screen.getByText("Done"));
    await Promise.resolve();
    fireEvent.click(screen.getByText("Yes, they are stored safely"));
    await Promise.resolve();
    // The final dialog must be gone and the phrase wiped from process
    // memory. The ceremony DOM node itself stays mounted in jsdom because
    // the fade Transition waits for transitionend, which never fires in a
    // simulated environment; the wipe is the state close() controls.
    expect(screen.queryByText("One last check")).toBeNull();
    expect(takeHeldPhrase("recovery")).toBeNull();
  });
});
