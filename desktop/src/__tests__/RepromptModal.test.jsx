// Regression: the reprompt dialog renders through ConsolePanel's Portal.
// Wrapping that Portal in <Transition> detached the portal marker at
// delegation-registration time, so document.body never became a delegated
// container and every click/key inside the dialog was silently dropped
// (typing showed dots, but Confirm/Cancel/Enter did nothing). These tests
// drive real DOM events — they fail on the Transition wrapper and pass
// without it.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, waitFor, fireEvent, cleanup } from "@solidjs/testing-library";
import { flush } from "solid-js";
import fs from "node:fs";

const daemonMock = vi.fn();
vi.mock("../lib/daemon.js", () => ({ daemon: (...args) => daemonMock(...args) }));

import { I18nProvider } from "../i18n/index.jsx";
import RepromptModal from "../components/RepromptModal.jsx";

const findCancelButton = () =>
  [...document.querySelectorAll("button")].find((b) => b.textContent.trim() === "Cancel");
// Portal content mounts under document.body, outside the render container —
// the container-scoped testing-library queries cannot see it.
const q = (id) => document.querySelector(`[data-testid="${id}"]`);
const waitForId = async (id) => waitFor(() => { const el = q(id); expect(el).toBeTruthy(); return el; });

describe("RepromptModal portal event delivery", () => {
  beforeEach(() => {
    cleanup();
    const store = new Map();
    globalThis.localStorage = {
      getItem: (k) => store.get(k) ?? null,
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: (k) => store.delete(k),
      clear: () => store.clear(),
    };
    daemonMock.mockReset();
    daemonMock.mockResolvedValue({ success: true, payload: "" });
    delete window.__baluardReprompt;
  });

  it("carries a typed password to vault.reprompt_verify and closes", async () => {
    const callback = vi.fn();
    render(
      () => <I18nProvider><RepromptModal /></I18nProvider>,
    );
    expect(q("reprompt-input")).toBeNull();
    window.__baluardReprompt.show(callback);
    flush();
    const input = await waitForId("reprompt-input");
    fireEvent.input(input, { target: { value: "master-pw" } });
    flush();
    fireEvent.click(q("reprompt-confirm"));
    await waitFor(() =>
      expect(daemonMock).toHaveBeenCalledWith("vault.reprompt_verify", "master-pw"),
    );
    await waitFor(() => expect(callback).toHaveBeenCalledWith("master-pw"));
    await waitFor(() => expect(q("reprompt-input")).toBeNull());
  });

  it("submits on Enter", async () => {
    const callback = vi.fn();
    render(
      () => <I18nProvider><RepromptModal /></I18nProvider>,
    );
    window.__baluardReprompt.show(callback);
    flush();
    const input = await waitForId("reprompt-input");
    fireEvent.input(input, { target: { value: "master-pw" } });
    flush();
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() =>
      expect(daemonMock).toHaveBeenCalledWith("vault.reprompt_verify", "master-pw"),
    );
    await waitFor(() => expect(q("reprompt-input")).toBeNull());
  });

  it("closes on Cancel without contacting the daemon", async () => {
    const callback = vi.fn();
    render(
      () => <I18nProvider><RepromptModal /></I18nProvider>,
    );
    window.__baluardReprompt.show(callback);
    await waitForId("reprompt-input");
    const cancel = await waitFor(() => {
      const b = findCancelButton();
      expect(b).toBeTruthy();
      return b;
    });
    fireEvent.click(cancel);
    await waitFor(() => expect(q("reprompt-input")).toBeNull());
    expect(daemonMock).not.toHaveBeenCalled();
    expect(callback).not.toHaveBeenCalled();
  });

  it("shows the failure note and stays open on a wrong password", async () => {
    // daemon() rejects on a failed verify (mirrors the real daemon contract).
    daemonMock.mockRejectedValue(new Error("invalid password"));
    const callback = vi.fn();
    render(
      () => <I18nProvider><RepromptModal /></I18nProvider>,
    );
    window.__baluardReprompt.show(callback);
    flush();
    const input = await waitForId("reprompt-input");
    fireEvent.input(input, { target: { value: "wrong-pw" } });
    flush();
    fireEvent.click(q("reprompt-confirm"));
    await waitFor(() => expect(daemonMock).toHaveBeenCalledWith("vault.reprompt_verify", "wrong-pw"));
    flush();
    await waitFor(() => {
      const note = [...document.querySelectorAll("div")].find((d) => d.textContent === "Incorrect master password");
      expect(note).toBeTruthy();
    });
    expect(callback).not.toHaveBeenCalled();
    expect(q("reprompt-input")).toBeTruthy();
    // A rejected password must not survive in the field: a leftover guess
    // helps a human brute-force the next try.
    expect(q("reprompt-input").value).toBe("");
  });
});
