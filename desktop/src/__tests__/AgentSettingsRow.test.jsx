import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, waitFor, fireEvent, cleanup } from "@solidjs/testing-library";

const mocks = vi.hoisted(() => ({
  setYolo: vi.fn(),
  auditEvents: [
    {
      timestamp_ms: 1735689600000,
      event: "approved",
      exe_path: "/usr/bin/ssh",
      vault: "v",
      item_ids: [],
      outcome: "ok",
    },
  ],
}));

vi.mock("../context/AgentApprovalContext.jsx", () => ({
  useAgentApprovals: () => ({
    yolo: () => false,
    setYolo: mocks.setYolo,
    grants: () => [],
    events: () => mocks.auditEvents,
    refreshAudit: () => {},
  }),
}));

import { I18nProvider } from "../i18n/index.jsx";
import AgentSettingsRow from "../components/AgentSettingsRow.jsx";

describe("AgentSettingsRow yolo checkbox", () => {
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
    mocks.setYolo.mockReset();
  });

  it("reverts to unchecked when the confirmation is cancelled", async () => {
    const utils = render(
      <I18nProvider>
        <AgentSettingsRow />
      </I18nProvider>,
    );
    const box = utils.getByTestId("agent-yolo");
    expect(box.checked).toBe(false);
    fireEvent.click(box);
    // The warning modal opens; cancel it.
    const cancel = await waitFor(() => {
      const buttons = [...document.querySelectorAll("button")];
      const cancel = buttons.find((b) => b.textContent.trim() === "Cancel");
      expect(cancel).toBeTruthy();
      return cancel;
    });
    fireEvent.click(cancel);
    // The modal's exit transition never settles in jsdom; the observable
    // is the checkbox state and that no write was issued.
    expect(box.checked).toBe(false);
    expect(mocks.setYolo).not.toHaveBeenCalled();
  });
});

describe("AgentSettingsRow recent activity", () => {
  beforeEach(() => {
    cleanup();
    const store = new Map();
    globalThis.localStorage = {
      getItem: (k) => store.get(k) ?? null,
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: (k) => store.delete(k),
      clear: () => store.clear(),
    };
  });

  it("shows the event timestamp in the card header", () => {
    const toLocaleString = vi
      .spyOn(Date.prototype, "toLocaleString")
      .mockReturnValue("FORMATTED-TIME");
    const utils = render(
      <I18nProvider>
        <AgentSettingsRow />
      </I18nProvider>,
    );
    const card = utils.getByText("Access approved").closest("div.rounded");
    expect(card).toBeTruthy();
    // Timestamp sits in the same header row as the label, top right.
    const header = card.firstElementChild;
    expect(header.className).toContain("justify-between");
    expect(header.lastElementChild.textContent).toBe("FORMATTED-TIME");
    expect(card.textContent).toContain("/usr/bin/ssh");
    toLocaleString.mockRestore();
  });
});
