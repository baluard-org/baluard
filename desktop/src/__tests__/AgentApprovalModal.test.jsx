import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, fireEvent, waitFor, cleanup } from "@solidjs/testing-library";
import { flush } from "solid-js";
import AgentApprovalModal from "../components/AgentApprovalModal.jsx";

vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({ t: (key) => key }),
}));

const request = {
  request_id: "req-1",
  claimed_name: "Local agent",
  exe_path: "/usr/bin/local-agent",
  need: "GitHub deployment",
  item_ids: ["item-1", "item-2"],
};

describe("AgentApprovalModal", () => {
  beforeEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("shows the actual requester and approved item names", async () => {
    const screen = render(() => (
      <AgentApprovalModal
        request={request}
        requests={[request]}
        itemName={(id) => ({ "item-1": "GitHub", "item-2": "Deploy key" })[id] || id}
        onApprove={vi.fn()}
        onDeny={vi.fn()}
        onApproveAll={vi.fn()}
      />
    ));
    await waitFor(() => expect(document.querySelector('[data-testid="agent-approve"]')).toBeTruthy());
    expect(document.body.textContent).toContain("/usr/bin/local-agent");
    expect(document.body.textContent).toContain("GitHub deployment");
    expect(document.body.textContent).toContain("GitHub");
    expect(document.body.textContent).toContain("Deploy key");
    expect(document.querySelector('[data-testid="agent-approve-all"]')).toBeNull();
  });

  it("escape does not deny the pending request", async () => {
    const onDeny = vi.fn();
    render(() => (
      <AgentApprovalModal
        request={request}
        requests={[request]}
        itemName={(id) => id}
        onApprove={vi.fn()}
        onDeny={onDeny}
        onApproveAll={vi.fn()}
      />
    ));
    await waitFor(() => expect(document.querySelector('[data-testid="agent-deny"]')).toBeTruthy());
    // FocusTrap binds Escape on its container; the key event must bubble
    // from inside it.
    const denyButton = document.querySelector('[data-testid="agent-deny"]');
    await fireEvent.keyDown(denyButton, { key: "Escape" });
    flush();
    expect(onDeny).not.toHaveBeenCalled();
    // Explicit denial still works.
    await fireEvent.click(document.querySelector('[data-testid="agent-deny"]'));
    flush();
    expect(onDeny).toHaveBeenCalledWith("req-1");
  });

  it("emits approve and deny without any password field", async () => {
    const onApprove = vi.fn();
    const onDeny = vi.fn();
    const screen = render(() => (
      <AgentApprovalModal
        request={request}
        requests={[request]}
        itemName={(id) => id}
        onApprove={onApprove}
        onDeny={onDeny}
        onApproveAll={vi.fn()}
      />
    ));
    await waitFor(() => expect(document.querySelector('[data-testid="agent-approve"]')).toBeTruthy());
    expect(screen.queryByRole("textbox", { type: "password" })).toBeNull();
    await fireEvent.click(document.querySelector('[data-testid="agent-approve"]'));
    await fireEvent.click(document.querySelector('[data-testid="agent-deny"]'));
    flush();
    expect(onApprove).toHaveBeenCalledWith("req-1");
    expect(onDeny).toHaveBeenCalledWith("req-1");
  });

  it("offers batch approval only for multiple pending requests", async () => {
    const onApproveAll = vi.fn();
    const second = { ...request, request_id: "req-2" };
    const screen = render(() => (
      <AgentApprovalModal
        request={request}
        requests={[request, second]}
        itemName={(id) => id}
        onApprove={vi.fn()}
        onDeny={vi.fn()}
        onApproveAll={onApproveAll}
      />
    ));
    await waitFor(() => expect(document.querySelector('[data-testid="agent-approve-all"]')).toBeTruthy());
    await fireEvent.click(document.querySelector('[data-testid="agent-approve-all"]'));
    flush();
    expect(onApproveAll).toHaveBeenCalledOnce();
  });
});
