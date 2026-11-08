// DetachVaultModal: the destructive arms must gate on a credential and
// never send one on the safe arm. The daemon re-verifies everything;
// this suite pins the payload contract and the local required-field
// behavior.
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, fireEvent, cleanup } from "@solidjs/testing-library";
import DetachVaultModal from "../components/DetachVaultModal.jsx";

vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({ t: (key, p) => key }),
}));

const vault = {
  slug: "dev-vault",
  display_name: "dev-vault",
  path: "/tmp/dev-vault",
  provider: "github",
  remote_url: "https://github.com/esteban/dev-vault.git",
};

function lastPayloadOf(onConfirm) {
  return onConfirm.mock.calls.at(-1)?.[0];
}

describe("DetachVaultModal", () => {
  beforeEach(() => {
    cleanup();
  });

  it("safe arm sends only the slug", async () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    const { getByText, unmount } = render(() => (
      <DetachVaultModal show={true} setShow={() => {}} vault={vault} onConfirm={onConfirm} />
    ));
    fireEvent.click(getByText("vault.vaultSwitcher.detachSubmit"));
    await Promise.resolve();
    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(lastPayloadOf(onConfirm)).toEqual({ slug: "dev-vault" });
    unmount();
  });

  it("delete-from-device checkbox reveals the credential step and sends it", async () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    const { getByText, container, unmount } = render(() => (
      <DetachVaultModal show={true} setShow={() => {}} vault={vault} onConfirm={onConfirm} />
    ));
    // No credential UI before a destructive arm is chosen.
    expect(container.querySelector('input[name="detach-cred-kind"]')).toBeNull();

    const checkboxes = container.querySelectorAll('input[type="checkbox"]');
    fireEvent.click(checkboxes[0]); // delete from this device
    await Promise.resolve();

    const radios = container.querySelectorAll('input[name="detach-cred-kind"]');
    expect(radios.length).toBe(2);
    const inputs = container.querySelectorAll('input[type="password"]');
    fireEvent.input(inputs[0], { target: { value: "master-pw" } });
    await Promise.resolve();

    fireEvent.click(getByText("vault.vaultSwitcher.deleteSubmit"));
    await Promise.resolve();
    expect(lastPayloadOf(onConfirm)).toEqual({
      slug: "dev-vault",
      delete_from_disk: true,
      delete_remote: false,
      confirm: { kind: "password", value: "master-pw" },
    });
    unmount();
  });

  it("remote toggle requires a credential and sends delete_remote", async () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    const { getByText, container, unmount } = render(() => (
      <DetachVaultModal show={true} setShow={() => {}} vault={vault} onConfirm={onConfirm} />
    ));
    const checkboxes = container.querySelectorAll('input[type="checkbox"]');
    fireEvent.click(checkboxes[1]); // also delete the repository
    await Promise.resolve();
    // The remote arm is phrase-only: the kind radios disappear and the
    // note explains why.
    expect(
      container.querySelectorAll('input[name="detach-cred-kind"]').length
    ).toBe(0);
    expect(
      document.body.textContent
    ).toContain("vault.vaultSwitcher.verifyPhraseOnly");
    const inputs = container.querySelectorAll('input[type="password"]');
    fireEvent.input(inputs[0], { target: { value: "wrong" } });
    await Promise.resolve();

    fireEvent.click(getByText("vault.vaultSwitcher.deleteSubmit"));
    await Promise.resolve();
    expect(lastPayloadOf(onConfirm)).toEqual({
      slug: "dev-vault",
      delete_from_disk: false,
      delete_remote: true,
      confirm: { kind: "phrase", value: "wrong" },
    });
    unmount();
  });

  it("checking the remote toggle next to device-delete forces the phrase kind", async () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    const { getByText, container, unmount } = render(() => (
      <DetachVaultModal show={true} setShow={() => {}} vault={vault} onConfirm={onConfirm} />
    ));
    const checkboxes = container.querySelectorAll('input[type="checkbox"]');
    fireEvent.click(checkboxes[0]); // delete from this device (password default)
    await Promise.resolve();
    expect(
      container.querySelectorAll('input[name="detach-cred-kind"]').length
    ).toBe(2);
    fireEvent.click(checkboxes[1]); // also delete the repository
    await Promise.resolve();
    expect(
      container.querySelectorAll('input[name="detach-cred-kind"]').length
    ).toBe(0);
    const inputs = container.querySelectorAll('input[type="password"]');
    fireEvent.input(inputs[0], { target: { value: "phrase-words" } });
    await Promise.resolve();

    fireEvent.click(getByText("vault.vaultSwitcher.deleteSubmit"));
    await Promise.resolve();
    expect(lastPayloadOf(onConfirm)).toEqual({
      slug: "dev-vault",
      delete_from_disk: true,
      delete_remote: true,
      confirm: { kind: "phrase", value: "phrase-words" },
    });
    unmount();
  });

  it("destructive submit without a credential shows the required error and never calls the daemon", async () => {
    const onConfirm = vi.fn();
    const { getByText, container, unmount } = render(() => (
      <DetachVaultModal show={true} setShow={() => {}} vault={vault} onConfirm={onConfirm} />
    ));
    const checkboxes = container.querySelectorAll('input[type="checkbox"]');
    fireEvent.click(checkboxes[0]);
    await Promise.resolve();
    fireEvent.click(getByText("vault.vaultSwitcher.deleteSubmit"));
    await Promise.resolve();
    expect(onConfirm).not.toHaveBeenCalled();
    expect(document.body.textContent).toContain("vault.vaultSwitcher.verifyRequired");
    unmount();
  });

  it("a failed confirm surfaces the daemon error and keeps the modal open", async () => {
    const onConfirm = vi.fn().mockRejectedValue(new Error("verification failed: nope"));
    const { getByText, unmount } = render(() => (
      <DetachVaultModal show={true} setShow={() => {}} vault={vault} onConfirm={onConfirm} />
    ));
    fireEvent.click(getByText("vault.vaultSwitcher.detachSubmit"));
    await new Promise((r) => setTimeout(r, 0));
    expect(document.body.textContent).toContain("verification failed: nope");
    unmount();
  });

  it("vaults without a connected provider get no remote toggle", () => {
    const onConfirm = vi.fn();
    const { container, unmount } = render(() => (
      <DetachVaultModal
        show={true}
        setShow={() => {}}
        vault={{ ...vault, provider: null, remote_url: null }}
        onConfirm={onConfirm}
      />
    ));
    expect(container.querySelectorAll('input[type="checkbox"]').length).toBe(1);
    unmount();
  });
});
