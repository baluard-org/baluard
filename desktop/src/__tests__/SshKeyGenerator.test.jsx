// Tests for desktop/src/components/SshKeyGenerator.jsx — pure UI that
// triggers the ssh.generate_key daemon route on button click and renders
// fingerprint/public/private key blocks based on props.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { flush } from "solid-js";

// vi.mock is hoisted to the top of the file, so it must be declared before
// the import bindings that depend on it. Declare all mocks here.
vi.mock("../lib/daemon.js", () => ({ daemon: vi.fn() }));
vi.mock("../context/toastSignal.js", () => ({
  toast: vi.fn(),
  toastSuccess: vi.fn(),
  toastError: vi.fn(),
  toastWarning: vi.fn(),
  toastInfo: vi.fn(),
  dismiss: vi.fn(),
  toasts: { length: 0 },
}));
// i18n: pass-through (echo key) — useI18n is read at render time.
vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({ t: (k, vars) => (vars ? `${k}(${JSON.stringify(vars)})` : k), locale: () => "en", setLocale: vi.fn() }),
  I18nProvider: (props) => props.children,
}));

import { render, fireEvent, waitFor, screen } from "@solidjs/testing-library";
import { daemon } from "../lib/daemon.js";
import { toastSuccess, toastError } from "../context/toastSignal.js";
import SshKeyGenerator from "../components/SshKeyGenerator.jsx";

describe("SshKeyGenerator", () => {
  beforeEach(() => {
    vi.mocked(daemon).mockReset();
    vi.mocked(toastSuccess).mockClear();
    vi.mocked(toastError).mockClear();
  });

  it("renders the generate button + key-type selector by default", () => {
    const { getByText } = render(() => <SshKeyGenerator />);
    expect(getByText("entry.sshKeyEd25519")).toBeTruthy();
    expect(getByText("entry.sshKeyEcdsa256")).toBeTruthy();
    expect(getByText("entry.sshGenerateKey")).toBeTruthy();
  });

  it("clicking generate calls daemon with the selected key type", async () => {
    vi.mocked(daemon).mockResolvedValue(
      JSON.stringify({
        public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test",
        private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----",
        fingerprint: "SHA256:abcdef",
      }),
    );
    const onGenerated = vi.fn();
    const { getByText } = render(() => <SshKeyGenerator onGenerated={onGenerated} />);

    fireEvent.click(getByText("entry.sshKeyEcdsa256"));
    flush();
    fireEvent.click(getByText("entry.sshGenerateKey"));
    flush();

    await waitFor(() => expect(daemon).toHaveBeenCalledTimes(1));
    expect(daemon).toHaveBeenCalledWith(
      "ssh.generate_key",
      JSON.stringify({ type: "ecdsa256" }),
    );
    await waitFor(() => expect(onGenerated).toHaveBeenCalledWith({
      publicKey: expect.stringContaining("ssh-ed25519"),
      privateKey: expect.stringContaining("OPENSSH PRIVATE KEY"),
      fingerprint: "SHA256:abcdef",
    }));
    expect(toastSuccess).toHaveBeenCalledWith("entry.sshKeyGenerated");
  });

  it("toast-error on daemon failure (e.g. biometric-only key type rejected)", async () => {
    vi.mocked(daemon).mockRejectedValue(new Error("Unknown SSH key type"));
    const { getByText } = render(() => <SshKeyGenerator />);

    fireEvent.click(getByText("entry.sshGenerateKey"));
    flush();

    await waitFor(() => expect(toastError).toHaveBeenCalled());
  });

  it("does NOT call onGenerated when daemon fails", async () => {
    vi.mocked(daemon).mockRejectedValue(new Error("boom"));
    const onGenerated = vi.fn();
    const { getByText } = render(() => <SshKeyGenerator onGenerated={onGenerated} />);

    fireEvent.click(getByText("entry.sshGenerateKey"));
    flush();
    await waitFor(() => expect(toastError).toHaveBeenCalled());
    expect(onGenerated).not.toHaveBeenCalled();
  });

  it("renders fingerprint + public key blocks when provided via props", () => {
    const { getByText } = render(() => (
      <SshKeyGenerator
        fingerprint="SHA256:abc123"
        publicKey="ssh-ed25519 AAAAC3Nz test"
      />
    ));
    expect(getByText("SHA256:abc123")).toBeTruthy();
    expect(getByText("ssh-ed25519 AAAAC3Nz test")).toBeTruthy();
  });

  it("renders the private key warning block when privateKey prop is set", () => {
    const { container } = render(() => (
      <SshKeyGenerator privateKey="-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----" />
    ));
    // The block is gated behind <details> with "Show private key" summary.
    expect(container.textContent).toContain("Private Key");
    expect(container.textContent).toContain("Show private key");
  });

  it("does NOT render key blocks when no props provided", () => {
    const { container } = render(() => <SshKeyGenerator />);
    expect(container.textContent).not.toContain("Fingerprint");
    expect(container.textContent).not.toContain("Public Key");
  });
});