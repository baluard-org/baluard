// Tests for MarkdownContent.jsx — link click interception: only
// browser-safe schemes (http/https/mailto) reach the Tauri opener;
// everything else is refused in place.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, fireEvent, cleanup } from "@solidjs/testing-library";
import MarkdownContent from "../components/MarkdownContent.jsx";

vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({ t: (k) => k }),
}));

const openUrlMock = vi.fn().mockResolvedValue(undefined);
vi.mock("@tauri-apps/plugin-opener", () => ({ openUrl: (...a) => openUrlMock(...a) }));

const toastErrorMock = vi.fn();
vi.mock("../context/toastSignal.js", () => ({ toastError: (...a) => toastErrorMock(...a) }));

describe("MarkdownContent link interception", () => {
  beforeEach(() => {
    openUrlMock.mockClear();
    toastErrorMock.mockClear();
    cleanup();
  });

  it("opens https links through the opener", async () => {
    const { container } = render(() => <MarkdownContent text="[x](https://example.com)" />);
    fireEvent.click(container.querySelector("a"));
    await vi.waitFor(() => expect(openUrlMock).toHaveBeenCalledWith("https://example.com"));
  });

  it("opens mailto links through the opener", async () => {
    const { container } = render(() => <MarkdownContent text="[x](mailto:a@b.c)" />);
    fireEvent.click(container.querySelector("a"));
    await vi.waitFor(() => expect(openUrlMock).toHaveBeenCalledWith("mailto:a@b.c"));
  });

  it("refuses tel: links (never reaches the opener)", async () => {
    // DOMPurify lets tel: through by URI policy; the click gate must stop it.
    const { container } = render(() => <MarkdownContent text="[x](tel:+123)" />);
    const a = container.querySelector("a");
    expect(a.getAttribute("href")).toBe("tel:+123");
    fireEvent.click(a);
    expect(openUrlMock).not.toHaveBeenCalled();
  });

  it("refuses relative/junk hrefs", () => {
    const { container } = render(() => (
      // innerHTML source is our own sanitizer; feed a div link directly
      <MarkdownContent text="plain" />
    ));
    container.querySelector("div").innerHTML = '<a href="not-a-url">x</a>';
    fireEvent.click(container.querySelector("a"));
    expect(openUrlMock).not.toHaveBeenCalled();
  });

  it("toasts when the opener fails", async () => {
    openUrlMock.mockRejectedValueOnce(new Error("no handler"));
    const { container } = render(() => <MarkdownContent text="[x](https://example.com)" />);
    fireEvent.click(container.querySelector("a"));
    await vi.waitFor(() => expect(toastErrorMock).toHaveBeenCalled());
  });
});
