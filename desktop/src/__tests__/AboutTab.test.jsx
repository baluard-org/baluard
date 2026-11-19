import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup } from "@solidjs/testing-library";

const { updaterStatus, invoke } = vi.hoisted(() => ({
  updaterStatus: vi.fn(),
  invoke: vi.fn(),
}));

vi.mock("../lib/update.js", () => ({
  updaterStatus: (...a) => updaterStatus(...a),
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...a) => invoke(...a),
}));

vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({ t: (key) => key }),
}));

import AboutTab from "../components/AboutTab.jsx";

describe("AboutTab", () => {
  beforeEach(() => {
    updaterStatus.mockReset();
    invoke.mockReset();
  });
  afterEach(() => cleanup());

  it("shows the installed version once the status lands", async () => {
    updaterStatus.mockResolvedValue({ configured: true, channel: "stable", version: "0.5.2" });
    render(() => <AboutTab />);
    await screen.findByText("Baluard v0.5.2");
    expect(screen.getByText("settings.aboutTitle")).toBeTruthy();
  });

  it("keeps rendering without a version when the status call fails", async () => {
    updaterStatus.mockRejectedValue(new Error("boom"));
    render(() => <AboutTab />);
    expect(screen.getByText("settings.aboutTitle")).toBeTruthy();
    expect(screen.queryByText(/Baluard v/)).toBeNull();
  });

  it("shows the running daemon version next to the app version", async () => {
    updaterStatus.mockResolvedValue({ version: "0.5.2" });
    invoke.mockResolvedValue({ version: "0.7.4", expected: "0.7.4", matches: true });
    render(() => <AboutTab />);
    await screen.findByText("Baluard v0.5.2");
    expect(screen.getByTestId("about-daemon").textContent).toBe("settings.aboutDaemon v0.7.4");
  });

  it("hides the daemon line when the daemon does not answer", async () => {
    updaterStatus.mockResolvedValue({ version: "0.5.2" });
    invoke.mockRejectedValue(new Error("no daemon"));
    render(() => <AboutTab />);
    await screen.findByText("Baluard v0.5.2");
    expect(screen.queryByTestId("about-daemon")).toBeNull();
  });

  it("hides the daemon line on an empty handshake version", async () => {
    updaterStatus.mockResolvedValue({ version: "0.5.2" });
    invoke.mockResolvedValue({ version: "", expected: "0.7.4", matches: false });
    render(() => <AboutTab />);
    await screen.findByText("Baluard v0.5.2");
    expect(screen.queryByTestId("about-daemon")).toBeNull();
  });
});
