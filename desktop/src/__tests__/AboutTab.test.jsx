import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup } from "@solidjs/testing-library";

const { updaterStatus } = vi.hoisted(() => ({ updaterStatus: vi.fn() }));

vi.mock("../lib/update.js", () => ({
  updaterStatus: (...a) => updaterStatus(...a),
}));

vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({ t: (key) => key }),
}));

import AboutTab from "../components/AboutTab.jsx";

describe("AboutTab", () => {
  beforeEach(() => {
    updaterStatus.mockReset();
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
});
