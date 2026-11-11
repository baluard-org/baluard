import { describe, it, expect } from "vitest";
import { nextStoredTheme } from "../context/themeSignal.js";

// Pure decision table: the next stored value for every combination of the
// three stored states and both OS preferences. Importing this module in a
// vitest env does not host Solid module-scope signals faithfully, so the
// honest seam is the pure decision, not the signal.
describe("nextStoredTheme decision table", () => {
  it("dark OS (systemIsLight=false)", () => {
    expect(nextStoredTheme("system", false)).toBe("light");
    expect(nextStoredTheme("light", false)).toBe("system"); // target dark == OS: release
    expect(nextStoredTheme("dark", false)).toBe("light");
  });

  it("light OS (systemIsLight=true)", () => {
    expect(nextStoredTheme("system", true)).toBe("dark");
    expect(nextStoredTheme("dark", true)).toBe("system"); // target light == OS: release
    expect(nextStoredTheme("light", true)).toBe("dark");
  });
});
