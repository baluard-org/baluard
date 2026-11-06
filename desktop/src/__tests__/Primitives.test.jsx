import { describe, expect, it } from "vitest";
import { render } from "@solidjs/testing-library";
import { Button } from "../components/Primitives.jsx";

describe("Button accessibility", () => {
  it("forwards disclosure relationships to the native button", () => {
    const rendered = render(() => (
      <Button aria-expanded={true} aria-controls="details">Show details</Button>
    ));
    const button = rendered.getByRole("button", { name: "Show details" });
    expect(button.getAttribute("aria-expanded")).toBe("true");
    expect(button.getAttribute("aria-controls")).toBe("details");
  });
});
