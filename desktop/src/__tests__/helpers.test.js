import { describe, it, expect } from "vitest";
import { detectCardBrand } from "../lib/utils.js";

describe("detectCardBrand", () => {
  it("maps leading digits to networks", () => {
    expect(detectCardBrand("4111111111111111")).toBe("Visa");
    expect(detectCardBrand("5500005555555559")).toBe("Mastercard");
    expect(detectCardBrand("2223003122003222")).toBe("Mastercard");
    expect(detectCardBrand("378282246310005")).toBe("Amex");
    expect(detectCardBrand("6011111111111117")).toBe("Discover");
    expect(detectCardBrand("3566002020360505")).toBe("JCB");
  });
  it("stays null while unknown or empty", () => {
    expect(detectCardBrand("")).toBeNull();
    expect(detectCardBrand("9")).toBeNull();
  });
});
