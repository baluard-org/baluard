import { describe, it, expect } from "vitest";
import { detectCardBrand } from "../lib/utils.js";
// helpers.js re-exports the utils detector; the handler below is the
// helpers-owned surface (imports detectCardBrand/formatCardNumber).
import { handleCardInput } from "../lib/helpers.js";

describe("handleCardInput", () => {
  it("formats, stores raw digits, and detects the brand", () => {
    const stored = {};
    const update = (k, v) => { stored[k] = v; };
    const target = { selectionStart: 0, value: "4111111111111111" };
    handleCardInput(update)({ target });
    expect(target.value).toBe("4111 1111 1111 1111");
    expect(stored.cardNumber).toBe("4111111111111111");
    expect(stored.cardBrand).toBe("Visa");
  });

  it("keeps the last recognized brand when digits shrink", () => {
    const stored = { cardBrand: "Visa" };
    const update = (k, v) => { stored[k] = v; };
    const target = { selectionStart: 0, value: "4111 1" };
    handleCardInput(update)({ target });
    expect(stored.cardBrand).toBe("Visa");
  });
});

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
