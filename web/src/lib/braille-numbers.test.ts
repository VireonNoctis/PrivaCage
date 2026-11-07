import { describe, expect, it } from "vitest";
import { BRAILLE_DIGITS, BRAILLE_NUMBER_SIGN, brailleDigit, braillePunctuation } from "./braille-numbers";

describe("Braille numeric display", () => {
  it("maps all ten decimal digits to the standard Braille digit cells", () => {
    expect(Array.from({ length: 10 }, (_, digit) => brailleDigit(digit))).toEqual(BRAILLE_DIGITS);
  });

  it("uses the Braille numeric indicator before a displayed number", () => {
    expect(BRAILLE_NUMBER_SIGN).toBe("⠼");
  });

  it("uses Braille comma punctuation for grouped counters", () => {
    expect(braillePunctuation(",")).toBe("⠂");
    expect(braillePunctuation(":")).toBe(":");
  });

  it("rejects values that are not one decimal digit", () => {
    expect(() => brailleDigit(-1)).toThrow(RangeError);
    expect(() => brailleDigit(10)).toThrow(RangeError);
    expect(() => brailleDigit(1.5)).toThrow(RangeError);
  });
});
