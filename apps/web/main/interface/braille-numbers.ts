export const BRAILLE_DIGITS = ["⠚", "⠁", "⠃", "⠉", "⠙", "⠑", "⠋", "⠛", "⠓", "⠊"] as const;
export const BRAILLE_NUMBER_SIGN = "⠼";

export function brailleDigit(value: number): string {
  if (!Number.isInteger(value) || value < 0 || value > 9) {
    throw new RangeError("Braille digit conversion accepts one decimal digit.");
  }
  return BRAILLE_DIGITS[value];
}

export function braillePunctuation(value: string): string {
  if (value === ",") return "⠂";
  return value;
}
