import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { encodeQr } from "../src/qr.js";

function reference(text: string): boolean[][] | null {
  try {
    const out = execFileSync("qrencode", ["-8", "-t", "ASCII", "-l", "M", "-m", "0", "-s", "1", text], {
      encoding: "utf8",
    });
    // ASCII output doubles each module horizontally ("##" = dark).
    return out
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line) => {
        const row: boolean[] = [];
        for (let i = 0; i < line.length; i += 2) row.push(line[i] === "#");
        return row;
      });
  } catch {
    return null; // qrencode is not installed: skip the cross-check
  }
}

const SAMPLES = [
  "hi",
  "otpauth://totp/secure-bb:bb?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=secure-bb",
  "x".repeat(120), // version 7: version-info blocks
  "y".repeat(200), // version 10: two block sizes
];

describe("qr encoder", () => {
  for (const text of SAMPLES) {
    it(`matches qrencode for a ${text.length}-char payload under some mask`, () => {
      const ref = reference(text);
      if (ref === null) return;
      const matches = [0, 1, 2, 3, 4, 5, 6, 7].some((mask) => {
        const mine = encodeQr(text, mask);
        return (
          mine.length === ref.length &&
          mine.every((row, y) => row.every((cell, x) => cell === ref[y]![x]))
        );
      });
      expect(matches).toBe(true);
    });
  }

  it("picks a valid mask automatically", () => {
    const m = encodeQr(SAMPLES[1]!);
    expect(m.length).toBe(m[0]!.length);
  });
});
