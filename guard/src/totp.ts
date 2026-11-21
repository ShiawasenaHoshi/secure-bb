// RFC 6238 TOTP on node:crypto — HMAC-SHA1, 6 digits, 30 s step, window ±1.
// Same arithmetic as the plugin's src/totp.ts (a test compares them); copied, not imported:
// the guard is installed on its own, root-owned, and must not read code from the plugin.
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export const TOTP_STEP_SEC = 30;
export const TOTP_DIGITS = 6;
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text: string): Buffer {
  const clean = text.toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error("invalid base32 secret");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function generateSecret(): string {
  return base32Encode(randomBytes(20));
}

export function hotp(secret: Buffer, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", secret).update(msg).digest();
  const offset = mac[mac.length - 1]! & 15;
  const bin = ((mac[offset]! & 127) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return String(bin % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, "0");
}

export const stepAt = (nowMs: number): number => Math.floor(nowMs / 1000 / TOTP_STEP_SEC);

export type TotpCheck = { ok: true; step: number } | { ok: false };

/** Accepts steps now-1..now+1 and refuses any step <= lastUsedStep: a code (or an older one) is never accepted twice. */
export function verifyTotp(secretB32: string, code: string, nowMs: number, lastUsedStep: number): TotpCheck {
  if (!/^\d{6}$/.test(code)) return { ok: false };
  const secret = base32Decode(secretB32);
  const current = stepAt(nowMs);
  let matched: number | null = null;
  for (const step of [current - 1, current, current + 1]) {
    const expected = Buffer.from(hotp(secret, step));
    const given = Buffer.from(code);
    // Every candidate is evaluated: timing must not reveal which step matched.
    if (timingSafeEqual(expected, given) && step > lastUsedStep && matched === null) matched = step;
  }
  return matched === null ? { ok: false } : { ok: true, step: matched };
}

export function otpauthUri(secretB32: string, issuer = "secure-bb-guard", account = "bb"): string {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secretB32}&issuer=${encodeURIComponent(issuer)}`;
}
