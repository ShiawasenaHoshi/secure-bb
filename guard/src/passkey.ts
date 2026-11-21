// WebAuthn on node:crypto, nothing else: the minimum of CBOR (an attestationObject and a COSE key: maps, arrays, integers, byte and text
// strings, simple values), the authenticator data layout, and ES256 (ECDSA over P-256 with SHA-256) verification.
//
// What is supported is exactly what the guard asks the browser for: `attestation: "none"` and the ES256 algorithm. Anything else
// (another key type, another curve, an attestation statement the guard did not ask for) is refused, not interpreted.
import { createHash, createPublicKey, randomBytes, verify, type KeyObject } from "node:crypto";

export class PasskeyError extends Error {}

// ---- base64url -------------------------------------------------------------------------------------------------
export const b64u = (b: Uint8Array): string => Buffer.from(b).toString("base64url");
export function fromB64u(v: unknown, name: string, max = 16 * 1024): Buffer {
  if (typeof v !== "string" || v.length === 0 || v.length > max || !/^[A-Za-z0-9_-]+$/.test(v)) throw new PasskeyError(`${name} must be base64url`);
  return Buffer.from(v, "base64url");
}
export const sha256 = (b: Uint8Array | string): Buffer => createHash("sha256").update(b).digest();

// ---- CBOR (RFC 8949), decoding only ----------------------------------------------------------------------------
export type Cbor = number | bigint | string | Buffer | boolean | null | undefined | Cbor[] | Map<Cbor, Cbor>;

const MAX_DEPTH = 8;
const MAX_ITEMS = 256;

/** Decodes one CBOR item; the whole input must be that one item (trailing bytes are an error). Indefinite lengths and tags are not accepted. */
export function cborDecode(buf: Uint8Array): Cbor {
  const b = Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength);
  const [value, end] = item(b, 0, 0);
  if (end !== b.length) throw new PasskeyError("CBOR: trailing bytes");
  return value;
}

/** Like `cborDecode`, but returns the end of the first item: the authenticator data carries a COSE key and then possibly extensions. */
export function cborDecodePrefix(buf: Buffer, offset: number): { value: Cbor; end: number } {
  const [value, end] = item(buf, offset, 0);
  return { value, end };
}

function head(b: Buffer, at: number): { major: number; arg: number | bigint; next: number } {
  if (at >= b.length) throw new PasskeyError("CBOR: truncated");
  const major = b[at]! >> 5;
  const info = b[at]! & 31;
  if (info < 24) return { major, arg: info, next: at + 1 };
  const size = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : 0;
  if (size === 0) throw new PasskeyError("CBOR: indefinite lengths and reserved values are not accepted");
  if (at + 1 + size > b.length) throw new PasskeyError("CBOR: truncated");
  const arg = size === 1 ? b[at + 1]! : size === 2 ? b.readUInt16BE(at + 1) : size === 4 ? b.readUInt32BE(at + 1) : b.readBigUInt64BE(at + 1);
  return { major, arg, next: at + 1 + size };
}

function item(b: Buffer, at: number, depth: number): [Cbor, number] {
  if (depth > MAX_DEPTH) throw new PasskeyError("CBOR: nested too deep");
  const { major, arg, next } = head(b, at);
  const small = (): number => {
    if (typeof arg !== "number" || arg > 1 << 20) throw new PasskeyError("CBOR: length too large");
    return arg;
  };
  switch (major) {
    case 0:
      return [typeof arg === "bigint" ? arg : arg, next];
    case 1:
      return [typeof arg === "bigint" ? -1n - arg : -1 - arg, next];
    case 2:
    case 3: {
      const n = small();
      if (next + n > b.length) throw new PasskeyError("CBOR: truncated");
      const raw = b.subarray(next, next + n);
      return [major === 2 ? Buffer.from(raw) : raw.toString("utf8"), next + n];
    }
    case 4: {
      const n = small();
      if (n > MAX_ITEMS) throw new PasskeyError("CBOR: too many items");
      const out: Cbor[] = [];
      let p = next;
      for (let i = 0; i < n; i++) {
        const [v, e] = item(b, p, depth + 1);
        out.push(v);
        p = e;
      }
      return [out, p];
    }
    case 5: {
      const n = small();
      if (n > MAX_ITEMS) throw new PasskeyError("CBOR: too many items");
      const out = new Map<Cbor, Cbor>();
      let p = next;
      for (let i = 0; i < n; i++) {
        const [k, e1] = item(b, p, depth + 1);
        const [v, e2] = item(b, e1, depth + 1);
        if (out.has(k)) throw new PasskeyError("CBOR: duplicate map key");
        out.set(k, v);
        p = e2;
      }
      return [out, p];
    }
    case 7:
      if (arg === 20) return [false, next];
      if (arg === 21) return [true, next];
      if (arg === 22) return [null, next];
      if (arg === 23) return [undefined, next];
      throw new PasskeyError("CBOR: floats and other simple values are not accepted");
    default:
      throw new PasskeyError("CBOR: tags are not accepted");
  }
}

// ---- authenticator data ----------------------------------------------------------------------------------------
export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_AT = 0x40;
export const FLAG_ED = 0x80;

export interface AuthData {
  rpIdHash: Buffer;
  flags: number;
  signCount: number;
  /** Present when the AT flag is set (registration). */
  attested: { aaguid: Buffer; credentialId: Buffer; publicKeySpki: Buffer } | null;
}

export function parseAuthData(data: Buffer): AuthData {
  if (data.length < 37) throw new PasskeyError("authenticator data is too short");
  const flags = data[32]!;
  const out: AuthData = { rpIdHash: data.subarray(0, 32), flags, signCount: data.readUInt32BE(33), attested: null };
  if ((flags & FLAG_AT) !== 0) {
    if (data.length < 55) throw new PasskeyError("attested credential data is truncated");
    const aaguid = data.subarray(37, 53);
    const idLen = data.readUInt16BE(53);
    if (idLen < 16 || idLen > 1023 || 55 + idLen > data.length) throw new PasskeyError("credential id has an impossible length");
    const credentialId = Buffer.from(data.subarray(55, 55 + idLen));
    const { value, end } = cborDecodePrefix(data, 55 + idLen);
    // After the key only extension data may follow, and only if the ED flag says so.
    if (end !== data.length && (flags & FLAG_ED) === 0) throw new PasskeyError("authenticator data has bytes the flags do not explain");
    out.attested = { aaguid: Buffer.from(aaguid), credentialId, publicKeySpki: coseToSpki(value) };
  } else if (data.length !== 37 && (flags & FLAG_ED) === 0) throw new PasskeyError("authenticator data has bytes the flags do not explain");
  return out;
}

/** A COSE_Key for ES256 (kty 2 = EC2, alg -7, crv 1 = P-256, x, y of 32 bytes) → the SPKI DER that node:crypto takes. Anything else is refused. */
export function coseToSpki(v: Cbor): Buffer {
  if (!(v instanceof Map)) throw new PasskeyError("the public key is not a COSE map");
  const kty = v.get(1);
  const alg = v.get(3);
  const crv = v.get(-1);
  const x = v.get(-2);
  const y = v.get(-3);
  if (kty !== 2 || alg !== -7 || crv !== 1) throw new PasskeyError("only ES256 keys on P-256 are accepted");
  if (!Buffer.isBuffer(x) || !Buffer.isBuffer(y) || x.length !== 32 || y.length !== 32) throw new PasskeyError("the public key coordinates are malformed");
  const key = createPublicKey({ key: { kty: "EC", crv: "P-256", x: x.toString("base64url"), y: y.toString("base64url") }, format: "jwk" });
  return key.export({ type: "spki", format: "der" });
}

export const keyFromSpki = (spki: Buffer): KeyObject => createPublicKey({ key: spki, format: "der", type: "spki" });

/** `attestation: "none"`: the object is {fmt: "none", attStmt: {}, authData}. A statement the guard did not ask for is not looked at, so it is refused. */
export function parseAttestationObject(raw: Buffer): AuthData & { authDataRaw: Buffer } {
  const o = cborDecode(raw);
  if (!(o instanceof Map)) throw new PasskeyError("the attestation object is not a map");
  if (o.get("fmt") !== "none") throw new PasskeyError('only attestation "none" is accepted');
  const stmt = o.get("attStmt");
  if (!(stmt instanceof Map) || stmt.size !== 0) throw new PasskeyError('attestation "none" has an empty statement');
  const authData = o.get("authData");
  if (!Buffer.isBuffer(authData)) throw new PasskeyError("the attestation object has no authenticator data");
  return { ...parseAuthData(authData), authDataRaw: authData };
}

/** ES256 over authData ‖ SHA-256(clientDataJSON); the signature is ASN.1 DER, as WebAuthn defines it. Never throws: a malformed signature is a failed one. */
export function verifyEs256(spki: Buffer, authData: Buffer, clientDataJSON: Buffer, signature: Buffer): boolean {
  try {
    return verify("sha256", Buffer.concat([authData, sha256(clientDataJSON)]), { key: keyFromSpki(spki), dsaEncoding: "der" }, signature);
  } catch {
    return false;
  }
}

export interface ClientData {
  type: string;
  challenge: string;
  origin: string;
  crossOrigin: boolean;
}
export function parseClientData(raw: Buffer): ClientData {
  let j: unknown;
  try {
    j = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new PasskeyError("clientDataJSON is not JSON");
  }
  if (typeof j !== "object" || j === null) throw new PasskeyError("clientDataJSON is not an object");
  const o = j as Record<string, unknown>;
  if (typeof o.type !== "string" || typeof o.challenge !== "string" || typeof o.origin !== "string") throw new PasskeyError("clientDataJSON lacks type, challenge or origin");
  return { type: o.type, challenge: o.challenge, origin: o.origin, crossOrigin: o.crossOrigin === true };
}

export const newNonce = (): Buffer => randomBytes(32);

/** A short readable one-time token for the console: 12 characters of an alphabet without look-alikes (60 bits), shown as XXXX-XXXX-XXXX. */
const TOKEN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
export function newToken(): string {
  const bytes = randomBytes(12);
  let s = "";
  // 256 is a multiple of 32: every byte maps to the alphabet without bias.
  for (const x of bytes) s += TOKEN_ALPHABET[x % 32];
  return `${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}`;
}
export const normalizeToken = (t: string): string => t.replace(/[\s-]/g, "").toUpperCase();
export const tokenDigest = (t: string): string => sha256(`sbb-guard passkey enrollment\0${normalizeToken(t)}`).toString("hex");
