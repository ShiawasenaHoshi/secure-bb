// A software authenticator for the tests: a P-256 key from node:crypto, and the bytes a browser would hand back
// (authenticatorData, clientDataJSON, attestationObject with `fmt: none`, ASN.1 DER ES256 signatures). The CBOR encoder is written here,
// independently of the guard's decoder, so a mistake in one does not hide a mistake in the other.
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";

const sha = (b: Buffer | string): Buffer => createHash("sha256").update(b).digest();
const b64u = (b: Buffer): string => b.toString("base64url");

// ---- CBOR encoder (just what an attestation object needs) ----
function head(major: number, n: number): Buffer {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  const b = Buffer.alloc(3);
  b[0] = (major << 5) | 25;
  b.writeUInt16BE(n, 1);
  return b;
}
export type Enc = number | string | Buffer | Map<Enc, Enc>;
export function cbor(v: Enc): Buffer {
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === "string") return Buffer.concat([head(3, Buffer.byteLength(v)), Buffer.from(v)]);
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  const parts: Buffer[] = [head(5, v.size)];
  for (const [k, x] of v) parts.push(cbor(k), cbor(x));
  return Buffer.concat(parts);
}

export const FLAGS = { UP: 0x01, UV: 0x04, AT: 0x40 };

export interface Overrides {
  /** What the browser would put in clientData.origin (a page somewhere else). */
  origin?: string;
  /** The RP ID the authenticator signs for. */
  rpId?: string;
  /** Flags to set; default UP | UV. */
  flags?: number;
  signCount?: number;
  type?: string;
  /** Sign something else than what is sent (a corrupted signature). */
  corrupt?: boolean;
  crossOrigin?: boolean;
}

export interface Assertion {
  credentialId: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
}

export class SoftAuthenticator {
  readonly credentialId = randomBytes(32);
  readonly aaguid = Buffer.alloc(16, 7);
  signCount: number;
  private readonly priv: KeyObject;
  private readonly x: Buffer;
  private readonly y: Buffer;
  readonly rpId: string;
  readonly origin: string;

  constructor(opts: { rpId?: string; origin?: string; signCount?: number } = {}) {
    this.rpId = opts.rpId ?? "localhost";
    this.origin = opts.origin ?? "http://localhost:38886";
    this.signCount = opts.signCount ?? 0;
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.priv = privateKey;
    const jwk = publicKey.export({ format: "jwk" });
    this.x = Buffer.from(jwk.x!, "base64url");
    this.y = Buffer.from(jwk.y!, "base64url");
  }

  private coseKey(): Buffer {
    return cbor(new Map<Enc, Enc>([[1, 2], [3, -7], [-1, 1], [-2, this.x], [-3, this.y]]));
  }

  private authData(o: Overrides, withKey: boolean): Buffer {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(o.signCount ?? this.signCount);
    const flags = (o.flags ?? FLAGS.UP | FLAGS.UV) | (withKey ? FLAGS.AT : 0);
    const head = Buffer.concat([sha(o.rpId ?? this.rpId), Buffer.from([flags]), counter]);
    if (!withKey) return head;
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(this.credentialId.length);
    return Buffer.concat([head, this.aaguid, idLen, this.credentialId, this.coseKey()]);
  }

  private clientData(type: string, challenge: string, o: Overrides): Buffer {
    return Buffer.from(JSON.stringify({ type: o.type ?? type, challenge, origin: o.origin ?? this.origin, crossOrigin: o.crossOrigin ?? false }));
  }

  /** `navigator.credentials.create` with the options the guard returned. */
  create(options: { challenge: string }, o: Overrides = {}): { clientDataJSON: string; attestationObject: string } {
    const authData = this.authData(o, true);
    const attestation = cbor(new Map<Enc, Enc>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
    return { clientDataJSON: b64u(this.clientData("webauthn.create", options.challenge, o)), attestationObject: b64u(attestation) };
  }

  /** `navigator.credentials.get` for a challenge the guard issued. The counter goes up by one unless overridden. */
  get(challenge: string, o: Overrides = {}): Assertion {
    if (o.signCount === undefined && this.signCount > 0) this.signCount++;
    const authData = this.authData(o, false);
    const cdj = this.clientData("webauthn.get", challenge, o);
    const sig = sign("sha256", Buffer.concat([authData, sha(cdj)]), { key: this.priv, dsaEncoding: "der" });
    if (o.corrupt) sig[sig.length - 1] = sig[sig.length - 1]! ^ 0xff;
    return { credentialId: b64u(this.credentialId), clientDataJSON: b64u(cdj), authenticatorData: b64u(authData), signature: b64u(sig) };
  }
}
