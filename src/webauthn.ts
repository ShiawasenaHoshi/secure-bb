// The browser half of passkeys: turns the guard's challenge into a `navigator.credentials.get` call and its answer into the fields the guard
// wants, and the same for registration. Pure functions over an injected `credentials` (the page passes `navigator.credentials`, tests a
// software authenticator), so nothing here touches the DOM. No dependencies: this file is bundled into the page that runs in bb's origin.
import type { PasskeyAssertion } from "./guardlink.js";

export const toB64u = (buf: ArrayBuffer | Uint8Array): string => {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
export const fromB64u = (text: string): Uint8Array<ArrayBuffer> => {
  const pad = "=".repeat((4 - (text.length % 4)) % 4);
  const bin = atob(text.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

/** The part of `navigator.credentials` that is used. */
export interface Credentials {
  create(options: { publicKey: Record<string, unknown> }): Promise<unknown>;
  get(options: { publicKey: Record<string, unknown> }): Promise<unknown>;
}

/**
 * WebAuthn needs the origin the guard was configured with (an IP address cannot be an RP ID, so 127.0.0.1 does not work). Returns the sentence
 * to show when this page is somewhere else, or null when it is the right place.
 */
export function originProblem(currentOrigin: string, guardOrigin: string): string | null {
  if (currentOrigin === guardOrigin) return null;
  return `Passkey работает только на ${guardOrigin}: откройте ${guardOrigin} (сейчас страница открыта на ${currentOrigin}; 127.0.0.1 не подходит, у WebAuthn нет RP ID для IP-адреса).`;
}

export interface TouchChallenge {
  challenge: string;
  allowCredentials: Array<{ type: "public-key"; id: string }>;
  rpId: string;
  origin: string;
}

/** Asks the authenticator to sign the guard's challenge; user verification (Touch ID, PIN) is required. */
export async function getAssertion(c: TouchChallenge, creds: Credentials, currentOrigin: string): Promise<PasskeyAssertion> {
  const problem = originProblem(currentOrigin, c.origin);
  if (problem) throw new Error(problem);
  const cred = (await creds.get({
    publicKey: {
      challenge: fromB64u(c.challenge),
      allowCredentials: c.allowCredentials.map((k) => ({ type: k.type, id: fromB64u(k.id) })),
      userVerification: "required",
      rpId: c.rpId,
      timeout: 120_000,
    },
  })) as { rawId: ArrayBuffer; response: { clientDataJSON: ArrayBuffer; authenticatorData: ArrayBuffer; signature: ArrayBuffer } } | null;
  if (!cred) throw new Error("касание отменено");
  return {
    credentialId: toB64u(cred.rawId),
    clientDataJSON: toB64u(cred.response.clientDataJSON),
    authenticatorData: toB64u(cred.response.authenticatorData),
    signature: toB64u(cred.response.signature),
  };
}

export interface CreationOptions {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: Array<{ type: "public-key"; alg: number }>;
  authenticatorSelection: Record<string, unknown>;
  attestation: string;
  excludeCredentials: Array<{ type: "public-key"; id: string }>;
  timeout: number;
}

/** Creates the key the guard asked for (ES256, user verification required, no attestation) and returns what the guard needs to store it. */
export async function createCredential(o: CreationOptions, creds: Credentials, currentOrigin: string, guardOrigin: string): Promise<{ clientDataJSON: string; attestationObject: string }> {
  const problem = originProblem(currentOrigin, guardOrigin);
  if (problem) throw new Error(problem);
  const cred = (await creds.create({
    publicKey: {
      challenge: fromB64u(o.challenge),
      rp: o.rp,
      user: { id: fromB64u(o.user.id), name: o.user.name, displayName: o.user.displayName },
      pubKeyCredParams: o.pubKeyCredParams,
      authenticatorSelection: o.authenticatorSelection,
      attestation: o.attestation,
      excludeCredentials: o.excludeCredentials.map((k) => ({ type: k.type, id: fromB64u(k.id) })),
      timeout: o.timeout,
    },
  })) as { response: { clientDataJSON: ArrayBuffer; attestationObject: ArrayBuffer } } | null;
  if (!cred) throw new Error("создание ключа отменено");
  return { clientDataJSON: toB64u(cred.response.clientDataJSON), attestationObject: toB64u(cred.response.attestationObject) };
}
