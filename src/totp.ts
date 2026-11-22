// TOTP (RFC 6238) is the guard's own module: the plugin reads it from `guard/src/totp.ts` (the trust border is one-way: the guard never imports the plugin,
// the plugin may import the guard's pure modules). This file is only the plugin's name for it, kept so that `src/gate.ts` and the tests import as before;
// it holds no arithmetic of its own. The one difference is the issuer the plugin's own second factor shows in the authenticator app.
import { otpauthUri as guardOtpauthUri } from "../guard/src/totp.ts";

export { TOTP_DIGITS, TOTP_STEP_SEC, base32Decode, base32Encode, generateSecret, hotp, stepAt, verifyTotp, type TotpCheck } from "../guard/src/totp.ts";

export const otpauthUri = (secretB32: string, issuer = "secure-bb", account = "bb"): string => guardOtpauthUri(secretB32, issuer, account);
