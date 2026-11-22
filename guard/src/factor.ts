// The second factor: TOTP codes, approval sessions and passkeys (enrollment, challenges, signatures), and `verifyFactor`, the one place that says whether a touch counts.
// It decides nothing about plugins: approvals and windows ask it, never the other way round.
import { readFileSync, renameSync, unlinkSync, openSync, closeSync, writeSync, constants } from "node:fs";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { b64u, fromB64u, newNonce, newToken, parseAttestationObject, parseAuthData, parseClientData, PasskeyError, sha256, tokenDigest, verifyEs256, FLAG_UP, FLAG_UV } from "./passkey.ts";
import { verifyTotp } from "./totp.ts";
import { SESSION_CAP_MS, SESSION_IDLE_MS, isRoutineAction } from "./session-rules.ts";
import { GuardError, HOUR_MS, MAX_FAILURES, PASSKEY_FAIL_LOG_EVERY_MS, sha256hex, ENROLL_WINDOW_MS, CHALLENGE_TTL_MS, MAX_OPEN_CHALLENGES, type Raw, str, type Proof, type Factor, factorDetail, type PasskeyRow } from "./guard-types.ts";
import { ActionGuard } from "./guard-actions.ts";

export class FactorGuard extends ActionGuard {
  // ---- TOTP ---------------------------------------------------------------
  /** The secret, or null. Only this file and the console command ever touch it. */
  protected secret(): string | null {
    try {
      const t = readFileSync(this.secretPath, "utf8").trim();
      return /^[A-Z2-7]{16,}$/.test(t) ? t : null;
    } catch {
      return null;
    }
  }
  totpRegistered(): boolean {
    return this.secret() !== null;
  }
  /** Until when wrong CODES block codes (and sessions: a token is a secret like a code); 0: not blocked. */
  blockedUntil(): number {
    const until = Number(this.meta("blocked_until") ?? 0);
    return until > this.now() ? until : 0;
  }
  /** Blocked after too many wrong codes (or session tokens): five in an hour block codes for an hour. Signatures are not touched by it. */
  protected assertCodesNotBlocked(): void {
    const until = this.blockedUntil();
    if (until > 0) throw new GuardError("blocked", `too many wrong codes; codes are blocked until ${new Date(until).toISOString()} (a passkey touch still works)`);
  }
  /**
   * A wrong code or session token (`totp.fail`: the fifth within an hour blocks codes for an hour), or a wrong signature (`passkey.fail`: counted
   * and journaled as a summary at most once a minute, never blocks). Always commits before the caller throws.
   */
  protected recordFailure(kind: "totp.fail" | "passkey.fail", purpose: string, extra: Record<string, unknown> = {}): void {
    if (kind === "passkey.fail") {
      this.passkeyFails++;
      this.flushPasskeyFails(purpose, extra);
      return;
    }
    this.tx(() => {
      this.db.prepare(`INSERT INTO attempts (ts, ok, purpose, kind) VALUES (?, 0, ?, 'code')`).run(this.now(), purpose);
      const since = Math.max(this.now() - HOUR_MS, Number(this.meta("fail_epoch") ?? 0));
      const n = (this.db.prepare(`SELECT COUNT(*) AS n FROM attempts WHERE ok = 0 AND kind = 'code' AND ts > ?`).get(since) as { n: number }).n;
      this.log(kind, null, null, { purpose, ...extra });
      if (n >= MAX_FAILURES) {
        const until = this.now() + HOUR_MS;
        this.setMeta("blocked_until", String(until));
        this.setMeta("fail_epoch", String(this.now()));
        this.log("totp.blocked", null, null, { purpose, until });
      }
    });
  }
  /** The summary of wrong signatures: when a minute has passed since the last one (or on the background pass). */
  protected flushPasskeyFails(purpose = "", extra: Record<string, unknown> = {}, inTx = false): void {
    if (this.passkeyFails === 0 || this.now() - this.passkeyFailLoggedAt < PASSKEY_FAIL_LOG_EVERY_MS) return;
    const failures = this.passkeyFails;
    this.passkeyFails = 0;
    this.passkeyFailLoggedAt = this.now();
    const write = (): unknown => this.log("passkey.fail", null, null, { ...(purpose ? { purpose } : {}), ...extra, failures });
    if (inTx) write();
    else this.tx(write);
  }
  /**
   * A touch: checks one TOTP code for `purpose`. A step (or any older one) is never accepted twice; five wrong
   * codes within an hour block every touch for an hour. Throws, so nothing after it runs on a bad code.
   */
  protected verifyCode(purpose: string, code: unknown): void {
    const secret = this.secret();
    if (secret === null) {
      if (this.totpDisabled()) throw new GuardError("not_registered", "codes are switched off at this guard: touch with a passkey (`sbb-guard totp-register` on the console switches them on again)");
      throw new GuardError("not_registered", "no second factor is registered; run `sbb-guard totp-register` on the console");
    }
    this.assertCodesNotBlocked();
    const given = typeof code === "string" ? code : "";
    const res = verifyTotp(secret, given, this.now(), Number(this.meta("last_step") ?? 0));
    if (!res.ok) {
      this.recordFailure("totp.fail", purpose);
      throw new GuardError("invalid_code", "invalid or already used code");
    }
    // The step is spent before the action runs, in a transaction of its own (a failure above also commits its record).
    // Callers check everything that can be checked without a code first, so a spent code is not wasted on a refusal.
    this.tx(() => {
      this.db.prepare(`INSERT INTO attempts (ts, ok, purpose, kind) VALUES (?, 1, ?, 'code')`).run(this.now(), purpose);
      this.setMeta("last_step", String(res.step));
    });
  }
  /**
   * One touch for one action: a passkey assertion when one is given (and then only that), else a TOTP code, else — for a routine action only —
   * the token of an approval session. A session offered for anything else is refused outright (not counted as a wrong code): it is the page asking
   * for something it must ask a human for.
   */
  protected verifyFactor(purpose: string, action: Record<string, unknown>, proof: Proof): Factor {
    if (proof.passkey !== undefined) return this.verifyPasskey(purpose, action, proof.passkey);
    if (proof.code === undefined && proof.session !== undefined) {
      if (!isRoutineAction(action)) throw new GuardError("invalid_code", "this needs a fresh touch (a code or a passkey): a session does not cover it");
      return this.verifySession(purpose, proof.session);
    }
    this.verifyCode(purpose, proof.code);
    return { via: "totp" };
  }
  // ---- approval sessions ---------------------------------------------------------------------------------------------------
  // The token is made here, goes back once to the page that touched, and lives in that page's memory. Only its SHA-256 is kept (and it is never in
  // the journal or the state). A session covers routine actions (isRoutineAction); each use slides the end 15 minutes ahead, never past the ceiling.
  protected verifySession(purpose: string, token: unknown): Factor {
    this.assertCodesNotBlocked();
    const row = typeof token === "string" && token.length >= 16 && token.length <= 256 ? (this.db.prepare(`SELECT * FROM sessions WHERE token_hash = ? AND closed_at IS NULL`).get(sha256hex(token)) as Raw | undefined) : undefined;
    const now = this.now();
    if (!row || now >= Number(row.expires_at) || now >= Number(row.hard_expires_at)) {
      if (row) this.tx(() => this.closeSessionInner(Number(row.id), "expired"));
      // A wrong, unknown, closed or expired token is a wrong code: the same counter.
      this.recordFailure("totp.fail", `session:${purpose}`, { via: "session" });
      throw new GuardError("invalid_code", "invalid or expired session");
    }
    this.tx(() => {
      // Sliding never takes time away: a session opened «на час» (its end is the ceiling from the start) keeps its hour.
      this.db.prepare(`UPDATE sessions SET expires_at = ?, uses = uses + 1 WHERE id = ?`).run(Math.max(Number(row.expires_at), Math.min(now + SESSION_IDLE_MS, Number(row.hard_expires_at))), Number(row.id));
    });
    return { via: "session", sessionId: Number(row.id) };
  }
  protected closeSessionInner(id: number, reason: string): void {
    const done = this.db.prepare(`UPDATE sessions SET closed_at = ?, closed_reason = ? WHERE id = ? AND closed_at IS NULL`).run(this.now(), reason, id);
    if (Number(done.changes) === 1) this.log(reason === "expired" ? "session.expire" : "session.close", null, null, { session: id, reason });
  }
  protected openSessions(): Raw[] {
    const now = this.now();
    return (this.db.prepare(`SELECT * FROM sessions WHERE closed_at IS NULL ORDER BY id`).all() as Raw[]).filter((r) => now < Number(r.expires_at) && now < Number(r.hard_expires_at));
  }
  /** `session-open`: a fresh touch (a session cannot open another). The old session, if any, is closed: there is one. */
  sessionOpen(raw: Record<string, unknown>): { token: string; idleMs: number; capMs: number; sessionId: number } {
    // «На 1 час»: the end is the ceiling from the start, nothing to keep alive; the ceiling is the same one, never more.
    const hour = raw.hour === true;
    const factor = this.verifyFactor("session.open", this.normalizeAction({ op: "session-open", ...(hour ? { hour: true } : {}) }), raw);
    const idleMs = hour ? SESSION_CAP_MS : SESSION_IDLE_MS;
    const token = randomBytes(32).toString("base64url");
    return this.tx(() => {
      for (const r of this.db.prepare(`SELECT id FROM sessions WHERE closed_at IS NULL`).all() as Array<{ id: number }>) this.closeSessionInner(Number(r.id), "replaced");
      const now = this.now();
      const info = this.db.prepare(`INSERT INTO sessions (token_hash, opened_at, expires_at, hard_expires_at) VALUES (?, ?, ?, ?)`).run(sha256hex(token), now, now + idleMs, now + SESSION_CAP_MS);
      const id = Number(info.lastInsertRowid);
      this.log("session.open", null, null, { session: id, idleMs, capMs: SESSION_CAP_MS, ...(hour ? { hour: true } : {}), ...factorDetail(factor) });
      return { token, idleMs, capMs: SESSION_CAP_MS, sessionId: id };
    });
  }
  /** "Lock": tightening, no touch. Closes every session. */
  sessionClose(reason = "locked"): { closed: number } {
    return this.tx(() => {
      let n = 0;
      for (const r of this.db.prepare(`SELECT id FROM sessions WHERE closed_at IS NULL`).all() as Array<{ id: number }>) {
        this.closeSessionInner(Number(r.id), reason);
        n++;
      }
      return { closed: n };
    });
  }
  totpDisabled(): boolean {
    return this.meta("totp_disabled") === "1";
  }
  /** Console only: codes off. Needs a working passkey (else nobody could touch anything) and removes the secret for good; `totp-register` makes a new one. */
  totpDisable(): void {
    if (this.activePasskeys().length === 0) throw new GuardError("conflict", "no active passkey: switching codes off would leave no way to touch (`sbb-guard passkey-enroll` first)");
    if (this.secret() === null) throw new GuardError("conflict", "no TOTP secret is registered; nothing to switch off");
    this.tx(() => {
      unlinkSync(this.secretPath);
      this.setMeta("totp_disabled", "1");
      this.log("totp.disabled", null, null, { via: "console" });
    });
  }
  /** Console only: verifies a first code of a new secret, then stores it. `replacing` needs a valid code of the old one first. */
  registerSecret(secretB32: string, code: string, opts: { replacingCode?: string } = {}): void {
    const existing = this.secret();
    if (existing !== null) {
      if (opts.replacingCode === undefined) throw new GuardError("conflict", "a second factor is already registered; replacing it needs a code of the current one");
      this.verifyCode("totp.replace", opts.replacingCode);
    }
    this.tx(() => {
      const res = verifyTotp(secretB32, code, this.now(), Number(this.meta("last_step") ?? 0));
      if (!res.ok) throw new GuardError("invalid_code", "the code does not match the new secret (or its time step was already used)");
      // Create the file exclusively with 0600 from the start (never briefly readable), then move it into place.
      const tmp = `${this.secretPath}.new`;
      const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC, 0o600);
      try {
        writeSync(fd, `${secretB32}\n`);
      } finally {
        closeSync(fd);
      }
      renameSync(tmp, this.secretPath);
      this.setMeta("last_step", String(res.step));
      this.setMeta("totp_disabled", "0");
      this.log(existing === null ? "totp.registered" : "totp.replaced", null, null, { via: "console" });
    });
  }
  // ---- touches for the plugin's own, local features ---------------------------------------------------
  /** Checks one code for an action the plugin itself performs (its config watchdog, skills, settings). Decides nothing in the guard. */
  touch(raw: Record<string, unknown>): { ok: true } {
    const purpose = str(raw.purpose, "purpose", 80, 1);
    const factor = this.verifyFactor(`touch:${purpose}`, this.normalizeAction({ op: "touch", purpose }), raw);
    this.record("touch", null, null, { purpose, ...factorDetail(factor) });
    return { ok: true };
  }
  // ---- Passkeys -----------------------------------------------------------------------------------------------------
  // Why: a code typed on the page passes through bb's process, where a harmful plugin can take it and spend it first. A passkey
  // signature is made over a challenge the guard issued for ONE normalized action, so a captured signature is good for that action
  // only, once, for two minutes. Keys are registered only through the console (`passkey-enroll`), never through bb.
  protected activePasskeys(): Array<Raw & { credential_id: string; public_key: string; label: string; sign_count: number; id: number }> {
    return this.db.prepare(`SELECT * FROM passkeys WHERE state = 'active' ORDER BY id`).all() as never;
  }
  protected passkeyOf(r: Raw): PasskeyRow {
    return {
      id: Number(r.id),
      label: String(r.label),
      aaguid: String(r.aaguid),
      fingerprint: String(r.fingerprint),
      state: r.state as PasskeyRow["state"],
      createdAt: Number(r.created_at),
      confirmedAt: r.confirmed_at === null ? null : Number(r.confirmed_at),
      lastUsedAt: r.last_used_at === null ? null : Number(r.last_used_at),
    };
  }
  /** Console: every key (active, waiting for confirmation, removed). */
  listPasskeys(): PasskeyRow[] {
    return (this.db.prepare(`SELECT * FROM passkeys ORDER BY id`).all() as Raw[]).map((r) => this.passkeyOf(r));
  }
  /** Console: removes a key. The last way to touch cannot be removed (no active passkey and no TOTP would lock the owner out). */
  removePasskey(id: number): PasskeyRow {
    const row = this.db.prepare(`SELECT * FROM passkeys WHERE id = ? AND state IN ('active', 'pending')`).get(id) as Raw | undefined;
    if (!row) throw new GuardError("not_found", `no key #${id}`);
    const rest = this.activePasskeys().filter((k) => k.id !== id).length;
    if (row.state === "active" && rest === 0 && this.secret() === null) throw new GuardError("conflict", "this is the last way to touch: register a TOTP (`sbb-guard totp-register`) or another passkey first");
    return this.tx(() => {
      this.db.prepare(`UPDATE passkeys SET state = 'removed', removed_at = ? WHERE id = ?`).run(this.now(), id);
      this.log("passkey.removed", null, null, { key: String(row.label), id, via: "console" });
      return this.passkeyOf({ ...row, state: "removed" });
    });
  }
  // ---- enrollment (console) ----
  protected enrollmentRow(id: number): Raw | undefined {
    return this.db.prepare(`SELECT * FROM enrollments WHERE id = ?`).get(id) as Raw | undefined;
  }
  protected openEnrollment(): Raw | undefined {
    return this.db.prepare(`SELECT * FROM enrollments WHERE state = 'open' AND expires_at > ? ORDER BY id DESC LIMIT 1`).get(this.now()) as Raw | undefined;
  }
  /** Console (`setup`): the id of the newest journal record, so that a later look can ask only for what happened after. */
  lastJournalId(): number {
    return Number((this.db.prepare(`SELECT COALESCE(MAX(id), 0) AS n FROM journal`).get() as { n: number }).n);
  }
  /**
   * Console (`setup`): the touches for `purpose` that were made by a PASSKEY after journal record `sinceId`, newest first. Only a signature counts: a code
   * passes through bb and could be spent by anything in it, a signature over this action could not.
   */
  passkeyTouches(purpose: string, sinceId = 0): Array<{ id: number; ts: number; key: string }> {
    const rows = this.db.prepare(`SELECT id, ts, detail FROM journal WHERE kind = 'touch' AND id > ? ORDER BY id DESC LIMIT 200`).all(sinceId) as Raw[];
    const out: Array<{ id: number; ts: number; key: string }> = [];
    for (const r of rows) {
      const d = JSON.parse(String(r.detail ?? "null")) as { purpose?: unknown; via?: unknown; key?: unknown } | null;
      if (d && d.purpose === purpose && d.via === "passkey" && typeof d.key === "string") out.push({ id: Number(r.id), ts: Number(r.ts), key: d.key });
    }
    return out;
  }
  /** Active keys, for the console. */
  activeKeys(): PasskeyRow[] {
    return this.listPasskeys().filter((k) => k.state === "active");
  }
  /** Console only: opens the registration window (one at a time; an earlier one and its unconfirmed key are dropped) and returns the one-time token. */
  enrollStart(label: string): { id: number; token: string; label: string; expiresAt: number } {
    const name = str(label, "label", 64, 1);
    const token = newToken();
    return this.tx(() => {
      this.db.prepare(`UPDATE enrollments SET state = 'closed' WHERE state IN ('open', 'registered')`).run();
      this.db.prepare(`UPDATE passkeys SET state = 'removed', removed_at = ? WHERE state = 'pending'`).run(this.now());
      const now = this.now();
      const info = this.db
        .prepare(`INSERT INTO enrollments (token_digest, label, user_handle, opened_at, expires_at, state) VALUES (?, ?, ?, ?, ?, 'open')`)
        .run(tokenDigest(token), name, b64u(newNonce().subarray(0, 16)), now, now + ENROLL_WINDOW_MS);
      const id = Number(info.lastInsertRowid);
      this.log("passkey.enroll.open", null, null, { enrollment: id, label: name, expiresAt: now + ENROLL_WINDOW_MS, via: "console" });
      return { id, token, label: name, expiresAt: now + ENROLL_WINDOW_MS };
    });
  }
  /** Console: where the registration stands; `key` is what the page registered, waiting for the person at the console. */
  enrollmentStatus(id: number): { state: string; expiresAt: number; key: (PasskeyRow & { keyId: number }) | null } {
    const e = this.enrollmentRow(id);
    if (!e) throw new GuardError("not_found", "no such enrollment");
    let state = String(e.state);
    if (state === "open" && Number(e.expires_at) <= this.now()) state = "expired";
    const k = this.db.prepare(`SELECT * FROM passkeys WHERE enrollment_id = ? AND state = 'pending' ORDER BY id DESC LIMIT 1`).get(id) as Raw | undefined;
    return { state, expiresAt: Number(e.expires_at), key: k ? { ...this.passkeyOf(k), keyId: Number(k.id) } : null };
  }
  /** Console: the person saw the key (label, AAGUID, fingerprint) and said yes. Only now can it touch. */
  confirmEnrollment(id: number): PasskeyRow {
    return this.tx(() => {
      const e = this.enrollmentRow(id);
      if (!e || e.state !== "registered") throw new GuardError("conflict", "there is nothing registered to confirm in this enrollment");
      const k = this.db.prepare(`SELECT * FROM passkeys WHERE enrollment_id = ? AND state = 'pending' ORDER BY id DESC LIMIT 1`).get(id) as Raw | undefined;
      if (!k) throw new GuardError("conflict", "the registered key is gone");
      this.db.prepare(`UPDATE passkeys SET state = 'active', confirmed_at = ? WHERE id = ?`).run(this.now(), Number(k.id));
      this.db.prepare(`UPDATE enrollments SET state = 'confirmed' WHERE id = ?`).run(id);
      this.log("passkey.enrolled", null, null, { key: String(k.label), id: Number(k.id), aaguid: String(k.aaguid), fingerprint: String(k.fingerprint), via: "console" });
      return this.passkeyOf({ ...k, state: "active", confirmed_at: this.now() });
    });
  }
  /** Console: not confirmed (an answer of no, or the console gave up): the key is discarded and the window closes. */
  rejectEnrollment(id: number, why: string): void {
    this.tx(() => {
      const e = this.enrollmentRow(id);
      if (!e || (e.state !== "open" && e.state !== "registered")) return;
      const k = this.db.prepare(`SELECT id, label FROM passkeys WHERE enrollment_id = ? AND state = 'pending'`).get(id) as { id: number; label: string } | undefined;
      if (k) this.db.prepare(`UPDATE passkeys SET state = 'removed', removed_at = ? WHERE id = ?`).run(this.now(), k.id);
      this.db.prepare(`UPDATE enrollments SET state = 'closed' WHERE id = ?`).run(id);
      this.log("passkey.enroll.rejected", null, null, { enrollment: id, why, key: k?.label ?? null, via: "console" });
    });
  }
  // ---- registration (socket) ----
  protected checkToken(token: unknown): Raw {
    const e = this.openEnrollment();
    if (!e) throw new GuardError("conflict", "no passkey registration is open; run `sbb-guard passkey-enroll` on the console");
    const given = typeof token === "string" ? tokenDigest(token) : "";
    const ok = given.length === String(e.token_digest).length && timingSafeEqual(Buffer.from(given), Buffer.from(String(e.token_digest)));
    if (!ok) {
      // Five wrong tokens close the window: a token is 60 bits, but whoever can reach the socket must not get to try without end.
      const fails = Number(e.fails) + 1;
      this.tx(() => {
        this.db.prepare(`UPDATE enrollments SET fails = ?, state = CASE WHEN ? >= ${MAX_FAILURES} THEN 'closed' ELSE state END WHERE id = ?`).run(fails, fails, Number(e.id));
        this.log("passkey.token.fail", null, null, { enrollment: Number(e.id), fails, ...(fails >= MAX_FAILURES ? { closed: true } : {}) });
      });
      throw new GuardError("invalid_code", fails >= MAX_FAILURES ? "wrong token; the registration window is closed" : "wrong token");
    }
    return e;
  }
  /**
   * Step 1 (`{token}`): the token is right and the window is open → the creation options for `navigator.credentials.create`, with a challenge
   * bound to this enrollment. Step 2 (`{token, clientDataJSON, attestationObject}`): checks them and stores the key as PENDING; the console decides.
   */
  passkeyRegister(raw: Record<string, unknown>): Record<string, unknown> {
    const e = this.checkToken(raw.token);
    const enrollment = Number(e.id);
    if (raw.clientDataJSON === undefined && raw.attestationObject === undefined) {
      if (e.state !== "open") throw new GuardError("conflict", "a key was already registered in this window; it waits for the console");
      const nonce = newNonce();
      this.tx(() => {
        this.trimChallenges();
        this.db.prepare(`INSERT INTO challenges (nonce, kind, enrollment_id, created_at, expires_at) VALUES (?, 'register', ?, ?, ?)`).run(b64u(nonce), enrollment, this.now(), Math.min(this.now() + CHALLENGE_TTL_MS, Number(e.expires_at)));
      });
      return {
        options: {
          challenge: b64u(nonce),
          rp: { id: this.rp.rpId, name: "secure-bb guard" },
          user: { id: String(e.user_handle), name: "secure-bb", displayName: String(e.label) },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
          attestation: "none",
          excludeCredentials: this.activePasskeys().map((k) => ({ type: "public-key", id: k.credential_id })),
          timeout: CHALLENGE_TTL_MS,
        },
      };
    }
    if (e.state !== "open") throw new GuardError("conflict", "a key was already registered in this window; it waits for the console");
    let cdj: Buffer;
    let att: ReturnType<typeof parseAttestationObject>;
    let clientChallenge: string;
    try {
      cdj = fromB64u(raw.clientDataJSON, "clientDataJSON");
      const cd = parseClientData(cdj);
      if (cd.type !== "webauthn.create") throw new PasskeyError("the client data is not for a registration");
      if (cd.origin !== this.rp.origin || cd.crossOrigin) throw new PasskeyError(`the page must be opened at ${this.rp.origin}`);
      clientChallenge = cd.challenge;
      att = parseAttestationObject(fromB64u(raw.attestationObject, "attestationObject"));
    } catch (err) {
      if (err instanceof PasskeyError) throw new GuardError("invalid_passkey", err.message);
      throw err;
    }
    const ch = this.db.prepare(`SELECT * FROM challenges WHERE nonce = ? AND kind = 'register'`).get(clientChallenge) as Raw | undefined;
    if (!ch || Number(ch.enrollment_id) !== enrollment) throw new GuardError("invalid_passkey", "this registration was not started here");
    if (Number(ch.used) === 1) throw new GuardError("invalid_passkey", "this challenge was already used");
    if (Number(ch.expires_at) <= this.now()) throw new GuardError("expired", "the challenge has expired; start again");
    if (!att.rpIdHash.equals(sha256(this.rp.rpId))) throw new GuardError("invalid_passkey", "the key was made for another RP ID");
    if ((att.flags & FLAG_UP) === 0 || (att.flags & FLAG_UV) === 0) throw new GuardError("invalid_passkey", "the key must be used with user presence and verification (Touch ID, PIN)");
    if (!att.attested) throw new GuardError("invalid_passkey", "no credential in the attestation");
    const cred = b64u(att.attested.credentialId);
    if (this.db.prepare(`SELECT 1 FROM passkeys WHERE credential_id = ?`).get(cred)) throw new GuardError("conflict", "this credential is already known");
    const label = String(e.label);
    const aaguid = att.attested.aaguid.toString("hex");
    const fingerprint = sha256(att.attested.publicKeySpki).toString("hex").slice(0, 32);
    return this.tx(() => {
      this.db.prepare(`UPDATE challenges SET used = 1 WHERE nonce = ?`).run(clientChallenge);
      this.db
        .prepare(`INSERT INTO passkeys (credential_id, public_key, label, aaguid, fingerprint, sign_count, state, enrollment_id, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)`)
        .run(cred, b64u(att.attested!.publicKeySpki), label, aaguid, fingerprint, att.signCount, enrollment, this.now());
      this.db.prepare(`UPDATE enrollments SET state = 'registered' WHERE id = ?`).run(enrollment);
      this.log("passkey.registered", null, null, { key: label, aaguid, fingerprint, enrollment, note: "waits for confirmation on the console" });
      return { ok: true, label, note: "key registered; it is not active until you confirm it on the console" };
    });
  }
  protected trimChallenges(): void {
    this.db.prepare(`DELETE FROM challenges WHERE expires_at < ?`).run(this.now() - HOUR_MS);
    this.db.prepare(`DELETE FROM challenges WHERE kind = 'action' AND nonce NOT IN (SELECT nonce FROM challenges WHERE kind = 'action' ORDER BY created_at DESC, rowid DESC LIMIT ?)`).run(MAX_OPEN_CHALLENGES);
  }
  /** `challenge {action}`: no secret needed (it decides nothing: only a signature made by a registered key on the console's side of Touch ID does). */
  challenge(raw: Record<string, unknown>): { challenge: string; allowCredentials: Array<{ type: "public-key"; id: string }>; description: string; rpId: string; origin: string; expiresAt: number } {
    const keys = this.activePasskeys();
    if (keys.length === 0) throw new GuardError("not_registered", "no passkey is registered; run `sbb-guard passkey-enroll` on the console");
    const action = this.normalizeAction(raw.action);
    const description = this.describe(action);
    const nonce = b64u(newNonce());
    const expiresAt = this.now() + CHALLENGE_TTL_MS;
    this.tx(() => {
      this.trimChallenges();
      this.db.prepare(`INSERT INTO challenges (nonce, kind, action_json, created_at, expires_at) VALUES (?, 'action', ?, ?, ?)`).run(nonce, JSON.stringify(action), this.now(), expiresAt);
    });
    return { challenge: nonce, allowCredentials: keys.map((k) => ({ type: "public-key" as const, id: k.credential_id })), description, rpId: this.rp.rpId, origin: this.rp.origin, expiresAt };
  }
  /**
   * Checks an assertion for `action` (the normalized command that just arrived). Order: shape → the challenge (unknown, used, expired: plain refusals,
   * not counted) → everything the signature covers (counted, on the counter of signatures: not the one of codes) → the challenge is spent in one transaction with the key's counter.
   */
  protected verifyPasskey(purpose: string, action: Record<string, unknown>, assertion: unknown): Factor {
    if (this.activePasskeys().length === 0) throw new GuardError("not_registered", "no passkey is registered; run `sbb-guard passkey-enroll` on the console");
    if (typeof assertion !== "object" || assertion === null || Array.isArray(assertion)) throw new GuardError("invalid", "passkey is an object");
    const p = assertion as Record<string, unknown>;
    let credId: string;
    let cdj: Buffer;
    let authDataRaw: Buffer;
    let sig: Buffer;
    let clientChallenge: string;
    let cd: ReturnType<typeof parseClientData>;
    try {
      credId = b64u(fromB64u(p.credentialId, "credentialId", 1400));
      cdj = fromB64u(p.clientDataJSON, "clientDataJSON");
      authDataRaw = fromB64u(p.authenticatorData, "authenticatorData");
      sig = fromB64u(p.signature, "signature", 512);
      cd = parseClientData(cdj);
      clientChallenge = cd.challenge;
    } catch (err) {
      if (err instanceof PasskeyError) throw new GuardError("invalid", err.message);
      throw err;
    }
    const ch = this.db.prepare(`SELECT * FROM challenges WHERE nonce = ? AND kind = 'action'`).get(clientChallenge) as Raw | undefined;
    if (!ch) throw new GuardError("invalid_passkey", "unknown challenge (it was not issued by this guard, or it is long gone)");
    if (Number(ch.used) === 1) throw new GuardError("invalid_passkey", "this challenge was already used");
    if (Number(ch.expires_at) <= this.now()) throw new GuardError("expired", "the challenge has expired; ask for a new one");

    const fail = (reason: string): never => {
      this.recordFailure("passkey.fail", purpose, { reason });
      throw new GuardError("invalid_passkey", reason);
    };
    const key = this.activePasskeys().find((k) => k.credential_id === credId);
    if (!key) return fail("this key is not registered here");
    if (cd.type !== "webauthn.get") return fail("the client data is not for a touch");
    if (cd.origin !== this.rp.origin || cd.crossOrigin) return fail(`the touch was made on another origin than ${this.rp.origin}`);
    let auth: ReturnType<typeof parseAuthData>;
    try {
      auth = parseAuthData(authDataRaw);
    } catch {
      return fail("malformed authenticator data");
    }
    if (!auth.rpIdHash.equals(sha256(this.rp.rpId))) return fail("the touch was made for another RP ID");
    if ((auth.flags & FLAG_UP) === 0) return fail("no user presence");
    if ((auth.flags & FLAG_UV) === 0) return fail("no user verification (Touch ID or PIN)");
    if (!verifyEs256(Buffer.from(String(key.public_key), "base64url"), authDataRaw, cdj, sig)) return fail("invalid signature");
    // The signature is genuine. Is it for THIS action? A captured signature spent on another action stops here.
    if (String(ch.action_json) !== JSON.stringify(action)) return fail("the challenge was issued for another action");
    // Authenticators that count must count up; those that do not (synced passkeys report 0) stay at 0.
    if ((auth.signCount !== 0 || Number(key.sign_count) !== 0) && auth.signCount <= Number(key.sign_count)) return fail("the key's counter did not increase (a cloned key?)");

    this.tx(() => {
      const spent = this.db.prepare(`UPDATE challenges SET used = 1 WHERE nonce = ? AND used = 0`).run(clientChallenge);
      if (Number(spent.changes) !== 1) throw new GuardError("invalid_passkey", "this challenge was already used");
      this.db.prepare(`UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?`).run(auth.signCount, this.now(), key.id);
      this.db.prepare(`INSERT INTO attempts (ts, ok, purpose, kind) VALUES (?, 1, ?, 'passkey')`).run(this.now(), purpose);
    });
    return { via: "passkey", key: String(key.label), action };
  }
}
