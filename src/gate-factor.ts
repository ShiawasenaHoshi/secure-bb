// The second factor on this side: TOTP (registration, the external secret, the block after wrong codes), `touch`, and the approval session (open, use, close, expire).
// It decides nothing about plugins; with a guard the guard checks the factor and this layer only passes the proof on.
import { readFileSync } from "node:fs";
import { groupOf, hashToken, mintListProof, mintSessionProof, newToken, SessionProof, ListProof, type Proof, type RpcName } from "./approval.js";
import { SESSION_CAP_MS, SESSION_IDLE_MS } from "../guard/src/session-rules.ts";
import type { GuardProof } from "./guardlink.js";
import { GateError } from "./errors.js";
import { generateSecret, otpauthUri, verifyTotp, stepAt } from "../guard/src/totp.ts";
import { type TotpState, HOUR_MS, MAX_FAILURES, secretFromFile } from "./gate-types.js";
import { GateBase } from "./gate-base.js";

export class GateFactor extends GateBase {
  // ---- TOTP --------------------------------------------------------------
  /** Guard mode: whether the guard said, last time we asked, that it has a second factor (the secret itself is never here). */
  protected guardRegistered = false;
  isGuarded(): boolean {
    return this.d.guard !== undefined;
  }
  noteGuardState(registered: boolean): void {
    this.guardRegistered = registered;
  }
  totpState(): TotpState {
    // The secret is held outside bb by the guard: for the page that is the same as an external secret file.
    if (this.d.guard) return this.guardRegistered ? "external" : "none";
    if (this.d.externalTotpFile !== null) return this.readExternal() === null ? "external-broken" : "external";
    return this.store.totp()?.state ?? "none";
  }
  protected readExternal(): string | null {
    try {
      return secretFromFile(readFileSync(this.d.externalTotpFile!, "utf8"));
    } catch {
      return null;
    }
  }
  blockedUntil(): number {
    const until = Number(this.store.getMeta("blocked_until") ?? 0);
    return until > this.now ? until : 0;
  }
  protected assertNotBlocked(): void {
    const until = this.blockedUntil();
    if (until > 0) throw new GateError("blocked", `too many wrong codes; approvals are blocked until ${new Date(until).toISOString()}`);
  }
  protected recordFailure(purpose: string, message = "invalid or already used code"): never {
    this.store.recordAttempt(false, purpose);
    const epoch = Number(this.store.getMeta("fail_epoch") ?? 0);
    const since = Math.max(this.now - HOUR_MS, epoch);
    if (this.store.failuresSince(since) >= MAX_FAILURES) {
      this.store.setMeta("blocked_until", String(this.now + HOUR_MS));
      this.store.setMeta("fail_epoch", String(this.now));
      this.store.log("totp.blocked", null, null, { purpose });
    }
    this.store.log("totp.fail", null, null, { purpose });
    throw new GateError("invalid_code", message);
  }
  /**
   * A touch: proves a human holds the TOTP secret, or holds the token of a session that such a code opened.
   * A fresh code (a string) consumes one 30-second step; a step (or any older one) is never accepted twice.
   * A session proof is only ever made by `proofFor`, which looked at the RPC table first.
   */
  touch(purpose: string, proof: Proof): void {
    if (proof instanceof ListProof) return; // one code for a whole fixed list was accepted a moment ago (`approveList`), or the guard checked this one
    if (this.d.guard) throw new GateError("invalid_code", "in guard mode the guard checks every code; this one did not go through it");
    const code = proof instanceof SessionProof ? null : proof;
    const state = this.totpState();
    if (state === "none" || state === "pending") throw new GateError("not_registered", "no second factor is registered yet; register one on the secure-bb page");
    if (state === "external-broken") throw new GateError("not_registered", "the external TOTP secret file cannot be read");
    this.assertNotBlocked();
    if (proof instanceof SessionProof) return this.useSession(purpose, proof.token);
    const external = state === "external";
    const secret = external ? this.readExternal()! : this.store.totp()!.secret;
    const last = external ? this.store.externalLastStep() : this.store.totp()!.lastStep;
    const res = verifyTotp(secret, code!, this.now, last);
    if (!res.ok) this.recordFailure(purpose);
    this.store.recordAttempt(true, purpose);
    if (external) this.store.setExternalLastStep(res.step);
    else this.store.setLastStep(res.step);
  }
  // ---- approval session (docs: secure-bb-approval-ux.md §1) ------------------------------------------------------------
  /**
   * What an RPC may use as its proof. `escalate`: this call is the dangerous kind of an otherwise routine RPC (lifting a block,
   * widening); it then needs a fresh code, as every "dangerous" RPC does. A fresh code is always welcome, whatever the group.
   * This gate takes a session token only without a guard. With a guard it takes none: the guard checks the session, and only for routine actions
   * (guard/src/session-rules.ts); a token the page sends goes to the guard (`withGuardTouch` in server.ts), never to this method.
   */
  proofFor(rpc: RpcName, cred: { code?: string; session?: string }, opts: { escalate?: boolean } = {}): Proof {
    if (cred.code !== undefined) return cred.code;
    if (cred.session !== undefined) {
      if (this.d.guard) throw new GateError("invalid_code", "with a guard this gate takes no session token: the guard checks the session, and only for routine actions");
      if (groupOf(rpc) !== "routine" || opts.escalate === true) throw new GateError("invalid_code", "this action needs a fresh code: a session does not cover it");
      return mintSessionProof(cred.session);
    }
    throw new GateError("invalid_code", "a code, or an open session, is needed");
  }
  /** A wrong, unknown, closed or expired token is a wrong code: same counter, same one-hour block. */
  protected useSession(purpose: string, token: string): void {
    const row = this.store.sessionByHash(hashToken(token));
    if (!row || this.now >= row.expiresAt || this.now >= row.hardExpiresAt) {
      if (row && this.store.closeSession(row.id, "expired")) this.store.log("session.expire", null, null);
      this.recordFailure(`session:${purpose}`, "invalid or expired session");
    }
    // Sliding: every use moves the end 15 minutes ahead, never past the ceiling.
    this.store.slideSession(row.id, this.now, Math.max(row.expiresAt, Math.min(this.now + SESSION_IDLE_MS, row.hardExpiresAt)));
    this.store.log("session.use", null, null, { purpose });
  }
  /** The plugins that keep a session closed: not every running third-party plugin, only the ones whose code could reach the token (see `sessionBlockers` in probe.ts). */
  protected async sessionBlockers(): Promise<string[]> {
    return this.d.sessionBlockers ? this.d.sessionBlockers() : this.d.thirdPartyRunning();
  }
  /**
   * Opens a session with one fresh code. Refused while any third-party plugin runs: its interface code lives in the page's
   * origin and could read the token. The old session (if any) is closed: there is one.
   */
  async openSession(code: string, hour = false): Promise<{ token: string; idleMs: number; capMs: number }> {
    const running = await this.sessionBlockers();
    if (running.length > 0)
      throw new GateError("conflict", `disable these third-party plugins first: their interface code could read the session token (${running.join(", ")})`, { plugins: running });
    this.touch("session.open", code);
    this.store.closeSessions("replaced");
    const token = newToken();
    // «На 1 час»: the end is the ceiling from the start (never more than the ceiling); sliding never takes time away from it.
    const idleMs = hour ? SESSION_CAP_MS : SESSION_IDLE_MS;
    this.store.insertSession(hashToken(token), this.now, this.now + idleMs, this.now + SESSION_CAP_MS);
    this.store.log("session.open", null, null, { idleMs, capMs: SESSION_CAP_MS, ...(hour ? { hour: true } : {}) });
    return { token, idleMs, capMs: SESSION_CAP_MS };
  }
  /**
   * Guard mode: the guard issues the session (a code or a signature, checked there) and keeps only the token's hash. The same rule as without a guard:
   * not while a third-party plugin runs (its interface code shares the page's origin and could read the token).
   */
  async openGuardSession(proof: GuardProof, hour = false): Promise<{ token: string; idleMs: number; capMs: number }> {
    const guard = this.d.guard;
    if (!guard) throw new GateError("invalid", "not in guard mode");
    const running = await this.sessionBlockers();
    if (running.length > 0)
      throw new GateError("conflict", `disable these third-party plugins first: their interface code could read the session token (${running.join(", ")})`, { plugins: running });
    const opened = await guard.sessionOpen(proof, hour);
    this.store.log("session.open", null, null, { idleMs: opened.idleMs, capMs: opened.capMs, at: "guard" });
    return opened;
  }
  /** "Lock": tightening, needs nothing. Says nothing about whether a session existed. */
  closeSessions(reason: string): void {
    if (this.store.closeSessions(reason) > 0) this.store.log("session.close", null, null, { reason });
  }
  /** Guard mode: the same, at the guard (no touch: it only tightens). */
  async closeGuardSessions(reason: string): Promise<void> {
    await this.d.guard?.sessionClose();
    this.store.log("session.close", null, null, { reason, at: "guard" });
  }
  /**
   * A session is only opened while no third-party plugin runs (its interface code shares the page's origin and could read the
   * token). If one starts afterwards, the session is closed at once (threat model: an agent enables a plugin while a session
   * is open). The interface of a plugin is not visible to us, so every running third-party plugin counts. Returns who ran.
   */
  async closeSessionsForThirdParty(): Promise<string[]> {
    if (this.d.guard) {
      // The sessions are the guard's: ask it whether one is open (no secret in the answer), and close it there if a third-party plugin runs.
      const open = (await this.d.guard.state().catch(() => null))?.sessions ?? [];
      if (open.length === 0) return [];
      const running = await this.sessionBlockers();
      if (running.length === 0) return [];
      await this.closeGuardSessions(`third-party plugin running: ${running.slice(0, 5).join(", ")}`);
      return running;
    }
    if (this.store.unclosedSessions().length === 0) return [];
    const running = await this.sessionBlockers();
    if (running.length === 0) return [];
    this.closeSessions(`third-party plugin running: ${running.slice(0, 5).join(", ")}`);
    return running;
  }
  /** Background pass: closes sessions whose time is up. */
  sweepSessions(): number {
    let n = 0;
    for (const row of this.store.unclosedSessions()) {
      if (this.now < row.expiresAt && this.now < row.hardExpiresAt) continue;
      if (this.store.closeSession(row.id, "expired")) {
        this.store.log("session.expire", null, null);
        n++;
      }
    }
    return n;
  }
  /** One code for a fixed list: the code (or session) is checked once, here; the items are then approved with the returned mark. */
  approveList(purpose: string, proof: Proof): ListProof {
    this.touch(purpose, proof);
    return mintListProof();
  }
  /**
   * Starts (or restarts) registration. Refused while any third-party plugin runs.
   * `attended` says the call came while the secure-bb page was open; a
   * registration started any other way cannot be confirmed (it must be
   * restarted from the page), so a process that merely calls the API cannot
   * quietly enrol its own authenticator.
   */
  async beginRegistration(opts: { attended: boolean; caller: string }): Promise<{ secret: string; uri: string }> {
    const state = this.totpState();
    if (state === "locked" || state === "external" || state === "external-broken")
      throw new GateError("conflict", "a second factor is already set up and cannot be shown again");
    const running = await this.d.thirdPartyRunning();
    if (running.length > 0)
      throw new GateError("conflict", "disable these third-party plugins before registering: their interface code could see the QR code", { plugins: running });
    const secret = generateSecret();
    this.store.putPendingTotp(secret);
    this.store.setMeta("pending_attended", opts.attended ? "1" : "0");
    this.store.log("totp.begin", null, null, { attended: opts.attended, caller: opts.caller });
    return { secret, uri: otpauthUri(secret, "secure-bb") };
  }
  /** True while a registration was started without the page open. */
  pendingUnattended(): boolean {
    return this.totpState() === "pending" && this.store.getMeta("pending_attended") !== "1";
  }
  /** First valid code locks the secret: it is never returned again. */
  confirmRegistration(code: string): void {
    const row = this.store.totp();
    if (this.totpState() !== "pending" || !row) throw new GateError("conflict", "no registration in progress");
    if (this.pendingUnattended())
      throw new GateError("conflict", "this registration was not started from the secure-bb page; press \"Start again\" on the page");
    this.assertNotBlocked();
    const res = verifyTotp(row.secret, code, this.now, 0);
    if (!res.ok) this.recordFailure("register");
    this.store.recordAttempt(true, "register");
    this.store.lockTotp(res.step);
    this.store.log("totp.registered", null, null);
  }
  // ---- views --------------------------------------------------------------
  currentStep(): number {
    return stepAt(this.now);
  }
}
