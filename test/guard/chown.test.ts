// The socket's group: a refusal of chown (the user is not in the group) is one sentence for the administrator, not a stack.
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { chownGroup, chownMessage, SocketGroupError } from "../../guard/src/chown.ts";
import { listen as listenHelper } from "../../guard/src/restore.ts";

const scratch = realpathSync(mkdtempSync(join(tmpdir(), "sbb-chown-")));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));
const eperm = (): never => {
  throw Object.assign(new Error("EPERM: operation not permitted, chown '/x'"), { code: "EPERM" });
};

describe("chownMessage", () => {
  it("EPERM says what to do: add the user to the group, restart; and that it gives no new rights", () => {
    const m = chownMessage({ program: "sbb-restore", uid: 1001 }, "/var/sbb-restore-run/restore.sock", 995, "EPERM");
    expect(m).toContain("sbb-restore: cannot give /var/sbb-restore-run/restore.sock to group 995");
    expect(m).toContain("EPERM");
    expect(m).toContain("uid 1001");
    expect(m).toContain("usermod -aG");
    expect(m).toContain("getent group 995");
    expect(m).toContain("restart the service");
    expect(m).toContain("no new rights");
    expect(m).not.toContain("    at ");
  });
  it("another error is short and has no advice about groups", () => {
    const m = chownMessage({ program: "sbb-guard" }, "/s", 5, "ENOENT");
    expect(m).toBe("sbb-guard: cannot give /s to group 5: failed (ENOENT).");
  });
});

describe("chownGroup", () => {
  it("turns EPERM into a SocketGroupError", () => {
    expect(() => chownGroup({ program: "sbb-restore" }, "/s", 7, eperm)).toThrow(SocketGroupError);
    try {
      chownGroup({ program: "sbb-restore" }, "/s", 7, eperm);
    } catch (err) {
      expect((err as SocketGroupError).message).toMatch(/group 7.*EPERM/s);
      expect((err as SocketGroupError).code).toBe("socket_group");
    }
  });
  it("calls chown with the group only (-1 for the user)", () => {
    const calls: unknown[][] = [];
    chownGroup({ program: "sbb-guard" }, "/s", 9, (...a) => void calls.push(a));
    expect(calls).toEqual([["/s", -1, 9]]);
  });
  it("an error that is not from the system passes through unchanged", () => {
    const boom = new Error("boom");
    expect(() => chownGroup({ program: "sbb-guard" }, "/s", 9, () => { throw boom; })).toThrow(boom);
  });
});

describe("the helper when chown of the socket is refused", () => {
  it("rejects with the sentence and leaves no live socket behind", async () => {
    const socket = join(scratch, "run", "restore.sock");
    await expect(listenHelper({ socket, socketGid: 4242, home: scratch, chown: (p) => { if (p.endsWith("restore.sock")) eperm(); } })).rejects.toThrow(/cannot give .* to group 4242.*EPERM/s);
    const live = await new Promise<boolean>((resolve) => {
      const c = net.connect(socket);
      c.once("connect", () => (c.destroy(), resolve(true)));
      c.once("error", () => resolve(false));
    });
    expect(live).toBe(false);
  });
});
