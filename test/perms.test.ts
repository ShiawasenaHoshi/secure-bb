import { chmodSync, lchmodSync, mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { describeIssues, serverIds, writableByOthers } from "../src/perms.js";

const ids = serverIds()!;
const mine = { uid: ids.uid, gid: -1 }; // gid -1: no "private group" excuse unless a test asks for it

function tree(): { root: string; plugin: string } {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "sbb-perms-")));
  const plugin = join(root, "parent", "plugin");
  mkdirSync(plugin, { recursive: true });
  writeFileSync(join(plugin, "server.ts"), "export default 1\n");
  for (const d of [root, join(root, "parent"), plugin]) chmodSync(d, 0o755);
  chmodSync(join(plugin, "server.ts"), 0o644);
  return { root, plugin };
}
const paths = (issues: Awaited<ReturnType<typeof writableByOthers>>) => issues.map((i) => `${i.where}:${i.why}`);

describe("writableByOthers (spec: only the server's user may write to where a plugin is installed from)", () => {
  it("accepts a directory only its owner can write, with an owner-only chain above it", async () => {
    const { plugin } = tree();
    // The chain above (the temp dir and "/") belongs to us or root and is not group/other-writable unless sticky.
    expect(await writableByOthers(plugin, mine)).toEqual([]);
  });

  it("flags the directory itself when group or others can write", async () => {
    const { plugin } = tree();
    chmodSync(plugin, 0o775);
    expect(paths(await writableByOthers(plugin, mine))).toEqual(["dir:group-write"]);
    chmodSync(plugin, 0o777);
    expect(paths(await writableByOthers(plugin, mine))).toEqual(["dir:other-write"]);
  });

  it("flags a file inside, and a nested directory", async () => {
    const { plugin } = tree();
    chmodSync(join(plugin, "server.ts"), 0o666);
    mkdirSync(join(plugin, "lib"));
    chmodSync(join(plugin, "lib"), 0o777);
    expect(paths(await writableByOthers(plugin, mine)).sort()).toEqual(["inside:other-write", "inside:other-write"]);
  });

  it("flags a writable PARENT: others could swap the whole directory", async () => {
    const { plugin, root } = tree();
    chmodSync(join(root, "parent"), 0o777);
    const issues = await writableByOthers(plugin, mine);
    expect(issues).toHaveLength(1);
    expect(issues[0]).toMatchObject({ where: "parent", why: "other-write", path: join(root, "parent") });
  });

  it("a sticky world-writable parent (like /tmp) is fine: others cannot replace our entry", async () => {
    const { plugin, root } = tree();
    chmodSync(join(root, "parent"), 0o1777);
    expect(await writableByOthers(plugin, mine)).toEqual([]);
    // ...but a sticky directory that IS the plugin directory lets others add files.
    chmodSync(plugin, 0o1777);
    expect(paths(await writableByOthers(plugin, mine))).toEqual(["dir:other-write"]);
  });

  it("a different owner is flagged everywhere on the chain (unless root)", async () => {
    const { plugin } = tree();
    const issues = await writableByOthers(plugin, { uid: ids.uid + 4242, gid: -1 });
    expect(issues.some((i) => i.where === "dir" && i.why === "owner")).toBe(true);
    expect(issues.some((i) => i.where === "parent" && i.why === "owner")).toBe(true);
    // root-owned entries (the top of the chain) are not flagged
    expect(issues.find((i) => i.path === "/")).toBeUndefined();
  });

  it("a group-writable entry in the user's own private group (gid = uid) is the user's own", async () => {
    const { plugin } = tree();
    chmodSync(plugin, 0o775);
    const st = (await import("node:fs")).lstatSync(plugin);
    // Only when the group really is private (gid === uid) is the excuse valid.
    const excused = await writableByOthers(plugin, { uid: st.uid, gid: st.gid });
    expect(excused.some((i) => i.why === "group-write")).toBe(st.gid !== st.uid);
  });

  it("resolves symlinks first: a link into a writable directory is judged by where it leads", async () => {
    const { plugin, root } = tree();
    const open = join(root, "open");
    mkdirSync(open);
    chmodSync(open, 0o777);
    const link = join(root, "link");
    symlinkSync(open, link);
    const issues = await writableByOthers(link, mine);
    expect(issues[0]).toMatchObject({ where: "dir", why: "other-write", path: open });
    expect(await writableByOthers(plugin, mine)).toEqual([]);
  });

  it("the mode of a symbolic link inside is never judged (on Linux a link is always rwxrwxrwx): node_modules/.bin/* is not «writable by others»", async () => {
    const { plugin } = tree();
    mkdirSync(join(plugin, "node_modules", ".bin"), { recursive: true });
    mkdirSync(join(plugin, "node_modules", "tool"), { recursive: true });
    for (const d of [join(plugin, "node_modules"), join(plugin, "node_modules", ".bin"), join(plugin, "node_modules", "tool")]) chmodSync(d, 0o755);
    writeFileSync(join(plugin, "node_modules", "tool", "cli.js"), "#!/usr/bin/env node\n", { mode: 0o755 });
    const link = join(plugin, "node_modules", ".bin", "tool");
    symlinkSync("../tool/cli.js", link);
    // macOS can give a link its own mode; Linux cannot (it is rwxrwxrwx already)
    if (typeof lchmodSync === "function") {
      try {
        lchmodSync(link, 0o777);
      } catch {
        /* not supported here */
      }
    }
    expect(await writableByOthers(plugin, mine)).toEqual([]);
  });

  it("a real file or directory behind the link is still judged where it really is", async () => {
    const { plugin } = tree();
    mkdirSync(join(plugin, "node_modules", "tool"), { recursive: true });
    for (const d of [join(plugin, "node_modules"), join(plugin, "node_modules", "tool")]) chmodSync(d, 0o755);
    writeFileSync(join(plugin, "node_modules", "tool", "cli.js"), "x\n", { mode: 0o666 });
    chmodSync(join(plugin, "node_modules", "tool", "cli.js"), 0o666);
    symlinkSync("tool/cli.js", join(plugin, "node_modules", "cli"));
    const issues = await writableByOthers(plugin, mine);
    expect(issues.map((i) => i.path)).toEqual([join(plugin, "node_modules", "tool", "cli.js")]);
  });

  it("describes issues for the page", () => {
    expect(describeIssues([{ path: "/a", why: "group-write", where: "parent" }])).toBe("/a (запись для группы, родитель)");
  });
});
