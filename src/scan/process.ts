// The only place that starts a model CLI. Everything about *what* to start lives in commands.ts.
import { spawn } from "node:child_process";
import type { CommandSpec, ProcessRunner, RawRun } from "./commands.js";

export const runProcess: ProcessRunner = (spec: CommandSpec) =>
  new Promise<RawRun>((resolve) => {
    let settled = false;
    const done = (r: RawRun) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(r);
    };
    let child: ReturnType<typeof spawn>;
    try {
      // No shell, an explicit environment (not the server's), the empty directory as cwd, a group of its own so a timeout takes the whole tree.
      child = spawn(spec.file, spec.args, { cwd: spec.cwd, env: spec.env, stdio: ["pipe", "pipe", "pipe"], shell: false, detached: true });
    } catch (err) {
      resolve({ kind: "spawn-failed", errno: (err as NodeJS.ErrnoException).code ?? "", message: err instanceof Error ? err.message : String(err) });
      return;
    }
    const kill = () => {
      try {
        if (child.pid) process.kill(-child.pid, "SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    };
    const timer = setTimeout(() => {
      kill();
      done({ kind: "timeout" });
    }, spec.timeoutMs);

    let stdout = "";
    let stderr = "";
    let size = 0;
    let truncated = false;
    child.stdout!.setEncoding("utf8");
    child.stderr!.setEncoding("utf8");
    child.stdout!.on("data", (c: string) => {
      size += c.length;
      if (size > spec.maxOutput) {
        truncated = true;
        kill();
      } else stdout += c;
    });
    child.stderr!.on("data", (c: string) => {
      if (stderr.length < 64 * 1024) stderr += c;
    });
    child.on("error", (err: NodeJS.ErrnoException) => done({ kind: "spawn-failed", errno: err.code ?? "", message: err.message }));
    child.on("close", (code) => done({ kind: "exit", code, stdout, stderr, truncated }));
    child.stdin!.on("error", () => undefined); // the child may exit before reading everything
    child.stdin!.end(spec.stdin);
  });
