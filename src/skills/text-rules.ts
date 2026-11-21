// The text rules live in guard/src/text-rules.ts (one module for the plugin and for the guard, which has no dependencies).
// Here: the re-export the skills code and its tests use, and what only skills need — capabilities of their scripts.
import type { FileClass } from "../../guard/src/text-rules.ts";
import type { SkillCapability } from "./types.js";

export { classify, invisibleInDoc, textFindings, DOC_EXT, type FileClass, type TextFile } from "../../guard/src/text-rules.ts";

// ---- capabilities of scripts that are not JS (JS goes through the AST checks of plugins) -----------------------------
const NET_CODE = /\b(?:requests|urllib|http\.client|aiohttp|httpx|socket|ftplib|smtplib|paramiko|Net::HTTP|open-uri|LWP|curl_exec|fsockopen)\b|file_get_contents\(\s*["']https?|\b(?:curl|wget|nc|ncat|ssh|scp|rsync|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/;
const PROC_CODE = /\b(?:subprocess|os\.system|os\.popen|popen|Popen|pexpect|Start-Process|spawn|system\s*\(|exec[lv]p?\s*\()|`[^`\n]+`/;
const DYN_CODE = /\b(?:eval|exec|compile|__import__|importlib|Invoke-Expression|iex|instance_eval|class_eval)\b\s*\(?/;
const ENV_CODE = /\b(?:os\.environ|os\.getenv|getenv|ENV\[|printenv|\$env:|%[A-Z_]+%)|^\s*env\s*$|\benv\s*\|/m;

export function scriptCapabilities(path: string, content: string, cls: FileClass): SkillCapability[] {
  const caps: SkillCapability[] = [{ kind: "script", detail: [`${path} (${cls})`] }];
  if (cls === "shell" || cls === "windows") caps.push({ kind: "child_process", detail: [`${path}: ${cls === "shell" ? "shell" : "Windows"} script`] });
  else if (PROC_CODE.test(content)) caps.push({ kind: "child_process", detail: [path] });
  if (NET_CODE.test(content)) caps.push({ kind: "network", detail: [path] });
  if (DYN_CODE.test(content)) caps.push({ kind: "dynamic_code", detail: [path] });
  if (ENV_CODE.test(content)) caps.push({ kind: "env", detail: [path] });
  return caps;
}
