// Reads the facts the watchdog compares. Every source is read independently and
// best-effort: a failure becomes "not observed" (never "removed", never "fine").
// Only names, states and hashes are kept: no env values (bb does not return
// them), no instruction or skill text in the snapshot.
import { createHash } from "node:crypto";
import { SENSITIVE_BUILTINS } from "../detect.js";
import type { InstalledPluginLite } from "../probe.js";
import type { SkillRef } from "../skills/types.js";
import type { Item, Observation, Unobserved } from "./model.js";

export interface SkillLite {
  id: string;
  name: string;
  scope: string;
  pluginId: string | null;
  manageable: boolean;
  /** Where bb installed the skill from (`github.com/owner/repo/skill`), if it did. */
  registrySkillId?: string | null;
}

/** Everything the watchdog reads from bb. Implemented over `bb.sdk` in server.ts; faked in tests. */
export interface WatchSource {
  listPlugins(): Promise<InstalledPluginLite[]>;
  accountState(): Promise<"signed-in" | "signed-out" | "unknown">;
  connectHoldExists(): boolean | null;
  marketplaces(): Promise<Array<{ name: string; source: string; subdirectory: string | null }>>;
  instructions(): Promise<string>;
  projects(): Promise<Array<{ id: string; name: string }>>;
  skills(projectId: string): Promise<SkillLite[]>;
  /** Hash-able revision of a skill's SKILL.md. */
  skillRevision(projectId: string, skillId: string): Promise<string>;
  machineEnv(): Promise<string[]>;
  projectEnv(projectId: string): Promise<string[]>;
  hosts(): Promise<Array<{ id: string; name: string; maxPermissionMode: string }>>;
  projectPermissionMode(projectId: string): Promise<string | null>;
  providerSettings(pluginId: string): Promise<Record<string, unknown>>;
  experiments(): Promise<Record<string, boolean>>;
  safeMode(): Promise<boolean>;
  /** Content of `.bb-env-setup.sh`, or null when the file does not exist. Throws when it cannot be read. */
  envSetup(projectId: string): Promise<string | null>;
}

/**
 * Thrown by a source for a thing that cannot exist here (a project without a local folder has no
 * `.bb-env-setup.sh`). It is listed as "not applicable", not as "could not be read".
 */
export class NotApplicableError extends Error {}

/** Provider settings that decide how much an agent is fenced in (spec §7, §9). */
export const WATCHED_PROVIDER_SETTINGS: Record<string, string[]> = {
  "provider-claude-code": ["sandboxEnabled", "fullAccessApprovalsEnabled", "chromeEnabled", "artifactsEnabled"],
  "provider-acp": ["customAgents"],
};

/** What bb's API cannot show: said on the page and in `bb secure-bb config`, never silently skipped. */
export const BLIND: Unobserved[] = [
  { source: "env-values", reason: "API bb отдаёт только имена переменных окружения: смена значения уже существующей переменной не наблюдается" },
  { source: "cookies", reason: "импорт cookie во встроенный браузер — разовая команда хост-демона, в состоянии bb следа нет" },
  { source: "claude-code-files", reason: "failIfUnavailable, allowUnsandboxedCommands и политика эскалации лежат в файлах самого Claude Code, не в API bb" },
  { source: "thread-modes", reason: "режим разрешений отдельных тредов (Full Access) в сторож не входит: наблюдаются потолок хоста и режим по умолчанию у проекта" },
];

export const sha = (text: string): string => createHash("sha256").update(text).digest("hex");
const short = (hash: string): string => hash.slice(0, 12);
const builtinKey = (id: string): string => id.replace(/^bb--/, "");

export async function collect(src: WatchSource, now: () => number): Promise<Observation> {
  const items: Item[] = [];
  const failed: Unobserved[] = [];
  const notApplicable: Unobserved[] = [];
  let instructionsText: string | null = null;
  const fail = (source: string, err: unknown) => (err instanceof NotApplicableError ? notApplicable : failed).push({ source, reason: err instanceof Error ? err.message : String(err) });
  const step = async (source: string, fn: () => Promise<void> | void) => {
    try {
      await fn();
    } catch (err) {
      fail(source, err);
    }
  };

  let projects: Array<{ id: string; name: string }> | null = null;
  const skillRefs = new Map<string, SkillRef>();

  await Promise.all([
    step("builtins", async () => {
      const plugins = await src.listPlugins();
      for (const id of SENSITIVE_BUILTINS) {
        const p = plugins.find((x) => x.provenance === "builtin" && builtinKey(x.id) === id);
        items.push({
          key: `builtin:${id}`,
          category: "builtins",
          source: "builtins",
          label: `встроенный плагин ${id}`,
          value: p ? (p.enabled ? "включён" : "выключен") : "нет в этом bb",
          ...(p?.enabled ? { rollback: { kind: "disable-plugin" as const, pluginId: p.id } } : {}),
        });
      }
    }),
    step("account", async () => {
      const state = await src.accountState();
      if (state === "unknown") throw new Error("состояние bb-аккаунта не прочитать (плагин bb-account выключен или не отвечает)");
      items.push({ key: "account", category: "account", source: "account", label: "вход в bb-аккаунт", value: state === "signed-in" ? "выполнен" : "не выполнен" });
    }),
    step("connect-hold", () => {
      const exists = src.connectHoldExists();
      if (exists === null) throw new Error("каталог данных сервера неизвестен");
      items.push({ key: "connect-hold", category: "connect-hold", source: "connect-hold", label: "server-connect-hold.json", value: exists ? "есть" : "нет" });
    }),
    step("catalogs", async () => {
      for (const m of await src.marketplaces()) {
        items.push({ key: `catalog:${m.name}`, category: "catalogs", source: "catalogs", label: `каталог плагинов ${m.name}`, value: `${m.source}${m.subdirectory ? `#${m.subdirectory}` : ""}` });
      }
    }),
    step("instructions", async () => {
      const text = await src.instructions();
      instructionsText = text;
      items.push({
        key: "instructions",
        category: "instructions",
        source: "instructions",
        label: "пользовательские инструкции",
        value: text.length === 0 ? "пусто" : `${short(sha(text))} · ${text.length} симв.`,
        rollback: { kind: "restore-instructions" },
      });
    }),
    step("env:machine", async () => {
      for (const name of await src.machineEnv()) {
        items.push({
          key: `env:machine:${name}`,
          category: "env",
          source: "env:machine",
          label: `переменная ${name} (машина)`,
          value: "задана",
          rollback: { kind: "delete-env", scope: "machine", projectId: null, name },
        });
      }
    }),
    step("hosts", async () => {
      for (const h of await src.hosts()) {
        items.push({ key: `host:${h.id}`, category: "permissions", source: "hosts", label: `потолок разрешений хоста ${h.name}`, value: h.maxPermissionMode });
      }
    }),
    step("experiments", async () => {
      for (const [k, v] of Object.entries(await src.experiments())) {
        items.push({ key: `experiment:${k}`, category: "experiments", source: "experiments", label: `эксперимент ${k}`, value: v ? "включён" : "выключен" });
      }
    }),
    step("safe-mode", async () => {
      items.push({ key: "safe-mode", category: "safe-mode", source: "safe-mode", label: "safe-mode плагинов", value: (await src.safeMode()) ? "включён" : "выключен" });
    }),
    ...Object.entries(WATCHED_PROVIDER_SETTINGS).map(([pluginId, keys]) =>
      step(`provider:${pluginId}`, async () => {
        const values = await src.providerSettings(pluginId);
        for (const k of keys) {
          const v = values[k];
          if (v === undefined) continue;
          // customAgents holds launch commands: compared by hash, never shown.
          const shown = typeof v === "string" ? (v.length === 0 ? "пусто" : `${short(sha(v))} · ${v.length} симв.`) : String(v);
          items.push({ key: `provider:${pluginId}:${k}`, category: "providers", source: `provider:${pluginId}`, label: `${pluginId}: ${k}`, value: shown });
        }
      }),
    ),
    step("projects", async () => {
      projects = await src.projects();
    }),
  ]);

  // Everything that hangs off projects. If the list itself failed, say so for each family.
  if (projects === null) {
    for (const s of ["env:project", "skills", "perm", "envsetup"]) failed.push({ source: s, reason: "список проектов не прочитан" });
  } else {
    const list: Array<{ id: string; name: string }> = projects;
    const globalSkills = new Map<string, Item>();
    let globalSkillsRead = false;
    await Promise.all(
      list.map(async (p) => {
        await step(`env:project:${p.id}`, async () => {
          for (const name of await src.projectEnv(p.id)) {
            items.push({
              key: `env:project:${p.id}:${name}`,
              category: "env",
              source: `env:project:${p.id}`,
              label: `переменная ${name} (проект ${p.name})`,
              value: "задана",
              rollback: { kind: "delete-env", scope: "project", projectId: p.id, name },
            });
          }
        });
        await step(`perm:${p.id}`, async () => {
          items.push({ key: `perm:${p.id}`, category: "permissions", source: `perm:${p.id}`, label: `режим разрешений по умолчанию (проект ${p.name})`, value: (await src.projectPermissionMode(p.id)) ?? "не задан" });
        });
        await step(`envsetup:${p.id}`, async () => {
          const body = await src.envSetup(p.id);
          items.push({ key: `envsetup:${p.id}`, category: "env-setup", source: `envsetup:${p.id}`, label: `.bb-env-setup.sh (проект ${p.name})`, value: body === null ? "нет" : `${short(sha(body))} · ${body.length} симв.` });
        });
        await step(`skills:${p.id}`, async () => {
          const skills = await src.skills(p.id);
          for (const s of skills) {
            // Plugin skills are the gate's business (their code is pinned there): membership only.
            const isPlugin = s.scope === "plugin";
            const projectScoped = s.scope === "bb-project" || s.scope === "shared-project" || s.scope === "provider-project";
            const key = projectScoped ? `skill:${p.id}:${s.scope}:${s.name}` : `skill:${s.scope}:${s.pluginId ?? ""}:${s.name}`;
            if (!skillRefs.has(key)) skillRefs.set(key, { key, id: s.id, projectId: p.id, name: s.name, scope: s.scope, pluginId: s.pluginId, manageable: s.manageable, registrySkillId: s.registrySkillId ?? null });
            // The guard sees the skill even when it cannot be read here (then it marks it unchecked).
            const value = isPlugin ? `плагин ${s.pluginId ?? "?"}` : short(sha(await src.skillRevision(p.id, s.id)));
            const label = `скилл ${s.name} (${s.scope})`;
            if (projectScoped) {
              items.push({ key, category: "skills", source: `skills:${p.id}`, label: `${label}, проект ${p.name}`, value });
            } else if (!globalSkills.has(key)) {
              globalSkills.set(key, { key, category: "skills", source: "skills:global", label, value });
            }
          }
          globalSkillsRead = true;
        });
      }),
    );
    items.push(...globalSkills.values());
    if (!globalSkillsRead && list.length > 0) failed.push({ source: "skills:global", reason: "скиллы не прочитаны ни в одном проекте" });
    if (list.length === 0) failed.push({ source: "skills:global", reason: "нет проектов, через которые можно прочитать скиллы" });
  }

  // Deterministic order (tests, stable page).
  items.sort((a, b) => a.key.localeCompare(b.key));
  return { at: now(), items, failed, notApplicable, blind: BLIND, instructionsText, skillRefs: [...skillRefs.values()] };
}
