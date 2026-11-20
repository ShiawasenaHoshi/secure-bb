// The watchdog's window onto bb: real SDK calls only (`bb.sdk.*`, the same API the
// `bb` CLI uses). Anything the API does not offer is not invented here: it is listed
// as "not observed" in collect.ts.
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { BbPluginApi } from "@get-bb/plugin-sdk";
import { fetchAccountState, type InstalledPluginLite } from "../probe.js";
import type { SkillLite, WatchSource } from "./collect.js";
import type { WatchActions } from "./watchdog.js";

type Sdk = BbPluginApi["sdk"];
export const CUSTOM_INSTRUCTIONS_PLUGIN = "custom-instructions";

export interface BbSourceDeps {
  sdk: Sdk;
  listPlugins: () => Promise<InstalledPluginLite[]>;
  loopbackBaseUrl: () => string;
  dataDir: () => string;
}

const ABSENT = /not.?found|no such file|enoent|does not exist|404/i;

export function bbWatchSource(d: BbSourceDeps): WatchSource {
  const { sdk } = d;
  return {
    listPlugins: d.listPlugins,
    accountState: () => fetchAccountState(d.loopbackBaseUrl()),
    connectHoldExists() {
      let dir = "";
      try {
        dir = d.dataDir();
      } catch {
        return null;
      }
      return dir ? existsSync(join(dir, "server-connect-hold.json")) : null;
    },
    async marketplaces() {
      const rows = (await sdk.plugins.marketplaces.list()) as Array<{ name: string; source: string; subdirectory?: string | null }>;
      return rows.map((m) => ({ name: m.name, source: m.source, subdirectory: m.subdirectory ?? null }));
    },
    async instructions() {
      const res = await sdk.plugins.getSettings({ pluginId: CUSTOM_INSTRUCTIONS_PLUGIN });
      const v = res.values.instructions;
      if (typeof v !== "string") throw new Error("настройка instructions не строка");
      return v;
    },
    async projects() {
      const rows = (await sdk.projects.list({ includePersonal: true })) as Array<{ id: string; name: string }>;
      return rows.map((p) => ({ id: p.id, name: p.name }));
    },
    async skills(projectId): Promise<SkillLite[]> {
      const res = await sdk.skills.list({ projectId, environmentId: null });
      return res.skills.map((s) => ({ id: s.id, name: s.name, scope: s.scope, pluginId: s.pluginId, manageable: s.manageable }));
    },
    async skillRevision(projectId, skillId) {
      const res = await sdk.skills.getContent({ projectId, environmentId: null, skillId, path: "SKILL.md" });
      return res.revision;
    },
    async machineEnv() {
      return (await sdk.system.machineEnvironment()).variables.map((v) => v.name);
    },
    async projectEnv(projectId) {
      return (await sdk.projects.machineEnvironment({ projectId })).variables.map((v) => v.name);
    },
    async hosts() {
      const rows = (await sdk.hosts.list()) as Array<{ id: string; name: string; maxPermissionMode: string }>;
      return rows.map((h) => ({ id: h.id, name: h.name, maxPermissionMode: h.maxPermissionMode }));
    },
    async projectPermissionMode(projectId) {
      const res = (await sdk.projects.defaultExecutionOptions({ projectId })) as { permissionMode?: string } | null;
      return res?.permissionMode ?? null;
    },
    async providerSettings(pluginId) {
      return (await sdk.plugins.getSettings({ pluginId })).values as Record<string, unknown>;
    },
    async experiments() {
      const cfg = (await sdk.system.config()) as { experiments?: Record<string, boolean> };
      return cfg.experiments ?? {};
    },
    async safeMode() {
      return (await sdk.plugins.experimental_getSafeMode()).enabled;
    },
    async envSetup(projectId) {
      try {
        const res = await sdk.projects.fileContent({ projectId, path: ".bb-env-setup.sh" });
        return res.contentEncoding === "base64" ? Buffer.from(res.content, "base64").toString("utf8") : res.content;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (ABSENT.test(msg)) return null;
        throw err;
      }
    },
  };
}

export function bbWatchActions(sdk: Sdk): WatchActions {
  return {
    async disablePlugin(pluginId) {
      await sdk.plugins.disable({ pluginId });
    },
    async deleteEnv(scope, projectId, name) {
      if (scope === "project" && projectId) await sdk.projects.deleteMachineEnvironmentVariable({ projectId, name });
      else await sdk.system.deleteMachineEnvironmentVariable({ name });
    },
    async restoreInstructions(text) {
      await sdk.plugins.updateSettings({ pluginId: CUSTOM_INSTRUCTIONS_PLUGIN, values: { instructions: text } });
    },
  };
}
