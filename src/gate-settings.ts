// The settings a person changes with a touch: the policy of trust windows, the trusted repositories, the AI scan, publishing. Widening any of them asks `touch`; the table of what widens is guard/src/policy.ts.
import { guardPolicyWidens, localPolicyWidens } from "../guard/src/policy.ts";
import { validateSecondModel } from "./scan/commands.js";
import type { AiSettings } from "./scan/types.js";
import { normalizePattern } from "./taint/repos.js";
import { checkBranch, checkRepoUrl, sameSettings } from "./publish/validate.js";
import type { PublishSettings } from "./publish/types.js";
import { GateError } from "./errors.js";
import type { Policy } from "./store.js";
import { GateFactor } from "./gate-factor.js";

export class GateSettings extends GateFactor {
  // ---- policy -------------------------------------------------------------
  setPolicy(patch: Partial<Policy>, code: string | undefined): Policy {
    const cur = this.store.policy();
    const next: Policy = { ...cur, ...patch };
    if (next.windowMin < 1 || next.capMin < 1 || next.capMin > 1440 || next.windowMin > next.capMin)
      throw new GateError("invalid", "window size must be at least 1 minute and not exceed the ceiling (at most 24 hours)");
    if (next.cfgWindowMin < 1 || next.cfgCapMin < 1 || next.cfgCapMin > 1440 || next.cfgWindowMin > next.cfgCapMin)
      throw new GateError("invalid", "configuration window size must be at least 1 minute and not exceed its ceiling (at most 24 hours)");
    const widens = guardPolicyWidens(cur, next) || localPolicyWidens(cur, next); // policy.ts: the one list of what widens
    if (widens) {
      if (code === undefined) throw new GateError("invalid_code", "widening the policy needs a code");
      this.touch("policy", code);
    }
    this.store.setPolicy(next);
    this.store.log("policy", null, null, { from: cur, to: next, touched: widens });
    return next;
  }
  // ---- trusted repositories (stage 5) -----------------------------------------------
  /** Adds or removes one pattern (`owner/name`, `owner/*`). Both directions need a code: a wider list means less pollution is noticed, a narrower one changes what windows survive. */
  setTrustedRepo(change: { add?: string; remove?: string }, code: string): string[] {
    if ((change.add === undefined) === (change.remove === undefined)) throw new GateError("invalid", "give exactly one of add / remove");
    const raw = (change.add ?? change.remove)!;
    const pattern = normalizePattern(raw);
    if (pattern === null) throw new GateError("invalid", "a trusted repository is `owner/name` or `owner/*` (github.com)");
    this.touch("trusted.repos", code);
    const changed = change.add !== undefined ? this.store.addTrustedRepo(pattern) : this.store.removeTrustedRepo(pattern);
    this.store.log(change.add !== undefined ? "trusted.add" : "trusted.remove", null, null, { pattern, changed });
    return this.store.trustedRepos();
  }
  // ---- AI scan settings (stage 3, spec §8) -------------------------------------
  /**
   * Changes the optional AI scan. Everything is off by default. Switching anything ON needs a code: it sends plugin code to a
   * cloud service (threat model F15). Switching an option OFF needs none: it only sends less (F8).
   */
  setAiSettings(patch: Partial<Omit<AiSettings, "freezePlugins">> & { freezePlugin?: { id: string; on: boolean } }, code: string | undefined): AiSettings {
    const cur = this.store.aiSettings();
    const next: AiSettings = { ...cur, freezePlugins: [...cur.freezePlugins] };
    for (const k of ["enabled", "autoFreeze", "autoExternal", "second"] as const) if (patch[k] !== undefined) next[k] = patch[k]!;
    if (patch.secondModel !== undefined) {
      const name = patch.secondModel.trim();
      const bad = name === "" ? null : validateSecondModel(name);
      if (bad) throw new GateError("invalid", bad);
      next.secondModel = name;
    }
    if (next.second && next.secondModel === "") throw new GateError("invalid", "укажите имя второй модели (не Anthropic) до того, как включать её");
    if (patch.freezePlugin) {
      const { id, on } = patch.freezePlugin;
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(id)) throw new GateError("invalid", "неверный id плагина");
      next.freezePlugins = on ? [...new Set([...next.freezePlugins, id])].sort() : next.freezePlugins.filter((x) => x !== id);
    }
    // Where code goes: a new option, a new plugin on the freeze list, or another second model while the second model is on.
    const switchedOn =
      (!cur.enabled && next.enabled) ||
      (!cur.autoFreeze && next.autoFreeze) ||
      (!cur.autoExternal && next.autoExternal) ||
      (!cur.second && next.second) ||
      (next.second && next.secondModel !== cur.secondModel) ||
      next.freezePlugins.some((id) => !cur.freezePlugins.includes(id));
    if (switchedOn) {
      if (code === undefined) throw new GateError("invalid_code", "включение ИИ-скана или его опции (код плагина уйдёт в облако) требует кода");
      this.touch("ai.settings", code);
    }
    this.store.setAiSettings(next);
    this.store.log("ai.settings", null, null, { from: cur, to: next, touched: switchedOn });
    return next;
  }
  // ---- publishing settings (stage 4, spec §14) ---------------------------------------
  /**
   * Turning publishing on, changing the address or the branch, and turning "on approval" on all need a code:
   * they decide where reviewed code is sent. Turning something off does not (it only publishes less).
   * The token is not a setting: it is a file named by an environment variable of the server.
   */
  setPublishSettings(patch: Partial<PublishSettings>, code: string | undefined): PublishSettings {
    const cur = this.store.publishSettings();
    const next: PublishSettings = { ...cur };
    if (patch.enabled !== undefined) next.enabled = patch.enabled;
    if (patch.onApprove !== undefined) next.onApprove = patch.onApprove;
    if (patch.repoUrl !== undefined) {
      const u = checkRepoUrl(patch.repoUrl, { allowFile: this.d.publishAllowFile });
      if (!u.ok) throw new GateError("invalid", u.error);
      next.repoUrl = u.url;
    }
    if (patch.branch !== undefined) {
      const bad = checkBranch(patch.branch);
      if (bad) throw new GateError("invalid", bad);
      next.branch = patch.branch.trim();
    }
    if (next.enabled && next.repoUrl === "") throw new GateError("invalid", "сначала задайте адрес репозитория");
    if (sameSettings(cur, next)) return cur;
    const widens = (next.enabled && !cur.enabled) || next.repoUrl !== cur.repoUrl || next.branch !== cur.branch || (next.onApprove && !cur.onApprove);
    if (widens) {
      if (code === undefined) throw new GateError("invalid_code", "включение публикации, смена адреса или ветки и публикация при одобрении требуют кода");
      this.touch("publish.settings", code);
    }
    this.store.setPublishSettings(next);
    this.store.log("publish.settings", null, null, { from: cur, to: next, touched: widens });
    return next;
  }
}
