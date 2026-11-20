// Config watchdog (spec §7): shared types. Everything here is plain data.

export type Category =
  | "instructions"
  | "skills"
  | "env"
  | "builtins"
  | "catalogs"
  | "account"
  | "connect-hold"
  | "permissions"
  | "providers"
  | "experiments"
  | "safe-mode"
  | "env-setup";

/** What a configuration trust window can be opened on (spec §6: instructions, skills, env, built-in plugins, catalogs). */
export const WINDOW_SCOPES = ["instructions", "skills", "env", "builtins", "catalogs"] as const;
export type WindowScope = (typeof WINDOW_SCOPES)[number];
export const isWindowScope = (c: string): c is WindowScope => (WINDOW_SCOPES as readonly string[]).includes(c);

/** A rollback is only ever one of these three (spec §7: "где безопасно"). */
export type Rollback =
  | { kind: "disable-plugin"; pluginId: string }
  | { kind: "delete-env"; scope: "machine" | "project"; projectId: string | null; name: string }
  | { kind: "restore-instructions" };

/**
 * One watched fact. `value` is compared as a string and is shown to people, so it
 * never holds a secret: hashes and states only (instruction text and env values
 * are not part of it).
 */
export interface Item {
  key: string;
  category: Category;
  /** The unit of observation; if reading it fails, every item of that source is "not observed", never "removed". */
  source: string;
  label: string;
  value: string;
  /** What undoes a change to / the appearance of this item, if anything safe does. */
  rollback?: Rollback;
}

export interface Unobserved {
  source: string;
  reason: string;
}

export interface Observation {
  at: number;
  items: Item[];
  /** Sources that could not be read this time. */
  failed: Unobserved[];
  /** Things the bb API cannot show at all (constant, honest). */
  blind: Unobserved[];
  /** Instruction text, kept only to restore it (held in the plugin's own database). */
  instructionsText: string | null;
}

export type DriftKind = "added" | "removed" | "changed";
export type DriftStatus = "open" | "rolled-back" | "rollback-failed" | "accepted-window" | "accepted-touch" | "reverted";

export interface Drift {
  id: number;
  key: string;
  category: Category;
  source: string;
  kind: DriftKind;
  label: string;
  before: string | null;
  after: string | null;
  firstSeen: number;
  lastSeen: number;
  status: DriftStatus;
  resolvedAt: number | null;
  note: string | null;
  /** Whether a safe rollback exists for this drift (decided when it was found). */
  rollbackable: boolean;
}

export interface SnapshotRow {
  key: string;
  category: Category;
  source: string;
  label: string;
  value: string;
  approvedAt: number;
  via: string;
}

export interface ConfigWindowRow {
  id: number;
  scopes: WindowScope[];
  mode: "sliding" | "fixed";
  sizeSec: number;
  capSec: number;
  openedAt: number;
  expiresAt: number;
  hardExpiresAt: number;
  closedAt: number | null;
  closedReason: string | null;
}

export const SCOPE_LABEL: Record<WindowScope, string> = {
  instructions: "инструкции",
  skills: "скиллы",
  env: "переменные окружения",
  builtins: "встроенные плагины",
  catalogs: "каталоги плагинов",
};

export const CATEGORY_LABEL: Record<Category, string> = {
  instructions: "инструкции",
  skills: "скиллы",
  env: "переменные окружения",
  builtins: "встроенные плагины",
  catalogs: "каталоги плагинов",
  account: "вход в bb-аккаунт",
  "connect-hold": "server-connect-hold.json",
  permissions: "разрешения",
  providers: "настройки провайдеров",
  experiments: "эксперименты",
  "safe-mode": "safe-mode",
  "env-setup": ".bb-env-setup.sh",
};
