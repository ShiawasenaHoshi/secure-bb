// Approval without "a code for every click" (docs: secure-bb-approval-ux.md §1–2).
//
// The API on 127.0.0.1 has no authentication: any local process, an agent included, can call any RPC. So an approval is always
// proof of a secret the agent does not have: a fresh TOTP code, or the token of an approval session that one code opened on
// a page. The token lives only in the memory of that page; the server keeps its hash.
//
// This file holds the ONE table that says which RPC a session covers ("routine") and which always needs a fresh code
// ("dangerous"). The README prints the same table (generated from it, and a test checks that they agree).
import { createHash, randomBytes } from "node:crypto";
import type { rpcContract } from "./contract.js";

export type RpcName = keyof typeof rpcContract;

/**
 * routine   — a session covers it (or a fresh code, as before).
 * dangerous — always a fresh code; the RPC does not even accept a session token.
 * free      — needs no secret (reads, and changes that only tighten); listed so that no RPC is left out.
 */
export type RpcGroup = "routine" | "dangerous" | "free";

export interface RpcAuth {
  group: RpcGroup;
  /** One line for the README: what it is, and when a routine RPC turns dangerous. */
  note: string;
}

/** Every RPC of the contract, exactly once. A test fails if one is missing, extra, or in a different group than the spec says. */
export const RPC_AUTH = {
  // ---- routine: one session covers them -----------------------------------------------------------------------
  "queue.approve": { group: "routine", note: "одобрить удержанную версию; со снятием блока проверок — dangerous (нужен свежий код)" },
  "queue.dismiss": { group: "free", note: "отклонить удержанную версию: ужесточение, кода не требует и не зависит от блокировки после неверных кодов" },
  "window.open": { group: "routine", note: "открыть/продлить окно доверия; «на всё дерево», когда политика «только тред», — dangerous" },
  "window.close": { group: "free", note: "закрыть окно доверия: ужесточение, кода не требует и не зависит от блокировки после неверных кодов" },
  "approval.revoke": { group: "free", note: "отозвать одобрение версии (выключает плагин): ужесточение, кода не требует и не зависит от блокировки" },
  "watch.accept": { group: "routine", note: "принять расхождение сторожа" },
  "watch.acceptAll": { group: "routine", note: "принять эталон конфигурации целиком" },
  "watch.rollback": { group: "routine", note: "откатить одно расхождение" },
  "watch.window.open": { group: "routine", note: "открыть окно «конфигурация»" },
  "watch.window.close": { group: "free", note: "закрыть окно «конфигурация»: ужесточение, кода не требует" },
  "skills.approve": { group: "routine", note: "одобрить скилл; со снятием блока проверок — dangerous (нужен свежий код)" },
  "batch.approve": { group: "routine", note: "одобрить выбранный список (пакет): версии, скиллы, расхождения; блоки в пакет не входят" },

  // ---- dangerous: always a fresh code -------------------------------------------------------------------------
  "session.open": { group: "dangerous", note: "открыть сессию подтверждения (сама сессия её открыть не может)" },
  "totp.confirm": { group: "dangerous", note: "регистрация второго фактора; повторная невозможна (секрет заперт)" },
  "trusted.set": { group: "dangerous", note: "изменить доверенные репозитории" },
  "skills.trusted": { group: "dangerous", note: "изменить доверенные источники скиллов" },
  "policy.set": { group: "dangerous", note: "размер и потолок окна, режим, «на всё дерево», автопропуск безопасного класса (расширение — со свежим кодом; сужение — без кода)" },
  "watch.rollbackMode": { group: "dangerous", note: "выключить автоматический откат (включение — без кода: это ужесточение)" },
  "ai.settings": { group: "dangerous", note: "включить ИИ-скан или его опцию: код плагина уходит в облако (выключение — без кода)" },
  "publish.settings": { group: "dangerous", note: "включить публикацию, сменить адрес или ветку (выключение — без кода)" },
  "approvals.export": { group: "dangerous", note: "выгрузить одобрения в файл для `sbb-guard import` (перенос в сторож; файл делает код внутри bb, поэтому сторож показывает его целиком и не принимает без подтверждения на консоли)" },
  "sentinel.settings": { group: "dangerous", note: "настройки дозора: включение, провайдер, «во всех тредах», пороги и вопросы (только выключение дозора или сужение «во всех тредах» — без кода)" },

  // ---- free: no secret --------------------------------------------------------------------------------------------
  overview: { group: "free", note: "состояние страницы (только чтение)" },
  "journal.verify": { group: "free", note: "проверка цепочки журнала (только чтение)" },
  "guard.verify": { group: "free", note: "проверка цепочки журнала сторожа (только чтение; в режиме сторожа)" },
  "page.ping": { group: "free", note: "страница открыта (нужно для регистрации)" },
  "totp.begin": { group: "free", note: "начало регистрации: до первого кода, и не при сторонних плагинах" },
  "session.close": { group: "free", note: "«Заблокировать»: закрывает любые сессии, кодом не защищено — это ужесточение" },
  "batch.prepare": { group: "free", note: "зафиксировать список (ничего не одобряет)" },
  "watch.scan": { group: "free", note: "запустить скан конфигурации (кода не требует и раньше)" },
  "skills.scan": { group: "free", note: "запустить скан скиллов (кода не требует и раньше)" },
  "skills.remove": { group: "free", note: "удалить ожидающий скилл (ужесточение)" },
  "skills.removed": { group: "free", note: "показать удалённое (только чтение)" },
  "ai.scan": { group: "free", note: "запустить ИИ-скан (кода не требует и раньше)" },
  "publish.run": { group: "free", note: "опубликовать закреплённую версию (адрес задан кодом ранее)" },
} as const satisfies Record<RpcName, RpcAuth>;

export const groupOf = (rpc: RpcName): RpcGroup => RPC_AUTH[rpc].group;

/** The table as Markdown (README). */
export function authTableMarkdown(): string {
  const label: Record<RpcGroup, string> = { routine: "рутина — покрывает сессия", dangerous: "опасное — всегда свежий код", free: "без кода" };
  const rows = (Object.entries(RPC_AUTH) as Array<[string, RpcAuth]>).map(([rpc, a]) => `| \`${rpc}\` | ${label[a.group]} | ${a.note} |`);
  return ["| RPC | Группа | Что это |", "| --- | --- | --- |", ...rows].join("\n");
}

// ---- session ---------------------------------------------------------------------------------------------------------
export const SESSION_IDLE_MS = 15 * 60_000;
export const SESSION_CAP_MS = 60 * 60_000;

export const hashToken = (token: string): string => createHash("sha256").update(token, "utf8").digest("hex");
export const newToken = (): string => randomBytes(32).toString("base64url");

// ---- proofs ------------------------------------------------------------------------------------------------------------
// What `Gate.touch` accepts: a fresh code (a string), a session token, or the mark "a code for this whole list was just accepted".
// The last two cannot be built outside this module: the mint is not exported, and the gate hands them out only after it
// looked at the RPC table (routine) or consumed the code (batch).
const MINT = Symbol("mint");

export class SessionProof {
  constructor(
    readonly token: string,
    mint: symbol,
  ) {
    if (mint !== MINT) throw new Error("a session proof is made by the gate only");
  }
}
export class ListProof {
  constructor(mint: symbol) {
    if (mint !== MINT) throw new Error("a list proof is made by the gate only");
  }
}
export type Proof = string | SessionProof | ListProof;

/** Only `Gate` calls these. */
export const mintSessionProof = (token: string): SessionProof => new SessionProof(token, MINT);
export const mintListProof = (): ListProof => new ListProof(MINT);

// ---- batch ---------------------------------------------------------------------------------------------------------------
export type BatchKind = "queue" | "skill" | "drift";
export interface BatchItem {
  kind: BatchKind;
  id: number;
  /** What the item is right now (content hash, version…): if it differs when the code arrives, the item is not approved. */
  fingerprint: string;
  label: string;
}

/** Hash of the whole set: order does not matter; any item, id or fingerprint changed changes it. */
export function setHash(items: Array<Pick<BatchItem, "kind" | "id" | "fingerprint">>): string {
  const canon = items.map((i) => [i.kind, i.id, i.fingerprint] as const).sort((a, b) => (a[0] === b[0] ? a[1] - b[1] : a[0] < b[0] ? -1 : 1));
  return createHash("sha256").update(JSON.stringify(canon), "utf8").digest("hex");
}
