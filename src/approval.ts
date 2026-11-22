// Approval without "a code for every click" (docs: secure-bb-approval-ux.md §1–2).
//
// The API on 127.0.0.1 has no authentication: any local process, an agent included, can call any RPC. So an approval is always
// proof of a secret the agent does not have: a fresh TOTP code, or the token of an approval session that one code opened on
// a page. The token lives only in the memory of that page; the server keeps its hash.
// Words: «code» is the one-time code of the second factor (TOTP) and nothing else; what identifies a version is its hash; the plugin's own text is its source.
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
  "queue.approve": { group: "routine", note: "одобрить удержанную версию; со снятием блока проверок — dangerous (нужен свежий код; в режиме «Строгий» и при несовпадении хеша сторож отклоняет в любом случае)" },
  "queue.dismiss": { group: "free", note: "отклонить удержанную версию: ужесточение, кода не требует и не зависит от блокировки после неверных кодов" },
  "window.open": { group: "routine", note: "открыть/продлить окно доверия; «на всё дерево», когда политика «только тред», — dangerous" },
  "window.close": { group: "free", note: "закрыть окно доверия: ужесточение, кода не требует и не зависит от блокировки после неверных кодов" },
  "approval.revoke": { group: "free", note: "отозвать одобрение версии (выключает плагин): ужесточение, кода не требует и не зависит от блокировки" },
  "watch.accept": { group: "routine", note: "принять расхождение сторожа" },
  "watch.acceptAll": { group: "routine", note: "принять эталон конфигурации целиком" },
  "watch.rollback": { group: "routine", note: "откатить одно расхождение" },
  "watch.window.open": { group: "routine", note: "открыть окно «конфигурация»" },
  "agents.rollbackPart": { group: "free", note: "«Вернуть» одну часть изменения файла настроек агента (режим сторожа): откат к одобренному — ужесточение, кода не требует, КРОМЕ отката, который делает агента опаснее (вернуть правило, которое владелец убрал; снять запрет): тогда свежий код или касание (сторож оценивает результат, не название кнопки); только часть открытого расхождения, только по белому списку путей, только против того файла, который показан (иначе конфликт)" },
  "agents.revokeKept": { group: "free", note: "«Отозвать» оставленную часть файла настроек агента (режим сторожа, список исключений): часть уходит из файла и из одобренного вида; кода не требует, КРОМЕ отзыва, который ослабляет агента (оставленный запрет, ask, sandbox): тогда свежий код или касание" },
  "watch.window.close": { group: "free", note: "закрыть окно «конфигурация»: ужесточение, кода не требует" },
  "skills.approve": { group: "routine", note: "одобрить скилл; со снятием блока проверок — dangerous (нужен свежий код)" },
  "agents.keepPart": { group: "routine", note: "«Оставить» одну часть изменения файла настроек агента (режим сторожа): рутина, если часть не делает агента опаснее; если делает (bypass, shell или сеть в allow, hooks, env…) — свежий код или касание, сессия не годится; сторож сам сверяет признак опасности" },
  "batch.approve": { group: "routine", note: "одобрить выбранный список (пакет): версии, скиллы, расхождения; блоки в пакет не входят" },

  // ---- dangerous: always a fresh code -------------------------------------------------------------------------
  "session.open": { group: "dangerous", note: "открыть сессию подтверждения (сама сессия её открыть не может); в режиме сторожа её выдаёт сторож по касанию (код или passkey), у него остаётся только хеш токена" },
  "queue.approveTrust": { group: "dangerous", note: "«Вернуть и доверять источнику» (режим сторожа): одна операция сторожа — одобрить версию и добавить источник в «мои источники»; одно касание, одна запись в журнале; сессия не годится" },
  "totp.confirm": { group: "dangerous", note: "регистрация второго фактора; повторная невозможна (секрет заперт)" },
  "trusted.set": { group: "dangerous", note: "изменить репозитории, которые не загрязняют тред" },
  "skills.trusted": { group: "dangerous", note: "изменить источники скиллов" },
  "policy.set": { group: "dangerous", note: "размер и потолок окна, режим, «на всё дерево», автопропуск безопасного класса (расширение — со свежим кодом; сужение — без кода)" },
  "watch.rollbackMode": { group: "dangerous", note: "выключить автоматический откат (включение — без кода: это ужесточение)" },
  "ai.settings": { group: "dangerous", note: "включить ИИ-скан или его опцию: код плагина уходит в облако (выключение — без кода)" },
  "publish.settings": { group: "dangerous", note: "включить публикацию, сменить адрес или ветку (выключение — без кода)" },
  "setup-check": { group: "dangerous", note: "проверочное касание мастера `sbb-guard setup` (режим сторожа): ничего не одобряет и не меняет, только запись в журнале сторожа; нужна подпись passkey, сессия не годится" },
  "approvals.export": { group: "dangerous", note: "выгрузить одобрения в файл для `sbb-guard import` (перенос в сторож; файл делает код внутри bb, поэтому сторож показывает его целиком и не принимает без подтверждения на консоли)" },
  "agents.accept": { group: "dangerous", note: "принять расхождения в конфигурациях и памяти агентов в эталон наблюдателя: касание у сторожа (код или подпись passkey под эти расхождения), сессия не годится" },
  "agents.restore": { group: "dangerous", note: "«Вернуть как было» (режим сторожа): сторож через помощника sbb-restore записывает файл агента из СВОИХ одобренных настроек (или удаляет файл, которого там нет); нужно свежее касание на это расхождение, сессия не годится: иначе вредный процесс откатывал бы законные изменения владельца" },
  "trust.mode": { group: "dangerous", note: "режим доверия по источнику (Простой/Подробный/Строгий) у сторожа: ослабить — касание или код (сторож проверяет сам); усилить — без касания" },
  "trust.add": { group: "dangerous", note: "добавить «мой источник» (репозиторий или каталог, версии которого проходят сами при тех же правах): касание у сторожа, сессия не годится" },
  "trust.migrate": { group: "dangerous", note: "перенести старый список «репозитории, которые не загрязняют тред» в «мои источники» сторожа: касание, сессия не годится" },
  "sentinel.settings": { group: "dangerous", note: "настройки дозора: включение, провайдер, «во всех тредах», пороги и вопросы (только выключение дозора или сужение «во всех тредах» — без кода)" },

  // ---- free: no secret --------------------------------------------------------------------------------------------
  overview: { group: "free", note: "состояние страницы (только чтение)" },
  "journal.verify": { group: "free", note: "проверка цепочки журнала (только чтение)" },
  "alive.ack": { group: "free", note: "«Понятно» на спокойной строке о простое плагина в режиме сторожа; красную тревогу не скрывает" },
  "guard.verify": { group: "free", note: "проверка цепочки журнала сторожа (только чтение; в режиме сторожа)" },
  "passkey.challenge": { group: "free", note: "вызов у сторожа под конкретное действие (в режиме сторожа): сам ничего не разрешает, разрешает только подпись ключа на касании" },
  "passkey.register": { group: "free", note: "регистрация passkey (в режиме сторожа): нужен одноразовый токен с консоли сторожа, а ключ активен только после подтверждения `y` на консоли" },
  "page.ping": { group: "free", note: "страница открыта (нужно для регистрации)" },
  "totp.begin": { group: "free", note: "начало регистрации: до первого кода, и не при сторонних плагинах" },
  "session.close": { group: "free", note: "«Заблокировать»: закрывает любые сессии, кодом не защищено — это ужесточение" },
  "batch.prepare": { group: "free", note: "зафиксировать список (ничего не одобряет)" },
  "watch.scan": { group: "free", note: "запустить скан конфигурации (кода не требует и раньше)" },
  "skills.scan": { group: "free", note: "запустить скан скиллов (кода не требует и раньше)" },
  "trust.remove": { group: "free", note: "убрать «мой источник»: ужесточение, кода не требует и не зависит от блокировки после неверных кодов" },
  "skills.remove": { group: "free", note: "удалить ожидающий скилл (ужесточение)" },
  "skills.removed": { group: "free", note: "показать удалённое (только чтение)" },
  "agents.reject": { group: "free", note: "«Это не я — отклонить» изменение конфигурации агента: ужесточение, кода не требует; в эталон ничего не идёт, тревога и загрязнение остаются, пока файл не исправят" },
  "agents.stop": { group: "free", note: "«Остановить агентов»: остановить все работающие треды (threads.stop) и держать новые ходы, пока критичное расхождение не устранено: ужесточение, кода не требует" },
  "agents.scan": { group: "free", note: "попросить сторожа просмотреть файлы агентов (не чаще раза в 10 с; только чтение; в режиме сторожа)" },
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
// The session's numbers (15 minutes idle, one hour at most) and what it covers are the guard's: guard/src/session-rules.ts.

export const hashToken = (token: string): string => createHash("sha256").update(token, "utf8").digest("hex");
export const newToken = (): string => randomBytes(32).toString("base64url");

// ---- proofs ------------------------------------------------------------------------------------------------------------
// What `Gate.touch` accepts: a fresh code (a string), a session token, or the mark "a touch for this whole list was just accepted".
// The mint is not exported, so these two marks cannot be built by `new` outside this module. That is a guard against a slip, not a wall: the mint FUNCTIONS
// (`mintSessionProof`, `mintListProof`) are exported, and `Gate` and `server.ts` call them. `mintListProof` is called by the server for what the guard has
// checked («guard touched», see `GuardTouched`) and by the gate for a batch whose code it consumed; the session mark is handed out by the gate only,
// after it looked at the RPC table (routine).
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
/** The mark of «the guard checked the touch for this action»: made by `mintListProof` in the server and compared with `===` where it is expected. */
export type GuardTouched = ListProof;

/** Called by `Gate` (session, batch) and by `server.ts` (the guard's touch): the code that decides what a mark stands for. Nothing else should call them. */
export const mintSessionProof = (token: string): SessionProof => new SessionProof(token, MINT);
export const mintListProof = (): ListProof => new ListProof(MINT);

// ---- batch ---------------------------------------------------------------------------------------------------------------
export type BatchKind = "queue" | "skill" | "drift";
export interface BatchItem {
  kind: BatchKind;
  id: number;
  /** What the item is right now (content hash, version…): if it differs when the touch arrives, the item is not approved. */
  fingerprint: string;
  label: string;
}

/** Hash of the whole set: order does not matter; any item, id or fingerprint changed changes it. */
export function setHash(items: Array<Pick<BatchItem, "kind" | "id" | "fingerprint">>): string {
  const canon = items.map((i) => [i.kind, i.id, i.fingerprint] as const).sort((a, b) => (a[0] === b[0] ? a[1] - b[1] : a[0] < b[0] ? -1 : 1));
  return createHash("sha256").update(JSON.stringify(canon), "utf8").digest("hex");
}
