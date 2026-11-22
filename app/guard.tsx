import { useState } from "react";
import { useRpc } from "@get-bb/plugin-sdk/app";
import type { SecureBbRpc } from "../server";
import type { Overview } from "../src/overview";
import { createCredential, type CreationOptions } from "../src/webauthn";
import type { PasskeyAssertion } from "../src/guardlink";
import { MODE_DESCRIPTIONS, MODE_NAMES, SAVED_NARROWING, aaguidName, isPasswordManager } from "../src/ux";
import { useCodeAction, CodeField, type Rpc, usePasskey, TouchNote, touchFor } from "./code";
import { card, btn, btnPrimary, input, muted, when, Fold, Msg } from "./ui";

export function GuardAlarm({ ov }: { ov: Overview }) {
  const g = ov.guard;
  if (!g) return null;
  if (!g.connected)
    return (
      <div className="rounded-md border-2 border-destructive bg-destructive/10 p-2 text-destructive" role="alert" data-secure-bb-alarm>
        <p className="font-semibold">Защита решений не отвечает</p>
        <p className="mt-1 text-xs">Ядро держит всё не встроенное: новые плагины не загрузятся, уже загруженные работают. Одобрить сейчас ничего нельзя. Проверьте службу защиты (<span className="font-mono">sbb-guard status</span> на машине). {g.error}</p>
      </div>
    );
  if (g.journal && !g.journal.valid)
    return (
      <div className="rounded-md border-2 border-destructive bg-destructive/10 p-2 text-destructive" role="alert" data-secure-bb-alarm>
        <p className="font-semibold">ТРЕВОГА: журнал защиты повреждён</p>
        <ul className="mt-1 list-disc pl-5 text-xs">{g.journal.problems.slice(0, 5).map((p, i) => <li key={i}>{p.detail}</li>)}</ul>
        <p className="mt-1 text-xs">Файлы защиты изменены не ею. Всё, что она «одобрила» до этого места, нельзя считать надёжным.</p>
      </div>
    );
  return null;
}

/** Registering a key: the token comes from the console of the machine where the guard runs; the key is not active until it is confirmed there. */
export function PasskeyCard({ ov, rpc, refetch, enrollToken }: { ov: Overview; rpc: Rpc; refetch: () => void; enrollToken: string | null }) {
  const pk = ov.guard?.passkey ?? null;
  // The token from the link `sbb-guard setup` printed (#enroll=…) is already in the field; it is sent to the guard (passkey.register) and nowhere else.
  const [token, setToken] = useState(enrollToken ?? "");
  const [touching, setTouching] = useState<string | null>(null);
  const act = useCodeAction(refetch);
  const state = usePasskey(ov);
  if (!pk) return null;
  // «Проверить касание»: the touch `sbb-guard setup` waits for. The guard describes it, the key signs it, the guard writes it into its journal. Nothing is approved.
  const check = () =>
    void act.run(async () => {
      const t = await touchFor(rpc, { kind: "touch", purpose: "setup-check" }, setTouching);
      if (!t) throw new Error("сторож не попросил касания");
      await rpc.call("setup-check", { passkey: t.passkey } as never);
      setTouching(null);
      return { note: "Касание сработало. Ничего не одобрено и не изменено: сторож только записал проверку в журнал." };
    });
  const add = () =>
    void act.run(async () => {
      const first = await rpc.call("passkey.register", { token });
      const options = first.options as CreationOptions | undefined;
      if (!options) throw new Error("сторож не выдал параметры регистрации");
      const made = await createCredential(options, navigator.credentials as never, window.location.origin, pk.origin);
      const done = await rpc.call("passkey.register", { token, ...made });
      setToken("");
      return { note: typeof done.note === "string" ? done.note : "Ключ зарегистрирован; подтвердите его на консоли (y)." };
    });
  return (
    <div className={card}>
      <h3 className="font-semibold">Passkey (касание вместо кода)</h3>
      <p className={`mt-1 ${muted}`}>
        Подпись привязана к действию, которое описал сторож, и годится один раз: код, который прошёл через процесс bb, мог перехватить плагин, подпись — нет.
        Ключи: {pk.keys.length === 0 ? "нет" : pk.keys.map((k) => `${k.label} — хранится: ${aaguidName(k.aaguid)}${k.lastUsedAt ? ` (последний раз ${when(k.lastUsedAt)})` : ""}`).join("; ")}.
        {pk.totpOff ? " Коды (TOTP) у сторожа выключены: подтверждает только ключ." : " Код остаётся запасным путём."}
      </p>
      {pk.keys.some((k) => isPasswordManager(aaguidName(k.aaguid))) ? <p className="mt-2 text-foreground">Ключ сохранён в менеджере паролей, а не в системе. Его расширение в браузере может перехватить запрос на касание: если «ничего не происходит», посмотрите его окно.</p> : null}
      {state.problem ? <p className="mt-2 text-destructive">{state.problem}</p> : null}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <input className="w-52 rounded-md border border-border bg-background px-2 py-1.5 font-mono text-sm" placeholder="XXXX-XXXX-XXXX" aria-label="Токен с консоли сторожа" value={token} onChange={(e) => setToken(e.target.value.slice(0, 40))} />
        <button className={btn} disabled={act.busy || token.trim() === "" || state.problem !== null || !pk.enrollmentOpen} onClick={add}>
          Добавить passkey
        </button>
        {pk.enrollmentOpen ? null : <span className={muted}>Окно регистрации закрыто: на консоли сторожа выполните <span className="font-mono">sbb-guard setup</span> (или <span className="font-mono">passkey-enroll</span>): 5 минут, одноразовый токен.</span>}
      </div>
      {enrollToken !== null && token === enrollToken ? <p className={`mt-1 ${muted}`}>Токен подставлен из ссылки консоли. Нажмите «Добавить passkey» и приложите палец.</p> : null}
      {pk.keys.length > 0 ? (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <button className={btn} disabled={act.busy || state.problem !== null} onClick={check}>Проверить касание</button>
          <span className={muted}>Проверка ничего не одобряет: в журнал сторожа ложится только запись «касание сработало».</span>
        </div>
      ) : null}
      <TouchNote text={touching} />
      <p className={`mt-1 ${muted}`}>Ключ заработает только после подтверждения <span className="font-mono">y</span> на консоли: так вредный плагин не сможет зарегистрировать свой ключ раньше вас. Список и удаление ключей — только консоль (<span className="font-mono">passkey-list</span>, <span className="font-mono">passkey-remove</span>).</p>
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

/** The guard's own words for why a version passed by itself (journal record `approved.source`). */
export const whyOf = (detail: unknown): string | null => {
  const why = (detail as { why?: unknown } | null)?.why;
  return typeof why === "string" ? why : null;
};

export const MODE_RANK_UI = { simple: 0, detailed: 1, strict: 2 } as const;

/** Trust by source and rights: the mode and "my sources". Both are the guard's; the guard checks every touch itself. */
export function TrustCard({ ov, rpc, refetch }: { ov: Overview; rpc: Rpc; refetch: () => void }) {
  const t = ov.guard?.trust ?? null;
  const [entry, setEntry] = useState("");
  const [code, setCode] = useState("");
  const [touching, setTouching] = useState<string | null>(null);
  const act = useCodeAction(refetch);
  const pk = usePasskey(ov);
  if (!t) return <div className={card}><p className={muted}>Этот сторож не знает «доверия по источнику» (старая версия): версии проходят только по одобрению или окну.</p></div>;
  /** Runs one action that may take a touch: a key if there is one and no code was typed, else the code. A narrowing needs none (the guard says so). */
  const touch = (query: Record<string, unknown>, send: (proof: { code?: string; passkey?: PasskeyAssertion }) => Promise<unknown>) =>
    void act.run(async () => {
      const k = pk.has && code.length !== 6 ? await touchFor(rpc, query, setTouching) : null;
      await send(k ? { passkey: k.passkey } : code.length === 6 ? { code } : {});
      setCode("");
      setTouching(null);
      if (k) return { note: `Сохранено касанием. Сторож описал действие так: «${k.description}».` };
      return code.length === 6 ? undefined : { note: SAVED_NARROWING };
    });
  const mine = t.mySources;
  const oldRepos = ov.trustedRepos.map((r) => `github:${r}`).filter((r) => !mine.includes(r));
  return (
    <div className={card}>
      <h3 className="font-semibold">Доверие по источнику и правам</h3>
      <p className={muted}>
        Новая версия плагина проходит сама, только если её источник «свой» (список ниже) или «известный» (официальный каталог, который назвал владелец сторожу), у плагина есть одобренная версия из того же источника, <b>права не выросли</b> и жёстких флагов нет. Права сторож считает сам, по каталогу плагина; слова плагина о себе не учитываются. Остальное идёт в очередь.
      </p>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <span>Режим:</span>
        {(["simple", "detailed", "strict"] as const).map((m) => (
          <button key={m} className={m === t.mode ? btnPrimary : btn} disabled={act.busy || m === t.mode || (MODE_RANK_UI[m] < MODE_RANK_UI[t.mode] && pk.has && pk.keyOnly && pk.problem !== null)} onClick={() => touch({ kind: "trust.mode", trustMode: m }, (proof) => rpc.call("trust.mode", { mode: m, ...proof } as never))}>
            {MODE_NAMES[m]}
          </button>
        ))}
        <span className={muted}>{MODE_DESCRIPTIONS[t.mode]}</span>
      </div>
      <p className={`mt-1 ${muted}`}>Усилить режим — без касания; ослабить — касанием или кодом.</p>
      <h4 className="mt-3 font-medium">Мои источники ({mine.length})</h4>
      {mine.length === 0 ? <p className={muted}>Список пуст: ничего не проходит само (кроме окон доверия и одобренных версий).</p> : (
        <ul className="mt-1 space-y-1 font-mono text-xs">
          {mine.map((e) => (
            <li key={e} className="flex items-center gap-2">
              {e}
              <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("trust.remove", { entry: e } as never); return { note: SAVED_NARROWING }; })}>Убрать</button>
            </li>
          ))}
        </ul>
      )}
      <p className={`mt-1 ${muted}`}>Убрать — без касания. Уже одобренные версии остаются одобренными; следующие версии из этого источника сторож спросит.</p>
      {t.known.length > 0 ? <p className={`mt-2 ${muted}`}>Известные источники (названы при запуске сторожа): <span className="font-mono">{t.known.join(", ")}</span></p> : null}
      {t.pluginsRoots === 0 ? <p className="mt-2 text-destructive">У сторожа не задан каталог плагинов ядра (<span className="font-mono">--plugins-root</span>): плагины из git сами не пройдут. Плагины с диска (<span className="font-mono">path:</span>) читаются по своему пути.</p> : null}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <input className="rounded border border-border bg-transparent px-2 py-1 font-mono text-xs" placeholder="owner/name, owner/* или path:/каталог" value={entry} onChange={(e) => setEntry(e.target.value)} />
        {pk.has ? <span className={muted}>касание или код:</span> : null}
        {pk.keyOnly ? null : <CodeField value={code} onChange={setCode} />}
        <button className={btnPrimary} disabled={act.busy || entry.trim() === "" || (!pk.has && code.length !== 6)} onClick={() => touch({ kind: "trust.add", entries: [entry.trim()] }, (proof) => rpc.call("trust.add", { entries: [entry.trim()], ...proof } as never).then(() => setEntry("")))}>
          Добавить (касание)
        </button>
        {oldRepos.length > 0 ? (
          <button className={btn} disabled={act.busy || (!pk.has && code.length !== 6)} onClick={() => touch({ kind: "trust.migrate" }, (proof) => rpc.call("trust.migrate", proof as never))}>
            Перенести из «доверенных репозиториев» ({oldRepos.length})
          </button>
        ) : null}
      </div>
      {pk.has && pk.problem ? <p className="mt-1 text-destructive">{pk.problem}</p> : null}
      <TouchNote text={touching} />
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

export function GuardCard({ ov, rpc, refetch, enrollToken }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void; enrollToken: string | null }) {
  const g = ov.guard;
  const act = useCodeAction(refetch);
  if (!g) return null;
  return (
    <div className="space-y-3">
      <PasskeyCard ov={ov} rpc={rpc} refetch={refetch} enrollToken={enrollToken} />
      <div className={card}>
        <p>
          Одобрения, окна доверия и секрет второго фактора — у <b>сторожа</b> (отдельный процесс и пользователь ОС). Здесь только интерфейс, проверки и «стоп по новой возможности»: этот плагин может лишь <b>добавить</b> удержание, разрешает только сторож.
        </p>
        <p className={`mt-1 ${muted}`}>
          {g.connected ? "Сторож отвечает." : "Сторож не отвечает."}
          {g.journal ? ` Журнал сторожа: ${g.journal.valid ? "цепочка цела" : "НАРУШЕН"}, записей ${g.journal.entries}, голова ${g.journal.head ?? "—"}.` : ""}
          {" "}Код, введённый здесь, проходит через процесс bb, поэтому вредный плагин мог бы его перехватить (с passkey подпись привязана к действию); после действия в журнале видно, что именно одобрено и чем.
        </p>
        <div className="mt-2">
          <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("guard.verify"); })}>Проверить журнал сторожа</button>
        </div>
        <Msg error={act.error} />
      </div>
      <Fold id="guard-journal" className={card} summaryClassName="cursor-pointer font-medium" summary={`Последние записи журнала сторожа (${g.recent.length})`}>
        <ul className="mt-2 space-y-1 font-mono text-xs">
          {g.recent.map((r) => (
            <li key={r.id} className="break-all">
              #{r.id} {when(r.ts)} {r.kind}{r.pluginId ? ` ${r.pluginId}` : ""}{whyOf(r.detail) ? ` — ${whyOf(r.detail)}` : ""}{r.detail ? ` ${JSON.stringify(r.detail).slice(0, 200)}` : ""}
            </li>
          ))}
        </ul>
      </Fold>
    </div>
  );
}

/** Migration: the approvals this plugin holds, to a file that `sbb-guard import` reads on the console. Works with or without a guard. */
export function MigrationCard({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const [code, setCode] = useState("");
  const [out, setOut] = useState<{ path: string; digest: string; count: number } | null>(null);
  const act = useCodeAction(refetch);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  return (
    <div className={card}>
      <p>Перенос одобрений этого плагина в сторож: выгрузка в файл (с кодом), затем на консоли <span className="font-mono">sudo sbb-guard import &lt;файл&gt;</span> — он покажет каждую строку и спросит подтверждение. Файл делает код внутри bb, поэтому сторож не верит ему без вашего подтверждения; сверьте контрольную сумму.</p>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <CodeField value={code} onChange={setCode} />
        <button className={btn} disabled={act.busy || code.length !== 6 || !registered} onClick={() => void act.run(async () => { setOut(await rpc.call("approvals.export", { code })); setCode(""); })}>
          Выгрузить одобрения
        </button>
      </div>
      {out ? (
        <div className="mt-2 text-xs">
          <p>Выгружено одобрений: {out.count}.</p>
          <p className="break-all font-mono">{out.path}</p>
          <p className="break-all font-mono">sha256 {out.digest}</p>
          <p className="break-all font-mono">sudo sbb-guard import {out.path} --digest {out.digest}</p>
        </div>
      ) : null}
      {!registered ? <p className={`mt-1 ${muted}`}>Нужен зарегистрированный второй фактор.</p> : null}
      <Msg error={act.error} />
    </div>
  );
}

// What the page SHOWS and which button leads where. The decisions are the guard's: every approval here goes through the same RPC and
// the same touch as before; nothing on this part of the page can approve anything the old page could not.
