import { useState } from "react";
import { useRpc } from "@get-bb/plugin-sdk/app";
import type { SecureBbRpc } from "../server";
import type { Overview } from "../src/overview";
import { createCredential, type CreationOptions } from "../src/webauthn";
import type { PasskeyAssertion } from "../src/guardlink";
import { MODE_DESCRIPTIONS, MODE_NAMES, SAVED_NARROWING, aaguidName, isPasswordManager } from "../src/ux";
import { useCodeAction, CodeField, TouchNote } from "./code";
import { type Rpc, usePasskey, touchFor } from "./touch";
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
