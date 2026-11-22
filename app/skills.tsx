import { useState } from "react";
import { useRpc } from "@get-bb/plugin-sdk/app";
import type { SecureBbRpc } from "../server";
import type { Overview } from "../src/overview";
import type { SkillQueueView } from "../src/skills/guard";
import { useApproval, RoutineCode } from "./approval";
import { useCodeAction, CodeField } from "./code";
import { card, btn, btnPrimary, input, muted, when, Fold, Msg } from "./ui";

export const skillState: Record<SkillQueueView["state"], string> = {
  held: "в очереди",
  alarm: "тревога",
  removed: "удалён",
  approved: "одобрен",
  gone: "исчез",
};

export function SkillRow({ q, registered, rpc, refetch }: { q: SkillQueueView; registered: boolean; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const ap = useApproval();
  const [code, setCode] = useState("");
  const [ack, setAck] = useState(false);
  const [shown, setShown] = useState<Array<{ path: string; content: string | null }> | null>(null);
  const act = useCodeAction(refetch);
  const isOpen = q.state === "held" || q.state === "alarm";
  const canApprove = isOpen || q.state === "removed";
  const findings = (q.check?.findings ?? []).filter((f) => f.severity !== "info");
  return (
    <div className={`${card} ${isOpen ? (q.decision === "block" ? "border-destructive" : "border-border") : ""}`}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="font-semibold">{q.name} <span className={`text-xs font-normal ${muted}`}>({q.scope})</span></h3>
        <span className={muted}>{skillState[q.state]} · {when(q.firstSeen)}</span>
      </div>
      <p className="break-all">
        {q.decision === "block" ? "Жёсткий признак. " : ""}{q.reason}
        {q.preexisting ? " Был до модуля скиллов: сам не удаляется." : ""}
      </p>
      {q.note ? <p className={muted}>{q.note}</p> : null}
      {findings.length > 0 ? (
        <ul className="mt-1 list-disc pl-5 text-xs">
          {findings.slice(0, 12).map((f, i) => (
            <li key={i} className="break-all">
              <b>{f.severity}</b> <span className="font-mono">{f.rule}</span> {f.file}{f.line ? `:${f.line}` : ""} — {f.excerpt}
            </li>
          ))}
        </ul>
      ) : null}
      {q.check && q.check.capabilities.length > 0 ? (
        <p className={`mt-1 text-xs ${muted}`}>Возможности скриптов: {q.check.capabilities.map((c) => `${c.kind}${c.detail.length ? ` (${c.detail.slice(0, 3).join(", ")})` : ""}`).join("; ")}</p>
      ) : null}
      {q.source ? <p className={`text-xs ${muted}`}>Источник по метке рядом со скиллом: <span className="font-mono">{q.source}</span> (метка не доказательство)</p> : null}
      {q.removed ? (
        <div className="mt-1">
          <p className={`text-xs ${muted}`}>Что было: {q.removed.map((f) => `${f.path} (${f.size})`).join(", ")}</p>
          <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { setShown(await rpc.call("skills.removed", { id: q.id })); })}>Показать содержимое</button>
          {shown ? <div className="mt-2 space-y-2">{shown.map((f) => <pre key={f.path} className="max-h-60 overflow-auto rounded border border-border p-2 text-xs"><b>{f.path}</b>{"\n"}{(f.content ?? "(не прочитан)").slice(0, 6000)}</pre>)}</div> : null}
        </div>
      ) : null}
      {canApprove && registered ? (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <RoutineCode value={code} onChange={setCode} dangerous={q.decision === "block"} />
          {q.decision === "block" ? <label className="flex items-center gap-1 text-xs"><input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} /> принимаю, несмотря на жёсткий признак</label> : null}
          <button className={btn} disabled={act.busy || !ap.ready(code, q.decision === "block") || (q.decision === "block" && !ack)} onClick={() => void act.run(async () => { const r = await ap.routine(code, (proof) => rpc.call("skills.approve", { id: q.id, ...proof, acknowledgeBlock: ack }), q.decision === "block"); setCode(""); setAck(false); return r; })}>
            {q.state === "removed" ? "Одобрить хеш (поставить снова)" : "Одобрить"}
          </button>
          {isOpen && q.removable ? <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("skills.remove", { id: q.id }); })}>Удалить скилл</button> : null}
        </div>
      ) : null}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

export function SkillTrusted({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const [pattern, setPattern] = useState("");
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const run = (change: { add: string } | { remove: string }) =>
    void act.run(async () => {
      const r = await rpc.call("skills.trusted", { ...change, code });
      setCode("");
      setPattern("");
      return r;
    });
  return (
    <div className={card}>
      <p>
        Доверенные источники: репозитории реестра скиллов (<span className="font-mono">owner/repo</span> или <span className="font-mono">owner/*</span>). Скилл, установленный оттуда, чистый по проверкам и не из очереди, принимается без кода. По умолчанию список пуст; менять — только с кодом. Источник определяется по метке рядом со скиллом, которую агент может подделать: проверки при этом всё равно проходят.
      </p>
      {ov.skills.trusted.length === 0 ? <p className={`mt-2 ${muted}`}>Список пуст: любой новый скилл вне окна «скиллы» ждёт вашего кода.</p> : (
        <ul className="mt-2 space-y-1 font-mono text-xs">
          {ov.skills.trusted.map((r) => (
            <li key={r} className="flex items-center gap-2">
              {r}
              <button className={btn} disabled={act.busy || code.length !== 6 || !registered} onClick={() => run({ remove: r })}>Убрать</button>
            </li>
          ))}
        </ul>
      )}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <input className="rounded border border-border bg-transparent px-2 py-1 font-mono text-xs" placeholder="owner/repo или owner/*" value={pattern} onChange={(e) => setPattern(e.target.value)} />
        <CodeField value={code} onChange={setCode} />
        <button className={btnPrimary} disabled={act.busy || code.length !== 6 || pattern.trim() === "" || !registered} onClick={() => run({ add: pattern })}>Добавить</button>
      </div>
      <Msg error={act.error} />
    </div>
  );
}

export function SkillsSection({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const k = ov.skills;
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const act = useCodeAction(refetch);
  return (
    <div className="space-y-3">
      <div className={card}>
        <p>
          {k.baselineAt === null ? <b>Первая проверка ещё не завершена: всё, что есть, будет закреплено как существовавшее до модуля.</b> : <>Закреплено хешей: {k.pinned.total} (встроенные bb: {k.pinned.builtin}, были до модуля: {k.pinned.baseline}, одобрены: {k.pinned.approved}).</>}
          {k.lastScanAt ? ` Последняя проверка — ${when(k.lastScanAt)}.` : ""}
        </p>
        <p className={`mt-1 ${muted}`}>
          Режим «после факта»: у bb нет хука установки скиллов, поэтому скилл уже работал, пока его не проверили. Жёсткий признак — скилл сразу удаляется (если bb позволяет), иначе тревога; сомнительный ждёт здесь, но остаётся установленным. Встроенные скиллы bb только закрепляются.
        </p>
        <div className="mt-2">
          <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("skills.scan"); })}>Проверить сейчас</button>
        </div>
        <Msg error={act.error} />
      </div>
      {k.unchecked.length > 0 ? (
        <div className={`${card} border-border`}>
          <h4 className="font-medium">Не удалось прочитать (проверка не проводилась, в окне не принимаются)</h4>
          <ul className="list-disc pl-5 font-mono text-xs">{k.unchecked.map((u) => <li key={u} className="break-all">{u}</li>)}</ul>
        </div>
      ) : null}
      <h3 className="font-semibold">Очередь скиллов ({k.open.length})</h3>
      {k.open.length === 0 ? <div className={`${card} ${muted}`}>Ничего не ждёт.</div> : k.open.map((q) => <SkillRow key={q.id} q={q} registered={registered} rpc={rpc} refetch={refetch} />)}
      {k.recent.length > 0 ? (
        <Fold id="skills-recent" summaryClassName={`cursor-pointer ${muted}`} summary={`Недавно рассмотренные (${k.recent.length})`}>
          <div className="mt-2 space-y-2">{k.recent.map((q) => <SkillRow key={q.id} q={q} registered={registered} rpc={rpc} refetch={refetch} />)}</div>
        </Fold>
      ) : null}
      <SkillTrusted ov={ov} rpc={rpc} refetch={refetch} />
      <Fold id="skills-blind" className={card} summaryClassName="cursor-pointer font-medium" summary={`Что не видно в скиллах (${k.blind.length})`}>
        <ul className="mt-2 list-disc pl-5">{k.blind.map((b) => <li key={b}>{b}</li>)}</ul>
      </Fold>
    </div>
  );
}


/** Guard mode: is the guard there, is its journal sound, what it has recorded lately. */
