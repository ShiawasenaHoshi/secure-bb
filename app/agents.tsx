import { useState } from "react";
import type { ReactNode } from "react";
import type { Overview } from "../src/overview";
import type { AgentDrift, SettingsPart } from "../src/guardlink";
import { humanError, clockText, agentAlarmText, PARTS_HEADLINE, PARTS_HELP, PART_BACK, PART_BACK_FRESH_NOTE, PART_FRESH_NOTE, PART_KEEP, PART_NO_BACK, drawableParts, isStalePart, partBackNote, partKeptNote, partNeedsFresh, partTitle, agentAcceptProblem, criticalAcceptTitle, manualRollback, criticalMeanings, isCriticalDrift, reconcileSelection, selectableDriftIds, toggleId } from "../src/ux";
import { restoreNote } from "../src/ux";
import { useApproval } from "./approval";
import { useDraftCode, useCodeAction, CodeField, type Rpc, type PasskeyState, usePasskey, TouchNote, touchFor } from "./code";
import { CodeHint, Rich } from "./confirm";
import { card, btn, btnPrimary, input, muted, cardBlocked, btnDanger, when, useSticky, Fold, Msg } from "./ui";

// Guard mode. The guard reads the agents' files (settings, rules, memory, MCP) and compares them with the baseline a human accepted;
// this page is its feed. A critical difference has already closed the windows of trust and marked the thread of its working
// directory polluted (v1: a signal, not a block). Accepting is a touch at the guard: a code or a passkey signature over exactly these ids.
export const CLASS_LABEL: Record<string, string> = { critical: "критично", instructions: "инструкции", other: "прочее" };

export const CLASS_STYLE: Record<string, string> = {
  critical: "border-red-600 bg-red-50 text-red-950 dark:border-red-500 dark:bg-red-950/40 dark:text-red-100",
  instructions: "border-yellow-500/70",
  other: "border-border",
};

/** What an alarm of the watch says: no access, or a link / a swap that led out of what is watched (nothing was read then). */
export const alarmText = (x: { kind: string; error: string }): string => (x.kind === "unreadable" ? `нет доступа (${x.error})` : x.kind === "outside" ? `ссылка ведёт за пределы наблюдаемого — ${x.error}` : `подмена во время чтения — ${x.error}`);

export const CHANGE_LABEL: Record<string, string> = { added: "новый файл", changed: "изменён", removed: "удалён" };

export const SEVERITY_STYLE: Record<string, string> = { block: "font-semibold text-red-700 dark:text-red-400", review: "text-yellow-700 dark:text-yellow-400", info: muted };

/** The alarms of the watch: always on top of the page, not only in its section. */
export function AgentsAlarm({ ov, onShow }: { ov: Overview; onShow: () => void }) {
  const a = ov.agents?.state;
  if (!ov.agents) return null;
  const alarms = a?.alarms ?? [];
  const critical = (a?.drifts ?? []).filter((d) => d.class === "critical" && !d.initial);
  if (ov.agents.error && !a)
    return (
      <div className="rounded-md border-2 border-destructive bg-destructive/10 p-2 text-destructive" role="alert" data-secure-bb-alarm>
        <p className="font-semibold">Наблюдатель за конфигурациями агентов не отвечает</p>
        <p className="mt-1 text-xs">{ov.agents.error}</p>
      </div>
    );
  if (alarms.length === 0 && critical.length === 0) return null;
  const alarmText2 = agentAlarmText();
  return (
    <div className="rounded-md border-2 border-destructive bg-destructive/10 p-2 text-destructive" role="alert" data-secure-bb-alarm>
      {alarms.length > 0 ? (
        <>
          <p className="font-semibold">ТРЕВОГА: защита не может прочитать файлы агентов ({alarms.length})</p>
          <ul className="mt-1 list-disc pl-5 text-xs">{alarms.slice(0, 5).map((x) => <li key={x.path} className="break-all">{x.path} — {alarmText(x)}</li>)}</ul>
          <p className="mt-1 text-xs">Так выглядит снятый ACL на каталоге агентов (его может снять владелец файлов — агент) или сломанные права. Пока доступа нет, наблюдатель слепой: изменения в этих путях никто не видит.</p>
        </>
      ) : null}
      {critical.length > 0 ? (
        <button type="button" className="block w-full text-left" onClick={onShow} data-secure-bb-agents-link>
          <p className="font-semibold underline">Критичные изменения в настройках агентов: {critical.length}</p>
          <p className="mt-1 text-xs">Это файлы с настройками ваших ИИ-агентов: что им разрешено делать без вопросов и какие инструменты подключены. Кто-то (или что-то) их поменял.</p>
          <p className="mt-1 text-xs"><span className="font-semibold">Пока не разобрано:</span> {alarmText2.blocked}</p>
          <p className="mt-1 text-xs"><span className="font-semibold">Работает как раньше:</span> {alarmText2.works}</p>
          <p className="mt-1 text-xs">Нажмите — раздел «Агенты: конфигурации и память» ниже: каждое изменение разбирается отдельно.</p>
        </button>
      ) : null}
    </div>
  );
}

export function DriftCard({ d, picked, onPick, threads, marked, accept }: { d: AgentDrift; picked: boolean; onPick: (on: boolean) => void; threads: string[]; marked: boolean; accept: ReactNode }) {
  const critical = isCriticalDrift(d);
  return (
    <div className={`rounded-lg border-2 p-3 text-sm ${CLASS_STYLE[d.class] ?? "border-border"}`} data-agent-drift={d.id}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        {critical ? (
          <span className="min-w-0 break-all font-semibold">{d.rel}</span>
        ) : (
          <label className="flex min-w-0 items-baseline gap-2">
            <input type="checkbox" checked={picked} onChange={(e) => onPick(e.target.checked)} aria-label={`выбрать ${d.rel}`} />
            <span className="break-all font-semibold">{d.rel}</span>
          </label>
        )}
        <span className={critical ? "font-semibold" : muted}>
          {CLASS_LABEL[d.class] ?? d.class} · {CHANGE_LABEL[d.change] ?? d.change}
          {d.initial ? " · первый просмотр" : ""} · {when(d.firstSeen)}
        </span>
      </div>
      <p className={`break-all text-xs ${muted}`}>
        {d.rootKind === "global" ? "домашний каталог агентов" : `рабочий каталог ${d.rootName}`} · {d.path}
        {threads.length > 0 ? ` · ${threads.length > 1 ? "чаты" : "чат"}: ${threads.join(", ")}` : ""}
      </p>
      {marked ? <p className="mt-1 text-xs font-semibold">Чат помечен «под подозрением»: временное доверие в нём и в его вложенных чатах закрыто.</p> : null}
      {d.reasons.length > 0 ? <ul className="mt-1 list-disc pl-5">{criticalMeanings(d.reasons).map((r, i) => <li key={i}><Rich text={r} /></li>)}</ul> : null}
      {d.findings.length > 0 ? (
        <ul className="mt-1 space-y-0.5 text-xs">
          {d.findings.slice(0, 12).map((f, i) => (
            <li key={i} className={SEVERITY_STYLE[f.severity] ?? ""}>
              {f.severity === "block" ? "⛔ " : ""}{f.rule}{f.line > 0 ? `, строка ${f.line}` : ""}: <span className="break-all font-mono">{f.excerpt}</span>
            </li>
          ))}
        </ul>
      ) : null}
      <Fold id={`drift-${d.id}-diff`} className="mt-1" summaryClassName={`cursor-pointer ${muted}`} summary={<><abbr title="diff — построчное сравнение: что было в файле и что в нём стало" className="cursor-help underline decoration-dotted underline-offset-2">Подробнее: что именно изменилось</abbr>{d.size !== null ? ` · ${d.size} байт` : ""}</>}>
        {d.reasons.length > 0 ? <p className={`mt-1 break-all text-xs ${muted}`}>Техническое описание: {d.reasons.join("; ")}</p> : null}
        <pre className="mt-1 max-h-96 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-background p-2 font-mono text-xs">{d.diff}</pre>
      </Fold>
      {accept}
    </div>
  );
}

/**
 * A settings file's difference split by the path inside the JSON: for each part «Оставить» (mine: it joins the approved settings; a fresh code or touch when it makes
 * the agent more dangerous) and «Вернуть» (theirs: only this goes out of the file, no code). A file that changed between the showing and the action is refused
 * by the guard and the page draws again.
 */
export function PartsPanel({ d, ov, rpc, refetch, canCode, pk }: { d: AgentDrift; ov: Overview; rpc: Rpc; refetch: () => void; canCode: boolean; pk: PasskeyState }) {
  const parts = drawableParts(d.parts);
  const [code, setCode] = useDraftCode(`parts:${d.path}`);
  const [touching, setTouching] = useState<string | null>(null);
  const ap = useApproval();
  const act = useCodeAction(refetch);
  const fileSha = d.newSha;
  if (parts.length === 0 || !fileSha) return null;
  // A refusal because the file moved on is not an error to read: the card is drawn again from the guard's new state.
  const guarded = (fn: () => Promise<unknown>) => async () => {
    try {
      return await fn();
    } catch (e) {
      if (isStalePart(e instanceof Error ? e.message : String(e))) refetch();
      throw e;
    }
  };
  const keep = (p: SettingsPart, by: "passkey" | "code") => {
    const fresh = partNeedsFresh(p);
    void act.run(
      guarded(async () => {
        setTouching(null);
        if (by === "passkey") {
          const t = await touchFor(rpc, { kind: "agents.keepPart", ids: [d.id], partId: p.id, fileSha, danger: fresh }, setTouching);
          if (!t) throw new Error("касание не требуется");
          const r = await rpc.call("agents.keepPart", { id: d.id, partId: p.id, fileSha, danger: fresh, passkey: t.passkey });
          setTouching(null);
          return r;
        }
        const r = await ap.routine(code, (proof) => rpc.call("agents.keepPart", { id: d.id, partId: p.id, fileSha, danger: fresh, ...proof }), fresh);
        setCode("");
        return r;
      }),
      partKeptNote(p, parts.length - 1),
    );
  };
  // Without a code only a tightening; a return that makes the agent more dangerous (a rule the person removed, a ban) is asked the way «Оставить» is.
  const back = (p: SettingsPart, by: "passkey" | "code" | "none") =>
    void act.run(
      guarded(async () => {
        setTouching(null);
        if (by === "passkey") {
          const t = await touchFor(rpc, { kind: "agents.rollbackPart", ids: [d.id], partId: p.id, fileSha }, setTouching);
          if (!t) throw new Error("касание не требуется");
          const r = await rpc.call("agents.rollbackPart", { id: d.id, partId: p.id, fileSha, passkey: t.passkey });
          setTouching(null);
          return r;
        }
        const r = await rpc.call("agents.rollbackPart", { id: d.id, partId: p.id, fileSha, ...(by === "code" ? { code } : {}) });
        if (by === "code") setCode("");
        return r;
      }),
      partBackNote(p),
    );
  const anyFresh = parts.some((p) => partNeedsFresh(p) || p.backDanger !== null);
  return (
    <div className="mt-2 rounded-md border border-border p-2" data-agent-parts={d.id}>
      <p className="font-semibold">{PARTS_HEADLINE}</p>
      <p className={`text-xs ${muted}`}>{PARTS_HELP}</p>
      <ul className="mt-2 space-y-2">
        {parts.map((p) => {
          const fresh = partNeedsFresh(p);
          return (
            <li key={p.id} className="rounded-md border border-border p-2" data-agent-part={p.id}>
              <p className="break-all">{partTitle(p)}</p>
              {fresh ? <p className="text-xs font-semibold text-red-800 dark:text-red-300">{PART_FRESH_NOTE} {p.danger}</p> : null}
              {p.restorable && p.backDanger !== null ? <p className="text-xs font-semibold text-red-800 dark:text-red-300">{PART_BACK_FRESH_NOTE} {p.backDanger}</p> : null}
              <div className="mt-1 flex flex-wrap items-center gap-2">
                {fresh && pk.has ? (
                  <button className={btnDanger} disabled={act.busy || pk.problem !== null} onClick={() => keep(p, "passkey")}>{PART_KEEP}: касанием</button>
                ) : null}
                {fresh && !canCode ? null : (
                  <button className={fresh ? btnDanger : btn} disabled={act.busy || !ap.ready(code, fresh)} onClick={() => keep(p, "code")}>{PART_KEEP}{fresh && pk.has ? " кодом" : ""}</button>
                )}
                {!p.restorable ? <span className={`text-xs ${muted}`}>{PART_NO_BACK}</span> : p.backDanger === null ? (
                  <button className={btnPrimary} disabled={act.busy} onClick={() => back(p, "none")} data-agent-part-back>{PART_BACK}</button>
                ) : (
                  <>
                    {pk.has ? <button className={btnDanger} disabled={act.busy || pk.problem !== null} onClick={() => back(p, "passkey")} data-agent-part-back>{PART_BACK}: касанием</button> : null}
                    {canCode ? <button className={pk.has ? btn : btnDanger} disabled={act.busy || code.length !== 6} onClick={() => back(p, "code")} data-agent-part-back>{PART_BACK}{pk.has ? " кодом" : ""}</button> : null}
                  </>
                )}
              </div>
            </li>
          );
        })}
      </ul>
      {canCode ? (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <CodeField value={code} onChange={setCode} />
          <CodeHint ov={ov} />
          <span className={`text-xs ${muted}`}>{anyFresh ? "код нужен только там, где написано; остальные «Вернуть» кода не требуют" : ap.session ? "или сессия подтверждения" : "для «Оставить»"}</span>
        </div>
      ) : null}
      <TouchNote text={touching} />
      <Msg error={act.error} ok={act.ok} reserve />
    </div>
  );
}

/** One critical difference: what accepting it lets the agent do, and its own fresh touch (a session does not cover it, and neither does a pack). */
export function CriticalAccept({ d, ov, rpc, refetch, canCode, pk }: { d: AgentDrift; ov: Overview; rpc: Rpc; refetch: () => void; canCode: boolean; pk: PasskeyState }) {
  const [code, setCode] = useDraftCode(`drift:${d.id}`);
  const ap = useApproval();
  const [touching, setTouching] = useState<string | null>(null);
  const act = useCodeAction(refetch);
  const title = criticalAcceptTitle(d.reasons);
  const restorable = d.restorable?.ok === true ? d.restorable : null;
  // «Вернуть как было»: the guard writes its own approved copy back through its helper; the touch is for exactly this difference.
  const restore = (by: "passkey" | "code") =>
    void act.run(async () => {
      setTouching(null);
      if (by === "passkey") {
        const t = await touchFor(rpc, { kind: "agents.restore", ids: [d.id] }, setTouching);
        if (!t) throw new Error("касание не требуется");
        const r = await rpc.call("agents.restore", { id: d.id, passkey: t.passkey });
        setTouching(null);
        return r;
      }
      const r = await rpc.call("agents.restore", { id: d.id, code });
      setCode("");
      return r;
    }, "Готово: настройки агента возвращены, тревога снята");
  const accept = (by: "passkey" | "code") =>
    void act.run(async () => {
      setTouching(null);
      if (by === "passkey") {
        const t = await touchFor(rpc, { kind: "agents.accept", ids: [d.id] }, setTouching);
        if (!t) throw new Error("касание не требуется");
        const r = await rpc.call("agents.accept", { ids: [d.id], passkey: t.passkey });
        setTouching(null);
        return { note: `${r.note}. Сторож описал действие так: «${t.description}».` };
      }
      const r = await rpc.call("agents.accept", { ids: [d.id], code });
      setCode("");
      return r;
    }, `принято изменение в ${d.rel}`);
  const reject = () =>
    void act.run(async () => {
      const r = await rpc.call("agents.reject", { ids: [d.id] });
      return { note: r.note };
    }, `отклонено изменение в ${d.rel}: тревога остаётся, пока файл не исправят`);
  const acceptControls = (
    <>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        {pk.has ? <button className={btnDanger} disabled={act.busy || pk.problem !== null} onClick={() => accept("passkey")}>Принять только это: касанием</button> : null}
        {canCode ? (
          <>
            {pk.has ? <span className={muted}>запасной путь — код:</span> : null}
            <CodeField value={code} onChange={setCode} />
            <button className={btnDanger} disabled={act.busy || code.length !== 6} onClick={() => accept("code")}>Принять только это{pk.has ? " кодом" : ""}</button>
          </>
        ) : null}
        <CodeHint ov={ov} />
      </div>
      <p className={`mt-1 text-xs ${muted}`}>Нужен свежий {pk.has ? "код или касание" : "код"} именно на это изменение: сессия и «выбрать все» его не принимают.</p>
    </>
  );
  const stop = ov.agents?.stop;
  return (
    <div className="mt-2 rounded-md border border-red-400 p-2 dark:border-red-700" data-agent-critical-accept={d.id}>
      <p className="font-semibold text-red-800 dark:text-red-300"><Rich text={title} /></p>
      {d.rejected ? <p className="mt-1 text-xs">Вы отклонили это изменение{d.rejectedAt ? ` (${clockText(d.rejectedAt, Date.now())}, кнопкой «Это не я»)` : ""}: в одобренные настройки оно не попало. Но в самом файле оно всё ещё есть, поэтому тревога и пометка «под подозрением» остаются.</p> : null}
      {restorable ? (
        <div className="mt-2" data-agent-restore={d.id}>
          <p>Агент работает с этим изменением прямо сейчас. {restorable.action === "delete" ? "Этого файла в одобренных настройках не было — он будет удалён." : restorable.action === "json" ? "В общем файле настроек агента будут возвращены только списки MCP-серверов, как вы их одобряли; всё остальное в файле останется как есть." : "Файл будет записан в том виде, в каком вы его одобряли."} После этого защита сама перечитает файл и снимет тревогу.</p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            {pk.has ? <button className={btnPrimary} disabled={act.busy || pk.problem !== null} onClick={() => restore("passkey")}>Вернуть как было — касанием</button> : null}
            {canCode ? (
              <>
                {pk.has ? <span className={muted}>запасной путь — код:</span> : null}
                <CodeField value={code} onChange={setCode} />
                <button className={pk.has ? btn : btnPrimary} disabled={act.busy || code.length !== 6} onClick={() => restore("code")}>Вернуть как было{pk.has ? " кодом" : ""}</button>
              </>
            ) : null}
            <CodeHint ov={ov} />
          </div>
          {restoreNote(ap.session !== null) ? <p className="mt-1 text-xs font-semibold" data-agent-restore-fresh={d.id}>{restoreNote(ap.session !== null)}</p> : null}
        </div>
      ) : (
        <p className="mt-2 text-xs" data-agent-no-restore={d.id}>Автоматически вернуть этот файл нельзя{d.restorable && !d.restorable.ok ? `: ${d.restorable.reason}` : ""}</p>
      )}
      <StopAgents rpc={rpc} refetch={refetch} stop={stop} />
      <Fold id={`drift-${d.id}-more`} className="mt-2" summaryClassName={`cursor-pointer text-xs ${muted}`} summary="Подробнее">
        <p className="mt-1 text-xs">Вручную: {manualRollback(d.path, d.reasons)}</p>
        {d.rejected ? null : (
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <button className={btn} disabled={act.busy} onClick={reject} title="Ничего не принимается и не удаляется: изменение помечается как чужое, тревога остаётся, пока файл не исправят. Код не нужен.">Это не я — отклонить</button>
            <span className={`text-xs ${muted}`}>Отклонить — без кода: оно не станет «нормой», тревога останется, файл не изменится.</span>
          </div>
        )}
        <Fold id={`drift-${d.id}-late-accept`} className="mt-2" summaryClassName={`cursor-pointer text-xs ${muted}`} summary="Это всё-таки вы? Принять изменение как есть">
          {acceptControls}
        </Fold>
      </Fold>
      <TouchNote text={touching} />
      <Msg error={act.error} ok={act.ok} reserve />
    </div>
  );
}

/** «Остановить агентов»: no code (a tightening). Says what was done, and honestly what cannot be held. */
export function StopAgents({ rpc, refetch, stop }: { rpc: Rpc; refetch: () => void; stop: NonNullable<Overview["agents"]>["stop"] }) {
  const act = useCodeAction(refetch);
  const stopped = stop?.stoppedAt != null;
  return (
    <div className="mt-2" data-agents-stop>
      <div className="flex flex-wrap items-center gap-2">
        <button className={btnDanger} disabled={act.busy} onClick={() => void act.run(async () => rpc.call("agents.stop", null))} title="Останавливает все работающие чаты. Код не нужен.">Остановить агентов</button>
        <span className={`text-xs ${muted}`}>сразу, без кода</span>
      </div>
      {stopped ? (
        <p className="mt-1 text-xs font-semibold">
          Агенты остановлены{stop?.stoppedAt ? ` (${clockText(stop.stoppedAt, Date.now())})` : ""}. Пока настройки не исправлены, лучше не запускать их снова.
          {stop?.holdAvailable ? " Новые сообщения агентам держатся, пока тревога не снята." : " Но удержать новые сообщения этот bb не позволяет: агенты могут быть запущены снова."}
        </p>
      ) : stop && !stop.holdAvailable ? (
        <p className={`mt-1 text-xs ${muted}`}>Этот bb не умеет удерживать новые сообщения: после остановки агентов их можно запустить снова.</p>
      ) : null}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

export function AgentsSection({ ov, rpc, refetch, showDone }: { ov: Overview; rpc: Rpc; refetch: () => void; showDone: boolean }) {
  const ag = ov.agents;
  const [pickedIds, setPickedIds] = useSticky<number[]>("agents-picked", []);
  const [code, setCode] = useState("");
  const [touching, setTouching] = useState<string | null>(null);
  const act = useCodeAction(refetch);
  const pk = usePasskey(ov);
  if (!ag) return <div className={`${card} ${muted}`}>Наблюдатель работает внутри сторожа решений; здесь его нет (режим сторожа выключен).</div>;
  const st = ag.state;
  if (!st) return <div className={card}><Msg error={ag.error ?? "сторож не ответил"} /></div>;
  if (!st.enabled) return <div className={`${card} ${muted}`}>Сторож запущен без наблюдателя (нет каталога агентов в его настройках).</div>;
  const drifts = st.drifts ?? [];
  const pending = st.initial?.pending ?? 0;
  const firstBaseline = pending > 0 && pending === drifts.length && (st.baselineFiles ?? 0) === 0;
  // The selection keeps what is still there and is not critical; a refresh itself neither adds nor removes anything.
  const chosen = reconcileSelection(pickedIds, drifts);
  const toggle = (id: number, on: boolean) => setPickedIds((p) => toggleId(reconcileSelection(p, drifts), id, on));
  const criticalCount = drifts.filter(isCriticalDrift).length;
  const plain = selectableDriftIds(drifts);
  const accept = (ids: number[], by: "passkey" | "code") =>
    void act.run(async () => {
      const problem = agentAcceptProblem(ids, drifts);
      if (problem) throw new Error(problem);
      setTouching(null);
      if (by === "passkey") {
        const t = await touchFor(rpc, { kind: "agents.accept", ids }, setTouching);
        if (!t) throw new Error("касание не требуется");
        const r = await rpc.call("agents.accept", { ids, passkey: t.passkey });
        setTouching(null);
        setPickedIds([]);
        return { note: `${r.note}. Сторож описал действие так: «${t.description}» (точное действие записано в его журнале).` };
      }
      const r = await rpc.call("agents.accept", { ids, code });
      setCode("");
      setPickedIds([]);
      return r;
    }, ids.length === 1 ? "принято одно изменение" : `приняты изменения: ${ids.length}`);
  const canCode = !pk.keyOnly;
  const buttons = (ids: number[], label: string) =>
    ids.length === 0 ? null : (
      <div className="flex flex-wrap items-center gap-2">
        {pk.has ? (
          <button className={btnPrimary} disabled={act.busy || pk.problem !== null} onClick={() => accept(ids, "passkey")}>
            {label} касанием
          </button>
        ) : null}
        {canCode ? (
          <>
            {pk.has ? <span className={muted}>запасной путь — код:</span> : null}
            <CodeField value={code} onChange={setCode} />
            <button className={pk.has ? btn : btnPrimary} disabled={act.busy || code.length !== 6} onClick={() => accept(ids, "code")}>
              {label}{pk.has ? " кодом" : ""}
            </button>
          </>
        ) : null}
        <CodeHint ov={ov} />
      </div>
    );
  return (
    <div className="space-y-3">
      <div className={`${card} space-y-1`}>
        <p>
          Защита следит за настройками, правилами и памятью агентов и сравнивает их с теми, что вы одобрили. Просмотрено файлов: {st.scannedFiles ?? 0}
          {st.lastScanAt ? `, последний просмотр ${when(st.lastScanAt)}` : ""}.
        </p>
        <Fold id="agents-more" summaryClassName={`cursor-pointer text-xs ${muted}`} summary="Подробнее">
          <p className={`mt-1 text-xs ${muted}`}>
            Одобренных файлов: {st.baselineFiles ?? 0}; каталогов-корней: {st.roots ?? 0}. Рабочие каталоги чатов защита находит сама; каталоги проектов в домашней папке в v1 не просматриваются. Критичное изменение закрывает временное доверие и помечает чат «под подозрением»; в его карточке есть кнопки «Вернуть как было» и «Остановить агентов».
          </p>
        </Fold>
        <div className="flex flex-wrap items-center gap-2">
          <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("agents.scan", null); })}>Просмотреть сейчас</button>
          <span className={`text-xs ${muted}`}>не чаще раза в 10 с</span>
        </div>
      </div>
      {ag.error ? <Msg error={`Защита не ответила на последний запрос: ${humanError(ag.error)}`} /> : null}
      {(st.alarms ?? []).length > 0 ? (
        <div className={cardBlocked} role="alert">
          <p className="font-semibold">Файлы агентов не читаются ({st.alarms!.length})</p>
          <ul className="mt-1 list-disc pl-5 text-xs">{st.alarms!.map((x) => <li key={x.path} className="break-all">{x.path} — {alarmText(x)}</li>)}</ul>
          <p className="mt-1 text-xs">Либо ACL чтения для пользователя сторожа снят или права сломаны, либо агент подсунул ссылку или подменил файл (сторож по ссылкам за пределы наблюдаемого не ходит и ничего оттуда не читает) (установщик выдаёт его, `--undo` снимает). Без него наблюдатель слепой.</p>
        </div>
      ) : null}
      {(st.notes ?? []).length > 0 ? (
        <ul className={`list-disc pl-5 text-xs ${muted}`}>{st.notes!.map((n, i) => <li key={i} className="break-all">{n.text}</li>)}</ul>
      ) : null}
      {firstBaseline ? (
        <div className={`${card} space-y-2 border-yellow-500/70`}>
          <h3 className="font-semibold">Первые одобренные настройки</h3>
          <p>Первый просмотр нашёл {pending} файлов. Если всё это — как должно быть, примите их как есть одним касанием; дальше каждое расхождение будет ждать решения.{criticalCount > 0 ? ` Критичных среди них ${criticalCount}: каждое принимается отдельно, ниже, со своим касанием и своим объяснением, что именно вы разрешаете.` : ""}</p>
          {buttons(plain, "Принять всё как есть")}
        </div>
      ) : null}
      {drifts.length === 0 ? <div className={`${card} ${muted}`}>Расхождений с одобренными настройками нет.</div> : null}
      {drifts.map((d) => (
        <DriftCard key={d.id} d={d} picked={chosen.includes(d.id)} onPick={(on) => toggle(d.id, on)} threads={ag.threads[d.root] ?? []} marked={(ag.threads[d.root] ?? []).some((t) => ag.marked[t]?.includes(d.id))} accept={<>{drawableParts(d.parts).length > 0 ? <PartsPanel d={d} ov={ov} rpc={rpc} refetch={refetch} canCode={canCode} pk={pk} /> : null}{isCriticalDrift(d) ? <CriticalAccept d={d} ov={ov} rpc={rpc} refetch={refetch} canCode={canCode} pk={pk} /> : null}</>} />
      ))}
      {plain.length > 0 && !firstBaseline ? (
        <div className={`${card} space-y-2`}>
          <div className="flex flex-wrap items-center gap-2">
            <button className={btn} onClick={() => setPickedIds(plain)}>Выбрать все ({plain.length}){criticalCount > 0 ? ", кроме критичных" : ""}</button>
            <button className={btn} onClick={() => setPickedIds([])}>Снять выбор</button>
            <span className={muted}>выбрано: {chosen.length}{(st.openTotal ?? 0) > drifts.length ? ` (показаны первые ${drifts.length} из ${st.openTotal})` : ""}</span>
          </div>
          {buttons(chosen, "Принять выбранные")}
          <p className={`text-xs ${muted}`}>Критичные изменения ({criticalCount}) в «выбрать все» не входят: у каждого свой блок с кнопкой выше. «Оставить» — ничего не нажимать: расхождение видно, пока его не примут или пока файл не вернут как был.</p>
        </div>
      ) : null}
      <TouchNote text={touching} />
      <Msg error={act.error} ok={act.ok} reserve />
      {(st.recent ?? []).length > 0 ? (
        <Fold id="agents-recent" summaryClassName={`cursor-pointer ${muted}`} summary={`Недавно закрытые (${st.recent!.length})`}>
          <ul className="mt-1 space-y-1 text-xs">
            {st.recent!.map((d) => (
              <li key={d.id} className="break-all">
                <span className="font-mono">{d.rel}</span> · {CLASS_LABEL[d.class] ?? d.class} · {d.status === "accepted" ? "принято вами" : d.status === "reverted" ? "файл вернули как был" : "заменено более новым изменением"}{d.resolvedAt ? ` ${clockText(d.resolvedAt, Date.now())}` : ""}
              </li>
            ))}
          </ul>
        </Fold>
      ) : null}
    </div>
  );
}
