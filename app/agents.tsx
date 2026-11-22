import { useState } from "react";
import type { ReactNode } from "react";
import type { Overview } from "../src/overview";
import type { AgentDrift, SettingsPart } from "../src/guardlink";
import { humanError, clockText, noRestoreText, rejectedDriftText, restoreActionText, agentAlarmText, PARTS_HEADLINE, PARTS_HELP, PART_BACK, PART_BACK_FRESH_NOTE, PART_FRESH_NOTE, PART_KEEP, PART_NO_BACK, drawableParts, isStalePart, partBackNote, partKeptNote, partNeedsFresh, partTitle, agentAcceptProblem, criticalAcceptTitle, manualRollback, criticalMeanings, isCriticalDrift, reconcileSelection, selectableDriftIds, toggleId } from "../src/ux";
import { restoreNote } from "../src/ux";
import { useApproval } from "./approval";
import { useCodeAction } from "./code";
import { type Rpc } from "./touch";
import { Rich } from "./confirm";
import { useProof } from "./proof";
import { card, btn, btnPrimary, input, muted, cardBlocked, btnDanger, when, useSticky, Fold, Msg } from "./ui";

// Guard mode. The guard reads the agents' files (settings, rules, memory, MCP) and compares them with the baseline a human accepted;
// this page is its feed. A critical difference has already closed the windows of trust and marked the thread of its working
// directory polluted (v1: a signal, not a block). Accepting is a touch at the guard: a code or a passkey signature over exactly these ids.
export const CLASS_LABEL: Record<string, string> = { critical: "критично", instructions: "инструкции", other: "прочее" };

export const CLASS_STYLE: Record<string, string> = {
  critical: "border-destructive bg-destructive/10 text-destructive",
  instructions: "border-border",
  other: "border-border",
};

/** What an alarm of the watch says: no access, or a link / a swap that led out of what is watched (nothing was read then). */
export const alarmText = (x: { kind: string; error: string }): string => (x.kind === "unreadable" ? `нет доступа (${x.error})` : x.kind === "outside" ? `ссылка ведёт за пределы наблюдаемого — ${x.error}` : `подмена во время чтения — ${x.error}`);

export const CHANGE_LABEL: Record<string, string> = { added: "новый файл", changed: "изменён", removed: "удалён" };

export const SEVERITY_STYLE: Record<string, string> = { block: "font-semibold text-destructive", review: "text-foreground", info: muted };

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
export function PartsPanel({ d, ov, rpc, refetch }: { d: AgentDrift; ov: Overview; rpc: Rpc; refetch: () => void }) {
  const parts = drawableParts(d.parts);
  const proof = useProof(ov, rpc, `parts:${d.path}`);
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
  const keep = (p: SettingsPart) => {
    const fresh = partNeedsFresh(p);
    void act.run(
      guarded(() => proof.run({ kind: "agents.keepPart", ids: [d.id], partId: p.id, fileSha, danger: fresh }, (pr) => rpc.call("agents.keepPart", { id: d.id, partId: p.id, fileSha, danger: fresh, ...pr } as never), { routine: true, dangerous: fresh, what: `${PART_KEEP}: ${partTitle(p)}`, ...(fresh && p.danger ? { detail: `${PART_FRESH_NOTE} ${p.danger}` } : {}) })),
      partKeptNote(p, parts.length - 1),
    );
  };
  // Without a code only a tightening; a return that makes the agent more dangerous (a rule the person removed, a ban) is asked the way «Оставить» is.
  const back = (p: SettingsPart, asks: boolean) =>
    void act.run(
      guarded(() =>
        asks
          ? proof.run({ kind: "agents.rollbackPart", ids: [d.id], partId: p.id, fileSha }, (pr) => rpc.call("agents.rollbackPart", { id: d.id, partId: p.id, fileSha, ...pr } as never), { what: `${PART_BACK}: ${partTitle(p)}`, ...(p.backDanger ? { detail: `${PART_BACK_FRESH_NOTE} ${p.backDanger}` } : {}) })
          : rpc.call("agents.rollbackPart", { id: d.id, partId: p.id, fileSha }),
      ),
      partBackNote(p),
    );
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
              {fresh ? <p className="text-xs font-semibold text-destructive">{PART_FRESH_NOTE} {p.danger}</p> : null}
              {p.restorable && p.backDanger !== null ? <p className="text-xs font-semibold text-destructive">{PART_BACK_FRESH_NOTE} {p.backDanger}</p> : null}
              <div className="mt-1 flex flex-wrap items-center gap-2">
                <button className={fresh ? btnDanger : btn} disabled={act.busy || !proof.ready()} onClick={() => keep(p)}>{PART_KEEP}</button>
                {!p.restorable ? <span className={`text-xs ${muted}`}>{PART_NO_BACK}</span> : (
                  <button className={p.backDanger === null ? btnPrimary : btnDanger} disabled={act.busy || (p.backDanger !== null && !proof.ready())} onClick={() => back(p, p.backDanger !== null)} data-agent-part-back>{PART_BACK}</button>
                )}
              </div>
            </li>
          );
        })}
      </ul>
      <Msg error={act.error} ok={act.ok} reserve />
    </div>
  );
}

type Crit = { d: AgentDrift; ov: Overview; rpc: Rpc; refetch: () => void };

/** The actions of one critical difference; each takes its own fresh touch (a session does not cover them). */
function useCriticalActions({ d, ov, rpc, refetch }: Crit) {
  const proof = useProof(ov, rpc, `drift:${d.id}`);
  const act = useCodeAction(refetch);
  const title = criticalAcceptTitle(d.reasons);
  // «Вернуть как было»: the guard writes its own approved copy back through its helper; the touch is for exactly this difference.
  const restore = () =>
    void act.run(async () => proof.run({ kind: "agents.restore", ids: [d.id] }, (p) => rpc.call("agents.restore", { id: d.id, ...p } as never), { what: `Вернуть как было: ${d.rel}`, detail: "Файл будет записан в том виде, в каком вы его одобряли." }), "Готово: настройки агента возвращены, тревога снята");
  const accept = () =>
    void act.run(async () => proof.run({ kind: "agents.accept", ids: [d.id] }, (p) => rpc.call("agents.accept", { ids: [d.id], ...p } as never), { what: `Принять изменение в ${d.rel}`, detail: title }), `принято изменение в ${d.rel}`);
  const reject = () =>
    void act.run(async () => {
      const r = await rpc.call("agents.reject", { ids: [d.id] });
      return { note: r.note };
    }, `отклонено изменение в ${d.rel}: тревога остаётся, пока файл не исправят`);
  return { proof, act, title, restore, accept, reject };
}
type CritCtl = ReturnType<typeof useCriticalActions>;

function RestoreBlock({ d, c }: { d: AgentDrift; c: CritCtl }) {
  const ap = useApproval();
  const restorable = d.restorable?.ok === true ? d.restorable : null;
  if (!restorable) return <p className="mt-2 text-xs" data-agent-no-restore={d.id}>{noRestoreText(d.restorable && !d.restorable.ok ? d.restorable.reason : null)}</p>;
  const fresh = restoreNote(ap.session !== null);
  return (
    <div className="mt-2" data-agent-restore={d.id}>
      <p>Агент работает с этим изменением прямо сейчас. {restoreActionText(restorable.action)} После этого защита сама перечитает файл и снимет тревогу.</p>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <button className={btnPrimary} disabled={c.act.busy || !c.proof.ready()} onClick={c.restore}>Вернуть как было</button>
      </div>
      {fresh ? <p className="mt-1 text-xs font-semibold" data-agent-restore-fresh={d.id}>{fresh}</p> : null}
    </div>
  );
}

function LateAccept({ c }: { c: CritCtl }) {
  return (
    <>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <button className={btnDanger} disabled={c.act.busy || !c.proof.ready()} onClick={c.accept}>Принять только это</button>
      </div>
      <p className={`mt-1 text-xs ${muted}`}>Нужен свежий {c.proof.pk.has ? "код или касание" : "код"} именно на это изменение: сессия и «выбрать все» его не принимают.</p>
    </>
  );
}

function MoreFold({ d, c }: { d: AgentDrift; c: CritCtl }) {
  return (
    <Fold id={`drift-${d.id}-more`} className="mt-2" summaryClassName={`cursor-pointer text-xs ${muted}`} summary="Подробнее">
      <p className="mt-1 text-xs">Вручную: {manualRollback(d.path, d.reasons)}</p>
      {d.rejected ? null : (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <button className={btn} disabled={c.act.busy} onClick={c.reject} title="Ничего не принимается и не удаляется: изменение помечается как чужое, тревога остаётся, пока файл не исправят. Код не нужен.">Это не я — отклонить</button>
          <span className={`text-xs ${muted}`}>Отклонить — без кода: оно не станет «нормой», тревога останется, файл не изменится.</span>
        </div>
      )}
      <Fold id={`drift-${d.id}-late-accept`} className="mt-2" summaryClassName={`cursor-pointer text-xs ${muted}`} summary="Это всё-таки вы? Принять изменение как есть">
        <LateAccept c={c} />
      </Fold>
    </Fold>
  );
}

/** One critical difference: what accepting it lets the agent do, and its own fresh touch (a session does not cover it, and neither does a pack). */
export function CriticalAccept(p: Crit) {
  const { d, ov, rpc, refetch } = p;
  const c = useCriticalActions(p);
  return (
    <div className="mt-2 rounded-md border border-destructive p-2" data-agent-critical-accept={d.id}>
      <p className="font-semibold text-destructive"><Rich text={c.title} /></p>
      {d.rejected ? <p className="mt-1 text-xs">{rejectedDriftText(d.rejectedAt, Date.now())}</p> : null}
      <RestoreBlock d={d} c={c} />
      <StopAgents rpc={rpc} refetch={refetch} stop={ov.agents?.stop} />
      <MoreFold d={d} c={c} />
      <Msg error={c.act.error} ok={c.act.ok} reserve />
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

type AgentsState = NonNullable<NonNullable<Overview["agents"]>["state"]>;

/** The selection and the one «accept» for a set of plain differences (a critical one is accepted alone, in its own block). */
function useAcceptSet({ ov, rpc, refetch }: { ov: Overview; rpc: Rpc; refetch: () => void }, drifts: AgentDrift[]) {
  const [pickedIds, setPickedIds] = useSticky<number[]>("agents-picked", []);
  const act = useCodeAction(refetch);
  const proof = useProof(ov, rpc, "agents-accept");
  // The selection keeps what is still there and is not critical; a refresh itself neither adds nor removes anything.
  const chosen = reconcileSelection(pickedIds, drifts);
  const toggle = (id: number, on: boolean) => setPickedIds((p) => toggleId(reconcileSelection(p, drifts), id, on));
  const accept = (ids: number[]) =>
    void act.run(async () => {
      const problem = agentAcceptProblem(ids, drifts);
      if (problem) throw new Error(problem);
      const r = (await proof.run({ kind: "agents.accept", ids }, (p) => rpc.call("agents.accept", { ids, ...p } as never), { what: ids.length === 1 ? "Принять одно изменение в настройках агентов" : `Принять изменения в настройках агентов: ${ids.length}` })) as { note: string };
      setPickedIds([]);
      return r;
    }, ids.length === 1 ? "принято одно изменение" : `приняты изменения: ${ids.length}`);
  return { act, proof, chosen, toggle, accept, setPickedIds };
}
type AcceptSet = ReturnType<typeof useAcceptSet>;

function AcceptButtons({ ids, label, set }: { ids: number[]; label: string; set: AcceptSet }) {
  if (ids.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-2">
      <button className={btnPrimary} disabled={set.act.busy || !set.proof.ready()} onClick={() => set.accept(ids)}>{label}</button>
    </div>
  );
}

function ScanBox({ st, rpc, set }: { st: AgentsState; rpc: Rpc; set: AcceptSet }) {
  return (
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
        <button className={btn} disabled={set.act.busy} onClick={() => void set.act.run(async () => { await rpc.call("agents.scan", null); })}>Просмотреть сейчас</button>
        <span className={`text-xs ${muted}`}>не чаще раза в 10 с</span>
      </div>
    </div>
  );
}

function UnreadableFiles({ st }: { st: AgentsState }) {
  const alarms = st.alarms ?? [];
  if (alarms.length === 0) return null;
  return (
    <div className={cardBlocked} role="alert">
      <p className="font-semibold">Файлы агентов не читаются ({alarms.length})</p>
      <ul className="mt-1 list-disc pl-5 text-xs">{alarms.map((x) => <li key={x.path} className="break-all">{x.path} — {alarmText(x)}</li>)}</ul>
      <p className="mt-1 text-xs">Либо ACL чтения для пользователя сторожа снят или права сломаны, либо агент подсунул ссылку или подменил файл (сторож по ссылкам за пределы наблюдаемого не ходит и ничего оттуда не читает) (установщик выдаёт его, `--undo` снимает). Без него наблюдатель слепой.</p>
    </div>
  );
}

function FirstBaseline({ pending, criticalCount, plain, set }: { pending: number; criticalCount: number; plain: number[]; set: AcceptSet }) {
  return (
    <div className={`${card} space-y-2 border-border`}>
      <h3 className="font-semibold">Первые одобренные настройки</h3>
      <p>Первый просмотр нашёл {pending} файлов. Если всё это — как должно быть, примите их как есть одним касанием; дальше каждое расхождение будет ждать решения.{criticalCount > 0 ? ` Критичных среди них ${criticalCount}: каждое принимается отдельно, ниже, со своим касанием и своим объяснением, что именно вы разрешаете.` : ""}</p>
      <AcceptButtons ids={plain} label="Принять всё как есть" set={set} />
    </div>
  );
}

function SelectAll({ st, drifts, plain, criticalCount, set }: { st: AgentsState; drifts: AgentDrift[]; plain: number[]; criticalCount: number; set: AcceptSet }) {
  const more = (st.openTotal ?? 0) > drifts.length ? ` (показаны первые ${drifts.length} из ${st.openTotal})` : "";
  return (
    <div className={`${card} space-y-2`}>
      <div className="flex flex-wrap items-center gap-2">
        <button className={btn} onClick={() => set.setPickedIds(plain)}>Выбрать все ({plain.length}){criticalCount > 0 ? ", кроме критичных" : ""}</button>
        <button className={btn} onClick={() => set.setPickedIds([])}>Снять выбор</button>
        <span className={muted}>выбрано: {set.chosen.length}{more}</span>
      </div>
      <AcceptButtons ids={set.chosen} label="Принять выбранные" set={set} />
      <p className={`text-xs ${muted}`}>Критичные изменения ({criticalCount}) в «выбрать все» не входят: у каждого свой блок с кнопкой выше. «Оставить» — ничего не нажимать: расхождение видно, пока его не примут или пока файл не вернут как был.</p>
    </div>
  );
}

const closedWord = (status: string): string => (status === "accepted" ? "принято вами" : status === "reverted" ? "файл вернули как был" : "заменено более новым изменением");

function RecentlyClosed({ st }: { st: AgentsState }) {
  const recent = st.recent ?? [];
  if (recent.length === 0) return null;
  return (
    <Fold id="agents-recent" summaryClassName={`cursor-pointer ${muted}`} summary={`Недавно закрытые (${recent.length})`}>
      <ul className="mt-1 space-y-1 text-xs">
        {recent.map((d) => (
          <li key={d.id} className="break-all">
            <span className="font-mono">{d.rel}</span> · {CLASS_LABEL[d.class] ?? d.class} · {closedWord(d.status)}{d.resolvedAt ? ` ${clockText(d.resolvedAt, Date.now())}` : ""}
          </li>
        ))}
      </ul>
    </Fold>
  );
}

function DriftList({ ov, rpc, refetch, drifts, set }: { ov: Overview; rpc: Rpc; refetch: () => void; drifts: AgentDrift[]; set: AcceptSet }) {
  const ag = ov.agents!;
  return (
    <>
      {drifts.length === 0 ? <div className={`${card} ${muted}`}>Расхождений с одобренными настройками нет.</div> : null}
      {drifts.map((d) => {
        const threads = ag.threads[d.root] ?? [];
        const accept = (
          <>
            {drawableParts(d.parts).length > 0 ? <PartsPanel d={d} ov={ov} rpc={rpc} refetch={refetch} /> : null}
            {isCriticalDrift(d) ? <CriticalAccept d={d} ov={ov} rpc={rpc} refetch={refetch} /> : null}
          </>
        );
        return <DriftCard key={d.id} d={d} picked={set.chosen.includes(d.id)} onPick={(on) => set.toggle(d.id, on)} threads={threads} marked={threads.some((t) => ag.marked[t]?.includes(d.id))} accept={accept} />;
      })}
    </>
  );
}

function AgentsBody({ ov, rpc, refetch, st }: { ov: Overview; rpc: Rpc; refetch: () => void; st: AgentsState }) {
  const drifts = st.drifts ?? [];
  const set = useAcceptSet({ ov, rpc, refetch }, drifts);
  const pending = st.initial?.pending ?? 0;
  const firstBaseline = pending > 0 && pending === drifts.length && (st.baselineFiles ?? 0) === 0;
  const criticalCount = drifts.filter(isCriticalDrift).length;
  const plain = selectableDriftIds(drifts);
  const notes = st.notes ?? [];
  return (
    <div className="space-y-3">
      <ScanBox st={st} rpc={rpc} set={set} />
      {ov.agents!.error ? <Msg error={`Защита не ответила на последний запрос: ${humanError(ov.agents!.error)}`} /> : null}
      <UnreadableFiles st={st} />
      {notes.length > 0 ? <ul className={`list-disc pl-5 text-xs ${muted}`}>{notes.map((n, i) => <li key={i} className="break-all">{n.text}</li>)}</ul> : null}
      {firstBaseline ? <FirstBaseline pending={pending} criticalCount={criticalCount} plain={plain} set={set} /> : null}
      <DriftList ov={ov} rpc={rpc} refetch={refetch} drifts={drifts} set={set} />
      {plain.length > 0 && !firstBaseline ? <SelectAll st={st} drifts={drifts} plain={plain} criticalCount={criticalCount} set={set} /> : null}
      <Msg error={set.act.error} ok={set.act.ok} reserve />
      <RecentlyClosed st={st} />
    </div>
  );
}

export function AgentsSection({ ov, rpc, refetch }: { ov: Overview; rpc: Rpc; refetch: () => void; showDone: boolean }) {
  const ag = ov.agents;
  if (!ag) return <div className={`${card} ${muted}`}>Наблюдатель работает внутри сторожа решений; здесь его нет (режим сторожа выключен).</div>;
  const st = ag.state;
  if (!st) return <div className={card}><Msg error={ag.error ?? "сторож не ответил"} /></div>;
  if (!st.enabled) return <div className={`${card} ${muted}`}>Сторож запущен без наблюдателя (нет каталога агентов в его настройках).</div>;
  return <AgentsBody ov={ov} rpc={rpc} refetch={refetch} st={st} />;
}
