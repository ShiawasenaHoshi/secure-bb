import { useState } from "react";
import type { Overview } from "../src/overview";
import type { TrustMode } from "../src/guardlink";
import { EXCEPTIONS_EMPTY, EXCEPTIONS_HELP, RESET_NOTE, SAVED_NARROWING, clockText, exceptionRows, exceptionsHeadline, type ExceptionRow, FREQ_SETTING_LABEL, MODE_DESCRIPTIONS, MODE_NAMES, REVOKE_CODE_NOTE, resetConfirmText, resetRows } from "../src/ux";
import { useCodeAction, usePasskey, type Rpc } from "./code";
import { useProof, type AnyProof } from "./confirm";
import { MODE_RANK_UI, ModePicker } from "./mode-picker";
import { muted, useNow, Msg, Section, FoldAccordion } from "./ui";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "../components/ui/alert-dialog";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { EmptyState } from "../components/ui/empty-state";
import { Input } from "../components/ui/input";
import { Switch } from "../components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";

const HOW_IT_WORKS =
  "Новая версия плагина проходит сама, только если её источник «свой» (список ниже) или «известный» (официальный каталог, который назвал владелец сторожу), у плагина есть одобренная версия из того же источника, права не выросли и жёстких флагов нет. Права сторож считает сам, по каталогу плагина; слова плагина о себе не учитываются. Остальное идёт в очередь. Усилить режим — без касания; ослабить — касанием или кодом.";

/** The mode as three cards, «Как это работает» under them, and «Мои источники» as a table. Both are the guard's; the guard checks every touch itself. */
export function TrustSection({ ov, rpc, refetch }: { ov: Overview; rpc: Rpc; refetch: () => void }) {
  const t = ov.guard?.trust ?? null;
  const [entry, setEntry] = useState("");
  const act = useCodeAction(refetch);
  const proof = useProof(ov, rpc, "trust");
  const pk = usePasskey(ov);
  if (!t) return <Card className="p-4 text-sm"><p className={muted}>Этот сторож не знает «доверия по источнику» (старая версия): версии проходят только по одобрению или окну.</p></Card>;
  const mine = t.mySources;
  const oldRepos = ov.trustedRepos.map((r) => `github:${r}`).filter((r) => !mine.includes(r));
  const setMode = (m: TrustMode) => {
    if (m === t.mode) return;
    const weaker = MODE_RANK_UI[m] < MODE_RANK_UI[t.mode];
    void act.run(async () => {
      await proof.run({ kind: "trust.mode", trustMode: m }, (p) => rpc.call("trust.mode", { mode: m, ...p } as never), { optional: true, what: `Режим «${MODE_NAMES[m]}»`, detail: weaker ? `Защита станет слабее: ${MODE_DESCRIPTIONS[m]}` : MODE_DESCRIPTIONS[m] });
      return { note: `Режим: «${MODE_NAMES[m]}».` };
    });
  };
  const add = () => {
    const e = entry.trim();
    if (e === "") return;
    void act.run(async () => {
      await proof.run({ kind: "trust.add", entries: [e] }, (p) => rpc.call("trust.add", { entries: [e], ...p } as never), { what: `Добавить источник «${e}»`, detail: "Новые версии оттуда пойдут без вопросов, пока плагин не попросит новых прав." });
      setEntry("");
      return { note: "Источник добавлен." };
    });
  };
  return (
    <div className="space-y-6">
      <Section title="Режим проверки">
        <ModePicker value={t.mode} onChange={setMode} disabled={act.busy || (pk.has && pk.keyOnly && pk.problem !== null)} />
        <FoldAccordion id="trust-how" title="Как это работает"><p className={muted}>{HOW_IT_WORKS}</p></FoldAccordion>
      </Section>
      <Section title={`Мои источники (${mine.length})`}>
        {mine.length === 0 ? (
          <EmptyState message="Список пуст: ничего не проходит само (кроме окон доверия и одобренных версий)." />
        ) : (
          <Card className="p-0">
            <Table data-secure-bb-sources>
              <TableHeader>
                <TableRow>
                  <TableHead>Источник</TableHead>
                  <TableHead className="w-24 text-right"><span className="sr-only">Действие</span></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {mine.map((e) => (
                  <TableRow key={e}>
                    <TableCell className="break-all font-mono text-xs">{e}</TableCell>
                    <TableCell className="text-right">
                      <Button size="sm" variant="ghost" aria-label={`Убрать источник ${e}`} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("trust.remove", { entry: e } as never); return { note: SAVED_NARROWING }; })}>Убрать</Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        )}
        <p className={`text-xs ${muted}`}>Убрать — без касания. Уже одобренные версии остаются одобренными; следующие версии из этого источника сторож спросит.</p>
        {t.known.length > 0 ? <p className={`text-xs ${muted}`}>Известные источники (названы при запуске сторожа): <span className="font-mono">{t.known.join(", ")}</span></p> : null}
        {t.pluginsRoots === 0 ? <p className="text-sm text-destructive">У сторожа не задан каталог плагинов ядра (<span className="font-mono">--plugins-root</span>): плагины из git сами не пройдут. Плагины с диска (<span className="font-mono">path:</span>) читаются по своему пути.</p> : null}
        <div className="flex flex-wrap items-center gap-2">
          <Input className="min-w-0 flex-1 font-mono text-xs" placeholder="owner/name, owner/* или path:/каталог" aria-label="Новый источник" value={entry} onChange={(e) => setEntry(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") add(); }} />
          <Button size="sm" disabled={act.busy || entry.trim() === "" || !proof.registered} onClick={add}>Добавить</Button>
          {oldRepos.length > 0 ? (
            <Button size="sm" variant="outline" disabled={act.busy || !proof.registered} onClick={() => void act.run(async () => { await proof.run({ kind: "trust.migrate" }, (p) => rpc.call("trust.migrate", p as never), { what: "Перенести «доверенные репозитории» в мои источники" }); return { note: "Перенесено." }; })}>
              Перенести из «доверенных репозиториев» ({oldRepos.length})
            </Button>
          ) : null}
        </div>
        <Msg error={act.error} ok={act.ok} />
      </Section>
    </div>
  );
}

export function ExceptionsTab({ ov, rpc, refetch, freqOff, onFreqOff }: { ov: Overview; rpc: Rpc; refetch: () => void; freqOff: boolean; onFreqOff: (off: boolean) => void }) {
  const now = useNow();
  const act = useCodeAction(refetch);
  const proof = useProof(ov, rpc, "exceptions");
  const [day, setDay] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const input = {
    windows: ov.windows.map((w) => ({ id: w.id, pluginId: w.pluginId, openedAt: w.openedAt, remainingSec: Math.max(0, Math.ceil((Math.min(w.expiresAt, w.hardExpiresAt) - now) / 1000)) })),
    cfgWindows: ov.watch.windows.map((w) => ({ id: w.id, openedAt: w.openedAt, scopeLabels: w.scopeLabels, remainingSec: Math.max(0, Math.ceil((Math.min(w.expiresAt, w.hardExpiresAt) - now) / 1000)) })),
    approvals: ov.plugins.flatMap((p) => p.history.map((a) => ({ ...a, pluginId: p.id }))),
    sources: ov.guard?.trust?.mySources ?? [],
    kept: ov.agents?.state?.kept ?? [],
  };
  const all = exceptionRows(input, now);
  const rows = day ? exceptionRows(input, now, true) : all;
  // «Отозвать» of any kind only tightens: no code. Each calls the rpc that is its own.
  const revoke = async (r: ExceptionRow, proofArg: AnyProof = {}): Promise<void> => {
    switch (r.revoke.kind) {
      case "window":
        await rpc.call("window.close", { windowId: r.revoke.id as number });
        break;
      case "cfgWindow":
        await rpc.call("watch.window.close", { windowId: r.revoke.id as number });
        break;
      case "approval":
        await rpc.call("approval.revoke", { approvalId: r.revoke.id as number });
        break;
      case "source":
        await rpc.call("trust.remove", { entry: r.revoke.id as string } as never);
        break;
      case "kept":
        await rpc.call("agents.revokeKept", { id: r.revoke.id as number, ...proofArg } as never);
        break;
    }
  };
  const reset = () =>
    void act.run(async () => {
      // All of it only tightens: no touch. The mode stays (weakening it takes a touch, so a reset must not do it either).
      // Only what tightens: a kept ban would weaken the agent when taken back, so it stays for a code of its own.
      for (const r of resetRows(all)) await revoke(r);
      setConfirm(false);
      return { note: "Сброшено: окна закрыты, одобрения и оставленные изменения отозваны, «мои источники» очищены. Режим не менялся." };
    });
  const take = (r: ExceptionRow) =>
    void act.run(async () => {
      if (r.needsCode === null) await revoke(r);
      else await proof.run({ kind: "agents.revokeKept", ids: [r.revoke.id as number] }, (p) => revoke(r, p), { what: `Отозвать: ${r.title}`, detail: `${REVOKE_CODE_NOTE} ${r.needsCode}` });
      return { note: "Отозвано." };
    });
  return (
    <div className="space-y-6">
      {ov.guard ? <TrustSection ov={ov} rpc={rpc} refetch={refetch} /> : <Card className={`p-4 text-sm ${muted}`}>Режимы и «мои источники» есть только у сторожа решений.</Card>}
      <Section title={exceptionsHeadline(all.length)}>
        <p className={`text-xs ${muted}`}>{EXCEPTIONS_HELP}</p>
        <label className="flex items-center gap-2 text-sm"><Switch checked={day} onCheckedChange={setDay} aria-label="Только за последние 24 часа" /> только за последние 24 часа</label>
        {rows.length === 0 ? (
          <EmptyState message={EXCEPTIONS_EMPTY} />
        ) : (
          <Card className="p-0">
            <Table data-secure-bb-exceptions>
              <TableHeader>
                <TableRow>
                  <TableHead>Что</TableHead>
                  <TableHead className="hidden sm:table-cell">Когда</TableHead>
                  <TableHead className="hidden sm:table-cell">Чем подтверждено</TableHead>
                  <TableHead className="w-28 text-right"><span className="sr-only">Действие</span></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((r) => (
                  <TableRow key={r.key} data-exception={r.kind}>
                    <TableCell className="whitespace-normal break-words">
                      {r.title}
                      {/* on a narrow screen the two columns are lines under the name: the table does not scroll sideways */}
                      <span className={`block text-xs sm:hidden ${muted}`}>{[r.at === null ? null : clockText(r.at, now), r.detail].filter(Boolean).join(" · ")}</span>
                      {r.needsCode !== null ? <span className="block text-xs font-medium text-destructive sm:hidden">{REVOKE_CODE_NOTE} {r.needsCode}</span> : null}
                    </TableCell>
                    <TableCell className={`hidden whitespace-nowrap text-xs sm:table-cell ${muted}`}>{r.at === null ? "—" : clockText(r.at, now)}</TableCell>
                    <TableCell className={`hidden whitespace-normal break-words text-xs sm:table-cell ${muted}`}>
                      {r.detail ?? "—"}
                      {r.needsCode !== null ? <span className="block font-medium text-destructive">{REVOKE_CODE_NOTE} {r.needsCode}</span> : null}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button size="sm" variant="outline" aria-label={`Отозвать: ${r.title}`} disabled={act.busy} onClick={() => take(r)}>Отозвать</Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        )}
        <Msg error={act.error} ok={act.ok} />
      </Section>
      <Section title="Подсказки">
        <label className="flex items-center gap-2 text-sm" data-secure-bb-freq-setting>
          <Switch checked={!freqOff} onCheckedChange={(on) => onFreqOff(!on)} aria-label={FREQ_SETTING_LABEL} /> {FREQ_SETTING_LABEL}
        </label>
      </Section>
      <section className="space-y-2">
        <p className={`text-xs ${muted}`}>{RESET_NOTE}</p>
        <Button size="sm" variant="outline" onClick={() => setConfirm(true)}>Сбросить к умолчаниям…</Button>
        <AlertDialog open={confirm} onOpenChange={setConfirm}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>{resetConfirmText(all)}</AlertDialogTitle>
              <AlertDialogDescription>{RESET_NOTE}</AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogAction disabled={act.busy} onClick={reset}>Да, сбросить</AlertDialogAction>
              <AlertDialogCancel>Нет</AlertDialogCancel>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </section>
    </div>
  );
}
