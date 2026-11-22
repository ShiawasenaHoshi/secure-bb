import { useRpc } from "@get-bb/plugin-sdk/app";
import type { SecureBbRpc } from "../server";
import type { Overview } from "../src/overview";
import { NOT_OBSERVED, TAINT_LABEL } from "../src/taint/classify";
import type { TaintKind } from "../src/taint/classify";
import { useCodeAction } from "./code";
import { card, btn, muted, when, Fold, Msg } from "./ui";

export function TaintCard({ ov }: { ov: Overview }) {
  return (
    <div className={card}>
      <p>
        Тред, который прочитал недоверенное (веб, чужой репозиторий, инструмент MCP, установка скилла, проект с <span className="font-mono">.bb-env-setup.sh</span>), закрывает окно доверия плагина, если он в его дереве, и окно конфигурации. Окно не открыть заново само: нужно новое касание.
      </p>
      {ov.tainted.length === 0 ? (
        <p className={`mt-2 ${muted}`}>Пока ни один просмотренный тред не отмечен.</p>
      ) : (
        <ul className="mt-2 space-y-1 text-xs">
          {ov.tainted.map((t) => (
            <li key={t.threadId} className="break-all">
              <span className="font-mono">{t.threadId}</span> · {t.kinds.map((k) => TAINT_LABEL[k as TaintKind] ?? k).join(", ")} · {when(t.first)}{t.last !== t.first ? ` … ${when(t.last)}` : ""}
            </li>
          ))}
        </ul>
      )}
      <Fold id="taint-not-observed" className="mt-2" summaryClassName={`cursor-pointer ${muted}`} summary="Что не наблюдается (честно)">
        <ul className="mt-1 list-disc pl-5 text-xs">{NOT_OBSERVED.map((n) => <li key={n}>{n}</li>)}</ul>
        <p className={`mt-1 text-xs ${muted}`}>Источник — история событий треда в API bb. Берутся только события после открытия окна; «проект с .bb-env-setup.sh» считается всегда.</p>
      </Fold>
    </div>
  );
}

export function logExtra(l: Overview["log"][number]): string {
  const d = (l.detail ?? {}) as Record<string, unknown>;
  if (l.kind === "window.taint" || l.kind === "watch.window.taint")
    return ` · окно закрыто: загрязнение (${((d.kinds as string[] | undefined) ?? []).map((k) => TAINT_LABEL[k as TaintKind] ?? k).join(", ")}); ${((d.lines as string[] | undefined) ?? []).join("; ")}`;
  if (l.kind === "trusted.add" || l.kind === "trusted.remove") return ` · ${(d.pattern as string | undefined) ?? ""}`;
  if (l.kind === "journal.alarm") return ` · цепочка нарушена: ${((d.problems as Array<{ kind: string; id: number | null }> | undefined) ?? []).map((p) => `${p.kind}${p.id ? ` #${p.id}` : ""}`).join(", ")}`;
  return "";
}

export function LogCard({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const act = useCodeAction(refetch);
  const j = ov.journal;
  return (
    <div className={card}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className={j.ok ? "text-foreground" : "font-semibold text-destructive"}>
          {j.ok ? `Цепочка хешей цела: ${j.entries} записей, голова ${j.head ?? "—"}` : `Цепочка НАРУШЕНА (${j.problems.length}), записей ${j.entries}`}
        </p>
        <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => rpc.call("journal.verify"))}>Проверить целостность</button>
      </div>
      <p className={`text-xs ${muted}`}>
        Проверено {when(j.checkedAt)}. Каждая запись содержит хеш предыдущей; голова цепочки дополнительно лежит в файле рядом с базой, одобрение без записи в журнале — тоже тревога.
        {j.sealedLegacy > 0 ? ` ${j.sealedLegacy} записей были до цепочки: их целостность до этого момента не доказать.` : ""} Кто может писать и в базу, и в этот файл (тот же пользователь ОС, пока нет ступени 3), перепишет цепочку целиком незаметно.
      </p>
      <Msg error={act.error} />
      {ov.log.length === 0 ? <p className={muted}>Пока пусто.</p> : (
        <ul className="mt-2 space-y-1 font-mono text-xs">
          {ov.log.map((l) => (
            <li key={l.id}>
              {when(l.ts)} · {l.kind}{l.pluginId ? ` · ${l.pluginId}` : ""}
              {l.kind === "window.freeze" ? ` · закреплена версия ${(l.detail as { pinnedVersion?: string | null } | null)?.pinnedVersion ?? "—"}` : ""}
              {l.kind === "totp.begin" ? ` · ${(l.detail as { attended?: boolean; caller?: string } | null)?.attended ? "со страницы" : "НЕ со страницы"} (${(l.detail as { caller?: string } | null)?.caller ?? "?"})` : ""}
              {l.kind === "hold" && (l.detail as { reason?: string } | null)?.reason ? ` · ${(l.detail as { reason: string }).reason}` : ""}
              {logExtra(l)}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
