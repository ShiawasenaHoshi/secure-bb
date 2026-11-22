import { useState } from "react";
import type { ReactNode } from "react";
import { useRpc } from "@get-bb/plugin-sdk/app";
import type { SecureBbRpc } from "../server";
import type { Overview } from "../src/overview";
import { T } from "../src/text";
import { useCodeAction, CodeField } from "./code";
import { card, btnPrimary, muted, Fold, Msg } from "./ui";

export const dot: Record<string, string> = { ok: "bg-foreground", warn: "bg-muted-foreground", bad: "bg-destructive", unknown: "bg-gray-400" };

export function StageCard({ ov }: { ov: Overview }) {
  const a = ov.assessment;
  const names = ["Ступень 0 — обычный bb", "Ступень 1 — bb с хуком", "Ступень 2 — гейт обязателен", "Ступень 3 — агенты отдельно", "Ступень 4 — сеть закрыта", "Ступень 5 — аутентификация API"];
  return (
    <div className={card}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-lg font-semibold">{names[a.stage]}</h3>
        <span className={muted}>{ov.hookRegistered ? "проверка до загрузки кода" : "режим «после факта»"}</span>
      </div>
      {a.honest.map((h) => (
        <p key={h} className="mt-2 rounded-md border border-border bg-muted p-2">
          {h}
        </p>
      ))}
      <div className="mt-3 grid gap-3 md:grid-cols-2">
        <div>
          <h4 className="font-medium">Что защищено</h4>
          <ul className="list-disc pl-5">{a.protects.map((p) => <li key={p}>{p}</li>)}</ul>
        </div>
        <div>
          <h4 className="font-medium">Чего нет</h4>
          {a.missing.length === 0 ? <p className={muted}>—</p> : <ul className="list-disc pl-5">{a.missing.map((p) => <li key={p}>{p}</li>)}</ul>}
        </div>
      </div>
      <p className="mt-3"><span className="font-medium">Следующий шаг: </span>{a.nextStep}</p>
      <Fold id="stage-checks" className="mt-3" summaryClassName="cursor-pointer font-medium" summary="Проверки">
        <ul className="mt-2 space-y-1.5">
          {a.checks.map((c) => (
            <li key={c.id} className="flex gap-2">
              <span className={`mt-1.5 size-2.5 shrink-0 rounded-full ${dot[c.state]}`} aria-label={c.state} />
              <span><span className="font-medium">{c.label}.</span> {c.detail}</span>
            </li>
          ))}
        </ul>
      </Fold>
    </div>
  );
}

export function Registration({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const [qr, setQr] = useState<{ secret: string; uri: string; matrix: boolean[][] } | null>(null);
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const state = ov.totp.state;

  if (ov.guard) {
    return state === "external" ? (
      <div className={card}>✓ Второй фактор у сторожа: секрет лежит в его каталоге, через bb не проходил и нигде не показывается.</div>
    ) : (
      <div className={`${card} border-2 border-destructive`}>
        <h3 className="text-base font-semibold text-destructive">Второй фактор не зарегистрирован у сторожа</h3>
        <p className="mt-1">Регистрация — только на консоли машины, где работает сторож: <span className="font-mono">sudo sbb-guard totp-register</span> (QR выводится в терминал) или passkey: <span className="font-mono">sbb-guard passkey-enroll</span>. Через bb секрет не проходит, поэтому его не может перехватить плагин.</p>
        {ov.guard.connected ? null : <p className="mt-1 text-destructive">Сторож сейчас не отвечает.</p>}
      </div>
    );
  }

  if (state === "locked") return <div className={card}>✓ Второй фактор (TOTP) зарегистрирован. Секрет больше нигде не показывается.</div>;
  if (state === "external") return <div className={card}>✓ Секрет TOTP берётся из внешнего файла (BB_SECURE_BB_TOTP_FILE).</div>;
  if (state === "external-broken") return <div className={`${card} border-destructive`}>Задан BB_SECURE_BB_TOTP_FILE, но файл не читается или в нём нет секрета. Одобрения невозможны.</div>;

  const blockedByPlugins = ov.thirdPartyRunning.length > 0;
  return (
    <div className={`${card} border-2 border-destructive`}>
      <h3 className="text-base font-semibold text-destructive">Зарегистрируйте второй фактор сейчас</h3>
      {ov.totp.pendingUnattended && qr === null ? (
        <p className="mt-1 rounded-md border border-destructive p-2 text-destructive">
          Регистрация была начата не с этой страницы (кто — см. журнал). Её нельзя подтвердить: нажмите «Начать заново» и сканируйте новый код.
        </p>
      ) : null}
      <p className="mt-1">
        Без неё одобрить плагин нельзя. Сделайте это сразу: до регистрации любой процесс на этой машине (в том числе агент) может её начать раньше вас.
      </p>
      <p className="mt-1 rounded-md border border-destructive p-2 text-destructive">{T.totpFile.registerWarning}</p>
      {blockedByPlugins ? (
        <div className="mt-2">
          <p className="text-destructive">Выключите сторонние плагины — их код интерфейса увидел бы QR-код:</p>
          <ul className="list-disc pl-5 font-mono">{ov.thirdPartyRunning.map((p) => <li key={p}>{p}</li>)}</ul>
        </div>
      ) : null}
      {qr === null ? (
        <button
          className={`${btnPrimary} mt-3`}
          disabled={act.busy || blockedByPlugins}
          onClick={() => void act.run(async () => { await rpc.call("page.ping"); setQr(await rpc.call("totp.begin")); })}
        >
          {state === "pending" ? "Начать заново" : "Показать QR-код"}
        </button>
      ) : (
        <div className="mt-3 space-y-3">
          <QrSvg matrix={qr.matrix} />
          <p>Отсканируйте в приложении-аутентификаторе или введите ключ вручную:</p>
          <p className="break-all font-mono text-base">{qr.secret}</p>
          <div className="flex items-center gap-2">
            <CodeField value={code} onChange={setCode} />
            <button
              className={btnPrimary}
              disabled={act.busy || code.length !== 6}
              onClick={() =>
                void act.run(async () => {
                  await rpc.call("totp.confirm", { code });
                  setQr(null);
                  setCode("");
                })
              }
            >
              Подтвердить и запереть
            </button>
          </div>
        </div>
      )}
      <Msg error={act.error} />
    </div>
  );
}

export function QrSvg({ matrix }: { matrix: boolean[][] }) {
  const quiet = 4;
  const n = matrix.length + quiet * 2;
  const cells: ReactNode[] = [];
  matrix.forEach((row, y) =>
    row.forEach((dark, x) => {
      if (dark) cells.push(<rect key={`${x}-${y}`} x={x + quiet} y={y + quiet} width={1} height={1} />);
    }),
  );
  return (
    <svg viewBox={`0 0 ${n} ${n}`} className="size-56 max-w-full rounded-md border border-border" role="img" aria-label="QR-код для приложения-аутентификатора" shapeRendering="crispEdges">
      {/* A QR code is dark on light in both themes (a scanner reads that polarity only): named colors on purpose, not the theme's. */}
      <rect width={n} height={n} fill="white" />
      <g fill="black">{cells}</g>
    </svg>
  );
}
