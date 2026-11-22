// The page's card of a critical change (app.tsx): buttons instead of a manual instruction (principle «автоматически по умолчанию, подробности по кнопке»).
import { describe, expect, it } from "vitest";
import { appFile } from "./support/app-source";

const app = appFile("agents.tsx");
const card = app.slice(app.indexOf("function CriticalAccept("), app.indexOf("function AgentsSection("));

describe("the card of a critical change", () => {
  it("has the two buttons and the words of the design", () => {
    expect(card).toContain("Вернуть как было");
    expect(card).toContain("Остановить агентов");
    expect(card).toContain("Готово: настройки агента возвращены, тревога снята");
    expect(card).toContain('rpc.call("agents.restore"');
    expect(card).toContain('rpc.call("agents.stop"');
    expect(card).toContain('kind: "agents.restore"'); // the passkey touch is asked for this action
  });

  it("the manual instruction is only inside «Подробнее»", () => {
    const uses = card.split("manualRollback(").length - 1;
    expect(uses).toBe(1);
    const more = card.indexOf('summary="Подробнее"');
    const manual = card.indexOf("manualRollback(");
    const mainBlock = card.slice(0, more);
    expect(more).toBeGreaterThan(0);
    expect(manual).toBeGreaterThan(more);
    expect(mainBlock).not.toContain("manualRollback(");
  });

  it("says plainly when the file cannot be put back automatically, with the guard's reason", () => {
    expect(card).toContain("Автоматически вернуть этот файл нельзя");
    expect(card).toContain("d.restorable.reason");
  });

  it("tells the truth about holding: «агенты могут быть запущены снова» when bb cannot hold new messages", () => {
    expect(card).toContain("агенты могут быть запущены снова");
    expect(card).toContain("holdAvailable");
  });
});
