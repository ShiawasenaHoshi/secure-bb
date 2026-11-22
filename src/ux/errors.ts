// Errors in plain Russian: what the server and the guard say, turned into a sentence a person reads.


/** What the server and the guard answer (English, with internal words) → what the person reads. Anything not known gets a general sentence, never the English text. */
const ERROR_TEXT: Array<[RegExp, string]> = [
  [/hash did not match|never approved/i, "Эту версию вернуть нельзя: её файлы изменились после проверки. Установите плагин заново из его источника."],
  [/hard flag|blocked by the checks/i, "У этой версии жёсткий признак опасности: обычным разрешением её не пропустить."],
  [/fresh touch|session does not cover/i, "Для этого нужен свежий код или касание: сессия здесь не помогает."],
  [/invalid or expired session|expired session/i, "Сессия закрылась. Откройте её снова или введите код."],
  [/invalid or already used code|invalid_code|code does not match/i, "Код не подошёл. Подождите, пока в приложении появится новый, и введите его."],
  [/a code or a touch is needed|a code is needed|code, or an open session/i, "Нужен код из приложения (или касание ключом)."],
  [/too many|blocked until|block/i, "Слишком много неверных кодов: ввод закрыт на час."],
  [/third-party plugins first|interface code could read/i, "Пока работают чужие плагины с интерфейсом, сессию открыть нельзя: они могли бы подсмотреть её."],
  [/directory that others can write/i, "Папка плагина доступна на запись другим пользователям: после проверки файлы можно подменить. Исправьте права или ставьте плагин другим способом."],
  [/window needs a fresh|fresh touch.*alarm/i, "Пока открыта тревога по настройкам агентов, окно доверия открывается только со свежим кодом или касанием."],
  [/changed since it was shown|not in the difference|not what the page showed/i, "Файл изменился между показом и действием: ничего не записано, показано заново."],
  [/is already (approved|dismissed|accepted|reverted|superseded)|already approved/i, "Это уже решено: обновите страницу."],
  [/no such|not found|no review|no request|no difference/i, "Этого уже нет: обновите страницу."],
  [/list expired|does not match the one that was shown|prepare it again/i, "Список устарел: соберите его заново."],
  [/did not come from a thread|trust window/i, "Для этого плагина временное доверие недоступно: разрешайте версию целиком."],
  [/challenge/i, "Подтверждение устарело. Нажмите ещё раз."],
  [/acknowledgeBlock|Строгий/i, "В строгом режиме остановку обойти нельзя. Сначала смягчите режим."],
  [/guard|ECONN|ENOENT|timeout|socket/i, "Защита не ответила. Проверьте, что она запущена, и повторите."],
];

export function humanError(raw: string): string {
  for (const [re, text] of ERROR_TEXT) if (re.test(raw)) return text;
  // Already in Russian: the page's own words, shown as they are.
  if (/[А-Яа-яЁё]/.test(raw)) return raw;
  return "Не получилось. Подробности записаны в журнал; повторите или позовите того, кто настраивал защиту.";
}
