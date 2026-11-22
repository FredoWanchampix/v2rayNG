package com.v2ray.ang.util

/**
 * Политика логирования пробы base64 в [Utils.decode].
 *
 * Вещдок лога владельца (22.11.2026, 4177 строк): 12 записей уровня E с полными
 * стектрейсами («bad base-64» + «Failed to decode standard/URL-safe base64») при
 * трёх обновлениях подписки, которые при этом ЗАВЕРШИЛИСЬ УСПЕШНО
 * («Subscription updated: …, 35 configs»). Причина: [Utils.decode] вызывается как
 * ПРОБА — `parseConfigViaSub` сначала пробует base64, а если не вышло, парсит тело
 * подписки как обычный текст. Для текстовой подписки отказ пробы ШТАТНЫЙ, но
 * логировался как ошибка со стектрейсом, и настоящие ошибки в нём тонули.
 *
 * Решение владельца (22.11.2026, «вариант номер два»): шум убрать, диагностику
 * сохранить. Отказ отдельной попытки — DEBUG без стектрейса; сводная строка
 * WARNING — один раз, только когда не удалось декодировать ни одним способом.
 *
 * Решение ВЫНЕСЕНО в чистый объект, потому что `android.util.Base64` недоступен в
 * JVM-тестах, а доказать уровнем лога нужно именно выбор уровня и текста
 * (тест Base64ProbePolicyTest). Логика декодирования не меняется.
 */
object Base64ProbePolicy {

    /** Уровень записи в лог. */
    enum class Level { NONE, DEBUG, WARNING }

    /** Что писать в лог: уровень и текст. `NONE` — не писать ничего. */
    data class Entry(val level: Level, val message: String)

    /**
     * Сообщение об отказе ОДНОЙ попытки декодирования (штатный исход пробы).
     *
     * @param form какое представление пробовалось: «standard» или «URL-safe».
     * @param exceptionClass имя класса исключения, без стектрейса:
     *   IllegalArgumentException("bad base-64") не несёт информации сверх факта.
     */
    fun attemptRejected(form: String, exceptionClass: String): Entry = Entry(
        level = Level.DEBUG,
        message = "Base64 probe: $form form rejected ($exceptionClass)",
    )

    /**
     * Сводное сообщение, когда НЕ удалось декодировать ни одним способом.
     *
     * Пишется только для непустого входа ([inputLength] > 0): пустая строка не
     * является признаком проблемы, и WARNING на ней был бы новым шумом.
     *
     * @param inputLength длина входа в символах — диагностика сохраняется.
     */
    fun allAttemptsRejected(inputLength: Int): Entry =
        if (inputLength <= 0) {
            Entry(Level.NONE, "")
        } else {
            Entry(
                level = Level.WARNING,
                message = "Base64 probe failed (standard, URL-safe, without padding): " +
                    "input $inputLength chars — treating content as plain text",
            )
        }
}
