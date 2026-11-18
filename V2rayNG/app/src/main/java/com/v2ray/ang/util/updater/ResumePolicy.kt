package com.v2ray.ang.util.updater

/**
 * Чистая логика HTTP-диапазонов (RFC 9110 §13-14) для встроенного загрузчика
 * обновлений. Всё, что решает «валиден ли объект на сервере» и «как трактовать
 * ответ на Range-запрос», вынесено сюда НАМЕРЕННО без android.*, LogUtil и MMKV:
 * эти решения критичны (ошибка = битый APK или вечный цикл докачки) и обязаны
 * доказываться JVM-тестом, а не только на устройстве.
 *
 * Контекст владельца: загрузка идёт в несколько параллельных потоков-сегментов,
 * каждый сегмент докачивается со своего байта; докачка может «порвать пару байт»
 * на стыке, поэтому корректность гарантируется ДВУМЯ независимыми механизмами:
 *  1. валидатор объекта (ETag/Last-Modified) — если сервер сменил объект между
 *     запросами сегментов, продолжать нельзя, нужен рестарт;
 *  2. итоговый стриминговый SHA-256 всего смерженного файла (см. [UpdateHashVerifier])
 *     — ловит ЛЮБУЮ порчу, включая внесённую возобновлением.
 */
object ResumePolicy {

    /**
     * Строит строку-валидатор объекта из ETag и/или Last-Modified.
     *
     * ETag приоритетнее (RFC 9110 §8.8.3: сильный валидатор предпочтительнее
     * даты с гранулярностью 1 секунда), но возвращаем ОБЪЕДИНЕНИЕ, чтобы даже
     * слабый/отсутствующий ETag не лишал нас проверки по дате, и наоборот.
     * Формат `<etag>|<lastModified>` стабилен и сравнивается потом как строка.
     */
    fun validatorOf(etag: String?, lastModified: String?): String? {
        val e = etag?.trim()?.takeIf { it.isNotEmpty() }
        val m = lastModified?.trim()?.takeIf { it.isNotEmpty() }
        return when {
            e != null && m != null -> "$e|$m"
            e != null -> e
            m != null -> m
            else -> null
        }
    }

    /**
     * Проверяет, что объект на сервере НЕ сменился между запросами: сравнивает
     * валидатор, под которым мы писали сегменты, с тем, что сервер вернул сейчас.
     *
     * @param saved валидатор из первого (пробного) ответа. null/пусто — сравнивать
     *   нечего; для CDN GitHub объект релиза иммутабелен, поэтому отсутствие метки
     *   трактуем как «не изменился» (иначе докачка вставала бы намертво).
     * @param received валидатор из текущего ответа сегмента (может быть null).
     * @return true — продолжать безопасно; false — объект сменился, нужен рестарт.
     */
    fun objectUnchanged(saved: String?, received: String?): Boolean {
        if (saved.isNullOrEmpty()) return true
        if (received.isNullOrEmpty()) return true
        return saved == received
    }

    /**
     * Результат разбора HTTP-ответа на Range-запрос сегмента.
     */
    sealed interface Outcome {
        /**
         * 206 Partial Content — корректная (до)качка сегмента.
         * @param start первый байт, который сервер прислал (из Content-Range).
         * @param total полный размер объекта (из Content-Range `.../total`).
         */
        data class Partial(val start: Long, val total: Long) : Outcome

        /**
         * 200 OK — сервер проигнорировал Range и прислал объект ЦЕЛИКОМ.
         * Диапазоны не поддерживаются: сегментная докачка невозможна, нужен
         * однопоточный режим без возобновления.
         * @param contentLength размер объекта из Content-Length (-1 если неизвестен).
         */
        data class FullObject(val contentLength: Long) : Outcome

        /**
         * 416 Range Not Satisfiable — запрошенный первый байт за пределами объекта
         * (сегмент уже скачан целиком, или объект сменился/укоротился). Продолжать
         * этот сегмент нечем: вызывающий код решает, рестартовать ли его.
         */
        object RangeNotSatisfiable : Outcome {
            override fun toString() = "RangeNotSatisfiable"
        }

        /** Прочий HTTP-статус (5xx ретраится вызывающим кодом, 4xx — ошибка). */
        data class HttpError(val code: Int) : Outcome
    }

    /**
     * Разбирает HTTP-ответ на Range-запрос в [Outcome].
     *
     * @param code статус ответа.
     * @param contentRange значение заголовка `Content-Range` (`bytes S-E/T`), null если нет.
     * @param contentLength значение `Content-Length` ответа (для 200 = размер объекта).
     */
    fun classify(code: Int, contentRange: String?, contentLength: Long): Outcome = when (code) {
        206 -> {
            val range = parseContentRange(contentRange)
            if (range != null) Outcome.Partial(start = range.first, total = range.second)
            else Outcome.RangeNotSatisfiable // 206 без внятного Content-Range недопустим
        }

        200 -> Outcome.FullObject(contentLength)
        416 -> Outcome.RangeNotSatisfiable
        else -> Outcome.HttpError(code)
    }

    /**
     * Разбирает `Content-Range: bytes <first>-<last>/<total>` в пару (first, total).
     *
     * `<last>` не нужен: мы пишем тело ответа до конца потока, а общий размер
     * берём из `<total>`. Особые формы трактуются так:
     *  - "bytes * slash total" (ответ на 416, диапазона нет) — нераспознано, null;
     *  - "bytes S-E slash *" (total неизвестен) — first валиден, total = -1.
     * Формулировка намеренно без символов деления подряд со звёздочкой: в Kotlin
     * блочные комментарии ВЛАГАЮТСЯ, и последовательность «слэш-звёздочка»
     * внутри KDoc открывает вложенный комментарий и ломает разбор файла.
     */
    fun parseContentRange(header: String?): Pair<Long, Long>? {
        if (header.isNullOrBlank()) return null
        val value = header.trim().removePrefix("bytes").trim()
        if (value.isEmpty() || value.startsWith("*")) return null
        val slash = value.indexOf('/')
        if (slash < 0) return null
        val rangePart = value.substring(0, slash).trim()
        val totalPart = value.substring(slash + 1).trim()
        val dash = rangePart.indexOf('-')
        if (dash < 0) return null
        val first = rangePart.substring(0, dash).trim().toLongOrNull() ?: return null
        val total = when {
            totalPart == "*" -> -1L
            else -> totalPart.toLongOrNull() ?: return null
        }
        return first to total
    }

    /**
     * Строит заголовок `Range` для докачки сегмента: `bytes=<from>-<endInclusive>`.
     *
     * ЗАКРЫТЫЙ конец обязателен: открытый `bytes=<from>-` на НЕпоследнем сегменте
     * скачал бы данные сверх границы сегмента (залез в следующий), и склейка дала
     * бы дубль байт. Поэтому каждый сегмент всегда запрашивает точно свой
     * полуинтервал. Если сегмент уже полностью скачан (from > end), возвращаем null.
     *
     * @param from абсолютный первый байт, который ещё нужно докачать.
     * @param endInclusive абсолютный последний байт сегмента (включительно).
     */
    fun segmentRangeHeader(from: Long, endInclusive: Long): String? {
        if (from > endInclusive) return null
        return "bytes=$from-$endInclusive"
    }
}
