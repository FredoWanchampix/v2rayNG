package com.v2ray.ang.util.updater

/**
 * Разбиение файла обновления на параллельные сегменты (многопоточная загрузка).
 *
 * Владелец требует: «файл скачивается в несколько потоков, максимум 24, но число
 * потоков настраивается в настройках». Этот объект — единственное место, где
 * решается, СКОЛЬКО сегментов и КАКИЕ именно байтовые полуинтервалы они
 * покрывают, поэтому решение чистое (без android.*, MMKV, сети) и доказуемо
 * JVM-тестом: ошибка здесь = дыра или дубль байт в склеенном APK.
 *
 * Сегменты НЕ перекрываются и покрывают файл сплошь:
 * `segment[i].endInclusive + 1 == segment[i+1].start`, последний байт = total-1.
 *
 * Зачем ограничивать число сегментов размером файла: 24 потока на файле в
 * 100 КБ дали бы 24 запроса по 4 КБ — чистые накладные расходы и риск упереться
 * в лимит одновременных соединений CDN. Поэтому сегмент короче
 * [MIN_SEGMENT_BYTES] не создаётся: эффективное число потоков = min(настройка,
 * total / MIN_SEGMENT_BYTES), но не больше [MAX_SEGMENTS].
 */
object SegmentPlan {

    /** Жёсткий потолок владельца: не больше 24 параллельных потоков. */
    const val MAX_SEGMENTS = 24

    /** Минимум — однопоточная загрузка (она же фолбэк, если Range не поддержан). */
    const val MIN_SEGMENTS = 1

    /**
     * Минимальный размер сегмента. 1 МиБ: APK форка ~95-330 МБ, так что потолок
     * в 24 потока достигается уже на файле в 24 МБ, а мелкие файлы не дробятся.
     */
    const val MIN_SEGMENT_BYTES = 1L * 1024L * 1024L

    /** Значение по умолчанию для настройки «потоков на загрузку». */
    const val DEFAULT_SEGMENT_COUNT = 8

    /**
     * Один сегмент: полуинтервал `[start, endInclusive]` абсолютных байтов файла.
     */
    data class Segment(
        val index: Int,
        val start: Long,
        val endInclusive: Long,
    ) {
        /** Размер сегмента в байтах (>= 1 по построению). */
        val size: Long get() = endInclusive - start + 1
    }

    /**
     * Приводит пользовательскую настройку к допустимому диапазону 1..24.
     *
     * Принимаем мусор безопасно: 0/отрицательное -> 1, больше 24 -> 24. Настройка
     * хранится строкой (паттерн существующих полей настроек форка), поэтому
     * нечисловое значение тоже должно давать валидное число, а не падение.
     */
    fun clampSegmentCount(requested: Int): Int = requested.coerceIn(MIN_SEGMENTS, MAX_SEGMENTS)

    /** Разбор строковой настройки; нечисловое/пустое -> [DEFAULT_SEGMENT_COUNT]. */
    fun parseSegmentCount(raw: String?): Int {
        val value = raw?.trim()?.toIntOrNull() ?: DEFAULT_SEGMENT_COUNT
        return clampSegmentCount(value)
    }

    /**
     * Реальное число сегментов для файла [totalBytes] при настройке [requested].
     *
     *  - размер неизвестен/нулевой ([totalBytes] <= 0) -> 1 (делить нечего);
     *  - иначе min(clamp(requested), total / MIN_SEGMENT_BYTES), но >= 1.
     */
    fun effectiveSegmentCount(totalBytes: Long, requested: Int): Int {
        if (totalBytes <= 0L) return MIN_SEGMENTS
        val bySize = (totalBytes / MIN_SEGMENT_BYTES).coerceAtLeast(1L).toInt()
        return clampSegmentCount(requested).coerceAtMost(bySize).coerceAtLeast(MIN_SEGMENTS)
    }

    /**
     * Строит план сегментов. Остаток от деления распределяется по одному байту
     * первым сегментам, поэтому сумма размеров ТОЧНО равна [totalBytes], а
     * последний сегмент всегда заканчивается на `totalBytes - 1`.
     *
     * @return пустой список, если размер неизвестен (<= 0) — вызывающий код
     *   обязан тогда качать одним потоком без Range.
     */
    fun plan(totalBytes: Long, requested: Int): List<Segment> {
        if (totalBytes <= 0L) return emptyList()
        val count = effectiveSegmentCount(totalBytes, requested)
        val base = totalBytes / count
        var remainder = totalBytes % count
        val segments = ArrayList<Segment>(count)
        var cursor = 0L
        for (i in 0 until count) {
            val extra = if (remainder > 0L) {
                remainder -= 1L
                1L
            } else {
                0L
            }
            val size = base + extra
            segments += Segment(index = i, start = cursor, endInclusive = cursor + size - 1)
            cursor += size
        }
        return segments
    }

    /**
     * Проверяет план на сплошность и точное покрытие — используется тестами и
     * самопроверкой перед склейкой: склеивать можно ТОЛЬКО корректный план,
     * иначе в APK появится дыра или дубль.
     */
    fun isContiguous(segments: List<Segment>, totalBytes: Long): Boolean {
        if (segments.isEmpty()) return false
        if (segments.first().start != 0L) return false
        var expected = 0L
        var sum = 0L
        for ((i, s) in segments.withIndex()) {
            if (s.index != i) return false
            if (s.start != expected) return false
            if (s.endInclusive < s.start) return false
            sum += s.size
            expected = s.endInclusive + 1
        }
        return expected == totalBytes && sum == totalBytes
    }
}
