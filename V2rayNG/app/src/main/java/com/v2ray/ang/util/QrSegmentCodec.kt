package com.v2ray.ang.util

import java.util.zip.CRC32

/**
 * Сегментированный протокол QR-экспорта БЕЗ сжатия и БЕЗ сокращений.
 *
 * Физика стандарта ISO/IEC 18004: один QR-код версии 40 (максимальной) в
 * байтовом режиме вмещает 2953 байта полезной нагрузки — большего QR не
 * существует ни в одной «версии». Поэтому длинные ссылки (wireguard с
 * шумом, vless с большим finalmask — тысячи байт) передаются ПОСЛЕДОВАТЕЛЬ-
 * НОСТЬЮ обычных QR-кодов, каждый из которых несёт целый читаемый кусок
 * ссылки без каких-либо преобразований содержимого:
 *
 *   V2NGQR1|<id>|<idx>|<cnt>|<crc32 payload>|<chunk>
 *
 *   id  — 8 hex-символов CRC32 полезной нагрузки (идентификатор серии);
 *   idx/cnt — номер сегмента и всего сегментов (1-based);
 *   crc32 — CRC32 ВСЕЙ полезной нагрузки (проверка целостности сборки);
 *   chunk — кусок исходной строки, разрезанный по границам UTF-8-символов.
 *
 * Ссылка, влезающая в один QR (<= [SINGLE_MAX_PAYLOAD_BYTES] байт),
 * кодируется как ОБЫЧНЫЙ QR без префикса — совместимость со всеми
 * сторонними сканерами сохраняется.
 *
 * Импорт: [Assembler] накапливает сегменты одной серии (в любом порядке,
 * дубликаты идемпотентны), проверяет CRC и возвращает полную строку, когда
 * собраны все cnt сегментов. Посторонние/чужие серии игнорируются.
 */
object QrSegmentCodec {

    const val MAGIC = "V2NGQR1"

    /** Полезная нагрузка одиночного QR, которая остаётся обычной ссылкой. */
    const val SINGLE_MAX_PAYLOAD_BYTES = 2800

    /** Бюджет байт на chunk внутри сегмента (префикс ~48 байт + запас). */
    private const val CHUNK_MAX_BYTES = 2700

    fun crc32(payload: String): String {
        val crc = CRC32()
        crc.update(payload.toByteArray(Charsets.UTF_8))
        return String.format("%08x", crc.value)
    }

    /** true, если текст — сегмент серии V2NGQR1. */
    fun isSegment(text: String): Boolean = text.startsWith("$MAGIC|")

    /**
     * Режет полезную нагрузку на сегменты. Короткая нагрузка возвращается
     * одним элементом БЕЗ префикса (обычный QR).
     */
    fun split(payload: String): List<String> {
        if (payload.toByteArray(Charsets.UTF_8).size <= SINGLE_MAX_PAYLOAD_BYTES) {
            return listOf(payload)
        }
        val id = crc32(payload)
        val chunks = mutableListOf<String>()
        var start = 0
        while (start < payload.length) {
            var end = payload.length
            // подбираем наибольшую границу, укладывающуюся в бюджет байт
            var bytes = payload.substring(start, end).toByteArray(Charsets.UTF_8).size
            while (bytes > CHUNK_MAX_BYTES && end > start + 1) {
                end -= maxOf(1, (bytes - CHUNK_MAX_BYTES) / 4 + 1)
                bytes = payload.substring(start, end).toByteArray(Charsets.UTF_8).size
            }
            // не рвём суррогатную пару (эмодзи в remarks): граница chunk —
            // только между целыми UTF-16 символами
            if (end < payload.length && end > start &&
                payload[end - 1].isHighSurrogate() && payload[end].isLowSurrogate()
            ) {
                end -= 1
            }
            // защита от вырожденного случая: если сдвиг границы оставил chunk
            // пустым (пара в самом начале куска), берём пару целиком —
            // 4 байта всегда влезают в бюджет, бесконечный цикл исключён
            if (end <= start) {
                end = (start + 2).coerceAtMost(payload.length)
            }
            chunks.add(payload.substring(start, end))
            start = end
        }
        val crc = crc32(payload)
        val cnt = chunks.size
        return chunks.mapIndexed { i, chunk ->
            "$MAGIC|$id|${i + 1}|$cnt|$crc|$chunk"
        }
    }

    /** Разобранный сегмент; null если текст не сегмент или битый. */
    data class Segment(
        val id: String,
        val index: Int,
        val count: Int,
        val crc: String,
        val chunk: String
    )

    fun parse(text: String): Segment? {
        if (!isSegment(text)) return null
        val parts = text.split("|", limit = 6)
        if (parts.size != 6) return null
        val idx = parts[2].toIntOrNull() ?: return null
        val cnt = parts[3].toIntOrNull() ?: return null
        if (idx < 1 || cnt < 1 || idx > cnt) return null
        if (!parts[1].matches(Regex("[0-9a-f]{8}"))) return null
        if (!parts[4].matches(Regex("[0-9a-f]{8}"))) return null
        return Segment(parts[1], idx, cnt, parts[4], parts[5])
    }

    /**
     * Накопитель сегментов одной серии. offer() возвращает полную полезную
     * нагрузку, когда серия собрана и CRC сошлась; иначе null.
     */
    class Assembler {
        private var seriesId: String? = null
        private var count = 0
        private var crc: String? = null
        private val chunks = mutableMapOf<Int, String>()

        /** Сколько сегментов собрано и сколько всего (для прогресса). */
        fun progress(): Pair<Int, Int> = chunks.size to count

        fun offer(text: String): String? {
            val seg = parse(text) ?: return null
            if (seriesId == null) {
                seriesId = seg.id
                count = seg.count
                crc = seg.crc
            } else if (seriesId != seg.id || count != seg.count || crc != seg.crc) {
                // чужая или перемешанная серия: начинаем новую серию,
                // чтобы старый хвост не мешал сканированию другого профиля
                seriesId = seg.id
                count = seg.count
                crc = seg.crc
                chunks.clear()
            }
            chunks[seg.index] = seg.chunk
            if (chunks.size < count) return null
            val payload = (1..count).joinToString("") { chunks[it].orEmpty() }
            if (crc32(payload) != crc) return null
            return payload
        }
    }
}