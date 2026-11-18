package com.v2ray.ang.util.updater

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Доказывает чистую логику HTTP-диапазонов (RFC 9110): заголовок Range для
 * сегмента, разбор Content-Range, классификацию ответов (200/206/416/5xx) и
 * валидацию объекта по ETag/Last-Modified. Любая ошибка здесь = дыра/дубль
 * байт в склеенном APK или вечный цикл докачки.
 */
class ResumePolicyTest {

    // --- segmentRangeHeader: закрытый диапазон обязателен ---

    @Test
    fun `range header is closed on both ends`() {
        // Открытый "bytes=5-" на не-последнем сегменте скачал бы чужие байты.
        assertEquals("bytes=100-199", ResumePolicy.segmentRangeHeader(100, 199))
        assertEquals("bytes=0-0", ResumePolicy.segmentRangeHeader(0, 0))
    }

    @Test
    fun `range header null when segment already complete`() {
        assertNull(ResumePolicy.segmentRangeHeader(200, 199))
    }

    // --- parseContentRange: реальные заголовки GitHub/Azure (замер 17.11.2026) ---

    @Test
    fun `parses real Azure Content-Range`() {
        // Живой ответ CDN релизов: Content-Range: bytes 0-10/473
        val parsed = ResumePolicy.parseContentRange("bytes 0-10/473")
        assertEquals(0L to 473L, parsed)
    }

    @Test
    fun `parses mid-file range and unknown total`() {
        assertEquals(1048576L to 99999999L, ResumePolicy.parseContentRange("bytes 1048576-2097151/99999999"))
        // total неизвестен -> -1, но first валиден
        assertEquals(5L to -1L, ResumePolicy.parseContentRange("bytes 5-10/*"))
    }

    @Test
    fun `rejects unsatisfiable and malformed Content-Range`() {
        assertNull(ResumePolicy.parseContentRange("bytes */473"))
        assertNull(ResumePolicy.parseContentRange(null))
        assertNull(ResumePolicy.parseContentRange(""))
        assertNull(ResumePolicy.parseContentRange("bytes garbage"))
        assertNull(ResumePolicy.parseContentRange("bytes 1-2"))
    }

    // --- classify: матрица ответов ---

    @Test
    fun `classify 206 with valid range is Partial`() {
        val outcome = ResumePolicy.classify(206, "bytes 50-99/200", 50)
        assertTrue(outcome is ResumePolicy.Outcome.Partial)
        outcome as ResumePolicy.Outcome.Partial
        assertEquals(50L, outcome.start)
        assertEquals(200L, outcome.total)
    }

    @Test
    fun `classify 206 without Content-Range falls back to RangeNotSatisfiable`() {
        assertEquals(ResumePolicy.Outcome.RangeNotSatisfiable, ResumePolicy.classify(206, null, 10))
    }

    @Test
    fun `classify 200 means server ignored Range`() {
        val outcome = ResumePolicy.classify(200, null, 12345)
        assertTrue(outcome is ResumePolicy.Outcome.FullObject)
        assertEquals(12345L, (outcome as ResumePolicy.Outcome.FullObject).contentLength)
    }

    @Test
    fun `classify 416 is RangeNotSatisfiable`() {
        assertEquals(ResumePolicy.Outcome.RangeNotSatisfiable, ResumePolicy.classify(416, "bytes */200", 0))
    }

    @Test
    fun `classify other codes are HttpError`() {
        assertEquals(ResumePolicy.Outcome.HttpError(503), ResumePolicy.classify(503, null, 0))
        assertEquals(ResumePolicy.Outcome.HttpError(404), ResumePolicy.classify(404, null, 0))
    }

    // --- валидатор объекта ---

    @Test
    fun `validator prefers etag but keeps both`() {
        assertEquals("\"abc\"|Mon, 17 Nov 2026 10:03:20 GMT",
            ResumePolicy.validatorOf("\"abc\"", "Mon, 17 Nov 2026 10:03:20 GMT"))
        assertEquals("\"abc\"", ResumePolicy.validatorOf("\"abc\"", null))
        assertEquals("date", ResumePolicy.validatorOf(null, "date"))
        assertNull(ResumePolicy.validatorOf(null, null))
        assertNull(ResumePolicy.validatorOf("  ", ""))
    }

    @Test
    fun `objectUnchanged detects swapped object`() {
        // Смена ETag между сегментами = другой объект: продолжать НЕЛЬЗЯ.
        assertFalse(ResumePolicy.objectUnchanged("\"old\"", "\"new\""))
        assertTrue(ResumePolicy.objectUnchanged("\"same\"", "\"same\""))
        // Нет сохранённой метки / сервер её не отдаёт — опереться не на что,
        // решит итоговый SHA-256: трактуем как «не изменился», чтобы докачка
        // не вставала намертво.
        assertTrue(ResumePolicy.objectUnchanged(null, "\"new\""))
        assertTrue(ResumePolicy.objectUnchanged("\"old\"", null))
    }
}
