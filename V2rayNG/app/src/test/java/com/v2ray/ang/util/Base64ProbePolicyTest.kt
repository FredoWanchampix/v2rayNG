package com.v2ray.ang.util

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Вещдок лога владельца (22.11.2026): 12 записей уровня E со стектрейсами при трёх
 * УСПЕШНЫХ обновлениях подписки — проба base64 логировала штатный отказ как
 * ошибку. Решение: отказ попытки — DEBUG без стектрейса, сводная строка — один
 * WARNING только когда не удалось декодировать ни одним способом.
 *
 * Тест доказывает выбор уровня и текста, не касаясь `android.util.Base64`.
 */
class Base64ProbePolicyTest {

    @Test
    fun `attempt rejection is debug and carries no stack trace`() {
        val entry = Base64ProbePolicy.attemptRejected(
            "standard",
            "IllegalArgumentException",
        )
        assertEquals(Base64ProbePolicy.Level.DEBUG, entry.level)
        assertEquals(
            "Base64 probe: standard form rejected (IllegalArgumentException)",
            entry.message,
        )
        assertTrue("at " !in entry.message, "в сообщении не должно быть кадра стектрейса")
    }

    @Test
    fun `url-safe attempt rejection names the form`() {
        val entry = Base64ProbePolicy.attemptRejected("URL-safe", "IllegalArgumentException")
        assertEquals(Base64ProbePolicy.Level.DEBUG, entry.level)
        assertTrue(entry.message.contains("URL-safe form rejected"))
    }

    @Test
    fun `full rejection of non-empty input is one warning with input size`() {
        val entry = Base64ProbePolicy.allAttemptsRejected(1234)
        assertEquals(Base64ProbePolicy.Level.WARNING, entry.level)
        assertTrue(entry.message.contains("input 1234 chars"))
        assertTrue(entry.message.contains("treating content as plain text"))
    }

    @Test
    fun `empty input logs nothing at all`() {
        for (length in intArrayOf(0, -1)) {
            val entry = Base64ProbePolicy.allAttemptsRejected(length)
            assertEquals(
                Base64ProbePolicy.Level.NONE,
                entry.level,
                "пустой вход не проблема, WARNING был бы новым шумом",
            )
            assertEquals("", entry.message)
        }
    }

    @Test
    fun `diagnostics are kept - message mentions all three tried forms`() {
        val entry = Base64ProbePolicy.allAttemptsRejected(500)
        for (form in listOf("standard", "URL-safe", "without padding")) {
            assertTrue(entry.message.contains(form), "в сводке должна быть форма: $form")
        }
    }
}
