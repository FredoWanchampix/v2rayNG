package com.v2ray.ang.ui.userasset

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Обновление geo-файлов «через активный профиль» НЕ должно откатываться на direct:
 * приложение исключено из собственного туннеля, поэтому прямой запрос обошёл бы
 * профиль. Проверяем чистую функцию выбора портов.
 */
class GeoPortsToTryTest {

    @Test
    fun `direct mode tries only port zero`() {
        // httpPort == 0 -> пользователь не требовал «через профиль».
        assertEquals(listOf(0), geoPortsToTry(0))
    }

    @Test
    fun `via-profile mode never falls back to direct`() {
        // httpPort != 0 -> строго через loopback HTTP-прокси, без отката на 0.
        assertEquals(listOf(10809), geoPortsToTry(10809))
        assertEquals(listOf(12345), geoPortsToTry(12345))
    }

    @Test
    fun `via-profile mode does not include the direct port`() {
        val ports = geoPortsToTry(10809)
        assertEquals(1, ports.size)
        assertEquals(false, ports.contains(0))
    }
}
