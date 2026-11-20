package com.v2ray.ang.util

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.MessageDigest

/**
 * Чистая логика [TlsCertFetcher]: формат отпечатка и запрос HTTP CONNECT.
 *
 * Формат ОБЯЗАН совпадать с нативной fetchTlsCertSha256 (64 строчных hex) —
 * это значение уходит в pinnedCA256 и затем в pinnedPeerCertSha256 ядра;
 * сверено побайтово на живых данных 20.11.2026 (fr.aichatik.online:8443 →
 * 69103e5ff502314f… = значение из подписки в MMKV).
 *
 * CONNECT-запрос обязан содержать Host (без него inbound ядра отвечает 400)
 * и Proxy-Authorization в UTF-8 (урок загрузчика: ISO-8859-1 ломает пароль
 * с символами вне латиницы, например «₽», прокси отвечает 407).
 */
class TlsCertFetcherTest {

    // ---------- формат отпечатка ----------

    @Test
    fun `sha256 hex of empty input matches known vector`() {
        // SHA-256("") — общеизвестный вектор
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            TlsCertFetcher.sha256Hex(ByteArray(0)),
        )
    }

    @Test
    fun `sha256 hex of abc matches known vector`() {
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            TlsCertFetcher.sha256Hex("abc".toByteArray()),
        )
    }

    @Test
    fun `sha256 hex agrees with java digest and is always 64 lowercase hex`() {
        val der = ByteArray(256) { (it * 37 % 251).toByte() }
        val hex = TlsCertFetcher.sha256Hex(der)
        val expected = MessageDigest.getInstance("SHA-256").digest(der)
            .joinToString("") { "%02x".format(it) }
        assertEquals(expected, hex)
        assertEquals(64, hex.length)
        assertTrue(hex.matches(Regex("^[0-9a-f]{64}$")))
    }

    @Test
    fun `sha256 hex is full length even for single byte input`() {
        // короткий вход (1 байт) всё равно обязан дать 64 hex-символа:
        // ведущие нули не теряются, иначе ядро не примет значение.
        val hex = TlsCertFetcher.sha256Hex(byteArrayOf(0x0A))
        assertEquals(64, hex.length)
        assertTrue(hex.matches(Regex("^[0-9a-f]{64}$")))
    }

    // ---------- запрос HTTP CONNECT ----------

    @Test
    fun `connect request without credentials has no authorization header`() {
        val req = TlsCertFetcher.buildConnectRequest("example.com", 443, null, null)
        assertTrue(req.startsWith("CONNECT example.com:443 HTTP/1.1\r\n"))
        assertTrue(req.contains("Host: example.com:443\r\n"))
        assertFalse(req.contains("Proxy-Authorization"))
        assertTrue(req.endsWith("\r\n\r\n"))
    }

    @Test
    fun `connect request with credentials carries basic authorization`() {
        val req = TlsCertFetcher.buildConnectRequest("example.com", 8443, "user", "pass")
        assertTrue(req.startsWith("CONNECT example.com:8443 HTTP/1.1\r\n"))
        assertTrue(req.contains("Proxy-Authorization: Basic "))
        // Base64("user:pass") = dXNlcjpwYXNz
        assertTrue(req.contains("dXNlcjpwYXNz"))
        assertTrue(req.endsWith("\r\n\r\n"))
    }

    @Test
    fun `credentials with non-latin characters are utf-8 encoded`() {
        // Урок загрузчика: пароль активного профиля содержит «₽»; ISO-8859-1
        // дал бы 407 от локального прокси. Проверяем UTF-8 base64 явно.
        val req = TlsCertFetcher.buildConnectRequest("example.com", 443, "Pxoek8ud", "9#=₽(&₽")
        val line = req.lines().first { it.startsWith("Proxy-Authorization:") }
        val b64 = line.substringAfter("Basic ").trim()
        val decoded = java.util.Base64.getDecoder().decode(b64).toString(Charsets.UTF_8)
        assertEquals("Pxoek8ud:9#=₽(&₽", decoded)
    }

    @Test
    fun `blank credentials are treated as absent`() {
        val req = TlsCertFetcher.buildConnectRequest("example.com", 443, "", "   ")
        assertFalse(req.contains("Proxy-Authorization"))
    }

    @Test
    fun `connect request is parseable by strict http parsers`() {
        // первая строка строго вида "CONNECT host:port HTTP/1.1", затем заголовки
        // "Name: value", затем пустая строка (\r\n\r\n) — как ждёт HTTP-прокси.
        val req = TlsCertFetcher.buildConnectRequest("1.2.3.4", 2053, "u", "p")
        val parts = req.split("\r\n\r\n")
        assertEquals(2, parts.size)
        assertEquals("", parts[1])
        val lines = parts[0].split("\r\n")
        assertEquals("CONNECT 1.2.3.4:2053 HTTP/1.1", lines[0])
        // все строки ПОСЛЕ первой — корректные заголовки "Name: value"
        assertTrue(lines.size >= 2)
        assertTrue(lines.drop(1).all { it.matches(Regex("[A-Za-z-]+: .+")) })
    }
}
