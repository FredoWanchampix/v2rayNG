package com.v2ray.ang.dto

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Доказывает, что функция «обновить через активный профиль» берёт адрес, порт,
 * учётные данные и флаги из РЕАЛЬНО запущенного конфига ядра, а не из настроек,
 * которые пользователь вправе сменить в любой момент.
 *
 * Каждый тест подаёт на вход тот JSON, который CoreConfigManager фактически
 * передаёт в coreController.startLoop() для конкретного режима, и проверяет, что
 * снимок совпадает с профилем - для любого сочетания режимов и настроек.
 */
class RunningProxyEndpointTest {

    /** Обычный профиль: SOCKS + HTTP inbound на loopback, с аутентификацией, UDP вкл. */
    private val configHevTun = """
        {
          "inbounds": [
            {
              "tag": "socks", "protocol": "socks", "port": 10808, "listen": "127.0.0.1",
              "settings": {
                "auth": "password",
                "udp": true,
                "accounts": [ { "user": "u1", "pass": "p1" } ]
              },
              "sniffing": { "enabled": true, "destOverride": ["http","tls"], "routeOnly": false }
            },
            {
              "tag": "http", "protocol": "http", "port": 10809, "listen": "127.0.0.1",
              "settings": { "accounts": [ { "user": "u1", "pass": "p1" } ] }
            }
          ],
          "outbounds": [ { "protocol": "freedom" } ]
        }
    """.trimIndent()

    /** Динамический порт: HTTP inbound на случайном порту, НЕ 10809. */
    private val configDynamicPort = """
        {
          "inbounds": [
            { "tag": "socks", "protocol": "socks", "port": 41233, "listen": "127.0.0.1",
              "settings": { "auth": "noauth", "udp": true } },
            { "tag": "http", "protocol": "http", "port": 41234, "listen": "127.0.0.1",
              "settings": {} }
          ]
        }
    """.trimIndent()

    /** Режим «поделиться прокси»: inbound слушает на 0.0.0.0 (не loopback). */
    private val configProxySharing = """
        {
          "inbounds": [
            { "tag": "socks", "protocol": "socks", "port": 10808, "listen": "0.0.0.0",
              "settings": { "udp": false } },
            { "tag": "http", "protocol": "http", "port": 10809, "listen": "0.0.0.0",
              "settings": {} }
          ]
        }
    """.trimIndent()

    /** Process-маршрутизация: sniffing.routeOnly = true. */
    private val configRouteOnly = """
        {
          "inbounds": [
            { "tag": "socks", "protocol": "socks", "port": 10808, "listen": "127.0.0.1",
              "settings": { "udp": true },
              "sniffing": { "enabled": true, "destOverride": ["http","tls","fakedns"], "routeOnly": true } },
            { "tag": "http", "protocol": "http", "port": 10809, "listen": "127.0.0.1", "settings": {} }
          ]
        }
    """.trimIndent()

    /** Профиль БЕЗ локального прокси: только tun inbound, HTTP inbound удалён. */
    private val configNoHttpInbound = """
        {
          "inbounds": [
            { "tag": "tun", "protocol": "dokodemo-door", "port": 0, "listen": "127.0.0.1",
              "settings": { "network": "tcp,udp", "mtu": 1500 } }
          ]
        }
    """.trimIndent()

    @Test
    fun `hev-tun and root - host, port and creds come from the running config`() {
        val e = RunningProxyEndpoint.fromCoreConfig(configHevTun, "VLESS")
        assertTrue(e != null)
        assertEquals("127.0.0.1", e!!.host)
        assertEquals(10809, e.port)          // порт HTTP inbound из конфига, не socks+1 из настроек
        assertEquals("u1", e.username)
        assertEquals("p1", e.password)
        assertTrue(e.udpEnabled)
        assertEquals(false, e.routeOnly)
        assertEquals("VLESS", e.configType)
    }

    @Test
    fun `dynamic port is taken from the profile, not derived as socks plus one`() {
        val e = RunningProxyEndpoint.fromCoreConfig(configDynamicPort, "TROJAN")
        // Если бы порт брался из настроек (10809), тест бы упал: реальный порт 41234.
        assertEquals(41234, e!!.port)
        assertEquals("127.0.0.1", e.host)
        assertNull(e.username)               // noauth - кредов нет
        assertTrue(e.udpEnabled)
    }

    @Test
    fun `proxy sharing (0 dot 0 dot 0 dot 0) resolves to loopback for in-app fetch`() {
        val e = RunningProxyEndpoint.fromCoreConfig(configProxySharing, "SHADOWSOCKS")
        // Inbound слушает на всех интерфейсах, но приложение подключается к loopback.
        assertEquals("127.0.0.1", e!!.host)
        assertEquals(10809, e.port)
        assertEquals(false, e.udpEnabled)
    }

    @Test
    fun `process routing mode exposes routeOnly flag`() {
        val e = RunningProxyEndpoint.fromCoreConfig(configRouteOnly, "VMESS")
        assertEquals(10809, e!!.port)
        assertTrue(e.routeOnly)
        assertTrue(e.udpEnabled)
    }

    @Test
    fun `profile without local proxy yields null so the call is refused not bypassed`() {
        val e = RunningProxyEndpoint.fromCoreConfig(configNoHttpInbound, "FPTN")
        // Нет HTTP inbound -> null: функция «через профиль» честно откажет,
        // а не уйдёт напрямую в обход профиля.
        assertNull(e)
    }

    @Test
    fun `blank or malformed config yields null instead of a bogus endpoint`() {
        assertNull(RunningProxyEndpoint.fromCoreConfig(null))
        assertNull(RunningProxyEndpoint.fromCoreConfig(""))
        assertNull(RunningProxyEndpoint.fromCoreConfig("{ not json"))
        assertNull(RunningProxyEndpoint.fromCoreConfig("{\"inbounds\": []}"))
    }

    @Test
    fun `first http inbound wins when several are present`() {
        val cfg = """
            {
              "inbounds": [
                { "protocol": "socks", "port": 10808, "listen": "127.0.0.1", "settings": {} },
                { "protocol": "http",  "port": 20001, "listen": "127.0.0.1", "settings": {} },
                { "protocol": "http",  "port": 20002, "listen": "127.0.0.1", "settings": {} }
              ]
            }
        """.trimIndent()
        assertEquals(20001, RunningProxyEndpoint.fromCoreConfig(cfg)!!.port)
    }
}
