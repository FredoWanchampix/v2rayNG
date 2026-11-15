package com.v2ray.ang.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Тесты чистых функций [FptnProbeRunner]: разбор результатов пробы, формирование
 * upstream-списка для dnsproxy и списка обходов туннеля.
 *
 * Все функции намеренно чистые (без root, сети и Android), чтобы критичную логику
 * можно было доказать unit-тестом, а не только «на глаз» по сгенерированному скрипту.
 */
class FptnProbeRunnerTest {

    // ================= разбор вывода скрипта =================

    @Test
    fun `parses attempt lines from script output`() {
        val output = """
            PROBE_STAGE measure-start attempts=2 bytes=10485760
            ATTEMPT 10485760 1.234567
            ATTEMPT 10485760 2.000000
            PROBE_STAGE measure-done
        """.trimIndent()
        val parsed = FptnProbeRunner.parseAttempts(output)
        assertEquals(2, parsed.size)
        assertEquals(10485760L, parsed[0].bytes)
        assertEquals(1234L, parsed[0].timeMs) // 1.234567 c -> 1234 мс (усечение)
        assertEquals(2000L, parsed[1].timeMs)
    }

    @Test
    fun `ignores malformed and non-attempt lines`() {
        val output = """
            ATTEMPT notanumber 1.0
            ATTEMPT 1024
            ATTEMPT 5000 0.5
            ATTEMPT 7000 zero
            DELAY 0.05
            PROBE_STAGE tun-up
            whatever
        """.trimIndent()
        val parsed = FptnProbeRunner.parseAttempts(output)
        assertEquals(1, parsed.size, "только полностью корректная строка ATTEMPT должна учитываться")
        assertEquals(5000L, parsed[0].bytes)
        assertEquals(500L, parsed[0].timeMs)
    }

    @Test
    fun `zero duration attempt is rejected to avoid division by zero`() {
        val parsed = FptnProbeRunner.parseAttempts("ATTEMPT 1000 0.000000")
        assertTrue(parsed.isEmpty(), "нулевая длительность недопустима: деление дало бы Infinity")
    }

    @Test
    fun `empty output yields no attempts`() {
        assertTrue(FptnProbeRunner.parseAttempts("").isEmpty())
        assertTrue(FptnProbeRunner.parseAttempts("PROBE_ERROR: tun did not come up").isEmpty())
    }

    // ================= агрегирование скорости =================

    @Test
    fun `speed is total bytes divided by total time`() {
        val attempts = listOf(
            FptnProbeRunner.Attempt(10_000_000L, 1_000L),
            FptnProbeRunner.Attempt(10_000_000L, 3_000L),
        )
        val (speed, stable) = FptnProbeRunner.aggregate(attempts, 10_000_000L, expectedAttempts = 2)
        assertEquals(20_000_000L * 1000L / 4_000L, speed)
        assertTrue(stable)
    }

    @Test
    fun `shaped line that never completes the file is not stable`() {
        // «Белый список второго типа»: байты идут, но файл не докачивается.
        val attempts = listOf(
            FptnProbeRunner.Attempt(300_000L, 10_000L),
            FptnProbeRunner.Attempt(250_000L, 10_000L),
        )
        val (speed, stable) = FptnProbeRunner.aggregate(attempts, 10_000_000L, expectedAttempts = 2)
        assertTrue(speed > 0L, "скорость должна быть положительной, чтобы UI показал число")
        assertFalse(stable, "неполные загрузки не могут считаться стабильными")
    }

    @Test
    fun `stable requires EVERY attempt to complete the file`() {
        val attempts = listOf(
            FptnProbeRunner.Attempt(10_000_000L, 1_000L),
            FptnProbeRunner.Attempt(1_000L, 1_000L),
        )
        val (_, stable) = FptnProbeRunner.aggregate(attempts, 10_000_000L, expectedAttempts = 2)
        assertFalse(stable)
    }

    @Test
    fun `all-zero attempts report zero speed and not stable`() {
        val attempts = listOf(
            FptnProbeRunner.Attempt(0L, 1_000L),
            FptnProbeRunner.Attempt(0L, 1_000L),
        )
        val (speed, stable) = FptnProbeRunner.aggregate(attempts, 10_000_000L, expectedAttempts = 2)
        assertEquals(0L, speed)
        assertFalse(stable)
    }

    @Test
    fun `no attempts at all is zero speed never negative`() {
        val (speed, stable) = FptnProbeRunner.aggregate(emptyList(), 10_000_000L, expectedAttempts = 2)
        assertEquals(0L, speed)
        assertFalse(stable)
    }

    // ================= разбор задержки =================

    @Test
    fun `parses delay in seconds into milliseconds`() {
        assertEquals(120L, FptnProbeRunner.parseDelay("PROBE_STAGE delay-start\nDELAY 0.119646\n"))
        assertEquals(1L, FptnProbeRunner.parseDelay("DELAY 0.0004"))
    }

    @Test
    fun `missing or zero delay is reported as failure`() {
        assertEquals(-1L, FptnProbeRunner.parseDelay("PROBE_ERROR: tun did not come up"))
        assertEquals(-1L, FptnProbeRunner.parseDelay("DELAY 0.000000"))
        assertEquals(-1L, FptnProbeRunner.parseDelay("DELAY garbage"))
        assertEquals(-1L, FptnProbeRunner.parseDelay(""))
    }

    // ================= DNS: upstream для dnsproxy =================
    //
    // Главное требование: DNS берётся ИСКЛЮЧИТЕЛЬНО из настройки пользователя,
    // без подмены провайдера. Строка настройки передаётся в --upstream почти как
    // есть, чтобы сохранялся транспорт (udp/tcp/tls/https/quic/sdns).

    @Test
    fun `quic scheme is passed through unchanged`() {
        val res = FptnProbeRunner.buildDnsProxyUpstreams(
            listOf("quic://94.140.14.14:853", "quic://94.140.15.15:853")
        )
        assertEquals(listOf("quic://94.140.14.14:853", "quic://94.140.15.15:853"), res)
    }

    @Test
    fun `all five user-configurable transports are preserved`() {
        val input = listOf(
            "udp://1.0.0.1",
            "tcp://1.0.0.2",
            "tls://dns.example.net",
            "https://dns.example.org/dns-query",
            "quic://94.140.14.14:853",
            "sdns://AQIAAAAAAAAA",
        )
        val res = FptnProbeRunner.buildDnsProxyUpstreams(input)
        assertEquals(input, res, "транспорты не должны изменяться или заменяться")
    }

    @Test
    fun `bare ip gets explicit udp scheme`() {
        assertEquals(listOf("udp://223.5.5.5"), FptnProbeRunner.buildDnsProxyUpstreams(listOf("223.5.5.5")))
    }

    @Test
    fun `bare domain gets explicit udp scheme`() {
        assertEquals(
            listOf("udp://dns.example.com"),
            FptnProbeRunner.buildDnsProxyUpstreams(listOf("dns.example.com"))
        )
    }

    @Test
    fun `localhost is never used as upstream to avoid recursion`() {
        // В netns на 127.0.0.1:53 слушает сам dnsproxy, поэтому localhost в
        // upstream дал бы бесконечную рекурсию (dnsproxy спрашивает сам себя).
        val res = FptnProbeRunner.buildDnsProxyUpstreams(listOf("localhost", "quic://94.140.14.14:853"))
        assertEquals(listOf("quic://94.140.14.14:853"), res)
        assertFalse(res.any { it.contains("localhost", ignoreCase = true) })
    }

    @Test
    fun `localhost alone yields empty upstream list so probe refuses instead of looping`() {
        assertTrue(FptnProbeRunner.buildDnsProxyUpstreams(listOf("localhost")).isEmpty())
        assertTrue(FptnProbeRunner.buildDnsProxyUpstreams(listOf("LOCALHOST")).isEmpty())
    }

    @Test
    fun `blank entries and duplicates are handled`() {
        val res = FptnProbeRunner.buildDnsProxyUpstreams(
            listOf("", "  ", "quic://1.2.3.4:853", "quic://1.2.3.4:853", "udp://1.2.3.4")
        )
        assertEquals(listOf("quic://1.2.3.4:853", "udp://1.2.3.4"), res)
    }

    @Test
    fun `empty settings yield empty list so caller reports failure honestly`() {
        assertTrue(FptnProbeRunner.buildDnsProxyUpstreams(emptyList()).isEmpty())
    }

    // ================= извлечение IP для bootstrap и exclude =================

    @Test
    fun `literal ips are extracted from schemes`() {
        val ips = FptnProbeRunner.extractLiteralDnsIps(
            listOf("quic://94.140.14.14:853", "tls://1.0.0.1", "8.8.4.4", "udp://[2001:4860:4860::8888]:853")
        )
        assertTrue(ips.contains("94.140.14.14"))
        assertTrue(ips.contains("1.0.0.1"))
        assertTrue(ips.contains("8.8.4.4"))
        assertTrue(ips.contains("2001:4860:4860::8888"), "IPv6 из скобок должен извлекаться")
    }

    @Test
    fun `domain upstreams are NOT turned into ips here (no silent provider substitution)`() {
        val ips = FptnProbeRunner.extractLiteralDnsIps(listOf("tls://dns.example.net", "dns.example.org"))
        assertTrue(ips.isEmpty(), "домены не должны подменяться IP: их резолвит bootstrap отдельно")
    }

    @Test
    fun `localhost and blanks are skipped`() {
        assertTrue(FptnProbeRunner.extractLiteralDnsIps(listOf("localhost", "")).isEmpty())
    }

    @Test
    fun `isPlainIp validates v4 and v6 and rejects junk`() {
        assertTrue(FptnProbeRunner.isPlainIp("1.1.1.1"))
        assertTrue(FptnProbeRunner.isPlainIp("255.255.255.255"))
        assertTrue(FptnProbeRunner.isPlainIp("2606:4700:4700::1111"))
        assertFalse(FptnProbeRunner.isPlainIp("256.1.1.1"))
        assertFalse(FptnProbeRunner.isPlainIp("1.2.3"))
        assertFalse(FptnProbeRunner.isPlainIp("dns.example.com"))
        assertFalse(FptnProbeRunner.isPlainIp(""))
        assertFalse(FptnProbeRunner.isPlainIp("1.1.1.1/24"), "CIDR не является IP-литералом")
    }

    // ================= exclude-tunnel-networks =================

    @Test
    fun `fptn default exclude networks are ALWAYS preserved`() {
        // Дефолт fptn-client 0.4.6: 10.0.0.0/8,192.168.0.0/16. Передача своего
        // значения ЗАМЕНЯЕТ дефолт, поэтому он обязан присутствовать в списке.
        val res = FptnProbeRunner.buildExcludeNetworks(listOf("1.2.3.4"), "10.128.0.0/30")
        assertTrue(res.contains("10.0.0.0/8"), "дефолт LAN 10/8 потерян")
        assertTrue(res.contains("192.168.0.0/16"), "дефолт LAN 192.168/16 потерян")
        assertTrue(res.contains("1.2.3.4"), "DNS-IP должен быть исключён из туннеля")
        assertTrue(res.contains("10.128.0.0/30"), "подсеть veth должна быть исключена")
    }

    @Test
    fun `ipv6 dns ips are excluded from the v4 exclude list`() {
        val res = FptnProbeRunner.buildExcludeNetworks(
            listOf("2606:4700:4700::1111", "1.0.0.1"), "10.128.0.0/30"
        )
        assertFalse(res.contains("2606:4700:4700::1111"), "IPv6 не должен попадать в v4-список")
        assertTrue(res.contains("1.0.0.1"))
    }

    @Test
    fun `exclude list is comma separated without duplicates`() {
        val res = FptnProbeRunner.buildExcludeNetworks(listOf("1.0.0.1", "1.0.0.1"), "10.128.0.0/30")
        assertFalse(res.contains(" "), "пробелы сломают парсинг CLI")
        assertEquals(res.split(",").size, res.split(",").distinct().size, "не должно быть дублей")
    }

    // ================= resolv.conf =================

    @Test
    fun `resolv conf always points to the local forwarder only`() {
        val conf = FptnProbeRunner.buildResolvConf()
        assertEquals(1, conf.lines().count { it.startsWith("nameserver ") },
            "должен быть ровно один nameserver - локальный dnsproxy")
        assertTrue(conf.contains("nameserver 127.0.0.1"))
        assertFalse(conf.contains("1.1.1.1"), "никакого жёстко заданного внешнего DNS")
        assertFalse(conf.contains("8.8.8.8"), "никакого жёстко заданного внешнего DNS")
        assertTrue(conf.contains("options timeout"), "таймауты ускоряют отказ при сбое DNS")
    }
}
