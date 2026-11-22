package com.v2ray.ang.handler

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Выбор типа рукопожатия для получения отпечатка сертификата.
 *
 * От этого выбора зависит план попыток (см. SubscriptionCertPolicyTest):
 * QUIC нельзя туннелировать через HTTP CONNECT, поэтому QUIC-профиль обязан
 * получать отпечаток напрямую. Ошибка здесь = либо ложный «via VIA_PROFILE»
 * в логе, либо бессмысленный сетевой запрос.
 */
class CertificateFingerprintManagerTest {

    private fun profile(type: EConfigType, security: String? = null, alpn: String? = null) =
        ProfileItem(configType = type).apply {
            this.security = security
            this.alpn = alpn
            server = "example.com"
            serverPort = "443"
        }

    @Test
    fun `hysteria profiles use quic handshake`() {
        assertTrue(CertificateFingerprintManager.usesQuicFor(profile(EConfigType.HYSTERIA2)))
        assertTrue(CertificateFingerprintManager.usesQuicFor(profile(EConfigType.HYSTERIA)))
    }

    @Test
    fun `vless and trojan with tls use tls handshake`() {
        assertFalse(CertificateFingerprintManager.usesQuicFor(profile(EConfigType.VLESS, AppConfig.TLS)))
        assertFalse(CertificateFingerprintManager.usesQuicFor(profile(EConfigType.TROJAN, AppConfig.TLS)))
        assertFalse(CertificateFingerprintManager.usesQuicFor(profile(EConfigType.VMESS, AppConfig.TLS)))
    }

    @Test
    fun `masque chooses handshake by alpn`() {
        // alpn h2 -> TLS (HTTP/2 поверх TCP), иначе -> QUIC
        assertFalse(CertificateFingerprintManager.usesQuicFor(profile(EConfigType.MASQUE, AppConfig.TLS, "h2")))
        assertTrue(CertificateFingerprintManager.usesQuicFor(profile(EConfigType.MASQUE, AppConfig.TLS, "h3")))
        assertTrue(CertificateFingerprintManager.usesQuicFor(profile(EConfigType.MASQUE, AppConfig.TLS)))
    }

    @Test
    fun `masque with mixed alpn list falls back to tls when h2 present and no h3`() {
        assertFalse(
            CertificateFingerprintManager.usesQuicFor(
                profile(EConfigType.MASQUE, AppConfig.TLS, "h2,http/1.1")
            )
        )
    }

    @Test
    fun `non tls non quic protocols never use quic`() {
        listOf(EConfigType.WIREGUARD, EConfigType.SHADOWSOCKS, EConfigType.SOCKS).forEach {
            assertFalse(CertificateFingerprintManager.usesQuicFor(profile(it)))
        }
    }

    /** Согласованность с существующим внутренним правилом по типу протокола. */
    @Test
    fun `usesQuicFor agrees with usesQuicHandshake for non masque`() {
        EConfigType.entries.filter { it != EConfigType.MASQUE }.forEach { type ->
            assertEquals(
                CertificateFingerprintManager.usesQuicHandshake(type),
                CertificateFingerprintManager.usesQuicFor(profile(type)),
                "расхождение для $type",
            )
        }
    }

    /** Пустой alpn у MASQUE: «h2» не в списке -> QUIC (прежнее поведение сохранено). */
    @Test
    fun `masque with blank alpn uses quic`() {
        assertTrue(CertificateFingerprintManager.usesQuicFor(profile(EConfigType.MASQUE, AppConfig.TLS, "")))
        assertTrue(CertificateFingerprintManager.usesQuicFor(profile(EConfigType.MASQUE, AppConfig.TLS, "   ")))
    }

    /** Пустой профиль: null поля не должны ронять выбор рукопожатия. */
    @Test
    fun `null alpn and security do not break handshake choice`() {
        val p = ProfileItem(configType = EConfigType.VLESS)
        assertFalse(CertificateFingerprintManager.usesQuicFor(p))
        assertNull(p.alpn)
    }

    // ---- Обфускация QUIC-рукопожатия (quicObfuscationFor) ----
    //
    // Регрессия, которую закрывают (вещдок 20.11.2026): нативная
    // fetchQuicCertSha256 делала чистое рукопожатие, серверы с obfs=salamander
    // его игнорировали, и все obfs-профили получали «context deadline exceeded»
    // (21 из 21 отказ), тогда как профили без obfs работали (4 из 4 успеха).

    private fun hy2(
        obfs: String?,
        obfsPassword: String?,
        min: String? = null,
        max: String? = null,
    ): ProfileItem = ProfileItem(configType = EConfigType.HYSTERIA2).apply {
        this.obfs = obfs
        this.obfsPassword = obfsPassword
        this.minPacketSize = min
        this.maxPacketSize = max
        server = "example.com"
        serverPort = "2096"
    }

    @Test
    fun `salamander profile sends obfuscation to native quic fetch`() {
        val obfs = CertificateFingerprintManager.quicObfuscationFor(
            hy2("salamander", "secretpsk")
        )

        assertEquals("salamander", obfs.type)
        assertEquals("secretpsk", obfs.password)
        // у salamander размеров пакетов нет — ядро берёт Config, не GeckoConfig
        assertEquals(0, obfs.minPacketSize)
        assertEquals(0, obfs.maxPacketSize)
    }

    @Test
    fun `gecko by explicit type uses default packet sizes`() {
        val obfs = CertificateFingerprintManager.quicObfuscationFor(
            hy2("gecko", "secretpsk")
        )

        assertEquals("gecko", obfs.type)
        assertEquals(
            CertificateFingerprintManager.QuicObfuscation.GECKO_DEFAULT_MIN_PACKET,
            obfs.minPacketSize,
        )
        assertEquals(
            CertificateFingerprintManager.QuicObfuscation.GECKO_DEFAULT_MAX_PACKET,
            obfs.maxPacketSize,
        )
    }

    @Test
    fun `gecko custom packet sizes are preserved`() {
        val obfs = CertificateFingerprintManager.quicObfuscationFor(
            hy2("gecko", "secretpsk", min = "600", max = "1300")
        )

        assertEquals("gecko", obfs.type)
        assertEquals(600, obfs.minPacketSize)
        assertEquals(1300, obfs.maxPacketSize)
    }

    @Test
    fun `packet sizes alone mark profile as gecko`() {
        // Критерий ядра: gecko отличается от salamander ИМЕННО наличием
        // MinPacketSize/MaxPacketSize (GeckoConfig живёт в пакете
        // finalmask.salamander, отдельного типа «gecko» в xray-core нет).
        val obfs = CertificateFingerprintManager.quicObfuscationFor(
            hy2("salamander", "secretpsk", min = "512", max = "1200")
        )

        assertEquals("gecko", obfs.type)
    }

    @Test
    fun `plain quic profile keeps legacy behaviour`() {
        // Инвариант опциональности: профиль БЕЗ обфускации обязан остаться
        // plain QUIC, иначе сломались бы работающие 4 из 4 профиля без obfs.
        assertEquals(
            CertificateFingerprintManager.QuicObfuscation.None,
            CertificateFingerprintManager.quicObfuscationFor(hy2(null, null)),
        )
        assertEquals(
            CertificateFingerprintManager.QuicObfuscation.None,
            CertificateFingerprintManager.quicObfuscationFor(hy2("none", "secretpsk")),
        )
        assertEquals(
            CertificateFingerprintManager.QuicObfuscation.None,
            CertificateFingerprintManager.quicObfuscationFor(hy2("salamander", null)),
        )
        assertEquals(
            CertificateFingerprintManager.QuicObfuscation.None,
            CertificateFingerprintManager.quicObfuscationFor(hy2("salamander", "   ")),
        )
    }

    @Test
    fun `hysteria v1 never gets salamander obfuscation`() {
        // У Hysteria v1 obfsPassword несёт obfs-СТРОКУ mihomo, а не PSK
        // salamander, поэтому передача обфускации для v1 была бы неверной.
        val v1 = ProfileItem(configType = EConfigType.HYSTERIA).apply {
            obfsPassword = "mihomo-obfs-string"
            obfs = "salamander"
        }

        assertEquals(
            CertificateFingerprintManager.QuicObfuscation.None,
            CertificateFingerprintManager.quicObfuscationFor(v1),
        )
    }

    @Test
    fun `obfs type is case insensitive`() {
        for (written in listOf("salamander", "Salamander", "SALAMANDER")) {
            assertEquals(
                "salamander",
                CertificateFingerprintManager.quicObfuscationFor(hy2(written, "psk")).type,
                "регистр $written обязан распознаваться",
            )
        }
    }

    // ---------- подсказка о причине отказа (failureHint) ----------
    //
    // Вещдок лога владельца 22.11.2026: профили группы заданы IP, а sni —
    // маскирующий домен чужого хоста; ядро сниффирует его и применяет СВОЁ
    // правило маршрутизации (detour [direct]), поэтому запрос уходит мимо
    // туннеля и сервер рвёт TLS. Отказ не должен выглядеть поломкой функции.

    private fun vlessIpWithMaskedSni(): ProfileItem =
        ProfileItem(configType = EConfigType.VLESS).apply {
            security = AppConfig.TLS
            server = "203.0.113.10"
            serverPort = "443"
            sni = "cdn.example.test"
        }

    @Test
    fun `masked sni on ip server explains direct routing`() {
        val p = vlessIpWithMaskedSni()
        val hint = CertificateFingerprintManager.failureHint(
            profile = p,
            server = p.server!!,
            serverName = p.sni,
            useQuic = false,
            attempts = listOf(SubscriptionCertPolicy.FetchAttempt.VIA_PROFILE),
        )

        assertTrue(hint.contains("маскирующий домен"), hint)
        assertTrue(hint.contains("direct"), hint)
        assertTrue(hint.contains("GoLog"), hint)
    }

    @Test
    fun `same sni and server gives generic profile hint`() {
        val p = ProfileItem(configType = EConfigType.VLESS).apply {
            security = AppConfig.TLS
            server = "example.com"
            serverPort = "443"
            sni = "example.com"
        }
        val hint = CertificateFingerprintManager.failureHint(
            profile = p,
            server = p.server!!,
            serverName = p.sni,
            useQuic = false,
            attempts = listOf(SubscriptionCertPolicy.FetchAttempt.VIA_PROFILE),
        )

        assertFalse(hint.contains("маскирующий домен"), hint)
        assertTrue(hint.contains("через профиль"), hint)
    }

    @Test
    fun `direct attempt gives no profile routing hint`() {
        val p = vlessIpWithMaskedSni()
        val hint = CertificateFingerprintManager.failureHint(
            profile = p,
            server = p.server!!,
            serverName = p.sni,
            useQuic = false,
            attempts = listOf(SubscriptionCertPolicy.FetchAttempt.DIRECT),
        )

        assertEquals("", hint)
    }

    @Test
    fun `quic with obfs mentions obfuscation requirement`() {
        val p = ProfileItem(configType = EConfigType.HYSTERIA2).apply {
            obfs = "salamander"
            obfsPassword = "secretpsk"
            server = "example.com"
            serverPort = "2096"
        }
        val hint = CertificateFingerprintManager.failureHint(
            profile = p,
            server = p.server!!,
            serverName = p.sni,
            useQuic = true,
            attempts = listOf(SubscriptionCertPolicy.FetchAttempt.DIRECT),
        )

        assertTrue(hint.contains("obfs=salamander"), hint)
        assertTrue(hint.contains("обфусцированное"), hint)
    }

    @Test
    fun `plain quic without obfs gives no obfs hint`() {
        val p = ProfileItem(configType = EConfigType.HYSTERIA2).apply {
            server = "example.com"
            serverPort = "443"
        }
        val hint = CertificateFingerprintManager.failureHint(
            profile = p,
            server = p.server!!,
            serverName = null,
            useQuic = true,
            attempts = listOf(SubscriptionCertPolicy.FetchAttempt.DIRECT),
        )

        assertEquals("", hint)
    }

    // ---------- обёртка failureHintFor (причина в видимой строке отказа) ----------
    //
    // Разрыв «видит юзер» ↔ «хранит код»: строка «Subscription cert NOT fetched»
    // (AngConfigManager.applyCertPolicies) шла БЕЗ причины, а причина писалась в
    // отдельную строку «no result after N attempt(s)». Вещдок лога владельца
    // 22.11.2026: три строки «NOT fetched … tried: profile» без объяснения.

    @Test
    fun `failureHintFor derives sni and quic from profile itself`() {
        val p = vlessIpWithMaskedSni()
        val hint = CertificateFingerprintManager.failureHintFor(
            p,
            listOf(SubscriptionCertPolicy.FetchAttempt.VIA_PROFILE),
        )

        // Тот же результат, что и у failureHint с вручную переданными параметрами.
        val direct = CertificateFingerprintManager.failureHint(
            profile = p,
            server = p.server!!,
            serverName = p.sni,
            useQuic = false,
            attempts = listOf(SubscriptionCertPolicy.FetchAttempt.VIA_PROFILE),
        )
        assertEquals(direct, hint)
        assertTrue(hint.contains("маскирующий домен"), hint)
    }

    @Test
    fun `failureHintFor detects quic profile without caller telling it`() {
        val p = ProfileItem(configType = EConfigType.HYSTERIA2).apply {
            obfs = "salamander"
            obfsPassword = "secretpsk"
            server = "example.com"
            serverPort = "2096"
        }
        val hint = CertificateFingerprintManager.failureHintFor(
            p,
            listOf(SubscriptionCertPolicy.FetchAttempt.DIRECT),
        )

        assertTrue(hint.contains("obfs=salamander"), hint)
    }

    @Test
    fun `failureHintFor returns empty for profile without server`() {
        val p = ProfileItem(configType = EConfigType.VLESS).apply {
            security = AppConfig.TLS
            server = "   "
            sni = "cdn.example.test"
        }
        assertEquals(
            "",
            CertificateFingerprintManager.failureHintFor(
                p,
                listOf(SubscriptionCertPolicy.FetchAttempt.VIA_PROFILE),
            ),
        )
    }

    @Test
    fun `failureHintFor keeps empty string when nothing to explain`() {
        val p = ProfileItem(configType = EConfigType.VLESS).apply {
            security = AppConfig.TLS
            server = "203.0.113.10"
            serverPort = "443"
        }
        assertEquals(
            "",
            CertificateFingerprintManager.failureHintFor(
                p,
                listOf(SubscriptionCertPolicy.FetchAttempt.DIRECT),
            ),
        )
    }
}
