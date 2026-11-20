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
}
