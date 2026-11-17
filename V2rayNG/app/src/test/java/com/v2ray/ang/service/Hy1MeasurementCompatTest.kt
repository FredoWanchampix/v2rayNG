package com.v2ray.ang.service

import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.handler.CertificateFingerprintManager
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Совместимость измерений и отпечатка с QUIC-протоколами форка, включая
 * Hysteria v1: TCPing к UDP-порту бессмыслен, отпечаток берётся
 * QUIC-рукопожатием. Предикаты internal — доступны unit-тестам.
 */
class Hy1MeasurementCompatTest {

    private fun profile(type: EConfigType, alpn: String? = null): ProfileItem {
        val p = ProfileItem.create(type)
        p.server = "1.2.3.4"
        p.serverPort = "8443"
        p.alpn = alpn
        return p
    }

    @Test
    fun `tcp probe not applicable to quic and wireguard`() {
        assertFalse(RealPingWorkerService.tcpProbeApplicable(profile(EConfigType.HYSTERIA)))
        assertFalse(RealPingWorkerService.tcpProbeApplicable(profile(EConfigType.HYSTERIA2)))
        assertFalse(RealPingWorkerService.tcpProbeApplicable(profile(EConfigType.WIREGUARD)))
        // alpn h3 -> QUIC даже для tcp-подобных типов
        assertFalse(RealPingWorkerService.tcpProbeApplicable(profile(EConfigType.VLESS, "h3")))
    }

    @Test
    fun `tcp probe applicable to tcp protocols`() {
        assertTrue(RealPingWorkerService.tcpProbeApplicable(profile(EConfigType.VLESS)))
        assertTrue(RealPingWorkerService.tcpProbeApplicable(profile(EConfigType.TROJAN, "h2,http/1.1")))
        assertTrue(RealPingWorkerService.tcpProbeApplicable(profile(EConfigType.SOCKS)))
    }

    @Test
    fun `quic handshake used for hy1 and hy2 fingerprint`() {
        assertTrue(CertificateFingerprintManager.usesQuicHandshake(EConfigType.HYSTERIA))
        assertTrue(CertificateFingerprintManager.usesQuicHandshake(EConfigType.HYSTERIA2))
        assertFalse(CertificateFingerprintManager.usesQuicHandshake(EConfigType.VLESS))
        assertFalse(CertificateFingerprintManager.usesQuicHandshake(EConfigType.WIREGUARD))
    }
}