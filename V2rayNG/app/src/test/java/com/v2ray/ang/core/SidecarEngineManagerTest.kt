package com.v2ray.ang.core

import com.v2ray.ang.enums.EConfigType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Доказывает матрицу «тип профиля -> ядро/движок» и правила измеримости.
 *
 * Почему это важно: форк поддерживает ЧЕТЫРЕ сайдкар-движка, и каждый тип профиля
 * обязан быть привязан ровно к своему движку. Если сопоставление потеряется,
 * профиль не запустится ни в одном режиме (VPN / proxy-only / root), потому что
 * Xray получит upstream на несуществующий порт.
 */
class SidecarEngineManagerTest {

    // --- Матрица: какой движок обслуживает какой тип профиля ---

    @Test
    fun `amneziawg is served by mihomo`() {
        assertEquals("mihomo", SidecarEngineManager.engineFor(EConfigType.AMNEZIAWG))
    }

    @Test
    fun `naiveproxy is served by sing-box`() {
        assertEquals("sing-box", SidecarEngineManager.engineFor(EConfigType.NAIVE))
    }

    @Test
    fun `openconnect is served by sing-box`() {
        assertEquals("sing-box", SidecarEngineManager.engineFor(EConfigType.OPENCONNECT))
    }

    @Test
    fun `mimic is served by mimic-client`() {
        assertEquals("mimic-client", SidecarEngineManager.engineFor(EConfigType.MIMIC))
    }

    @Test
    fun `all four bundled engines are mapped`() {
        // Именно четыре движка собираются в CI и кладутся в assets/engines:
        // fptn-client, mihomo, mimic-client, sing-box. Три из них обслуживаются
        // через SidecarEngineManager, четвёртый (fptn-client) - через FptnRootRunner.
        val engines = EConfigType.entries
            .mapNotNull { SidecarEngineManager.engineFor(it) }
            .distinct()
            .sorted()
        assertEquals(listOf("mihomo", "mimic-client", "sing-box"), engines)
    }

    // --- Типы, которым сайдкар НЕ нужен (родные протоколы Xray) ---

    @Test
    fun `xray-native types need no sidecar engine`() {
        for (type in listOf(
            EConfigType.VMESS, EConfigType.VLESS, EConfigType.SHADOWSOCKS,
            EConfigType.SOCKS, EConfigType.HTTP, EConfigType.TROJAN,
            EConfigType.WIREGUARD, EConfigType.HYSTERIA2, EConfigType.MASQUE,
            EConfigType.CUSTOM, EConfigType.POLICYGROUP, EConfigType.PROXYCHAIN,
            EConfigType.CUSTOM_OUTBOUND,
        )) {
            assertNull(SidecarEngineManager.engineFor(type), "у $type не должно быть движка")
            assertFalse(SidecarEngineManager.needsProbeEngine(type))
        }
    }

    @Test
    fun `sidecar types need a probe engine`() {
        for (type in listOf(
            EConfigType.AMNEZIAWG, EConfigType.NAIVE,
            EConfigType.OPENCONNECT, EConfigType.MIMIC,
        )) {
            assertTrue(
                SidecarEngineManager.needsProbeEngine(type),
                "$type обязан требовать локальный движок для пробы",
            )
        }
    }

    // --- FPTN: отдельный случай, Xray для него не используется ---

    @Test
    fun `fptn is not served by the sidecar manager`() {
        // fptn-client запускается через FptnRootRunner и владеет собственным TUN,
        // поэтому у него нет ни движка в SidecarEngineManager, ни Xray-outbound.
        assertNull(SidecarEngineManager.engineFor(EConfigType.FPTN))
        assertFalse(SidecarEngineManager.needsProbeEngine(EConfigType.FPTN))
    }

    @Test
    fun `fptn is the only type that cannot be measured by a temporary core`() {
        assertTrue(SidecarEngineManager.cannotMeasureInTempCore(EConfigType.FPTN))
        // Все остальные типы измеримы: сайдкар-типы - потому что движок поднимается
        // локально в процессе пробы, нативные - потому что Xray работает сам.
        for (type in EConfigType.entries) {
            if (type == EConfigType.FPTN) continue
            assertFalse(
                SidecarEngineManager.cannotMeasureInTempCore(type),
                "$type должен быть измерим временным ядром",
            )
        }
    }
}
