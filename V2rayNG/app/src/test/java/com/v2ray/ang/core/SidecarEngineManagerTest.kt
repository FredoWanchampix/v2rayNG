package com.v2ray.ang.core

import com.v2ray.ang.AppConfig
import com.v2ray.ang.enums.EConfigType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
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
        // Три движка обслуживаются через SidecarEngineManager (mihomo, sing-box,
        // mimic-client). Остальные три из упакованных в CI (fptn-client, dnsproxy,
        // speedprobe) не сопоставлены типу профиля: fptn-client стартует через
        // FptnRootRunner, а dnsproxy/speedprobe - служебные бинарники пробы FPTN.
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
    fun `hysteria v1 is served by mihomo`() {
        // Эксперимент на устройстве: libmihomo.so -t с hysteria-outbound =
        // "test is successful"; sing-box форка собран без QUIC
        // ("QUIC is not included in this build"). Значит v1 -> mihomo.
        assertEquals("mihomo", SidecarEngineManager.engineFor(EConfigType.HYSTERIA))
        assertTrue(SidecarEngineManager.needsProbeEngine(EConfigType.HYSTERIA))
    }

    @Test
    fun `mihomo hysteria v1 config carries all protocol fields`() {
        val profile = com.v2ray.ang.dto.entities.ProfileItem.create(EConfigType.HYSTERIA)
        profile.server = "hy.example.com"
        profile.serverPort = "8443"
        profile.password = "tok"
        profile.method = "wechat-video"
        profile.bandwidthUp = "100Mbps"
        profile.bandwidthDown = "200Mbps"
        profile.sni = "s.example.com"
        profile.insecure = true
        profile.alpn = "h3"
        profile.obfsPassword = "myobfs"
        profile.portHopping = "8443-8450"
        val cfg = SidecarConfigBuilder.build(profile, "mihomo", 39081)
        assertNotNull(cfg)
        assertTrue(cfg!!.contains("type: hysteria"), cfg)
        assertTrue(cfg.contains("auth_str: \"tok\""), cfg)
        assertTrue(cfg.contains("protocol: \"wechat-video\""), cfg)
        assertTrue(cfg.contains("up: \"100Mbps\""), cfg)
        assertTrue(cfg.contains("down: \"200Mbps\""), cfg)
        assertTrue(cfg.contains("sni: \"s.example.com\""), cfg)
        assertTrue(cfg.contains("skip-cert-verify: true"), cfg)
        assertTrue(cfg.contains("- \"h3\""), cfg)
        assertTrue(cfg.contains("obfs: \"myobfs\""), cfg)
        assertTrue(cfg.contains("ports: \"8443-8450\""), cfg)
        assertTrue(cfg.contains("mixed-port: 39081"), cfg)
    }

    @Test
    fun `mihomo hysteria v1 config carries tuning options`() {
        val profile = com.v2ray.ang.dto.entities.ProfileItem.create(EConfigType.HYSTERIA)
        profile.server = "hy.example.com"
        profile.serverPort = "8443"
        profile.password = "tok"
        profile.bandwidthUp = "100Mbps"
        profile.bandwidthDown = "100Mbps"
        profile.hysteriaOptions = """{"recvWindowConn":12345678,"recvWindow":12345678,"disableMtuDiscovery":true}"""
        val cfg = SidecarConfigBuilder.build(profile, "mihomo", 39084)
        assertNotNull(cfg)
        assertTrue(cfg!!.contains("recv-window-conn: 12345678"), cfg)
        assertTrue(cfg.contains("recv-window: 12345678"), cfg)
        assertTrue(cfg.contains("disable-mtu-discovery: true"), cfg)
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

    // --- Упаковка движков как lib*.so (перенос из assets/engines) ---
    //
    // Зачем эти тесты. На Android 10+ SELinux (W^X) запрещает untrusted_app
    // исполнять файлы из filesDir, поэтому движки обязаны лежать в libs/<abi>/
    // как lib*.so и запускаться из nativeLibraryDir. Два инварианта защищают от
    // регрессии, которую иначе невозможно заметить в unit-тестах:
    //   1) имя файла обязано начинаться с "lib" и заканчиваться на ".so" -
    //      иначе PackageManager вообще не извлечёт его из APK в nativeLibraryDir;
    //   2) каждому упакованному движку обязано соответствовать ровно одно
    //      lib-имя, и все lib-имена различны - иначе два движка легли бы в один
    //      файл и один из них молча исчез бы из сборки.

    @Test
    fun `every engine maps to its own lib name`() {
        val expected = mapOf(
            SidecarEngineManager.ENGINE_MIHOMO to AppConfig.ENGINE_MIHOMO_BIN,
            SidecarEngineManager.ENGINE_SINGBOX to AppConfig.ENGINE_SINGBOX_BIN,
            SidecarEngineManager.ENGINE_MIMIC to AppConfig.ENGINE_MIMIC_BIN,
            SidecarEngineManager.ENGINE_FPTN to AppConfig.ENGINE_FPTN_BIN,
            SidecarEngineManager.ENGINE_DNSPROXY to AppConfig.ENGINE_DNSPROXY_BIN,
            SidecarEngineManager.ENGINE_SPEEDPROBE to AppConfig.ENGINE_SPEEDPROBE_BIN,
        )
        assertEquals(expected.keys.toList(), SidecarEngineManager.ALL_ENGINES)
        for ((engine, lib) in expected) {
            assertEquals(lib, SidecarEngineManager.libNameFor(engine), "маппинг $engine")
        }
    }

    @Test
    fun `engine lib names are valid jniLibs file names`() {
        // Инвариант извлечения в nativeLibraryDir: lib*.so.
        for (engine in SidecarEngineManager.ALL_ENGINES) {
            val lib = SidecarEngineManager.libNameFor(engine)
            assertNotNull(lib, "у $engine обязано быть lib-имя")
            assertTrue(lib!!.startsWith("lib"), "$lib должен начинаться с 'lib'")
            assertTrue(lib.endsWith(".so"), "$lib должен заканчиваться на '.so'")
        }
        // Так же и для hev-бинарника root-режима (тот же механизм).
        assertTrue(AppConfig.ROOT_TUN2SOCKS_BIN.startsWith("lib"))
        assertTrue(AppConfig.ROOT_TUN2SOCKS_BIN.endsWith(".so"))
    }

    @Test
    fun `engine lib names are unique`() {
        val names = SidecarEngineManager.ALL_ENGINES.mapNotNull { SidecarEngineManager.libNameFor(it) }
        assertEquals(
            names.distinct().sorted(),
            names.sorted(),
            "два движка не могут претендовать на один lib*.so",
        )
    }

    @Test
    fun `unknown engine has no lib name`() {
        assertNull(SidecarEngineManager.libNameFor("mihomo2"))
        assertNull(SidecarEngineManager.libNameFor(""))
        assertNull(SidecarEngineManager.libNameFor("xray"))
    }

    @Test
    fun `engineFor always yields a bundled engine`() {
        // Каждое имя, которое может вернуть engineFor, обязано быть в ALL_ENGINES
        // и иметь lib-имя: иначе профиль запросил бы движок, которого нет в APK.
        for (type in EConfigType.entries) {
            val engine = SidecarEngineManager.engineFor(type) ?: continue
            assertTrue(engine in SidecarEngineManager.ALL_ENGINES, "$engine ($type) не упакован")
            assertNotNull(SidecarEngineManager.libNameFor(engine), "у $engine нет lib-имени")
        }
    }
}
