package com.v2ray.ang.handler

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Порядок и гейты автополучения отпечатка сертификата при обновлении подписки.
 *
 * Требование владельца (дословно по смыслу):
 *  - сертификат, пришедший С ПОДПИСКОЙ, лучше автоматически полученного:
 *    перезаписывать его ЗАПРЕЩЕНО;
 *  - отпечаток получаем только у профилей, где его нет и протокол его поддерживает;
 *  - авто-allowInsecure применяется ПОСЛЕ получения отпечатка, иначе он
 *    не увидит свежий сертификат и профиль останется с проверкой;
 *  - выключенный свитч не делает ничего (каждый свитч независим).
 */
// Тест обязан проверять устаревшее поле pinSHA256: оно ещё живое в сохранённых
// профилях (миграция SettingsManager переносит его в pinnedCA256 позже), поэтому
// правило «сертификат из подписки не перезаписывать» обязано учитывать оба поля.
// Подавление — чтобы не сдвигать базовую линию warnings (76) проекта.
@Suppress("DEPRECATION")
class SubscriptionCertPolicyTest {

    private fun tlsProfile(name: String = "tls") = ProfileItem(configType = EConfigType.VLESS).apply {
        remarks = name
        security = AppConfig.TLS
        server = "example.com"
        serverPort = "443"
    }

    private fun hy2Profile(name: String = "hy2") = ProfileItem(configType = EConfigType.HYSTERIA2).apply {
        remarks = name
        server = "example.com"
        serverPort = "443"
    }

    // ---------- шаг 0: распознавание сертификата из подписки ----------

    @Test
    fun `certificate from subscription detected in pinnedCA256`() {
        val p = tlsProfile().apply { pinnedCA256 = "AA" }
        assertTrue(SubscriptionCertPolicy.hasCertificateFromSubscription(p))
    }

    @Test
    fun `certificate from subscription detected in legacy pinSHA256`() {
        val p = hy2Profile().apply { pinSHA256 = "BB" }
        assertTrue(SubscriptionCertPolicy.hasCertificateFromSubscription(p))
    }

    @Test
    fun `blank certificate is not a certificate`() {
        val p = tlsProfile().apply { pinnedCA256 = "   "; pinSHA256 = "" }
        assertFalse(SubscriptionCertPolicy.hasCertificateFromSubscription(p))
    }

    // ---------- шаги 1-2: кого звать за отпечатком ----------

    @Test
    fun `fetch skipped when switch is off`() {
        assertFalse(SubscriptionCertPolicy.shouldFetchCertificate(tlsProfile(), false))
    }

    @Test
    fun `fetch skipped when subscription already carries certificate`() {
        val withPinned = tlsProfile().apply { pinnedCA256 = "AA" }
        val withLegacy = hy2Profile().apply { pinSHA256 = "BB" }
        assertFalse(SubscriptionCertPolicy.shouldFetchCertificate(withPinned, true))
        assertFalse(SubscriptionCertPolicy.shouldFetchCertificate(withLegacy, true))
    }

    @Test
    fun `fetch allowed for tls profile without certificate`() {
        assertTrue(SubscriptionCertPolicy.shouldFetchCertificate(tlsProfile(), true))
    }

    @Test
    fun `fetch allowed for quic hysteria profiles without certificate`() {
        assertTrue(SubscriptionCertPolicy.shouldFetchCertificate(hy2Profile(), true))
        assertTrue(
            SubscriptionCertPolicy.shouldFetchCertificate(
                ProfileItem(configType = EConfigType.HYSTERIA).apply {
                    server = "example.com"
                    serverPort = "443"
                }, true
            )
        )
    }

    @Test
    fun `fetch skipped for protocols without certificate support`() {
        val wireguard = ProfileItem(configType = EConfigType.WIREGUARD)
        val shadowsocks = ProfileItem(configType = EConfigType.SHADOWSOCKS)
        val socks = ProfileItem(configType = EConfigType.SOCKS)
        val reality = tlsProfile().apply { security = AppConfig.REALITY }
        val noSecurity = tlsProfile().apply { security = null }
        listOf(wireguard, shadowsocks, socks, reality, noSecurity).forEach {
            assertFalse(SubscriptionCertPolicy.shouldFetchCertificate(it, true))
        }
    }

    // ---------- шаг 2 (запись): запрет перезаписи сертификата подписки ----------

    @Test
    fun `fetched certificate is written into pinnedCA256`() {
        val p = tlsProfile()
        assertTrue(SubscriptionCertPolicy.applyFetchedCertificate(p, "CC"))
        assertEquals("CC", p.pinnedCA256)
    }

    @Test
    fun `fetched certificate never overwrites subscription certificate`() {
        val withPinned = tlsProfile().apply { pinnedCA256 = "ORIGINAL" }
        val withLegacy = hy2Profile().apply { pinSHA256 = "LEGACY" }
        assertFalse(SubscriptionCertPolicy.applyFetchedCertificate(withPinned, "NEW"))
        assertFalse(SubscriptionCertPolicy.applyFetchedCertificate(withLegacy, "NEW"))
        assertEquals("ORIGINAL", withPinned.pinnedCA256)
        assertEquals("LEGACY", withLegacy.pinSHA256)
    }

    @Test
    fun `empty fetch result changes nothing`() {
        val p = tlsProfile()
        assertFalse(SubscriptionCertPolicy.applyFetchedCertificate(p, null))
        assertFalse(SubscriptionCertPolicy.applyFetchedCertificate(p, "  "))
        assertNull(p.pinnedCA256)
    }

    @Test
    fun `legacy pinSHA256 is left untouched by fetched certificate`() {
        val p = tlsProfile()
        assertTrue(SubscriptionCertPolicy.applyFetchedCertificate(p, "CC"))
        assertNull(p.pinSHA256)
    }

    // ---------- шаг 3: авто-allowInsecure ----------

    @Test
    fun `auto insecure skipped when switch is off`() {
        val p = tlsProfile().apply { pinnedCA256 = "AA" }
        assertFalse(SubscriptionCertPolicy.applyAutoInsecure(p, false))
        assertNull(p.insecure)
    }

    @Test
    fun `auto insecure skipped without certificate`() {
        val p = tlsProfile()
        assertFalse(SubscriptionCertPolicy.applyAutoInsecure(p, true))
        assertNull(p.insecure)
    }

    /**
     * Поведение существующего свитча авто-allowInsecure сохранено ПОСЛОВНО: он
     * всегда считал сертификатом НЕПУСТОЕ значение (!isNullOrEmpty), включая
     * пробельное. Новый гейт получения отпечатка строже (isNullOrBlank), поэтому
     * пробельное «сертификатом» для получения не считается — но сам старый свитч
     * не меняет поведение ни на одном входе (бережное отношение к рабочей фиче).
     */
    @Test
    fun `auto insecure keeps legacy isNullOrEmpty semantics for blank value`() {
        val blank = tlsProfile().apply { pinnedCA256 = "   " }
        // пробел = непустая строка -> старый свитч всё так же включает insecure
        assertTrue(SubscriptionCertPolicy.applyAutoInsecure(blank, true))
        assertEquals(true, blank.insecure)
        // но гейт получения отпечатка считает пробел отсутствием сертификата
        assertFalse(SubscriptionCertPolicy.hasCertificateFromSubscription(blank))
        assertTrue(SubscriptionCertPolicy.shouldFetchCertificate(blank, true))
    }

    @Test
    fun `auto insecure applies for pinned and legacy certificates`() {
        val a = tlsProfile().apply { pinnedCA256 = "AA" }
        val b = hy2Profile().apply { pinSHA256 = "BB" }
        assertTrue(SubscriptionCertPolicy.applyAutoInsecure(a, true))
        assertTrue(SubscriptionCertPolicy.applyAutoInsecure(b, true))
        assertEquals(true, a.insecure)
        assertEquals(true, b.insecure)
    }

    @Test
    fun `auto insecure does not report change when already true`() {
        val p = tlsProfile().apply { pinnedCA256 = "AA"; insecure = true }
        assertFalse(SubscriptionCertPolicy.applyAutoInsecure(p, true))
        assertEquals(true, p.insecure)
    }

    @Test
    fun `auto insecure never disables explicit false`() {
        val p = tlsProfile()
        assertFalse(SubscriptionCertPolicy.applyAutoInsecure(p, true))
        assertNull(p.insecure)
    }

    // ---------- выверенная последовательность целиком ----------

    /**
     * Итог владельца: оба свитча включены; в подписке часть профилей уже
     * с сертификатом, часть — без. После обновления ВСЕ подходящие профили
     * имеют отпечаток и allowInsecure, а сертификаты подписки не перезаписаны.
     */
    @Test
    fun `full pipeline both switches on keeps subscription certs and fills the rest`() {
        val fromSub = tlsProfile("fromSub").apply { pinnedCA256 = "FROM_SUBSCRIPTION" }
        val legacyFromSub = hy2Profile("legacyFromSub").apply { pinSHA256 = "LEGACY_SUB" }
        val missing = tlsProfile("missing")
        val unsupported = ProfileItem(configType = EConfigType.WIREGUARD).apply { remarks = "unsupported" }

        val profiles = listOf(fromSub, legacyFromSub, missing, unsupported)

        // шаг 1-2: получение отпечатка только там, где его нет.
        // Ключом опроса служит имя профиля (ProfileItem — изменяемый data class,
        // его нельзя держать ключом коллекции: hashCode меняется вместе с полями).
        val probed = mutableListOf<String>()
        profiles.forEach { p ->
            if (SubscriptionCertPolicy.shouldFetchCertificate(p, true)) {
                probed.add(p.remarks)
                SubscriptionCertPolicy.applyFetchedCertificate(p, "FETCHED")
            }
        }
        assertEquals(listOf("missing"), probed)

        // шаг 3: авто-allowInsecure ПОСЛЕ получения
        profiles.forEach { SubscriptionCertPolicy.applyAutoInsecure(it, true) }

        assertEquals("FROM_SUBSCRIPTION", fromSub.pinnedCA256)
        assertEquals("LEGACY_SUB", legacyFromSub.pinSHA256)
        assertEquals("FETCHED", missing.pinnedCA256)
        assertEquals(true, fromSub.insecure)
        assertEquals(true, legacyFromSub.insecure)
        assertEquals(true, missing.insecure)
        // неподдерживаемый протокол не тронут вообще
        assertNull(unsupported.pinnedCA256)
        assertNull(unsupported.insecure)
    }

    /** Порядок важен: если allowInsecure применить ДО получения, свежий профиль его не получит. */
    @Test
    fun `wrong order would miss freshly fetched certificate`() {
        val p = tlsProfile()
        // намеренно неверный порядок — доказывает, почему он неверен
        SubscriptionCertPolicy.applyAutoInsecure(p, true)
        assertNull(p.insecure)
        assertTrue(SubscriptionCertPolicy.shouldFetchCertificate(p, true))
        SubscriptionCertPolicy.applyFetchedCertificate(p, "FETCHED")
        // правильный порядок добивает результат
        assertTrue(SubscriptionCertPolicy.applyAutoInsecure(p, true))
        assertEquals(true, p.insecure)
    }

    /** Каждый свитч независим: только авто-получение — allowInsecure не трогаем. */
    @Test
    fun `only fetch switch on does not enable insecure`() {
        val p = tlsProfile()
        assertTrue(SubscriptionCertPolicy.shouldFetchCertificate(p, true))
        SubscriptionCertPolicy.applyFetchedCertificate(p, "FETCHED")
        assertFalse(SubscriptionCertPolicy.applyAutoInsecure(p, false))
        assertEquals("FETCHED", p.pinnedCA256)
        assertNull(p.insecure)
    }

    /** Только авто-allowInsecure: сеть не зовём, сертификат из подписки honoured. */
    @Test
    fun `only insecure switch on does not fetch anything`() {
        val missing = tlsProfile()
        val fromSub = tlsProfile().apply { pinnedCA256 = "FROM_SUBSCRIPTION" }
        assertFalse(SubscriptionCertPolicy.shouldFetchCertificate(missing, false))
        assertFalse(SubscriptionCertPolicy.shouldFetchCertificate(fromSub, false))
        assertFalse(SubscriptionCertPolicy.applyAutoInsecure(missing, true))
        assertTrue(SubscriptionCertPolicy.applyAutoInsecure(fromSub, true))
        assertNull(missing.pinnedCA256)
        assertNull(missing.insecure)
        assertEquals(true, fromSub.insecure)
    }

    // ---------- дедупликация сетевых запросов по эндпоинту ----------

    @Test
    fun `endpoint key ignores password and transport but not configType`() {
        val a = tlsProfile().apply { password = "p1"; network = "ws"; sni = "s.example.com" }
        val b = tlsProfile().apply {
            password = "p2"; network = "grpc"; sni = "s.example.com"
        }
        assertEquals(SubscriptionCertPolicy.endpointKey(a), SubscriptionCertPolicy.endpointKey(b))
    }

    /**
     * КРИТИЧНО: отпечаток зависит от типа рукопожатия. VLESS-TLS и Hysteria2-QUIC
     * на одном host:port:sni должны дать РАЗНЫЕ ключи — иначе второй получит
     * чужой (TLS) отпечаток из общего кэша. Регрессия, найденная самоаудитом.
     */
    @Test
    fun `endpoint key separates tls from quic on same host`() {
        val tls = tlsProfile().apply { sni = "s.example.com" }
        val quic = hy2Profile().apply { sni = "s.example.com" }
        assertNotEquals(
            SubscriptionCertPolicy.endpointKey(tls),
            SubscriptionCertPolicy.endpointKey(quic),
        )
    }

    /** MASQUE выбирает QUIC/TLS по alpn — ключ обязан различать alpn. */
    @Test
    fun `endpoint key separates different alpn on same host`() {
        val h2 = tlsProfile().apply { alpn = "h2"; sni = "s.example.com" }
        val h3 = tlsProfile().apply { alpn = "h3"; sni = "s.example.com" }
        assertNotEquals(
            SubscriptionCertPolicy.endpointKey(h2),
            SubscriptionCertPolicy.endpointKey(h3),
        )
    }

    @Test
    fun `endpoint key separates port and sni`() {
        val base = tlsProfile().apply { sni = "s.example.com" }
        val otherPort = tlsProfile().apply { serverPort = "8443"; sni = "s.example.com" }
        val otherSni = tlsProfile().apply { sni = "other.example.com" }
        val otherHost = tlsProfile().apply { server = "other.com"; sni = "s.example.com" }
        val keys = listOf(base, otherPort, otherSni, otherHost).map { SubscriptionCertPolicy.endpointKey(it) }
        assertEquals(4, keys.toSet().size)
    }

    @Test
    fun `endpoint key normalizes missing port to default`() {
        val noPort = tlsProfile().apply { serverPort = null }
        val badPort = tlsProfile().apply { serverPort = "abc" }
        val explicit = tlsProfile().apply { serverPort = "443" }
        val k = SubscriptionCertPolicy.endpointKey(explicit)
        assertEquals(k, SubscriptionCertPolicy.endpointKey(noPort))
        assertEquals(k, SubscriptionCertPolicy.endpointKey(badPort))
    }

    // ---------- маршрут получения отпечатка (матрица режимов профиля) ----------

    @Test
    fun `route is direct when via-profile switch is off regardless of profile state`() {
        // свитч ВЫКЛ — прежнее поведение: напрямую, даже если профиль не запущен
        assertEquals(
            SubscriptionCertPolicy.FetchRoute.DIRECT,
            SubscriptionCertPolicy.decideFetchRoute(false, false, false, false),
        )
        assertEquals(
            SubscriptionCertPolicy.FetchRoute.DIRECT,
            SubscriptionCertPolicy.decideFetchRoute(false, true, false, true),
        )
    }

    @Test
    fun `route is via profile when switch on and loopback proxy listens`() {
        assertEquals(
            SubscriptionCertPolicy.FetchRoute.VIA_PROFILE,
            SubscriptionCertPolicy.decideFetchRoute(true, true, false, true),
        )
    }

    @Test
    fun `tunnel profile counts as direct because app is inside the tunnel`() {
        // FPTN: системный TUN, приложение внутри него — «напрямую» физически через профиль
        assertEquals(
            SubscriptionCertPolicy.FetchRoute.DIRECT,
            SubscriptionCertPolicy.decideFetchRoute(true, false, true, true),
        )
    }

    @Test
    fun `skip when switch on but profile runs without usable route`() {
        // VPN-tun без loopback-прокси: прямой запрос обошёл бы профиль
        assertEquals(
            SubscriptionCertPolicy.FetchRoute.SKIP,
            SubscriptionCertPolicy.decideFetchRoute(true, false, false, true),
        )
    }

    @Test
    fun `skip when switch on and no profile is running`() {
        assertEquals(
            SubscriptionCertPolicy.FetchRoute.SKIP,
            SubscriptionCertPolicy.decideFetchRoute(true, false, false, false),
        )
    }

    /** Оба свитча выключены — поведение ровно как до фичи. */
    @Test
    fun `both switches off leaves profile untouched`() {
        val fromSub = tlsProfile().apply { pinnedCA256 = "FROM_SUBSCRIPTION" }
        val missing = tlsProfile()
        listOf(fromSub, missing).forEach { p ->
            assertFalse(SubscriptionCertPolicy.shouldFetchCertificate(p, false))
            assertFalse(SubscriptionCertPolicy.applyAutoInsecure(p, false))
        }
        assertEquals("FROM_SUBSCRIPTION", fromSub.pinnedCA256)
        assertNull(fromSub.insecure)
        assertNull(missing.pinnedCA256)
        assertNull(missing.insecure)
    }
}
