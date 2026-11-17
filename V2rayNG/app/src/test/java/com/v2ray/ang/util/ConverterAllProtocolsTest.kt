package com.v2ray.ang.util

import android.text.TextUtils
import android.util.Base64
import android.util.Log
import com.v2ray.ang.fmt.AmneziaFmt
import com.v2ray.ang.fmt.Hysteria2Fmt
import com.v2ray.ang.fmt.HysteriaFmt
import com.v2ray.ang.fmt.MasqueFmt
import com.v2ray.ang.fmt.ShadowsocksFmt
import com.v2ray.ang.fmt.TrojanFmt
import com.v2ray.ang.fmt.VlessFmt
import com.v2ray.ang.fmt.VmessFmt
import com.v2ray.ang.fmt.FptnFmt
import com.v2ray.ang.fmt.MimicFmt
import com.v2ray.ang.fmt.NaiveFmt
import com.v2ray.ang.fmt.OpenconnectFmt
import com.v2ray.ang.fmt.SocksFmt
import com.v2ray.ang.fmt.WireguardFmt
import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.MockedStatic
import org.mockito.Mockito
import org.mockito.Mockito.mockStatic
import java.util.Base64 as JavaBase64

/**
 * Полнота конвертера по ВСЕМ протоколам форка: для каждого протокола: либо JSON -> ссылка
 * с round-trip «ссылка -> Fmt.parse -> эквивалентный профиль», либо явный
 * отказ (конфиг остаётся кастомным, причина в логе). Молчаливых пустых
 * списков и молчаливой потери обфускации быть не должно.
 */
class ConverterAllProtocolsTest {

    // vmess/ss-ссылки несут base64; android.util.Base64 на JVM замокан
    // (образец — ShadowsocksFmtTest). Log замокан, чтобы не тянуть MMKV.
    private lateinit var mockBase64: MockedStatic<Base64>
    private lateinit var mockLog: MockedStatic<Log>
    private lateinit var mockTextUtils: MockedStatic<TextUtils>

    @BeforeEach
    fun setUp() {
        mockLog = mockStatic(Log::class.java, Mockito.RETURNS_DEFAULTS)
        mockTextUtils = mockStatic(TextUtils::class.java)
        mockTextUtils.`when`<Boolean> {
            TextUtils.isEmpty(Mockito.any())
        }.thenAnswer { inv ->
            val s = inv.arguments[0] as CharSequence?
            s.isNullOrEmpty()
        }
        mockBase64 = mockStatic(Base64::class.java)
        mockBase64.`when`<ByteArray> {
            Base64.decode(Mockito.anyString(), Mockito.anyInt())
        }.thenAnswer { inv ->
            val input = inv.arguments[0] as String
            val flags = inv.arguments[1] as Int
            val decoder = if ((flags and Base64.URL_SAFE) != 0) JavaBase64.getUrlDecoder() else JavaBase64.getDecoder()
            decoder.decode(input)
        }
        mockBase64.`when`<String> {
            Base64.encodeToString(Mockito.any(ByteArray::class.java), Mockito.anyInt())
        }.thenAnswer { inv ->
            val input = inv.arguments[0] as ByteArray
            val flags = inv.arguments[1] as Int
            var encoder = if ((flags and Base64.URL_SAFE) != 0) JavaBase64.getUrlEncoder() else JavaBase64.getEncoder()
            if ((flags and Base64.NO_PADDING) != 0) encoder = encoder.withoutPadding()
            encoder.encodeToString(input)
        }
    }

    @AfterEach
    fun tearDown() {
        mockBase64.close()
        mockLog.close()
        mockTextUtils.close()
    }

    private fun convert(json: String): String =
        SubscriptionContentConverter.convert(json, decodeBase64 = false, customToLinks = true)

    // --- AmneziaWG: mihomo-стиль (type=wireguard + amnezia-wg-option) ---

    private val awgMihomo = """
        {
          "remarks": "AWG",
          "outbounds": [
            {
              "tag": "awg", "protocol": "wireguard",
              "server": "1.2.3.4", "port": 51820,
              "private-key": "PRIV=", "public-key": "PUB=",
              "ip": "172.16.0.2", "ipv6": "2606:4700::1", "mtu": 1280,
              "amnezia-wg-option": {
                "version": 3, "jc": 4, "jmin": 40, "jmax": 70,
                "s1": 15, "s2": 25, "h1": "123456", "h2": "234567",
                "header_protection_key": "KEYKEY", "random_trailers": true
              }
            }
          ]
        }
    """.trimIndent()

    @Test
    fun `amneziawg converts to awg link keeping obfuscation`() {
        val out = convert(awgMihomo)
        assertTrue(out.startsWith("awg://"), "ожидалась awg-ссылка, не plain wireguard: $out")
        assertFalse(out.startsWith("wireguard://"), "plain wireguard потерял бы обфускацию")
        val profile = AmneziaFmt.parse(out)
        assertNotNull(profile, "awg-ссылка обязана читаться AmneziaFmt")
        assertEquals("1.2.3.4", profile!!.server)
        assertEquals("51820", profile.serverPort)
        assertEquals("PRIV=", profile.secretKey)
        assertEquals("PUB=", profile.publicKey)
        assertEquals(1280, profile.mtu)
        // адрес дополнен масками (mihomo хранит без них)
        assertTrue(profile.localAddress!!.contains("172.16.0.2/32"), profile.localAddress)
        assertTrue(profile.localAddress!!.contains("2606:4700::1/128"), profile.localAddress)
        // ВСЕ опции пережили round-trip
        val opts = JSONObject(profile.amneziaOptions!!)
        assertEquals(3, opts.getInt("version"))
        assertEquals(4, opts.getInt("jc"))
        assertEquals(40, opts.getInt("jmin"))
        assertEquals(70, opts.getInt("jmax"))
        assertEquals(15, opts.getInt("s1"))
        assertEquals(25, opts.getInt("s2"))
        assertEquals("123456", opts.getString("h1"))
        assertEquals("234567", opts.getString("h2"))
        assertEquals("KEYKEY", opts.getString("header-protection-key"))
        assertTrue(opts.getBoolean("random-trailers"))
    }

    @Test
    fun `amneziawg export reimport keeps boolean options`() {
        // Регрессия AmneziaFmt.toUri: camelCase-ключи редактора обязаны
        // экспортироваться в kebab-case, иначе повторный импорт их терял.
        val profile = AmneziaFmt.parse(convert(awgMihomo))!!
        // имитируем хранение редактором (camelCase, как buildAmneziaOptions)
        val opts = JSONObject(profile.amneziaOptions!!)
        opts.remove("random-trailers"); opts.put("randomTrailers", true)
        opts.put("disableCookies", true)
        profile.amneziaOptions = opts.toString()
        val uri = "awg://" + AmneziaFmt.toUri(profile)
        val again = AmneziaFmt.parse(uri)
        assertNotNull(again)
        val opts2 = JSONObject(again!!.amneziaOptions!!)
        assertTrue(opts2.getBoolean("random-trailers"), "randomTrailers обязан пережить export/import")
        assertTrue(opts2.getBoolean("disable-cookies"), "disableCookies обязан пережить export/import")
    }

    @Test
    fun `amneziawg legacy v1 options survive`() {
        val legacy = JSONObject(awgMihomo)
        val ob = legacy.getJSONArray("outbounds").getJSONObject(0)
        ob.put("amnezia-wg-option", JSONObject()
            .put("jc", 5).put("jmin", 10).put("jmax", 50)
            .put("j1", "<b 0xce00000001>").put("itime", 30))
        val out = convert(legacy.toString())
        assertTrue(out.startsWith("awg://"), out)
        val profile = AmneziaFmt.parse(out)!!
        val opts = JSONObject(profile.amneziaOptions!!)
        assertFalse(opts.has("version"), "версия не навязывается: legacy остаётся legacy")
        assertEquals("<b 0xce00000001>", opts.getString("j1"))
        assertEquals(30, opts.getInt("itime"))
    }

    @Test
    fun `amneziawg with non-numeric version stays custom`() {
        val bad = JSONObject(awgMihomo)
        bad.getJSONArray("outbounds").getJSONObject(0)
            .getJSONObject("amnezia-wg-option").put("version", "abc")
        val out = convert(bad.toString())
        assertFalse(out.startsWith("awg://"), "нечисловой version нельзя терять молча: $out")
        assertTrue(out.contains("amnezia-wg-option"), "конфиг остаётся кастомным: $out")
    }

    @Test
    fun `wireguard without amnezia options converts to plain wireguard`() {
        // Опциональность обфускации: xray wireguard-outbound БЕЗ
        // amnezia-wg-option — это plain wireguard, ссылка обязана быть
        // wireguard:// (не awg://), профиль импортируется без обфускации.
        val cfg = """
            { "remarks": "WG plain", "outbounds": [ { "tag": "wg", "protocol": "wireguard",
              "settings": { "secretKey": "PRIV=", "address": ["172.16.0.2/32"], "mtu": 1280,
                "peers": [ { "endpoint": "1.2.3.4:51820", "publicKey": "PUB=",
                  "allowedIPs": ["0.0.0.0/0", "::/0"] } ] } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertTrue(out.startsWith("wireguard://"), out)
        assertFalse(out.startsWith("awg://"), out)
        val profile = WireguardFmt.parse(out)
        assertNotNull(profile)
        assertEquals("PRIV=", profile!!.secretKey)
        assertEquals("PUB=", profile.publicKey)
        assertEquals(1280, profile.mtu)
        assertNull(profile.amneziaOptions, "обфускации не было — её не должно появиться")
        assertNull(profile.noisesJson, "шума не было — он не навязывается")
    }

    @Test
    fun `wireguard with amnezia options never degrades to plain`() {
        // awg-опции есть, но endpoint отсутствует: сборка невозможна.
        // Отказ, а не plain wireguard:// с потерей обфускации.
        val broken = JSONObject(awgMihomo)
        val ob = broken.getJSONArray("outbounds").getJSONObject(0)
        ob.remove("server"); ob.remove("port")
        val out = convert(broken.toString())
        assertFalse(out.startsWith("wireguard://"), "нельзя молча потерять обфускацию: $out")
        assertFalse(out.startsWith("awg://"), "сборка невозможна без endpoint: $out")
        assertTrue(out.contains("amnezia-wg-option"))
    }

    // --- Mimic ---

    @Test
    fun `singbox mimic converts with domains round trip`() {
        val sb = """
            { "type": "mimic", "tag": "m", "server": "m.example.com", "server_port": 8443,
              "uuid": "uuid-1",
              "domains": [ { "domain": "www.microsoft.com", "preset": "chrome" }, "cdn.example.com" ] }
        """.trimIndent()
        val out = convert(sb)
        assertTrue(out.startsWith("mimic://"), out)
        val profile = MimicFmt.parse(out)
        assertNotNull(profile)
        assertEquals("m.example.com", profile!!.server)
        assertEquals("8443", profile.serverPort)
        assertEquals("uuid-1", profile.password)
        val domains = JSONArray(profile.mimicDomains!!)
        assertEquals(2, domains.length())
        assertEquals("www.microsoft.com", domains.getJSONObject(0).getString("domain"))
        assertEquals("chrome", domains.getJSONObject(0).getString("preset"))
        assertEquals("cdn.example.com", domains.getString(1))
        // и обратно: toUri -> parse даёт тот же профиль
        val again = MimicFmt.parse("mimic://" + MimicFmt.toUri(profile))!!
        assertEquals(profile.password, again.password)
        assertTrue(TestJson.similar(JSONArray(profile.mimicDomains!!), JSONArray(again.mimicDomains!!)))
    }

    @Test
    fun `xray mimic outbound converts`() {
        val cfg = """
            { "remarks": "M", "outbounds": [ { "tag": "m", "protocol": "mimic",
              "settings": { "address": "m.example.com", "port": 8443, "uuid": "uuid-2",
                "domains": ["a.example.com"] } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertTrue(out.startsWith("mimic://"), out)
        val profile = MimicFmt.parse(out)!!
        assertEquals("uuid-2", profile.password)
        assertEquals("8443", profile.serverPort)
    }

    @Test
    fun `mimic without uuid stays custom`() {
        val sb = """{ "type": "mimic", "server": "m.example.com", "server_port": 8443 }"""
        val out = convert(sb)
        assertFalse(out.startsWith("mimic://"), out)
        assertTrue(out.contains("\"mimic\""), "конфиг сохранён: $out")
    }

    // --- socks/http в полном Xray-конфиге (settings.servers[]) ---

    @Test
    fun `xray socks outbound with servers converts`() {
        val cfg = """
            { "remarks": "S", "outbounds": [ { "tag": "s", "protocol": "socks",
              "settings": { "servers": [ { "address": "1.2.3.4", "port": 1080,
                "users": [ { "user": "u", "pass": "p" } ] } ] } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertTrue(out.startsWith("socks://"), out)
        val profile = SocksFmt.parse(out)
        assertNotNull(profile)
        assertEquals("1.2.3.4", profile!!.server)
        assertEquals("1080", profile.serverPort)
        assertEquals("u", profile.username)
        assertEquals("p", profile.password)
    }

    @Test
    fun `xray http outbound stays custom because fork cannot import http links`() {
        // http:// ссылки форк не импортирует (схемы нет в configFmtParsers), а
        // для приватного IP строка ещё и ушла бы в подписку (isValidSubUrl).
        // Мёртвая/подменённая ссылка недопустима — честный отказ.
        val cfg = """
            { "remarks": "H", "outbounds": [ { "tag": "h", "protocol": "http",
              "settings": { "servers": [ { "address": "5.6.7.8", "port": 8080 } ] } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertFalse(out.startsWith("http://"), "мёртвая ссылка недопустима: $out")
        assertTrue(out.contains("\"http\""), "конфиг сохранён кастомным: $out")
    }

    @Test
    fun `singbox http outbound stays custom too`() {
        val sb = """{ "type": "http", "server": "5.6.7.8", "server_port": 8080 }"""
        val out = convert(sb)
        assertFalse(out.startsWith("http://"), out)
        assertTrue(out.contains("\"http\""), out)
    }

    @Test
    fun `xray socks with two servers stays custom`() {
        val cfg = """
            { "outbounds": [ { "tag": "s", "protocol": "socks",
              "settings": { "servers": [
                { "address": "1.1.1.1", "port": 1080 },
                { "address": "2.2.2.2", "port": 1080 } ] } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertFalse(out.startsWith("socks://"), "multi-server не выражается одной ссылкой: $out")
        assertTrue(out.contains("\"socks\""))
    }

    // --- FPTN / POLICYGROUP / PROXYCHAIN / CUSTOM: явный отказ ---

    @Test
    fun `fptn json stays custom with explicit protocol`() {
        val cfg = """{ "outbounds": [ { "tag": "f", "protocol": "fptn", "settings": { "token": "JWT" } } ] }"""
        val out = convert(cfg)
        assertFalse(out.startsWith("fptn://"), "FPTN не выражается outbound-конфигом: $out")
        assertTrue(out.contains("\"fptn\""), "конфиг сохранён как кастом: $out")
    }

    @Test
    fun `fptn link itself still parses`() {
        // Ссылка fptn:// — валидный вход (это не JSON-конвертация).
        val profile = FptnFmt.parse("fptn://user:pass@f.example.com:443?token=JWT&sni=s.example.com#F")
        assertNotNull(profile)
        assertEquals("JWT", profile!!.fptnToken)
        assertEquals("s.example.com", profile.sni)
        assertEquals("user", profile.username)
    }

    @Test
    fun `policygroup and proxychain stay custom`() {
        for (proto in listOf("policygroup", "proxychain")) {
            val cfg = """{ "outbounds": [ { "tag": "g", "protocol": "$proto", "settings": {} } ] }"""
            val out = convert(cfg)
            assertTrue(out.contains("\"$proto\""), "$proto обязан остаться кастомным: $out")
        }
    }

    @Test
    fun `custom and custom_outbound protocols stay custom with reason`() {
        for (proto in listOf("custom", "custom_outbound")) {
            val cfg = """{ "outbounds": [ { "tag": "c", "protocol": "$proto", "settings": {} } ] }"""
            val out = convert(cfg)
            assertTrue(out.contains("\"$proto\""), "$proto сохраняется как есть: $out")
            assertFalse(out.contains("://"), "ссылок из $proto быть не должно: $out")
        }
    }

    @Test
    fun `hysteria v1 converts to hysteria link served by mihomo`() {
        // mihomo v1.19.33 принимает hysteria v1 (эксперимент `mihomo -t`
        // green на устройстве владельца), sing-box форка собран без QUIC —
        // поэтому v1 конвертируется в hysteria:// и обслуживается mihomo.
        val cfg = """
            { "remarks": "H1", "outbounds": [ { "tag": "h", "protocol": "hysteria",
              "settings": { "address": "hy.example.com", "port": 443, "auth": "authstr",
                "up": "100 Mbps", "down": "100 Mbps" },
              "streamSettings": { "hysteriaSettings": { "version": 1 },
                "tlsSettings": { "serverName": "hy.example.com", "alpn": ["h3"] } } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertTrue(out.startsWith("hysteria://"), out)
        val profile = HysteriaFmt.parse(out)!!
        assertEquals("hy.example.com", profile.server)
        assertEquals("443", profile.serverPort)
        assertEquals("authstr", profile.password)
        assertEquals("100Mbps", profile.bandwidthUp)
        assertEquals("100Mbps", profile.bandwidthDown)
        assertEquals("hy.example.com", profile.sni)
        assertEquals("h3", profile.alpn)
    }

    @Test
    fun `hysteria v1 without auth stays custom`() {
        val cfg = """
            { "remarks": "H1-noauth", "outbounds": [ { "tag": "h", "protocol": "hysteria",
              "settings": { "address": "hy.example.com", "port": 443 },
              "streamSettings": { "hysteriaSettings": { "version": 1 } } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertFalse(out.startsWith("hysteria://"), "без auth ссылка нерабочая: $out")
        assertTrue(out.contains("\"hysteria\""), "конфиг сохранён кастомным: $out")
    }

    @Test
    fun `hysteria v1 with recv-window stays custom`() {
        // Схема hysteria:// не выражает recv-window: конвертация молча
        // потеряла бы tuning — честный отказ, профиль кастомный.
        val cfg = """
            { "remarks": "H1-rw", "outbounds": [ { "tag": "h", "protocol": "hysteria",
              "settings": { "address": "hy.example.com", "port": 443, "auth": "a",
                "up": "100 Mbps", "down": "100 Mbps" },
              "streamSettings": { "hysteriaSettings": { "version": 1, "recvWindowConn": 123 } } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertFalse(out.startsWith("hysteria://"), "recv-window нельзя терять молча: $out")
        assertTrue(out.contains("\"hysteria\""), out)
    }

    @Test
    fun `singbox hysteria v1 converts to hysteria link`() {
        val sb = """
            { "type": "hysteria", "tag": "h", "server": "hy.example.com", "server_port": 8443,
              "auth_str": "tok", "up_mbps": 50, "down_mbps": 80, "obfs": "myobfs",
              "tls": { "server_name": "hy.example.com", "insecure": true } }
        """.trimIndent()
        val out = convert(sb)
        assertTrue(out.startsWith("hysteria://"), out)
        val profile = HysteriaFmt.parse(out)!!
        assertEquals("tok", profile.password)
        assertEquals("50Mbps", profile.bandwidthUp)
        assertEquals("80Mbps", profile.bandwidthDown)
        assertEquals("myobfs", profile.obfsPassword)
        assertEquals(true, profile.insecure)
    }

    @Test
    fun `service only config stays custom`() {
        val cfg = """{ "outbounds": [ { "tag": "direct", "protocol": "freedom" }, { "tag": "block", "protocol": "blackhole" } ] }"""
        val out = convert(cfg)
        assertTrue(out.contains("freedom"), "служебный конфиг сохранён: $out")
        assertFalse(out.contains("://"), "ссылок из служебных outbound быть не должно: $out")
    }

    // --- мульти-сервер: всё или ничего ---

    @Test
    fun `vless multi-server outbound stays custom instead of losing servers`() {
        // Ссылка выражает один сервер: раньше молча брался vnext[0],
        // остальные сервера терялись. Теперь честный отказ.
        val cfg = """
            { "remarks": "MS", "outbounds": [ { "tag": "v", "protocol": "vless",
              "settings": { "vnext": [
                { "address": "1.1.1.1", "port": 443, "users": [ { "id": "u1", "encryption": "none" } ] },
                { "address": "2.2.2.2", "port": 443, "users": [ { "id": "u1", "encryption": "none" } ] }
              ] },
              "streamSettings": { "network": "tcp", "security": "none" } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertFalse(out.startsWith("vless://"), "multi-server нельзя терять молча: $out")
        assertTrue(out.contains("\"vless\""), "конфиг сохранён целиком: $out")
    }

    @Test
    fun `trojan multi-server outbound stays custom`() {
        val cfg = """
            { "remarks": "TJ-ms", "outbounds": [ { "tag": "t", "protocol": "trojan",
              "settings": { "servers": [
                { "address": "1.1.1.1", "port": 443, "password": "pw" },
                { "address": "2.2.2.2", "port": 443, "password": "pw" } ] },
              "streamSettings": { "network": "tcp", "security": "tls" } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertFalse(out.startsWith("trojan://"), out)
        assertTrue(out.contains("\"trojan\""), out)
    }

    @Test
    fun `multi server with one broken outbound keeps whole config`() {
        // Раньше возвращалось подмножество ссылок, а несконвертированный
        // outbound МОЛЧА терялся. Теперь: конфиг целиком кастомный.
        val cfg = """
            { "remarks": "Mix", "outbounds": [
              { "tag": "ok", "protocol": "vless",
                "settings": { "vnext": [ { "address": "1.2.3.4", "port": 443,
                  "users": [ { "id": "uuid-1", "encryption": "none" } ] } ] },
                "streamSettings": { "network": "tcp", "security": "none" } },
              { "tag": "broken", "protocol": "socks", "settings": { "servers": [] } }
            ] }
        """.trimIndent()
        val out = convert(cfg)
        assertFalse(out.contains("vless://"), "подмножество терять нельзя: $out")
        assertTrue(out.contains("\"broken\""), "весь конфиг сохранён: $out")
        assertTrue(out.contains("\"ok\""), "и конвертируемая часть тоже: $out")
    }

    @Test
    fun `multi server all convertible emits all links`() {
        val cfg = """
            { "remarks": "Two", "outbounds": [
              { "tag": "a", "protocol": "vless",
                "settings": { "vnext": [ { "address": "1.2.3.4", "port": 443,
                  "users": [ { "id": "uuid-1", "encryption": "none" } ] } ] },
                "streamSettings": { "network": "tcp", "security": "none" } },
              { "tag": "b", "protocol": "socks",
                "settings": { "servers": [ { "address": "5.6.7.8", "port": 1080 } ] } }
            ] }
        """.trimIndent()
        val out = convert(cfg)
        val lines = out.lines().filter { it.isNotBlank() }
        assertEquals(2, lines.size, "обе ссылки обязаны быть: $out")
        assertTrue(lines.any { it.startsWith("vless://") }, out)
        assertTrue(lines.any { it.startsWith("socks://") }, out)
    }

    // --- round-trip уже покрытых протоколов через ИХ парсеры ---

    @Test
    fun `singbox naive round trip via NaiveFmt`() {
        val sb = """
            { "type": "naive", "tag": "n", "server": "example.com", "server_port": 443,
              "username": "u", "password": "p", "tls": { "server_name": "example.com", "insecure": true } }
        """.trimIndent()
        val out = convert(sb)
        val profile = NaiveFmt.parse(out)
        assertNotNull(profile)
        assertEquals("u", profile!!.username)
        assertEquals("p", profile.password)
        assertEquals("example.com", profile.server)
        assertEquals("443", profile.serverPort)
        assertEquals("example.com", profile.sni)
        assertEquals(true, profile.insecure)
    }

    @Test
    fun `singbox vless grpc keeps service name`() {
        val sb = """
            { "type": "vless", "tag": "v", "server": "g.example.com", "server_port": 443,
              "uuid": "uuid-3", "flow": "", "transport": { "type": "grpc", "service_name": "grpcSvc" },
              "tls": { "server_name": "g.example.com" } }
        """.trimIndent()
        val out = convert(sb)
        assertTrue(out.startsWith("vless://"), out)
        assertTrue(out.contains("serviceName=grpcSvc"), "service_name обязан попасть в ссылку: $out")
        val profile = VlessFmt.parse(out)!!
        assertEquals("grpcSvc", profile.serviceName)
        assertEquals("grpc", profile.network)
    }

    @Test
    fun `singbox trojan ws keeps path and host`() {
        val sb = """
            { "type": "trojan", "tag": "t", "server": "t.example.com", "server_port": 443,
              "password": "pw", "transport": { "type": "ws", "path": "/trojan-ws",
                "headers": { "Host": "cdn.example.com" } },
              "tls": { "server_name": "t.example.com" } }
        """.trimIndent()
        val out = convert(sb)
        assertTrue(out.startsWith("trojan://"), out)
        val profile = TrojanFmt.parse(out)
        assertEquals("/trojan-ws", profile.path, "ws path обязан пережить конвертацию: $out")
        assertEquals("cdn.example.com", profile.host, "ws Host обязан пережить конвертацию: $out")
        assertEquals("ws", profile.network)
    }

    @Test
    fun `singbox anyconnect alias converts as openconnect`() {
        val sb = """
            { "type": "anyconnect", "tag": "oc", "server": "vpn.example.com", "server_port": 443,
              "username": "u", "password": "p", "auth_group": "g2" }
        """.trimIndent()
        val out = convert(sb)
        assertTrue(out.startsWith("openconnect://"), out)
        val profile = OpenconnectFmt.parse(out)!!
        assertEquals("g2", profile.ocservAuthGroup)
    }

    @Test
    fun `singbox vmess tls alpn fp insecure survive`() {
        val sb = """
            { "type": "vmess", "tag": "v", "server": "1.2.3.4", "server_port": 443,
              "uuid": "uuid-8", "alter_id": 0, "security": "auto",
              "transport": { "type": "ws", "path": "/vm", "headers": { "Host": "h.example.com" } },
              "tls": { "enabled": true, "server_name": "v.example.com", "insecure": true,
                "alpn": ["h2", "http/1.1"], "utls": { "fingerprint": "chrome" } } }
        """.trimIndent()
        val out = convert(sb)
        assertTrue(out.startsWith("vmess://"), out)
        val profile = VmessFmt.parse(out)!!
        assertEquals("h2,http/1.1", profile.alpn, "alpn обязан доехать: $out")
        assertEquals("chrome", profile.fingerPrint, "fp обязан доехать: $out")
        assertEquals(true, profile.insecure, "insecure обязан доехать: $out")
        assertEquals("/vm", profile.path)
        assertEquals("h.example.com", profile.host)
    }

    @Test
    fun `vmess allowInsecure survives as insecure key`() {
        // VmessFmt.parse читает только ключ insecure; конвертер обязан писать
        // его, иначе флаг терялся молча.
        val cfg = """
            { "remarks": "VM-ins", "outbounds": [ { "tag": "v", "protocol": "vmess",
              "settings": { "vnext": [ { "address": "1.2.3.4", "port": 443,
                "users": [ { "id": "uuid-7", "alterId": 0, "security": "auto" } ] } ] },
              "streamSettings": { "network": "tcp", "security": "tls",
                "tlsSettings": { "serverName": "v.example.com", "allowInsecure": true } } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertTrue(out.startsWith("vmess://"), out)
        val profile = VmessFmt.parse(out)!!
        assertEquals(true, profile.insecure, "allowInsecure обязан доехать как insecure: $out")
    }

    @Test
    fun `openconnect sni and insecure round trip`() {
        val sb = """
            { "type": "openconnect", "tag": "oc", "server": "vpn.example.com", "server_port": 443,
              "username": "u", "password": "p", "flavor": "gp",
              "tls": { "server_name": "oc.example.com", "insecure": true } }
        """.trimIndent()
        val out = convert(sb)
        assertTrue(out.startsWith("openconnect://"), out)
        assertTrue(out.contains("sni=oc.example.com"), "sni обязан попасть в ссылку: $out")
        assertTrue(out.contains("insecure=1"), out)
        val profile = OpenconnectFmt.parse(out)!!
        assertEquals("oc.example.com", profile.sni)
        assertEquals(true, profile.insecure)
    }

    @Test
    fun `singbox openconnect round trip via OpenconnectFmt`() {
        val sb = """
            { "type": "openconnect", "tag": "oc", "server": "vpn.example.com:443",
              "username": "u", "password": "p", "flavor": "gp", "auth_group": "g1" }
        """.trimIndent()
        val out = convert(sb)
        val profile = OpenconnectFmt.parse(out)
        assertNotNull(profile)
        assertEquals("u", profile!!.username)
        assertEquals("p", profile.password)
        assertEquals("vpn.example.com", profile.server)
        assertEquals("443", profile.serverPort)
        assertEquals("gp", profile.ocservFlavor)
        assertEquals("g1", profile.ocservAuthGroup)
    }

    @Test
    fun `tuic stays custom because fork parser is disabled`() {
        val cfg = """{ "outbounds": [ { "tag": "t", "protocol": "tuic",
          "server": "1.2.3.4", "server_port": 443, "uuid": "u", "password": "p" } ] }"""
        val out = convert(cfg)
        assertFalse(out.startsWith("tuic://"), "мёртвая ссылка недопустима: $out")
        assertTrue(out.contains("\"tuic\""), "конфиг сохранён: $out")
    }

    @Test
    fun `xray vmess round trip via VmessFmt`() {
        val cfg = """
            { "remarks": "VM", "outbounds": [ { "tag": "v", "protocol": "vmess",
              "settings": { "vnext": [ { "address": "1.2.3.4", "port": 443,
                "users": [ { "id": "uuid-1", "alterId": 0, "security": "auto" } ] } ] },
              "streamSettings": { "network": "ws", "security": "tls",
                "wsSettings": { "path": "/ws", "headers": { "Host": "cdn.example.com" } },
                "tlsSettings": { "serverName": "cdn.example.com" } } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertTrue(out.startsWith("vmess://"), out)
        val profile = VmessFmt.parse(out)
        assertNotNull(profile, "vmess-ссылка обязана читаться VmessFmt")
        assertEquals("1.2.3.4", profile!!.server)
        assertEquals("443", profile.serverPort)
        assertEquals("uuid-1", profile.password)
        assertEquals("ws", profile.network)
        assertEquals("/ws", profile.path)
        assertEquals("cdn.example.com", profile.host)
        assertEquals("tls", profile.security)
        assertEquals("cdn.example.com", profile.sni)
    }

    @Test
    fun `xray vmess grpc keeps service and authority`() {
        // Транспорт grpc обязан переехать: иначе туннель поднимется без
        // serviceName/authority и сервер не примет поток.
        val cfg = """
            { "remarks": "VM-grpc", "outbounds": [ { "tag": "v", "protocol": "vmess",
              "settings": { "vnext": [ { "address": "1.2.3.4", "port": 443,
                "users": [ { "id": "uuid-2", "alterId": 0, "security": "auto" } ] } ] },
              "streamSettings": { "network": "grpc", "security": "tls",
                "grpcSettings": { "mode": "multi", "serviceName": "svcName", "authority": "auth.example.com" },
                "tlsSettings": { "serverName": "g.example.com" } } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertTrue(out.startsWith("vmess://"), out)
        val profile = VmessFmt.parse(out)!!
        assertEquals("grpc", profile.network)
        assertEquals("multi", profile.mode)
        assertEquals("svcName", profile.serviceName)
        assertEquals("auth.example.com", profile.authority)
    }

    @Test
    fun `xray trojan kcp keeps header and seed`() {
        val cfg = """
            { "remarks": "TJ-kcp", "outbounds": [ { "tag": "t", "protocol": "trojan",
              "settings": { "servers": [ { "address": "1.2.3.4", "port": 443, "password": "pw" } ] },
              "streamSettings": { "network": "kcp", "security": "tls",
                "kcpSettings": { "seed": "kcpseed", "header": { "type": "wechat-video" } },
                "tlsSettings": { "serverName": "k.example.com" } } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertTrue(out.startsWith("trojan://"), out)
        val profile = TrojanFmt.parse(out)
        assertEquals("kcp", profile.network)
        assertEquals("kcpseed", profile.seed, "kcp seed обязан пережить конвертацию: $out")
        // parse хранит исходный headerType; нормализация wechat-video -> wechat
        // происходит позже в CoreOutboundBuilder.populateTransportSettings
        assertEquals("wechat-video", profile.headerType, out)
    }

    @Test
    fun `trojan xhttp stays custom because trojan link cannot express it`() {
        val cfg = """
            { "remarks": "TJ-x", "outbounds": [ { "tag": "t", "protocol": "trojan",
              "settings": { "servers": [ { "address": "1.2.3.4", "port": 443, "password": "pw" } ] },
              "streamSettings": { "network": "xhttp", "security": "tls",
                "xhttpSettings": { "mode": "stream-up", "path": "/x" } } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertFalse(out.startsWith("trojan://"), "xhttp не выражается trojan://: $out")
        assertTrue(out.contains("\"trojan\""), "конфиг сохранён кастомным: $out")
    }

    @Test
    fun `singbox vless xhttp keeps mode extra and host`() {
        val sb = """
            { "type": "vless", "tag": "v", "server": "x.example.com", "server_port": 443,
              "uuid": "uuid-4", "transport": { "type": "xhttp", "mode": "stream-up",
                "path": "/xh", "host": ["xh.example.com"],
                "extra": { "xPaddingBytes": "100-1600" } },
              "tls": { "server_name": "x.example.com" } }
        """.trimIndent()
        val out = convert(sb)
        assertTrue(out.startsWith("vless://"), out)
        assertTrue(out.contains("mode=stream-up"), "xhttp mode обязан попасть: $out")
        assertTrue(out.contains("extra="), "xhttp extra обязан попасть: $out")
        assertTrue(out.contains("xPaddingBytes"), out)
        val profile = VlessFmt.parse(out)!!
        assertEquals("xhttp", profile.network)
        assertEquals("stream-up", profile.xhttpMode)
        assertTrue(profile.xhttpExtra!!.contains("xPaddingBytes"))
    }

    @Test
    fun `vmess xhttp stays custom because v2 format cannot express it`() {
        val cfg = """
            { "remarks": "VM-xhttp", "outbounds": [ { "tag": "v", "protocol": "vmess",
              "settings": { "vnext": [ { "address": "1.2.3.4", "port": 443,
                "users": [ { "id": "uuid-9", "alterId": 0, "security": "auto" } ] } ] },
              "streamSettings": { "network": "xhttp", "security": "tls",
                "xhttpSettings": { "mode": "stream-up", "path": "/x" } } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertFalse(out.startsWith("vmess://"), "xhttp не выражается vmess v2: $out")
        assertTrue(out.contains("\"vmess\""), "конфиг сохранён кастомным: $out")
    }

    @Test
    fun `xray shadowsocks round trip via ShadowsocksFmt`() {
        val cfg = """
            { "remarks": "SS", "outbounds": [ { "tag": "s", "protocol": "shadowsocks",
              "settings": { "servers": [ { "address": "1.2.3.4", "port": 8388,
                "method": "aes-256-gcm", "password": "pass123" } ] } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertTrue(out.startsWith("ss://"), out)
        val profile = ShadowsocksFmt.parse(out)
        assertNotNull(profile)
        assertEquals("1.2.3.4", profile!!.server)
        assertEquals("8388", profile.serverPort)
        assertEquals("aes-256-gcm", profile.method)
        assertEquals("pass123", profile.password)
    }

    @Test
    fun `singbox ss obfs-local keeps plugin opts`() {
        val sb = """
            { "type": "shadowsocks", "tag": "s", "server": "ss.example.com", "server_port": 8388,
              "method": "aes-256-gcm", "password": "pw",
              "plugin": "obfs-local", "plugin_opts": "obfs=http;obfs-host=cdn.example.com" }
        """.trimIndent()
        val out = convert(sb)
        assertTrue(out.startsWith("ss://"), out)
        assertTrue(out.contains("plugin=obfs%3Dhttp"), "plugin_opts обязаны попасть в ссылку: $out")
        val profile = ShadowsocksFmt.parse(out)
        assertNotNull(profile)
    }

    @Test
    fun `singbox ss with unsupported plugin stays custom`() {
        val sb = """
            { "type": "shadowsocks", "tag": "s", "server": "ss.example.com", "server_port": 8388,
              "method": "aes-256-gcm", "password": "pw", "plugin": "v2ray-plugin" }
        """.trimIndent()
        val out = convert(sb)
        assertFalse(out.startsWith("ss://"), "неподдерживаемый plugin нельзя терять молча: $out")
        assertTrue(out.contains("\"shadowsocks\""), "конфиг сохранён кастомным: $out")
    }

    @Test
    fun `xray trojan round trip via TrojanFmt`() {
        val cfg = """
            { "remarks": "TJ", "outbounds": [ { "tag": "t", "protocol": "trojan",
              "settings": { "servers": [ { "address": "1.2.3.4", "port": 443, "password": "pw" } ] },
              "streamSettings": { "network": "tcp", "security": "tls",
                "tlsSettings": { "serverName": "t.example.com" } } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertTrue(out.startsWith("trojan://"), out)
        val profile = TrojanFmt.parse(out)
        assertNotNull(profile)
        assertEquals("1.2.3.4", profile!!.server)
        assertEquals("443", profile.serverPort)
        assertEquals("pw", profile.password)
        assertEquals("t.example.com", profile.sni)
    }

    @Test
    fun `xray hysteria2 gecko obfs from finalmask survives conversion`() {
        // Обфускация hy2 в xray-конфиге живёт в streamSettings.finalmask.udp
        // [type=salamander] с packetSize "min-max" (gecko). Потеря
        // obfs-password означала бы нерабочий туннель.
        val cfg = """
            { "remarks": "HY-gecko", "outbounds": [ { "tag": "h", "protocol": "hysteria2",
              "settings": { "address": "hy.example.com", "port": 8443 },
              "streamSettings": {
                "hysteriaSettings": { "version": 2, "auth": "authpw" },
                "tlsSettings": { "serverName": "hy.example.com" },
                "finalmask": { "udp": [ { "type": "salamander",
                  "settings": { "password": "obfspw", "packetSize": "512-1200" } } ] } } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertTrue(out.startsWith("hysteria2://"), out)
        assertTrue(out.contains("obfs=gecko"), "gecko обязан распознаться по packetSize: $out")
        assertTrue(out.contains("obfs-password=obfspw"), out)
        assertTrue(out.contains("minPacketSize=512"), out)
        assertTrue(out.contains("maxPacketSize=1200"), out)
        val profile = Hysteria2Fmt.parse(out)!!
        assertEquals("obfspw", profile.obfsPassword)
        assertEquals("512", profile.minPacketSize)
        assertEquals("1200", profile.maxPacketSize)
        assertTrue(profile.isGeckoObfs())
    }

    @Test
    fun `xray hysteria2 salamander without sizes stays salamander`() {
        val cfg = """
            { "remarks": "HY-sal", "outbounds": [ { "tag": "h", "protocol": "hysteria2",
              "settings": { "address": "hy.example.com", "port": 8443 },
              "streamSettings": {
                "hysteriaSettings": { "version": 2, "auth": "authpw" },
                "finalmask": { "udp": [ { "type": "salamander",
                  "settings": { "password": "pw2" } } ] } } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertTrue(out.contains("obfs=salamander"), out)
        assertFalse(out.contains("obfs=gecko"), out)
        val profile = Hysteria2Fmt.parse(out)!!
        assertEquals("pw2", profile.obfsPassword)
    }

    @Test
    fun `xray hysteria2 round trip via Hysteria2Fmt`() {
        val cfg = """
            { "remarks": "HY", "outbounds": [ { "tag": "h", "protocol": "hysteria2",
              "settings": { "address": "hy.example.com", "port": 8443 },
              "streamSettings": { "hysteriaSettings": { "version": 2, "auth": "authpw" },
                "tlsSettings": { "serverName": "hy.example.com" } } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertTrue(out.startsWith("hysteria2://"), out)
        val profile = Hysteria2Fmt.parse(out)
        assertNotNull(profile)
        assertEquals("hy.example.com", profile!!.server)
        assertEquals("8443", profile.serverPort)
        assertEquals("authpw", profile.password)
        assertEquals("hy.example.com", profile.sni)
    }

    @Test
    fun `xray masque round trip via MasqueFmt`() {
        val cfg = """
            { "remarks": "MQ", "outbounds": [ { "tag": "m", "protocol": "masque",
              "settings": { "address": "mq.example.com", "port": 443, "remoteDNS": ["1.1.1.1"] },
              "streamSettings": { "masqueSettings": {
                "host": "mq.example.com", "path": "/masque",
                "warp": { "privateKey": "PRIV=", "publicKey": "PUB=", "address": ["172.16.0.2/32"] } } } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertTrue(out.startsWith("masque://"), out)
        val profile = MasqueFmt.parse(out)
        assertNotNull(profile)
        assertEquals("mq.example.com", profile!!.server)
        assertEquals("443", profile.serverPort)
        assertEquals("PRIV=", profile.secretKey)
        assertEquals("PUB=", profile.publicKey)
        assertEquals("172.16.0.2/32", profile.localAddress)
        assertEquals("1.1.1.1", profile.remoteDNS)
    }

    // --- Реальные конфиги владельца: перенос БЕЗ потерь ---

    private val ownerWarpHex = "c90000000108b0dd8456e7cebf5a000044d2c1c8da18f9ce0f94e5fa499a43609d7738d0cd"

    private val ownerWarpConfig = """
        {
          "remarks": "🇪🇺 WARP",
          "outbounds": [
            {
              "tag": "warp", "protocol": "wireguard",
              "settings": {
                "mtu": 1280,
                "peers": [ { "endpoint": "162.159.195.1:500", "keepAlive": 5,
                  "publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                  "allowedIPs": ["0.0.0.0/0", "::/0"] } ],
                "address": ["172.16.0.2/32", "2606:4700:110:84f0:6de9:eb1f:cb41:ce39/128"],
                "secretKey": "aN6cG/eAT+l8u+Y0hF/0nmSZ0D7iMBtE8Yj+7swbukI="
              },
              "streamSettings": { "sockopt": { "dialerProxy": "noise-out" } }
            },
            {
              "tag": "noise-out", "protocol": "freedom",
              "settings": { "noises": [
                { "type": "hex", "delay": "1-2", "packet": "HEXPLACEHOLDER" },
                { "type": "rand", "delay": "1-3", "packet": "23-911" },
                { "type": "rand", "delay": "1-3", "packet": "23-911" },
                { "type": "rand", "delay": "1-3", "packet": "23-911" },
                { "type": "rand", "delay": "1-3", "packet": "23-911" },
                { "type": "rand", "delay": "1-3", "packet": "23-911" },
                { "type": "rand", "delay": "1-3", "packet": "23-911" },
                { "type": "rand", "delay": "1-3", "packet": "23-911" },
                { "type": "rand", "delay": "1-3", "packet": "23-911" }
              ], "domainStrategy": "AsIs" }
            }
          ]
        }
    """.trimIndent().replace("HEXPLACEHOLDER", ownerWarpHex)

    @Test
    fun `owner warp config carries tunnel dns into link and editor field`() {
        // В кастомном конфиге владельца DNS туннеля живёт в глобальной секции
        // dns.servers (outbound remoteDNS отсутствует). Конвертер обязан
        // перенести его в ссылку, иначе поле remoteDNS редактора осталось бы
        // пустым и туннель молча пошёл бы на дефолтный DNS приложения.
        val cfg = JSONObject(ownerWarpConfig)
        cfg.put("dns", JSONObject().put("servers", org.json.JSONArray().apply {
            put("1.1.1.1"); put("1.0.0.1"); put("2606:4700:4700::1111"); put("2606:4700:4700::1001")
        }))
        val out = convert(cfg.toString())
        assertTrue(out.startsWith("wireguard://"), out)
        assertTrue(out.contains("dns=1.1.1.1"), "dns обязан попасть в ссылку: $out")
        val profile = WireguardFmt.parse(out)!!
        assertEquals("1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001", profile.remoteDNS)
        // и обратно в ссылку без потерь и без пустого dns=
        val again = "wireguard://" + WireguardFmt.toUri(profile)
        assertTrue(again.contains("dns=1.1.1.1"), again)
    }

    @Test
    fun `wireguard without dns keeps field empty and link clean`() {
        // Опциональность: нет dns ни в outbound, ни в секции dns — поле пусто,
        // в ссылке нет пустого dns=.
        val out = convert(ownerWarpConfig)
        assertTrue(out.startsWith("wireguard://"), out)
        assertFalse(out.contains("dns=&"), "пустой dns= запрещён: $out")
        val profile = WireguardFmt.parse(out)!!
        assertNull(profile.remoteDNS)
    }

    @Test
    fun `owner warp config converts with the whole hex noise intact`() {
        // Доказательство переноса: весь hex-пакет (не обрезанный) и все 9
        // элементов шума доходят до ссылки, а из ссылки — в поля профиля.
        val out = convert(ownerWarpConfig)
        assertTrue(out.startsWith("wireguard://"), out)
        assertTrue(out.contains(ownerWarpHex), "hex-пакет обязан дойти целиком: ${out.take(200)}")
        val q = out.substringAfter("?").substringBefore("#")
            .split("&").associate { val (k, v) = it.split("=", limit = 2); k to java.net.URLDecoder.decode(v, "UTF-8") }
        val fm = JSONObject(q["fm"]!!)
        val noise = fm.getJSONArray("udp").getJSONObject(0)
            .getJSONObject("settings").getJSONArray("noise")
        assertEquals(9, noise.length())
        assertEquals(ownerWarpHex, noise.getJSONObject(0).getString("packet"))
        assertEquals("1-2", noise.getJSONObject(0).getString("delay"))
        assertEquals("23-911", noise.getJSONObject(8).getString("rand"))
        // профиль из ссылки: поле шума заполнено, fm совпадает структурно
        val profile = WireguardFmt.parse(out)!!
        assertNotNull(profile.noisesJson)
        val pn = JSONArray(profile.noisesJson!!)
        assertEquals(9, pn.length())
        assertEquals(ownerWarpHex, pn.getJSONObject(0).getString("packet"))
        assertEquals("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", profile.publicKey)
        assertEquals("172.16.0.2/32,2606:4700:110:84f0:6de9:eb1f:cb41:ce39/128", profile.localAddress)
    }

    @Test
    fun `owner vless xhttp config keeps finalmask xrayJson and extra`() {
        // finalmask формата xrayJson (op/set) и xhttp extra — НЕ шум; они
        // обязаны переехать в ссылку как есть (fm и extra), а не потеряться.
        val cfg = """
            {
              "remarks": "🇫🇷 Франция [xHTTP]",
              "outbounds": [
                {
                  "tag": "proxy", "protocol": "vless",
                  "settings": { "address": "138.124.254.68", "port": 8443,
                    "encryption": "none", "id": "ca382fc9-d753-45fa-a10d-835478ab4199" },
                  "streamSettings": {
                    "network": "xhttp", "security": "tls",
                    "finalmask": { "base64": [], "mihomo": [], "xrayJson": [
                      { "op": "set", "to": "streamSettings.xhttpSettings.mode", "value": "stream-up" },
                      { "op": "set", "to": "streamSettings.xhttpSettings.extra.xPaddingBytes", "value": "100-1600" }
                    ] },
                    "tlsSettings": { "serverName": "river-4-416.rtbcdn.ru", "alpn": ["h2"],
                      "fingerprint": "firefox",
                      "pinnedPeerCertSha256": "69103e5ff502314fad6345ce7f208d70574e65968462dd6168e227055ed294d6" },
                    "xhttpSettings": { "mode": "stream-up", "path": "/hls/vod/",
                      "extra": { "xPaddingBytes": "64-2048", "scStreamUpServerSecs": "15-40" } }
                  }
                }
              ]
            }
        """.trimIndent()
        val out = convert(cfg)
        assertTrue(out.startsWith("vless://"), out)
        assertTrue(out.contains("fm="), "finalmask xrayJson обязан попасть в fm: $out")
        assertTrue(out.contains("extra="), "xhttp extra обязан попасть в extra: $out")
        assertTrue(out.contains("stream-up"), out)
        assertTrue(out.contains("xPaddingBytes"), out)
        assertTrue(out.contains("69103e5ff502314fad6345ce7f208d70574e65968462dd6168e227055ed294d6"), "pin обязан дойти: $out")
        // fm в ссылке — тот же xrayJson, без потерь
        val q = out.substringAfter("?").substringBefore("#")
            .split("&").associate { val (k, v) = it.split("=", limit = 2); k to java.net.URLDecoder.decode(v, "UTF-8") }
        val fm = JSONObject(q["fm"]!!)
        assertEquals(2, fm.getJSONArray("xrayJson").length())
        assertEquals("streamSettings.xhttpSettings.extra.xPaddingBytes",
            fm.getJSONArray("xrayJson").getJSONObject(1).getString("to"))
    }

    @Test
    fun `xray masque tls sni alpn fp survive`() {
        val cfg = """
            { "remarks": "MQ-tls", "outbounds": [ { "tag": "m", "protocol": "masque",
              "settings": { "address": "mq.example.com", "port": 443 },
              "streamSettings": {
                "masqueSettings": { "host": "mq.example.com", "path": "/m",
                  "warp": { "privateKey": "P1=", "publicKey": "P2=", "address": ["172.16.0.2/32"] } },
                "tlsSettings": { "serverName": "sni.example.com", "alpn": ["h3"], "fingerprint": "chrome" } } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertTrue(out.startsWith("masque://"), out)
        assertTrue(out.contains("sni=sni.example.com"), out)
        assertTrue(out.contains("alpn=h3"), out)
        assertTrue(out.contains("fp=chrome"), out)
        val profile = MasqueFmt.parse(out)!!
        assertEquals("sni.example.com", profile.sni)
        assertEquals("h3", profile.alpn)
        assertEquals("chrome", profile.fingerPrint)
    }

    @Test
    fun `wireguard round trip via WireguardFmt with noise`() {
        val cfg = """
            { "remarks": "WG", "outbounds": [ { "tag": "wg", "protocol": "wireguard",
              "settings": { "secretKey": "S=", "address": ["172.16.0.2/32"], "mtu": 1280,
                "peers": [ { "endpoint": "162.159.195.1:500", "publicKey": "P=", "allowedIPs": ["0.0.0.0/0","::/0"] } ] },
              "streamSettings": { "finalmask": { "udp": [ { "type": "noise",
                "settings": { "noise": [ { "rand": "23-911", "delay": "1-3" } ] } } ] } } } ] }
        """.trimIndent()
        val out = convert(cfg)
        val profile = WireguardFmt.parse(out)
        assertNotNull(profile)
        assertEquals("S=", profile!!.secretKey)
        assertEquals("P=", profile.publicKey)
        assertEquals("162.159.195.1", profile.server)
        assertEquals("500", profile.serverPort)
        assertEquals(1280, profile.mtu)
        assertNotNull(profile.noisesJson, "шум обязан быть в поле профиля после round-trip")
        assertEquals("23-911", JSONArray(profile.noisesJson!!).getJSONObject(0).getString("rand"))
        // и экспорт профиля не теряет шум
        val again = WireguardFmt.parse("wireguard://" + WireguardFmt.toUri(profile))!!
        assertTrue(TestJson.similar(JSONArray(profile.noisesJson!!), JSONArray(again.noisesJson!!)))
    }
}