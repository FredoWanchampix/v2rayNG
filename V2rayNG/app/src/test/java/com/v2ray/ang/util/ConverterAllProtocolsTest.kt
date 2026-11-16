package com.v2ray.ang.util

import android.text.TextUtils
import android.util.Base64
import android.util.Log
import com.v2ray.ang.fmt.AmneziaFmt
import com.v2ray.ang.fmt.Hysteria2Fmt
import com.v2ray.ang.fmt.MasqueFmt
import com.v2ray.ang.fmt.ShadowsocksFmt
import com.v2ray.ang.fmt.TrojanFmt
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
        assertTrue(JSONArray(profile.mimicDomains!!).similar(JSONArray(again.mimicDomains!!)))
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
    fun `xray http outbound without auth converts`() {
        val cfg = """
            { "remarks": "H", "outbounds": [ { "tag": "h", "protocol": "http",
              "settings": { "servers": [ { "address": "5.6.7.8", "port": 8080 } ] } } ] }
        """.trimIndent()
        val out = convert(cfg)
        assertTrue(out.startsWith("http://"), out)
        assertTrue(out.contains("5.6.7.8:8080"), out)
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
    fun `service only config stays custom`() {
        val cfg = """{ "outbounds": [ { "tag": "direct", "protocol": "freedom" }, { "tag": "block", "protocol": "blackhole" } ] }"""
        val out = convert(cfg)
        assertTrue(out.contains("freedom"), "служебный конфиг сохранён: $out")
        assertFalse(out.contains("://"), "ссылок из служебных outbound быть не должно: $out")
    }

    // --- мульти-сервер: всё или ничего ---

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
        assertTrue(JSONArray(profile.noisesJson!!).similar(JSONArray(again.noisesJson!!)))
    }
}