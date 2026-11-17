package com.v2ray.ang.fmt

import android.util.Base64
import android.util.Log
import com.v2ray.ang.enums.EConfigType
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.MockedStatic
import org.mockito.Mockito
import org.mockito.Mockito.mockStatic
import java.util.Base64 as JavaBase64

/**
 * Hysteria v1: ссылка hysteria:// (импорт/экспорт) и профиль.
 * Поддержка v1 опирается на сайдкар mihomo (эксперимент `mihomo -t` green),
 * sing-box форка собран без QUIC.
 */
class HysteriaFmtTest {

    // android.util.Base64 — заглушка на JVM; мок по образцу ShadowsocksFmtTest
    private lateinit var mockBase64: MockedStatic<Base64>
    private lateinit var mockLog: MockedStatic<Log>

    @BeforeEach
    fun setUp() {
        mockLog = mockStatic(Log::class.java, Mockito.RETURNS_DEFAULTS)
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
            JavaBase64.getEncoder().encodeToString(inv.arguments[0] as ByteArray)
        }
    }

    @AfterEach
    fun tearDown() {
        mockBase64.close()
        mockLog.close()
    }

    @Test
    fun `parse full v1 link`() {
        val link = "hysteria://hy.example.com:8443?auth=tok123&protocol=wechat-video" +
            "&upmbps=100&downmbps=200&peer=sni.example.com&insecure=1&alpn=h3&obfs=myobfs&mport=8443-8450#H1"
        val p = HysteriaFmt.parse(link)
        assertNotNull(p)
        assertEquals(EConfigType.HYSTERIA, p!!.configType)
        assertEquals("hy.example.com", p.server)
        assertEquals("8443", p.serverPort)
        assertEquals("tok123", p.password)
        assertEquals("wechat-video", p.method)
        assertEquals("100Mbps", p.bandwidthUp)
        assertEquals("200Mbps", p.bandwidthDown)
        assertEquals("sni.example.com", p.sni)
        assertEquals(true, p.insecure)
        assertEquals("h3", p.alpn)
        assertEquals("myobfs", p.obfsPassword)
        assertEquals("8443-8450", p.portHopping)
        assertEquals("H1", p.remarks)
    }

    @Test
    fun `parse base64 auth is decoded`() {
        // auth=base64("secret-token")
        val b64 = java.util.Base64.getEncoder().encodeToString("secret-token".toByteArray())
        val link = "hysteria://1.2.3.4:443?auth=$b64#B"
        val p = HysteriaFmt.parse(link)!!
        assertEquals("secret-token", p.password)
    }

    @Test
    fun `parse minimal link defaults`() {
        val p = HysteriaFmt.parse("hysteria://1.2.3.4:443#M")
        assertNotNull(p)
        assertEquals("udp", p!!.method)
        assertNull(p.password)
        assertEquals(false, p.insecure)
        // mihomo требует up/down: parse дополняет дефолтом, профиль не мёртвый
        assertEquals("100Mbps", p.bandwidthUp)
        assertEquals("100Mbps", p.bandwidthDown)
    }

    @Test
    fun `round trip keeps all fields`() {
        val link = "hysteria://hy.example.com:8443?auth=tok123&protocol=faketcp" +
            "&upmbps=50&downmbps=80&peer=s.example.com&insecure=1&alpn=h3,h2&obfs=ob&mport=9000-9010#RT"
        val p = HysteriaFmt.parse(link)!!
        val out = "hysteria://" + HysteriaFmt.toUri(p)
        val again = HysteriaFmt.parse(out)!!
        assertEquals(p.password, again.password)
        assertEquals(p.method, again.method)
        assertEquals(p.bandwidthUp, again.bandwidthUp)
        assertEquals(p.bandwidthDown, again.bandwidthDown)
        assertEquals(p.sni, again.sni)
        assertEquals(p.insecure, again.insecure)
        assertEquals(p.alpn, again.alpn)
        assertEquals(p.obfsPassword, again.obfsPassword)
        assertEquals(p.portHopping, again.portHopping)
        assertEquals(p.server, again.server)
        assertEquals(p.serverPort, again.serverPort)
    }

    @Test
    fun `toUri omits empty optionals`() {
        val p = HysteriaFmt.parse("hysteria://1.2.3.4:443?auth=a#X")!!
        val out = "hysteria://" + HysteriaFmt.toUri(p)
        assertTrue(out.startsWith("hysteria://1.2.3.4:443?auth=a#"), out)
        assertTrue(!out.contains("protocol="), out)
        assertTrue(!out.contains("upmbps="), out)
    }
}