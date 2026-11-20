package com.v2ray.ang.fmt

import com.v2ray.ang.AppConfig
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.URI
import java.net.URLEncoder

class Hysteria2FmtTest {

    @Test
    fun hysteria2WithoutPortUses443() {
        val profile = Hysteria2Fmt.parse("hysteria2://test@example.com/")

        assertEquals("example.com", profile.server)
        assertEquals("443", profile.serverPort)
    }

    @Test
    fun hy2WithoutPortUses443() {
        val profile = Hysteria2Fmt.parse("hy2://test@example.com/")

        assertEquals("example.com", profile.server)
        assertEquals("443", profile.serverPort)
    }

    @Test
    fun uriWithoutCredentialsUses443() {
        val profile = Hysteria2Fmt.parse("hysteria2://example.com/")

        assertEquals("example.com", profile.server)
        assertEquals("443", profile.serverPort)
    }

    @Test
    fun omittedPortPreservesTlsParameters() {
        val profile = Hysteria2Fmt.parse(
            "hy2://test@example.com/?sni=example.org&insecure=0&pinSHA256=test-pin#example"
        )

        assertEquals("test", profile.password)
        assertEquals("example", profile.remarks)
        assertEquals(AppConfig.TLS, profile.security)
        assertEquals("example.org", profile.sni)
        assertEquals(false, profile.insecure)
        assertEquals("test-pin", profile.pinnedCA256)
        assertEquals("443", profile.serverPort)
    }

    @Test
    fun ipv6WithoutPortUses443() {
        val profile = Hysteria2Fmt.parse("hysteria2://test@[2001:db8::1]/")

        assertEquals("2001:db8::1", profile.server)
        assertEquals("443", profile.serverPort)
    }

    @Test
    fun explicitPortsArePreserved() {
        for (scheme in listOf("hysteria2", "hy2")) {
            // Port range validation is separate from choosing a missing-port default.
            for (port in listOf(0, 443, 8443, 65535, 65536)) {
                val profile = Hysteria2Fmt.parse("$scheme://test@example.com:$port/")

                assertEquals("example.com", profile.server)
                assertEquals(port.toString(), profile.serverPort)
            }
        }
    }

    @Test
    fun nonnumericPortDoesNotAcquireAHost() {
        val profile = Hysteria2Fmt.parse("hysteria2://test@example.com:invalid/")

        assertEquals("", profile.server)
    }

    @Test
    fun defaultPortSurvivesUriRoundTrip() {
        val profile = Hysteria2Fmt.parse("hy2://test@example.com/?sni=example.org")
        val exported = "hysteria2://${Hysteria2Fmt.toUri(profile)}"
        val reparsed = Hysteria2Fmt.parse(exported)

        assertEquals(443, URI(exported).port)
        assertEquals("443", reparsed.serverPort)
        assertEquals(profile.server, reparsed.server)
        assertEquals(profile.password, reparsed.password)
        assertEquals(profile.sni, reparsed.sni)
    }

    @Test
    fun geckoObfsDefaultsPacketSizeWhenOmitted() {
        val profile = Hysteria2Fmt.parse("hy2://test@example.com/?obfs=gecko&obfs-password=secret")

        assertEquals("gecko", profile.obfs)
        assertEquals("secret", profile.obfsPassword)
        assertEquals("512", profile.minPacketSize)
        assertEquals("1200", profile.maxPacketSize)
    }

    @Test
    fun geckoObfsCustomPacketSizePreserved() {
        val profile = Hysteria2Fmt.parse(
            "hy2://test@example.com/?obfs=gecko&obfs-password=secret&minPacketSize=600&maxPacketSize=1300"
        )

        assertEquals("gecko", profile.obfs)
        assertEquals("secret", profile.obfsPassword)
        assertEquals("600", profile.minPacketSize)
        assertEquals("1300", profile.maxPacketSize)
    }

    @Test
    fun geckoObfsSurvivesUriRoundTrip() {
        val profile = Hysteria2Fmt.parse(
            "hy2://test@example.com/?obfs=gecko&obfs-password=secret&minPacketSize=600&maxPacketSize=1300"
        )
        val exported = "hysteria2://${Hysteria2Fmt.toUri(profile)}"
        val reparsed = Hysteria2Fmt.parse(exported)

        assertEquals("gecko", reparsed.obfs)
        assertEquals("secret", reparsed.obfsPassword)
        assertEquals("600", reparsed.minPacketSize)
        assertEquals("1300", reparsed.maxPacketSize)
    }

    @Test
    fun salamanderObfsDoesNotSetPacketSize() {
        val profile = Hysteria2Fmt.parse("hy2://test@example.com/?obfs=salamander&obfs-password=secret")

        assertEquals("salamander", profile.obfs)
        assertEquals("secret", profile.obfsPassword)
        assertEquals(null, profile.minPacketSize)
        assertEquals(null, profile.maxPacketSize)
    }

    @Test
    fun obfsNoneDoesNotSetObfs() {
        val profile = Hysteria2Fmt.parse("hy2://test@example.com/?obfs=none&obfs-password=secret")

        assertEquals(null, profile.obfs)
    }

    @Test
    fun portHoppingIntervalSurvivesRoundTrip() {
        val profile = Hysteria2Fmt.parse(
            "hy2://pw@example.com/?mport=40000-41000&mportInterval=20-30"
        )

        assertEquals("40000-41000", profile.portHopping)
        assertEquals("20-30", profile.portHoppingInterval)

        val exported = "hysteria2://${Hysteria2Fmt.toUri(profile)}"
        val reparsed = Hysteria2Fmt.parse(exported)
        assertEquals("40000-41000", reparsed.portHopping)
        assertEquals("20-30", reparsed.portHoppingInterval)
    }

    @Test
    fun sessionResumptionFlagSurvivesRoundTrip() {
        // Провайдер задал enableSessionResumption; раньше поле терялось и ядро
        // получало null (своё значение по умолчанию).
        for (raw in listOf("0", "1")) {
            val profile = Hysteria2Fmt.parse("hy2://pw@example.com/?esr=$raw")
            assertEquals(raw == "1", profile.enableSessionResumption)

            val reparsed = Hysteria2Fmt.parse("hysteria2://${Hysteria2Fmt.toUri(profile)}")
            assertEquals(raw == "1", reparsed.enableSessionResumption)
        }
    }

    @Test
    fun sessionResumptionAbsentStaysNull() {
        // null (а не false) обязателен: иначе форк навязывал бы значение,
        // которого провайдер не задавал.
        val profile = Hysteria2Fmt.parse("hy2://pw@example.com/?sni=example.org")

        assertEquals(null, profile.enableSessionResumption)
        assertFalse("hysteria2://${Hysteria2Fmt.toUri(profile)}".contains("esr="))
    }

    @Test
    fun fingerprintSurvivesRoundTrip() {
        val profile = Hysteria2Fmt.parse("hy2://pw@example.com/?fp=firefox")

        assertEquals("firefox", profile.fingerPrint)
        val exported = "hysteria2://${Hysteria2Fmt.toUri(profile)}"
        assertTrue(exported.contains("fp=firefox"), exported)
        assertEquals("firefox", Hysteria2Fmt.parse(exported).fingerPrint)
    }

    @Test
    fun pinSha256FromFmtBaseIsNotOverwrittenByEmptyLegacyKey() {
        // FmtBase.getItemFormQuery читает отпечаток из ключа pcs, а hy2 исторически
        // несёт pinSHA256. Без elvis ссылка только с pcs обнуляла отпечаток.
        val fromPcs = Hysteria2Fmt.parse("hy2://pw@example.com/?pcs=abcd1234")
        assertEquals("abcd1234", fromPcs.pinnedCA256)

        val legacy = Hysteria2Fmt.parse("hy2://pw@example.com/?pinSHA256=ffff0000")
        assertEquals("ffff0000", legacy.pinnedCA256)
    }

    @Test
    fun finalMaskWithNoiseSurvivesRoundTrip() {
        // Шум DPI-защиты и quicParams формат hy2-ссылки иначе не выражает:
        // они обязаны доехать ключом fm и пережить экспорт обратно.
        val fm = """{"udp":[{"type":"noise","settings":{"noise":[{"rand":"100-200"}],"reset":"0"}}],""" +
            """"quicParams":{"bbrProfile":"aggressive","congestion":"bbr"}}"""
        val profile = Hysteria2Fmt.parse(
            "hy2://pw@example.com/?obfs=salamander&obfs-password=pw&fm=" +
                URLEncoder.encode(fm, "UTF-8").replace("+", "%20")
        )

        assertEquals(fm, profile.finalMask)
        assertEquals("salamander", profile.obfs)

        val exported = "hysteria2://${Hysteria2Fmt.toUri(profile)}"
        val reparsed = Hysteria2Fmt.parse(exported)
        assertEquals(fm, reparsed.finalMask)
        assertEquals("pw", reparsed.obfsPassword)
    }

    @Test
    fun emptyFinalMaskIsNotExported() {
        val profile = Hysteria2Fmt.parse("hy2://pw@example.com/?sni=example.org")

        assertEquals(null, profile.finalMask)
        assertFalse("hysteria2://${Hysteria2Fmt.toUri(profile)}".contains("fm="))
    }

    @Test
    fun noObfsSurvivesUriRoundTrip() {
        val profile = Hysteria2Fmt.parse("hy2://test@example.com/?sni=example.com")
        val exported = "hysteria2://${Hysteria2Fmt.toUri(profile)}"
        val reparsed = Hysteria2Fmt.parse(exported)

        assertEquals(null, reparsed.obfs)
        assertEquals(null, reparsed.obfsPassword)
        assertEquals(null, reparsed.minPacketSize)
        assertEquals(null, reparsed.maxPacketSize)
    }
}
