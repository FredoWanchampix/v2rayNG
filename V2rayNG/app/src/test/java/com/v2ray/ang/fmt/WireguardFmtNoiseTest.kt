package com.v2ray.ang.fmt

import com.v2ray.ang.util.NoiseProfileUtil
import com.v2ray.ang.util.TestJson
import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Шум DPI-защиты в wireguard-ссылках: импорт (fm/noises), экспорт («весь
 * контекст») и обратная совместимость со старыми ссылками только с fm.
 * Требование владельца: импортировал ссылку из буфера — поле шума в
 * редакторе заполнено; поделился профилем — шум не потерялся.
 */
class WireguardFmtNoiseTest {

    private val noiseArr = """[{"type":"hex","packet":"576172704e6f697365","delay":"1-3"},{"rand":"23-911","delay":"1-3"}]"""

    private fun fmOf(noises: String): String =
        JSONObject().put("udp", JSONArray().put(
            JSONObject().put("type", "noise")
                .put("settings", JSONObject().put("noise", JSONArray(noises)))
        )).toString()

    private fun link(query: String): String =
        "wireguard://SECRET%3D@162.159.195.1:500?publickey=PUB%3D&address=172.16.0.2%2F32&mtu=1280&$query#WARP"

    private fun enc(s: String): String =
        java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20")

    @Test
    fun `parse fm only link fills both profile fields`() {
        // Старая ссылка (до появления ключа noises): шум только в fm.
        val profile = WireguardFmt.parse(link("fm=${enc(fmOf(noiseArr))}"))
        assertNotNull(profile)
        assertNotNull(profile!!.finalMask)
        assertNotNull(profile.noisesJson, "поле шума обязано заполниться из fm сразу при импорте")
        val arr = JSONArray(profile.noisesJson!!)
        assertEquals(2, arr.length())
        assertEquals("hex", arr.getJSONObject(0).getString("type"))
        assertEquals("23-911", arr.getJSONObject(1).getString("rand"))
    }

    @Test
    fun `parse noises only link builds fm`() {
        val profile = WireguardFmt.parse(link("noises=${enc(noiseArr)}"))
        assertNotNull(profile)
        assertNotNull(profile!!.noisesJson)
        assertNotNull(profile.finalMask, "fm обязан собраться из явного списка шумов")
        assertTrue(TestJson.similar(JSONArray(profile.noisesJson!!), JSONArray(NoiseProfileUtil.extractNoises(profile.finalMask)!!)))
        // базовые поля не пострадали
        assertEquals("162.159.195.1", profile.server)
        assertEquals("500", profile.serverPort)
        assertEquals("SECRET=", profile.secretKey)
        assertEquals("PUB=", profile.publicKey)
        assertEquals(1280, profile.mtu)
    }

    @Test
    fun `parse both keys prefers explicit noises`() {
        val other = """[{"rand":"40-70","delay":"10-20"}]"""
        val profile = WireguardFmt.parse(link("fm=${enc(fmOf(noiseArr))}&noises=${enc(other)}"))
        assertNotNull(profile)
        val arr = JSONArray(profile!!.noisesJson!!)
        assertEquals(1, arr.length())
        assertEquals("40-70", arr.getJSONObject(0).getString("rand"))
        // fm пересобран под явный список
        assertTrue(TestJson.similar(JSONArray(profile.noisesJson!!), JSONArray(NoiseProfileUtil.extractNoises(profile.finalMask)!!)))
    }

    @Test
    fun `broken noises do not block import of a valid profile`() {
        // ЖЁСТКАЯ ОПЦИОНАЛЬНОСТЬ: шум — надстройка. Битый ключ noises не может
        // лишить владельца профиля: ссылка импортируется, fm хранится как есть,
        // шум восстановится из fm, если fm валиден.
        val profile = WireguardFmt.parse(link("noises=${enc("""[{"type":"bogus"}]""")}&fm=${enc(fmOf(noiseArr))}"))
        assertNotNull(profile, "профиль обязан импортироваться несмотря на битый noises")
        assertEquals("SECRET=", profile!!.secretKey)
        assertEquals("162.159.195.1", profile.server)
        // шум восстановлен из валидного fm
        assertNotNull(profile.noisesJson)
        assertEquals(2, JSONArray(profile.noisesJson!!).length())
        // битый noises БЕЗ fm: профиль тоже импортируется, просто без шума
        val noFm = WireguardFmt.parse(link("noises=${enc("""[{"type":"bogus"}]""")}"))
        assertNotNull(noFm)
        assertNull(noFm!!.noisesJson)
        assertNull(noFm.finalMask)
    }

    @Test
    fun `parse link without noise leaves fields empty`() {
        // Опциональность: профиль БЕЗ шума — полностью валидный профиль.
        val profile = WireguardFmt.parse(link(""))
        assertNotNull(profile)
        assertNull(profile!!.noisesJson)
        assertNull(profile.finalMask)
        // и экспорт такого профиля не добавляет ни fm, ни noises
        val uri = "wireguard://" + WireguardFmt.toUri(profile)
        assertFalse(uri.contains("fm="), uri)
        assertFalse(uri.contains("noises="), uri)
        // и эффективный finalmask для конфига отсутствует
        assertNull(NoiseProfileUtil.effectiveFinalMask(profile.finalMask, profile.noisesJson))
    }

    @Test
    fun `toUri exports full context fm and noises`() {
        val profile = WireguardFmt.parse(link("noises=${enc(noiseArr)}"))!!
        val uri = "wireguard://" + WireguardFmt.toUri(profile)
        assertTrue(uri.contains("fm="), "экспорт обязан нести fm: $uri")
        assertTrue(uri.contains("noises="), "экспорт обязан нести noises: $uri")
        // round-trip: повторный импорт даёт те же поля
        val again = WireguardFmt.parse(uri)
        assertNotNull(again)
        // Сравниваем структуры, а не строки: порядок ключей org.json на JVM
        // не гарантирован спецификацией.
        assertEquals(
            JSONArray(profile.noisesJson!!).toString(),
            JSONArray(again!!.noisesJson!!).toString()
        )
        assertTrue(
            TestJson.similar(JSONObject(profile.finalMask!!), JSONObject(again.finalMask!!)),
            "finalMask обязан совпадать структурно"
        )
        assertEquals(profile.secretKey, again.secretKey)
        assertEquals(profile.publicKey, again.publicKey)
        assertEquals(profile.server, again.server)
        assertEquals(profile.serverPort, again.serverPort)
        assertEquals(profile.mtu, again.mtu)
    }

    @Test
    fun `toUri of legacy profile restores noises from fm`() {
        // Профиль, сохранённый старой версией: noisesJson отсутствует.
        val profile = WireguardFmt.parse(link("fm=${enc(fmOf(noiseArr))}"))!!
        profile.noisesJson = null
        val uri = "wireguard://" + WireguardFmt.toUri(profile)
        assertTrue(uri.contains("noises="), "список обязан восстановиться из fm при экспорте: $uri")
        val again = WireguardFmt.parse(uri)!!
        assertNotNull(again.noisesJson)
        assertEquals(2, JSONArray(again.noisesJson!!).length())
    }

    @Test
    fun `conf file with noises and fm is imported`() {
        val conf = """
            [Interface]
            PrivateKey = SECRET=
            Address = 172.16.0.2/32
            MTU = 1280
            Noises = $noiseArr

            [Peer]
            PublicKey = PUB=
            Endpoint = 162.159.195.1:500
        """.trimIndent()
        val profile = WireguardFmt.parseWireguardConfFile(conf)
        assertNotNull(profile.noisesJson)
        assertNotNull(profile.finalMask)
        assertEquals(2, JSONArray(profile.noisesJson!!).length())
    }

    @Test
    fun `conf file with broken noises stays usable`() {
        val conf = """
            [Interface]
            PrivateKey = SECRET=
            Address = 172.16.0.2/32
            Noises = [{"type":"bogus"}]

            [Peer]
            PublicKey = PUB=
            Endpoint = 1.2.3.4:500
        """.trimIndent()
        val profile = WireguardFmt.parseWireguardConfFile(conf)
        // профиль пригоден, шум просто не синхронизирован
        assertEquals("SECRET=", profile.secretKey)
        assertNull(profile.noisesJson)
    }
}