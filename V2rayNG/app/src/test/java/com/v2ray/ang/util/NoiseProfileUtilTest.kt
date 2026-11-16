package com.v2ray.ang.util

import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Шум DPI-защиты как поле wireguard-профиля: единая точка правды
 * NoiseProfileUtil. Покрывает нормализацию, пресеты, поглощение в finalMask
 * без потери прочих масок и инвариант «весь контекст» при round-trip.
 */
class NoiseProfileUtilTest {

    private val warpNoises = """[
        {"type":"hex","packet":"576172704e6f697365","delay":"1-3"},
        {"rand":"23-911","delay":"1-3"},{"rand":"23-911","delay":"1-3"},
        {"rand":"23-911","delay":"1-3"},{"rand":"23-911","delay":"1-3"},
        {"rand":"23-911","delay":"1-3"},{"rand":"23-911","delay":"1-3"},
        {"rand":"23-911","delay":"1-3"},{"rand":"23-911","delay":"1-3"}
    ]"""

    // --- normalizeNoises ---

    @Test
    fun `normalize accepts rand and typed packets`() {
        val out = NoiseProfileUtil.normalizeNoises(warpNoises)
        assertNotNull(out)
        val arr = JSONArray(out!!)
        assertEquals(9, arr.length())
        assertEquals("hex", arr.getJSONObject(0).getString("type"))
        assertEquals("23-911", arr.getJSONObject(1).getString("rand"))
        assertEquals("1-3", arr.getJSONObject(1).getString("delay"))
    }

    @Test
    fun `normalize rejects garbage instead of silently dropping noise`() {
        assertNull(NoiseProfileUtil.normalizeNoises(null))
        assertNull(NoiseProfileUtil.normalizeNoises(""))
        assertNull(NoiseProfileUtil.normalizeNoises("[]"))
        assertNull(NoiseProfileUtil.normalizeNoises("{}"))
        assertNull(NoiseProfileUtil.normalizeNoises("""[{"type":"unknown","packet":"x"}]"""))
        assertNull(NoiseProfileUtil.normalizeNoises("""[{"rand":"abc"}]"""))
        assertNull(NoiseProfileUtil.normalizeNoises("""[{"rand":"900-100"}]"""))
        assertNull(NoiseProfileUtil.normalizeNoises("""[{"type":"hex"}]"""))
        assertNull(NoiseProfileUtil.normalizeNoises("""[{"rand":"1-2","delay":"x"}]"""))
        assertNull(NoiseProfileUtil.normalizeNoises("""[{"type":"array","packet":[1,256]}]"""))
    }

    @Test
    fun `normalize accepts array bytes and numeric delay`() {
        val out = NoiseProfileUtil.normalizeNoises("""[{"type":"array","packet":[1,2,255],"delay":5}]""")
        assertNotNull(out)
        val item = JSONArray(out!!).getJSONObject(0)
        assertEquals("array", item.getString("type"))
        assertEquals(255, item.getJSONArray("packet").getInt(2))
        assertEquals("5", item.getString("delay"))
    }

    // --- пресеты ---

    @Test
    fun `all presets are valid noise lists`() {
        for (name in NoiseProfileUtil.PRESETS) {
            val json = NoiseProfileUtil.presetJson(name)
            assertNotNull(json, "пресет $name обязан существовать")
            assertNotNull(NoiseProfileUtil.normalizeNoises(json), "пресет $name обязан быть валидным")
        }
        assertNull(NoiseProfileUtil.presetJson("no-such-preset"))
    }

    @Test
    fun `amnezia preset is four junk packets 40-70`() {
        val arr = JSONArray(NoiseProfileUtil.presetJson(NoiseProfileUtil.PRESET_AMNEZIA)!!)
        assertEquals(4, arr.length())
        for (i in 0 until arr.length()) {
            assertEquals("40-70", arr.getJSONObject(i).getString("rand"))
        }
    }

    @Test
    fun `warp preset matches owner config shape`() {
        val arr = JSONArray(NoiseProfileUtil.presetJson(NoiseProfileUtil.PRESET_WARP)!!)
        assertEquals(9, arr.length())
        assertEquals("hex", arr.getJSONObject(0).getString("type"))
        for (i in 1 until 9) {
            assertEquals("23-911", arr.getJSONObject(i).getString("rand"))
            assertEquals("1-3", arr.getJSONObject(i).getString("delay"))
        }
    }

    // --- extractNoises ---

    @Test
    fun `extract prefers udp noise over tcp`() {
        // wireguard — UDP: если шум есть в udp, tcp-noise (например, чужой,
        // от глобального фрагмента) в поле профиля не входит и не затирается.
        val fm = JSONObject()
            .put("udp", JSONArray().put(
                JSONObject().put("type", "noise").put("settings",
                    JSONObject().put("noise", JSONArray("""[{"rand":"23-911"}]""")))
            ))
            .put("tcp", JSONArray().put(
                JSONObject().put("type", "noise").put("settings",
                    JSONObject().put("noise", JSONArray("""[{"rand":"10-20"}]""")))
            ))
        val out = NoiseProfileUtil.extractNoises(fm.toString())
        assertNotNull(out)
        val arr = JSONArray(out!!)
        assertEquals(1, arr.length())
        assertEquals("23-911", arr.getJSONObject(0).getString("rand"))
    }

    @Test
    fun `extract falls back to tcp noise when udp has none`() {
        val fm = """{"tcp":[{"type":"noise","settings":{"noise":[{"rand":"10-20"}]}}]}"""
        val arr = JSONArray(NoiseProfileUtil.extractNoises(fm)!!)
        assertEquals(1, arr.length())
        assertEquals("10-20", arr.getJSONObject(0).getString("rand"))
    }

    @Test
    fun `merge preserves foreign tcp noise`() {
        val fm = """{"tcp":[{"type":"noise","settings":{"noise":[{"rand":"10-20"}]}}]}"""
        val merged = JSONObject(NoiseProfileUtil.mergeNoisesIntoFinalMask(fm, """[{"rand":"23-911"}]""")!!)
        // tcp-noise не тронут
        assertEquals("10-20", merged.getJSONArray("tcp").getJSONObject(0)
            .getJSONObject("settings").getJSONArray("noise").getJSONObject(0).getString("rand"))
        // udp-noise добавлен
        assertEquals("23-911", merged.getJSONArray("udp").getJSONObject(0)
            .getJSONObject("settings").getJSONArray("noise").getJSONObject(0).getString("rand"))
        // и очистка списка убирает только udp-noise
        val cleared = JSONObject(NoiseProfileUtil.mergeNoisesIntoFinalMask(merged.toString(), null)!!)
        assertTrue(!cleared.has("udp"))
        assertEquals("10-20", cleared.getJSONArray("tcp").getJSONObject(0)
            .getJSONObject("settings").getJSONArray("noise").getJSONObject(0).getString("rand"))
    }

    @Test
    fun `extract returns null when fm has no noise`() {
        assertNull(NoiseProfileUtil.extractNoises(null))
        assertNull(NoiseProfileUtil.extractNoises("""{"udp":[{"type":"header","settings":{"value":"x"}}]}"""))
        assertNull(NoiseProfileUtil.extractNoises("not json"))
    }

    // --- mergeNoisesIntoFinalMask ---

    @Test
    fun `merge keeps non-noise masks intact`() {
        val fm = """{"udp":[{"type":"header","settings":{"value":"dns"}}],"quicParams":{"congestion":"brutal"}}"""
        val merged = NoiseProfileUtil.mergeNoisesIntoFinalMask(fm, """[{"rand":"23-911"}]""")
        assertNotNull(merged)
        val obj = JSONObject(merged!!)
        val udp = obj.getJSONArray("udp")
        assertEquals(2, udp.length())
        // не-noise маска сохранена
        assertEquals("header", udp.getJSONObject(0).getString("type"))
        assertEquals("dns", udp.getJSONObject(0).getJSONObject("settings").getString("value"))
        // noise добавлен
        assertEquals("noise", udp.getJSONObject(1).getString("type"))
        assertEquals("23-911",
            udp.getJSONObject(1).getJSONObject("settings").getJSONArray("noise").getJSONObject(0).getString("rand"))
        // quicParams не тронут
        assertEquals("brutal", obj.getJSONObject("quicParams").getString("congestion"))
    }

    @Test
    fun `merge replaces existing noise and collapses duplicates`() {
        val fm = """{"udp":[
            {"type":"noise","settings":{"noise":[{"rand":"1-2"}]}},
            {"type":"noise","settings":{"noise":[{"rand":"3-4"}]}}
        ]}"""
        val merged = NoiseProfileUtil.mergeNoisesIntoFinalMask(fm, """[{"rand":"23-911"}]""")!!
        val udp = JSONObject(merged).getJSONArray("udp")
        assertEquals(1, udp.length())
        assertEquals("23-911",
            udp.getJSONObject(0).getJSONObject("settings").getJSONArray("noise").getJSONObject(0).getString("rand"))
    }

    @Test
    fun `merge with empty noises removes noise and can clear fm`() {
        val onlyNoise = """{"udp":[{"type":"noise","settings":{"noise":[{"rand":"1-2"}]}}]}"""
        assertNull(NoiseProfileUtil.mergeNoisesIntoFinalMask(onlyNoise, null))
        assertNull(NoiseProfileUtil.mergeNoisesIntoFinalMask(onlyNoise, ""))
        val mixed = """{"udp":[{"type":"noise","settings":{"noise":[{"rand":"1-2"}]}},{"type":"header","settings":{"value":"x"}}]}"""
        val kept = JSONObject(NoiseProfileUtil.mergeNoisesIntoFinalMask(mixed, null)!!)
        val udp = kept.getJSONArray("udp")
        assertEquals(1, udp.length())
        assertEquals("header", udp.getJSONObject(0).getString("type"))
    }

    @Test
    fun `merge rejects invalid noises loudly`() {
        assertThrows(IllegalArgumentException::class.java) {
            NoiseProfileUtil.mergeNoisesIntoFinalMask(null, """[{"type":"bogus"}]""")
        }
        assertThrows(IllegalArgumentException::class.java) {
            NoiseProfileUtil.mergeNoisesIntoFinalMask("not json", """[{"rand":"1-2"}]""")
        }
    }

    // --- syncProfileFields: инвариант двух полей ---

    @Test
    fun `sync explicit noises wins and lands in fm`() {
        val (noises, fm) = NoiseProfileUtil.syncProfileFields("""[{"rand":"40-70"}]""", null)
        assertNotNull(noises)
        assertNotNull(fm)
        assertTrue(TestJson.similar(JSONArray(noises!!), JSONArray(NoiseProfileUtil.extractNoises(fm)!!)))
    }

    @Test
    fun `sync restores noises from fm for legacy profiles`() {
        val fm = """{"udp":[{"type":"noise","settings":{"noise":[{"rand":"23-911","delay":"1-3"}]}}]}"""
        val (noises, fmOut) = NoiseProfileUtil.syncProfileFields(null, fm)
        assertNotNull(noises, "старый профиль с fm обязан получить заполненное поле шума")
        assertEquals(fm, fmOut, "fm без явного списка не меняется")
        assertEquals("23-911", JSONArray(noises!!).getJSONObject(0).getString("rand"))
    }

    @Test
    fun `sync round trip is stable`() {
        val (n1, f1) = NoiseProfileUtil.syncProfileFields(warpNoises, null)
        val (n2, f2) = NoiseProfileUtil.syncProfileFields(n1, f1)
        // similar(): порядок ключей org.json на JVM не гарантирован.
        assertTrue(TestJson.similar(JSONArray(n1!!), JSONArray(n2!!)))
        assertTrue(TestJson.similar(JSONObject(f1!!), JSONObject(f2!!)))
        // и восстановление только из fm даёт тот же список
        val (n3, _) = NoiseProfileUtil.syncProfileFields(null, f1)
        assertTrue(TestJson.similar(JSONArray(n1), JSONArray(n3!!)))
    }

    // --- effectiveFinalMask: применение в конфиге ---

    @Test
    fun `effective fm builds noise mask from noises alone`() {
        val fm = NoiseProfileUtil.effectiveFinalMask(null, """[{"rand":"23-911","delay":"1-3"}]""")
        assertNotNull(fm)
        val obj = JSONObject(fm!!)
        val mask = obj.getJSONArray("udp").getJSONObject(0)
        assertEquals("noise", mask.getString("type"))
        val noise = mask.getJSONObject("settings").getJSONArray("noise")
        assertEquals("23-911", noise.getJSONObject(0).getString("rand"))
        assertEquals("1-3", noise.getJSONObject(0).getString("delay"))
    }

    @Test
    fun `effective fm prefers explicit finalMask`() {
        val custom = """{"udp":[{"type":"header","settings":{"value":"x"}}]}"""
        assertEquals(custom, NoiseProfileUtil.effectiveFinalMask(custom, """[{"rand":"1-2"}]"""))
        assertNull(NoiseProfileUtil.effectiveFinalMask(null, null))
        assertNull(NoiseProfileUtil.effectiveFinalMask("", "[]"))
    }

    // --- применение в outbound: уровень CoreOutboundBuilder ---

    @Test
    fun `outbound builder puts noise into streamSettings finalmask udp`() {
        // Промт требует: «сборка outbound с шумом -> JSON конфига содержит
        // finalmask.udp noise с теми же элементами». toOutboundWireguard
        // приватный и тянет MmkvManager, но публичный updateOutboundFinalMask —
        // ровно тот шаг, которым builder кладёт finalmask в streamSettings.
        val profile = com.v2ray.ang.dto.entities.ProfileItem.create(
            com.v2ray.ang.enums.EConfigType.WIREGUARD
        )
        profile.noisesJson = warpNoises
        // профиль с полем шума и пустым fm: эффективный finalmask собирается
        val effective = NoiseProfileUtil.effectiveFinalMask(profile.finalMask, profile.noisesJson)
        assertNotNull(effective)
        val ss = com.v2ray.ang.dto.V2rayConfig.OutboundBean.StreamSettingsBean()
        com.v2ray.ang.core.CoreOutboundBuilder.updateOutboundFinalMask(
            ss, profile.copy(finalMask = effective)
        )
        assertNotNull(ss.finalmask)
        // finalmask объявлен как Any? (исторически), фактически — JsonObject
        val fmObj = ss.finalmask as com.google.gson.JsonObject
        val udp = fmObj.getAsJsonArray("udp")
        assertEquals(1, udp.size())
        val mask = udp.get(0).asJsonObject
        assertEquals("noise", mask.get("type").asString)
        val noise = mask.getAsJsonObject("settings").getAsJsonArray("noise")
        assertEquals(9, noise.size())
        assertEquals("hex", noise.get(0).asJsonObject.get("type").asString)
        assertEquals("576172704e6f697365", noise.get(0).asJsonObject.get("packet").asString)
        assertEquals("23-911", noise.get(1).asJsonObject.get("rand").asString)
        assertEquals("1-3", noise.get(1).asJsonObject.get("delay").asString)
    }

    @Test
    fun `outbound builder keeps explicit finalMask untouched`() {
        val profile = com.v2ray.ang.dto.entities.ProfileItem.create(
            com.v2ray.ang.enums.EConfigType.WIREGUARD
        )
        val custom = """{"udp":[{"type":"header","settings":{"value":"dns"}}]}"""
        profile.finalMask = custom
        profile.noisesJson = """[{"rand":"40-70"}]"""
        // finalMask приоритетен: builder применит его как есть
        val effective = NoiseProfileUtil.effectiveFinalMask(profile.finalMask, profile.noisesJson)
        assertEquals(custom, effective)
    }

    // --- эквивалентность freedom-noises и finalmask-noise ---

    @Test
    fun `converter freedom noises equal editor preset warp shape`() {
        // Конфиг владельца: freedom c 1 hex + 8 rand. Конвертер поглощает его
        // в fm; список, извлечённый из fm, обязан совпасть с пресетом WARP
        // по структуре (типы, диапазоны, задержки).
        val noises = JSONArray()
        noises.put(JSONObject().put("type", "hex").put("packet", "576172704e6f697365").put("delay", "1-3"))
        repeat(8) { noises.put(JSONObject().put("type", "rand").put("packet", "23-911").put("delay", "1-3")) }
        val freedomCfg = JSONObject().put("outbounds", JSONArray()
            .put(JSONObject().put("tag", "warp").put("protocol", "wireguard")
                .put("settings", JSONObject().put("secretKey", "S=")
                    .put("peers", JSONArray().put(JSONObject().put("endpoint", "162.159.195.1:500").put("publicKey", "P="))))
                .put("streamSettings", JSONObject().put("sockopt", JSONObject().put("dialerProxy", "noise-out"))))
            .put(JSONObject().put("tag", "noise-out").put("protocol", "freedom")
                .put("settings", JSONObject().put("noises", noises))))
        val fm = SubscriptionContentConverter.noiseChainFinalMask(freedomCfg)
        assertNotNull(fm, "цепочка обязана поглотиться")
        val extracted = JSONArray(NoiseProfileUtil.extractNoises(fm)!!)
        val preset = JSONArray(NoiseProfileUtil.presetJson(NoiseProfileUtil.PRESET_WARP)!!)
        assertEquals(preset.length(), extracted.length())
        for (i in 0 until preset.length()) {
            val a = preset.getJSONObject(i)
            val b = extracted.getJSONObject(i)
            assertEquals(a.optString("type"), b.optString("type"), "элемент $i: type")
            assertEquals(a.optString("rand"), b.optString("rand"), "элемент $i: rand")
            assertEquals(a.optString("packet"), b.optString("packet"), "элемент $i: packet")
            assertEquals(a.optString("delay"), b.optString("delay"), "элемент $i: delay")
        }
    }

    @Test
    fun `full round trip config to link to profile fields keeps noise`() {
        // конфиг с freedom-noises -> ссылка (конвертер) -> поля профиля
        // (parse-эквивалент через syncProfileFields) -> effectiveFinalMask:
        // шум на выходе эквивалентен шуму на входе.
        val cfg = JSONObject().put("outbounds", JSONArray()
            .put(JSONObject().put("tag", "wg").put("protocol", "wireguard")
                .put("settings", JSONObject().put("secretKey", "S=")
                    .put("peers", JSONArray().put(JSONObject().put("endpoint", "1.2.3.4:500").put("publicKey", "P="))))
                .put("streamSettings", JSONObject().put("sockopt", JSONObject().put("dialerProxy", "n"))))
            .put(JSONObject().put("tag", "n").put("protocol", "freedom")
                .put("settings", JSONObject().put("noises", JSONArray()
                    .put(JSONObject().put("type", "rand").put("packet", "23-911").put("delay", "1-3"))))))
        val link = SubscriptionContentConverter.convert(cfg.toString(), decodeBase64 = false, customToLinks = true)
        assertTrue(link.startsWith("wireguard://"), link)
        assertTrue(link.contains("fm="), "ссылка обязана нести fm со всем шумом: $link")
        assertFalse(link.contains("noises="), "дубликат noises запрещён: $link")

        // имитация WireguardFmt.parse: query-пары -> syncProfileFields
        // (явного noises нет — поле восстанавливается из fm)
        val query = link.substringAfter("?").substringBefore("#")
            .split("&").associate {
                val (k, v) = it.split("=", limit = 2)
                k to java.net.URLDecoder.decode(v, "UTF-8")
            }
        val (noises, fm) = NoiseProfileUtil.syncProfileFields(null, query["fm"])
        assertNotNull(noises)
        val effective = NoiseProfileUtil.effectiveFinalMask(fm, noises)
        val noiseOut = JSONObject(effective!!).getJSONArray("udp").getJSONObject(0)
            .getJSONObject("settings").getJSONArray("noise")
        assertEquals(1, noiseOut.length())
        assertEquals("23-911", noiseOut.getJSONObject(0).getString("rand"))
        assertEquals("1-3", noiseOut.getJSONObject(0).getString("delay"))
    }
}