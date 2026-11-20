package com.v2ray.ang.util

import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Тесты слияния finalmask Hysteria2 ([Hysteria2FinalMask.merge]).
 *
 * Регрессия, которую закрывают: явный finalMask профиля ЗАМЕНЯЛ собранный
 * форком, из-за чего обфускация salamander (и port hopping) молча терялись —
 * сервер отвергал туннель. Вещдок 20.11.2026: конфиг провайдера с
 * salamander + noise + quicParams{udpHop,bbrProfile,congestion}.
 */
class Hysteria2FinalMaskTest {

    /** finalmask, собранный форком из полей профиля (obfs salamander). */
    private val builtSalamander = """
        {"udp":[{"type":"salamander","settings":{"password":"builtPsk"}}],"quicParams":{}}
    """.trimIndent()

    /**
     * Конфиг провайдера: salamander + noise + udpHop/bbrProfile/congestion.
     * Структура — как в реальном кастомном профиле владельца.
     */
    private val userWithNoiseAndHop = """
        {"udp":[
           {"type":"salamander","settings":{"password":"userPsk"}},
           {"type":"noise","settings":{"noise":[
              {"rand":"100-200","delay":"5-10","randRange":"0-127"}],"reset":"0"}}],
         "quicParams":{"udpHop":{"ports":"40000-41000","interval":"20-30"},
                       "bbrProfile":"aggressive","congestion":"bbr"}}
    """.trimIndent()

    @Test
    fun `user salamander wins over built one but noise is kept`() {
        val merged = JSONObject(Hysteria2FinalMask.merge(builtSalamander, userWithNoiseAndHop)!!)
        val udp = merged.getJSONArray("udp")

        assertEquals(2, udp.length(), "обе маски обязаны остаться: $merged")
        val salamander = (0 until udp.length())
            .map { udp.getJSONObject(it) }
            .first { it.optString("type") == "salamander" }
        assertEquals(
            "userPsk",
            salamander.getJSONObject("settings").getString("password"),
            "явный finalmask приоритетен для того же типа маски",
        )
    }

    @Test
    fun `built salamander survives when user finalmask has no obfuscation`() {
        val userNoiseOnly = """{"udp":[{"type":"noise","settings":{"noise":[{"rand":"1-8"}]}}]}"""

        val merged = JSONObject(Hysteria2FinalMask.merge(builtSalamander, userNoiseOnly)!!)
        val types = (0 until merged.getJSONArray("udp").length())
            .map { merged.getJSONArray("udp").getJSONObject(it).getString("type") }
            .toSet()

        assertEquals(setOf("salamander", "noise"), types)
        assertEquals(
            "builtPsk",
            (0 until merged.getJSONArray("udp").length())
                .map { merged.getJSONArray("udp").getJSONObject(it) }
                .first { it.getString("type") == "salamander" }
                .getJSONObject("settings").getString("password"),
            "обфускация из полей профиля НЕ должна теряться",
        )
    }

    @Test
    fun `quicParams merged so tuning of provider survives`() {
        val merged = JSONObject(Hysteria2FinalMask.merge(builtSalamander, userWithNoiseAndHop)!!)
        val qp = merged.getJSONObject("quicParams")

        assertEquals("aggressive", qp.getString("bbrProfile"))
        assertEquals("bbr", qp.getString("congestion"))
        assertEquals("40000-41000", qp.getJSONObject("udpHop").getString("ports"))
    }

    @Test
    fun `built congestion survives when user quicParams has no congestion`() {
        val built = """{"quicParams":{"congestion":"brutal","brutalUp":"100"}}"""
        val user = """{"quicParams":{"bbrProfile":"aggressive"}}"""

        val qp = JSONObject(Hysteria2FinalMask.merge(built, user)!!).getJSONObject("quicParams")

        assertEquals("brutal", qp.getString("congestion"))
        assertEquals("100", qp.getString("brutalUp"))
        assertEquals("aggressive", qp.getString("bbrProfile"))
    }

    @Test
    fun `unknown finalmask keys of provider are preserved`() {
        val user = """{"udp":[{"type":"noise","settings":{"noise":[{"rand":"1-8"}]}}],"futureMask":{"a":1}}"""

        val merged = JSONObject(Hysteria2FinalMask.merge(builtSalamander, user)!!)

        assertTrue(merged.has("futureMask"), "неизвестный ключ обязан сохраниться: $merged")
        assertEquals(1, merged.getJSONObject("futureMask").getInt("a"))
    }

    @Test
    fun `invalid user json falls back to built finalmask`() {
        val merged = JSONObject(Hysteria2FinalMask.merge(builtSalamander, "{broken json")!!)

        assertEquals(
            "builtPsk",
            merged.getJSONArray("udp").getJSONObject(0)
                .getJSONObject("settings").getString("password"),
        )
    }

    @Test
    fun `gson literal null is not treated as finalmask`() {
        // JsonUtil.toJson(null) возвращает СТРОКУ «null» (Gson), а не пустую
        // строку. Без защиты merge вернул бы мусор вместо finalmask.
        assertNull(Hysteria2FinalMask.merge("null", null))
        assertNull(Hysteria2FinalMask.merge(null, null))
        assertNull(Hysteria2FinalMask.merge("null", ""))

        val merged = Hysteria2FinalMask.merge("null", userWithNoiseAndHop)
        assertNotNull(merged)
        assertFalse(merged == "null", "литерал null не должен стать результатом")
        assertTrue(JSONObject(merged!!).has("udp"))
    }

    @Test
    fun `built udphop survives user noise`() {
        val built = """
            {"udp":[{"type":"salamander","settings":{"password":"p"}},
                    {"type":"udphop","settings":{"mode":"intervallocal,intervalremote","interval":"20-30","remotePorts":"40000-41000"}}]}
        """.trimIndent()
        val user = """{"udp":[{"type":"noise","settings":{"noise":[{"rand":"1-8"}]}}]}"""

        val udp = JSONObject(Hysteria2FinalMask.merge(built, user)!!).getJSONArray("udp")
        val types = (0 until udp.length()).map { udp.getJSONObject(it).getString("type") }.toSet()

        assertTrue("salamander" in types, "обфускация потерялась: $types")
        assertTrue("udphop" in types, "смена портов потерялась: $types")
        assertTrue("noise" in types, "шум провайдера потерян: $types")
    }
}
