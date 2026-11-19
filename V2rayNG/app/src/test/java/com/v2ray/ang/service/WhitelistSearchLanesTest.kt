package com.v2ray.ang.service

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Дефект устройства 19.11 06:33: надпись «speed FPTN» показывалась при
 * сканировании ЛЮБЫХ профилей — деструктуризация partition в фазе скорости
 * перепутала дорожки (обычные профили уходили в FPTN-фазу, а FPTN — в
 * параллельную обычную, нарушая инвариант «FPTN строго по одному»).
 * Разделение вынесено в чистую splitProbeLanes и доказывается этим тестом.
 */
class WhitelistSearchLanesTest {

    @Test
    fun `only normal profiles go to normal lane and FPTN lane is empty`() {
        val candidates = listOf("n1", "n2", "n3")
        val (fptn, normal) = WhitelistSearchWorkerService.splitProbeLanes(candidates, emptySet())
        assertTrue(fptn.isEmpty(), "FPTN-дорожка обязана быть пустой без FPTN-профилей")
        assertEquals(candidates, normal)
    }

    @Test
    fun `only fptn profiles go to fptn lane and normal lane is empty`() {
        val candidates = listOf("f1", "f2")
        val (fptn, normal) = WhitelistSearchWorkerService.splitProbeLanes(candidates, setOf("f1", "f2"))
        assertEquals(candidates, fptn)
        assertTrue(normal.isEmpty(), "обычная дорожка обязана быть пустой без обычных профилей")
    }

    @Test
    fun `mixed candidates split by membership preserving order`() {
        val candidates = listOf("n1", "f1", "n2", "f2", "n3")
        val (fptn, normal) = WhitelistSearchWorkerService.splitProbeLanes(candidates, setOf("f1", "f2"))
        assertEquals(listOf("f1", "f2"), fptn)
        assertEquals(listOf("n1", "n2", "n3"), normal)
    }

    @Test
    fun `empty candidates give two empty lanes`() {
        val (fptn, normal) = WhitelistSearchWorkerService.splitProbeLanes(emptyList(), setOf("f1"))
        assertTrue(fptn.isEmpty())
        assertTrue(normal.isEmpty())
    }
}
