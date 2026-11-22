package com.v2ray.ang.service

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Скоуп действий на финише теста обязан совпадать со скоупом ИЗМЕРЕНИЯ воркера.
 *
 * Три дефекта, закрытые этой политикой (вещдоки кода и лога владельца
 * 22.11.2026):
 * 1. вкладка «Все» (`subscriptionId == ""`) — авто-удаление недействительных и
 *    сортировка по пингу не выполнялись ВОВСЕ, хотя воркер измерил каждый
 *    профиль каждой подписки (`decodeAllServerList`);
 * 2. при активном фильтре по слову измерены только `serverGuids`, а удаление шло
 *    по ВСЕЙ подписке — стирались профили, которые в этом прогоне не мерились
 *    (потеря данных);
 * 3. сортировка по скорости после «Поиска стабильных профилей» имела те же две
 *    дыры (плюс была под свитчом вместо безусловной).
 */
class TestFinishScopePolicyTest {

    private val defaultSub = "__default_subscription__"

    // ---------- invalidCleanup: выбор скоупа авто-удаления ----------

    @Test
    fun `filter by keyword limits cleanup to measured guids only`() {
        // самый опасный дефект: фильтром измерена часть подписки, а удаление
        // шло бы по всей подписке и стёрло неизмеренные профили
        assertEquals(
            TestFinishScopePolicy.InvalidCleanup.GUIDS,
            TestFinishScopePolicy.invalidCleanup(
                serverGuids = listOf("g1", "g2"),
                subscriptionId = "sub1",
            ),
        )
    }

    @Test
    fun `guids win over subscription even on all tab`() {
        assertEquals(
            TestFinishScopePolicy.InvalidCleanup.GUIDS,
            TestFinishScopePolicy.invalidCleanup(serverGuids = listOf("g1"), subscriptionId = ""),
        )
    }

    @Test
    fun `single subscription keeps previous behaviour`() {
        assertEquals(
            TestFinishScopePolicy.InvalidCleanup.SUBSCRIPTION,
            TestFinishScopePolicy.invalidCleanup(serverGuids = emptyList(), subscriptionId = "sub1"),
        )
    }

    @Test
    fun `all tab cleans every subscription instead of nothing`() {
        assertEquals(
            TestFinishScopePolicy.InvalidCleanup.ALL,
            TestFinishScopePolicy.invalidCleanup(serverGuids = emptyList(), subscriptionId = ""),
        )
    }

    // ---------- sortTargets: какие списки сортировать ----------

    @Test
    fun `selected subscription sorts only itself and ignores subs list`() {
        val targets = TestFinishScopePolicy.sortTargets(
            subscriptionId = "sub2",
            subsList = listOf("sub1", "sub2", "sub3"),
            defaultSubId = defaultSub,
        )
        assertEquals(listOf("sub2"), targets)
    }

    @Test
    fun `all-tab sorts every subscription`() {
        val targets = TestFinishScopePolicy.sortTargets(
            subscriptionId = "",
            subsList = listOf("sub1", "sub2"),
            defaultSubId = defaultSub,
        )
        assertEquals(listOf(defaultSub, "sub1", "sub2"), targets)
    }

    @Test
    fun `all-tab prepends default subscription when index lacks it`() {
        val targets = TestFinishScopePolicy.sortTargets(
            subscriptionId = "",
            subsList = listOf("sub1"),
            defaultSubId = defaultSub,
        )
        assertEquals(listOf(defaultSub, "sub1"), targets)
    }

    @Test
    fun `all-tab keeps order and does not duplicate default subscription`() {
        val targets = TestFinishScopePolicy.sortTargets(
            subscriptionId = "",
            subsList = listOf(defaultSub, "sub1", "sub2"),
            defaultSubId = defaultSub,
        )
        assertEquals(listOf(defaultSub, "sub1", "sub2"), targets)
        assertEquals(targets.distinct(), targets, "дублей подписок быть не должно")
    }

    @Test
    fun `all-tab with empty index still covers ungrouped servers`() {
        val targets = TestFinishScopePolicy.sortTargets(
            subscriptionId = "",
            subsList = emptyList(),
            defaultSubId = defaultSub,
        )
        assertEquals(listOf(defaultSub), targets)
    }

    @Test
    fun `every subscription measured by all tab is covered`() {
        // инвариант покрытия: воркер на «Все» мерил decodeAllServerList, значит
        // ни одна подписка из индекса не может выпасть из сортировки
        val subs = listOf("a", "b", defaultSub, "c")
        val targets = TestFinishScopePolicy.sortTargets("", subs, defaultSub)
        assertEquals(subs.toSet(), targets.toSet(), "покрытие обязано быть полным")
        assertEquals(targets.distinct(), targets)
    }
}
