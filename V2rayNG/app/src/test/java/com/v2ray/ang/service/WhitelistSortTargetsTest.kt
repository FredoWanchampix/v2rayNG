package com.v2ray.ang.service

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Требование владельца (22.11.2026): «когда именно функция поиск стабильных
 * профилей закончит работать, чтобы она сортировала не по пингу, а по скорости».
 *
 * Дефект первой попытки: сортировка была внутри `if (PREF_AUTO_SORT_AFTER_TEST)`,
 * то есть требование выполнилось бы НЕ безусловно — с выключенным свитчом поиск
 * продолжал бы оставлять порядок по пингу. Плюс была закрыта только одна
 * поверхность (выбранная подписка): на вкладке «Все» поиск меряет каждую
 * подписку, а порядок серверов хранится отдельно по каждой, поэтому сортировка
 * одного списка не меняла бы порядок ни в одной подписке.
 *
 * Выбор списков вынесен в чистую [WhitelistSortPolicy.targets] и
 * доказывается этим тестом.
 */
class WhitelistSortTargetsTest {

    private val defaultSub = "__default_subscription__"

    @Test
    fun `selected subscription sorts only itself and ignores subs list`() {
        val targets = WhitelistSortPolicy.targets(
            subscriptionId = "sub2",
            subsList = listOf("sub1", "sub2", "sub3"),
            defaultSubId = defaultSub,
        )
        assertEquals(listOf("sub2"), targets)
    }

    @Test
    fun `all-tab sorts every subscription`() {
        val targets = WhitelistSortPolicy.targets(
            subscriptionId = "",
            subsList = listOf("sub1", "sub2"),
            defaultSubId = defaultSub,
        )
        assertEquals(listOf(defaultSub, "sub1", "sub2"), targets)
    }

    @Test
    fun `all-tab prepends default subscription when index lacks it`() {
        val targets = WhitelistSortPolicy.targets(
            subscriptionId = "",
            subsList = listOf("sub1"),
            defaultSubId = defaultSub,
        )
        assertEquals(listOf(defaultSub, "sub1"), targets)
    }

    @Test
    fun `all-tab keeps order and does not duplicate default subscription`() {
        val targets = WhitelistSortPolicy.targets(
            subscriptionId = "",
            subsList = listOf(defaultSub, "sub1", "sub2"),
            defaultSubId = defaultSub,
        )
        assertEquals(listOf(defaultSub, "sub1", "sub2"), targets)
        assertEquals(targets.distinct(), targets, "дублей подписок быть не должно")
    }

    @Test
    fun `all-tab with empty index still sorts ungrouped servers`() {
        val targets = WhitelistSortPolicy.targets(
            subscriptionId = "",
            subsList = emptyList(),
            defaultSubId = defaultSub,
        )
        assertEquals(listOf(defaultSub), targets)
    }
}
