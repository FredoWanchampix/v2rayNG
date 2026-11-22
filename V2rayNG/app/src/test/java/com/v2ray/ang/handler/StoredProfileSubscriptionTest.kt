package com.v2ray.ang.handler

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

/**
 * Форк-дефект: `MmkvManager.removeServer` определял подписку через
 * `decodeServerConfig`, которая в форке возвращает null ещё и при
 * невосстановимом `configType` (хотя JSON валиден и подписка известна). Тогда
 * подставлялась DEFAULT-подписка: payload стирался, а guid навсегда оставался
 * мёртвым в индексе своей подписки.
 *
 * Чтение подписки напрямую из JSON не зависит от `configType` — это и проверяется.
 */
class StoredProfileSubscriptionTest {

    @Test
    fun `reads subscription id from a valid profile`() {
        val json = """{"configType":"VLESS","subscriptionId":"sub-1","server":"example.test"}"""
        assertEquals("sub-1", StoredProfileSubscription.fromProfileJson(json))
    }

    @Test
    fun `reads subscription id even when configType is broken`() {
        // именно этот случай ломал removeServer: тип не восстановим, подписка есть
        assertEquals(
            "sub-2",
            StoredProfileSubscription.fromProfileJson(
                """{"configType":null,"subscriptionId":"sub-2","server":"example.test"}"""
            ),
        )
        assertEquals(
            "sub-3",
            StoredProfileSubscription.fromProfileJson(
                """{"configType":"","subscriptionId":"sub-3"}"""
            ),
        )
        // числовой тип, которого нет в enum (TUIC(8) закомментирован)
        assertEquals(
            "sub-4",
            StoredProfileSubscription.fromProfileJson(
                """{"configType":8,"subscriptionId":"sub-4"}"""
            ),
        )
    }

    @Test
    fun `reads subscription id when profile has no type at all`() {
        assertEquals(
            "sub-5",
            StoredProfileSubscription.fromProfileJson("""{"subscriptionId":"sub-5"}"""),
        )
    }

    @Test
    fun `empty subscription id is returned as is so caller falls back to default`() {
        assertEquals(
            "",
            StoredProfileSubscription.fromProfileJson("""{"subscriptionId":""}"""),
        )
    }

    @Test
    fun `unreadable profile gives null - previous behaviour preserved`() {
        assertNull(StoredProfileSubscription.fromProfileJson(null))
        assertNull(StoredProfileSubscription.fromProfileJson(""))
        assertNull(StoredProfileSubscription.fromProfileJson("   "))
        assertNull(StoredProfileSubscription.fromProfileJson("not a json"))
        assertNull(StoredProfileSubscription.fromProfileJson("[1,2,3]"))
    }

    @Test
    fun `missing or non-primitive field gives null`() {
        assertNull(StoredProfileSubscription.fromProfileJson("""{"server":"example.test"}"""))
        assertNull(
            StoredProfileSubscription.fromProfileJson(
                """{"subscriptionId":{"nested":true}}"""
            ),
        )
        assertNull(StoredProfileSubscription.fromProfileJson("""{"subscriptionId":null}"""))
    }
}
