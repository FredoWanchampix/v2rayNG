package com.v2ray.ang.util

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Дефект ФОРКА (не апстрима): `removeZeroSpeedServer` удалял профиль при
 * `testSpeedBytesPerSec == 0L`, но `0L` — значение по умолчанию и для профиля,
 * у которого скорость НЕ измерялась. Форк сам ввёл флаг `testSpeedPresent`
 * для различения этих случаев, но функция удаления его не использовала.
 *
 * Следствие (потеря данных): обычный тест задержки создаёт запись со
 * `speed=0, present=false`, и пункт меню «Удалить профили с нулевой скоростью»
 * стирал ВСЕ такие профили, включая рабочие.
 *
 * Тест доказывает исправленную политику [ZeroSpeedRemovalPolicy.shouldRemove].
 */
class ZeroSpeedRemovalPolicyTest {

    @Test
    fun `probed zero speed is removed`() {
        assertTrue(
            ZeroSpeedRemovalPolicy.shouldRemove(testSpeedPresent = true, testSpeedBytesPerSec = 0L),
            "реально измеренная нулевая скорость — профиль должен удаляться",
        )
    }

    @Test
    fun `never speed-tested profile is NOT removed even though speed is zero`() {
        assertFalse(
            ZeroSpeedRemovalPolicy.shouldRemove(testSpeedPresent = false, testSpeedBytesPerSec = 0L),
            "главный дефект: неизмеренный профиль (present=false, speed=0) терять нельзя",
        )
    }

    @Test
    fun `probed positive speed is kept`() {
        assertFalse(ZeroSpeedRemovalPolicy.shouldRemove(true, 1_500_000L))
        assertFalse(ZeroSpeedRemovalPolicy.shouldRemove(true, 1L))
    }

    @Test
    fun `failed probe (-1) is NOT removed as zero speed`() {
        // -1 = проба не удалась (сеть/таймаут), а не нулевая скорость;
        // профиль может быть рабочим — удалять по этому признаку небезопасно
        assertFalse(
            ZeroSpeedRemovalPolicy.shouldRemove(testSpeedPresent = true, testSpeedBytesPerSec = -1L),
            "провал пробы (-1) не должен считаться нулевой скоростью",
        )
    }

    @Test
    fun `untested profile with stale negative speed is not removed`() {
        assertFalse(ZeroSpeedRemovalPolicy.shouldRemove(false, -1L))
    }

    @Test
    fun `only present-and-zero is removed - exhaustive over the decision matrix`() {
        // полная матрица: present ∈ {false,true} × скорость ∈ {0, >0, <0}
        val removed = mutableListOf<Pair<Boolean, Long>>()
        for (present in listOf(false, true)) {
            for (speed in listOf(0L, 100L, -1L)) {
                if (ZeroSpeedRemovalPolicy.shouldRemove(present, speed)) {
                    removed.add(present to speed)
                }
            }
        }
        assertTrue(
            removed == listOf(true to 0L),
            "удаляться должен РОВНО один случай: present=true && speed=0, получено $removed",
        )
    }
}
