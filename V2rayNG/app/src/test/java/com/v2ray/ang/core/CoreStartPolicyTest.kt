package com.v2ray.ang.core

import com.v2ray.ang.core.CoreStartPolicy.StartOutcome
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Тесты чистых правил запуска ядра ([CoreStartPolicy]).
 *
 * Запуск ядра стал асинхронным (DNS-резолв/сайдкар/нативный старт убраны с
 * главного потока — NetworkOnMainThreadException, вещдок 20.11.2026), поэтому
 * появились гонки, которые раньше были невозможны при синхронном старте.
 * Каждая проверка ниже — одна конкретная гонка.
 */
class CoreStartPolicyTest {

    @Test
    fun `start allowed only when core is down and no start in flight`() {
        assertTrue(CoreStartPolicy.canStart(coreRunning = false, startInFlight = false))
    }

    @Test
    fun `second onStartCommand during in-flight start is rejected`() {
        // Между входом в IO-диспетчер и реальным подъёмом ядра isRunning() ещё
        // false, поэтому без флага «старт идёт» повторный запрос запустил бы
        // второе ядро на тех же портах.
        assertFalse(CoreStartPolicy.canStart(coreRunning = false, startInFlight = true))
    }

    @Test
    fun `start rejected when core already running`() {
        assertFalse(CoreStartPolicy.canStart(coreRunning = true, startInFlight = false))
        assertFalse(CoreStartPolicy.canStart(coreRunning = true, startInFlight = true))
    }

    @Test
    fun `successful start of current generation keeps service running`() {
        assertEquals(
            StartOutcome.RUNNING,
            CoreStartPolicy.decide(started = true, generation = 5, currentGeneration = 5),
        )
    }

    @Test
    fun `failed start must stop the service`() {
        // Иначе foreground-уведомление осталось бы висеть при неподнятом
        // профиле — пользователь видит «подключено», а трафик не идёт.
        assertEquals(
            StartOutcome.STOP_SERVICE,
            CoreStartPolicy.decide(started = false, generation = 5, currentGeneration = 5),
        )
    }

    @Test
    fun `stop during start makes result stale even when core did start`() {
        // Гонка «stop во время старта»: startCoreLoop успел поднять ядро, но
        // stopCoreLoop отработал раньше, когда isRunning() был ещё false, и
        // потому НЕ вызвал stopLoop. Результат обязан быть проигнорирован,
        // а ядро — остановлено (компенсация в CoreServiceManager).
        assertEquals(
            StartOutcome.STALE,
            CoreStartPolicy.decide(started = true, generation = 5, currentGeneration = 6),
        )
    }

    @Test
    fun `stale result wins over failure too`() {
        // Сервис уже уничтожен: вызывать stopService повторно нельзя (состояние
        // принадлежит новому запуску).
        assertEquals(
            StartOutcome.STALE,
            CoreStartPolicy.decide(started = false, generation = 5, currentGeneration = 9),
        )
    }

    @Test
    fun `older generation is never treated as current`() {
        for (current in 6..12) {
            assertEquals(
                StartOutcome.STALE,
                CoreStartPolicy.decide(started = true, generation = 5, currentGeneration = current),
                "поколение 5 при текущем $current обязано быть устаревшим",
            )
        }
    }
}
