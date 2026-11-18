package com.v2ray.ang.util.updater

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Доказывает вычисление скорости/ETA по скользящему окну. Владелец требует
 * показывать скорость «Б/КБ/МБ/ГБ в секунду», обновляемую раз в секунду, и она
 * обязана быть честной: на плохой сети мгновенный отсчёт скачет, поэтому
 * скорость = (байты за окно)/(время окна), а не «последний дельта/интервал».
 *
 * Класс чистый (время подаётся параметром), поэтому тестируется детерминированно.
 */
class SpeedTrackerTest {

    @Test
    fun `steady rate yields that rate in bytes per second`() {
        val tracker = SpeedTracker(windowMillis = 5_000L)
        var t = 0L
        var bytes = 0L
        // 1 МБ/с в течение 5 секунд, отсчёт каждые 500 мс.
        repeat(11) {
            tracker.record(bytes, t)
            t += 500L
            bytes += 512L * 1024L // 512 КБ за 500 мс = 1 МБ/с
        }
        val speed = tracker.bytesPerSecond(t)
        // ~1 МБ/с (±округление окна).
        assertTrue(speed in 900_000L..1_200_000L, "ожидали ~1 МБ/с, получили $speed Б/с")
    }

    @Test
    fun `zero progress gives zero speed and no eta`() {
        val tracker = SpeedTracker(windowMillis = 5_000L)
        tracker.record(1000L, 0L)
        tracker.record(1000L, 1000L)
        tracker.record(1000L, 2000L)
        assertEquals(0L, tracker.bytesPerSecond(2000L))
        assertNull(tracker.etaMillis(2000L, 10_000L), "при нулевой скорости ETA не показываем")
    }

    @Test
    fun `eta is remaining bytes over current speed`() {
        val tracker = SpeedTracker(windowMillis = 5_000L)
        // 2 МБ за 2 секунды => 1 МБ/с; осталось 8 МБ => ETA ~8 секунд.
        tracker.record(0L, 0L)
        tracker.record(1L * 1024 * 1024, 1000L)
        tracker.record(2L * 1024 * 1024, 2000L)
        val eta = tracker.etaMillis(2000L, 10L * 1024 * 1024)
        assertTrue(eta != null && eta in 6_000L..12_000L, "ожидали ETA ~8с, получили $eta мс")
    }

    @Test
    fun `eta zero when file already fully downloaded`() {
        val tracker = SpeedTracker(windowMillis = 5_000L)
        tracker.record(0L, 0L)
        tracker.record(100L, 1000L)
        assertEquals(0L, tracker.etaMillis(1000L, 100L))
    }

    @Test
    fun `unknown total size gives no eta`() {
        val tracker = SpeedTracker(windowMillis = 5_000L)
        tracker.record(0L, 0L)
        tracker.record(1024L, 1000L)
        assertNull(tracker.etaMillis(1000L, -1L))
        assertNull(tracker.etaMillis(1000L, 0L))
    }

    @Test
    fun `old samples evicted outside window so stale burst does not inflate speed`() {
        val tracker = SpeedTracker(windowMillis = 2_000L)
        // Быстрый всплеск в самом начале, затем долгое плато.
        tracker.record(0L, 0L)
        tracker.record(10L * 1024 * 1024, 500L) // всплеск
        tracker.record(10L * 1024 * 1024, 3000L) // плато
        tracker.record(10L * 1024 * 1024, 5000L) // плато, всплеск вне окна (2 с)
        // Скорость должна быть ~0: всплеск в t=500 уже вне окна относительно t=5000.
        assertEquals(0L, tracker.bytesPerSecond(5000L))
    }

    @Test
    fun `reset clears window`() {
        val tracker = SpeedTracker(windowMillis = 5_000L)
        tracker.record(0L, 0L)
        tracker.record(5L * 1024 * 1024, 1000L)
        assertTrue(tracker.bytesPerSecond(1000L) > 0L)
        tracker.reset()
        assertEquals(0L, tracker.bytesPerSecond(1000L))
    }

    @Test
    fun `single sample gives zero speed`() {
        val tracker = SpeedTracker(windowMillis = 5_000L)
        tracker.record(1000L, 0L)
        assertEquals(0L, tracker.bytesPerSecond(0L), "по одной точке скорость не определить")
    }
}
