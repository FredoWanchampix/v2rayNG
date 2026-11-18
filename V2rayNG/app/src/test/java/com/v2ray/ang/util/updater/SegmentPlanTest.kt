package com.v2ray.ang.util.updater

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Доказывает разбиение файла на параллельные сегменты: потолок 24 потока
 * (требование владельца «максимум 24»), настройка 1..24, сплошное покрытие
 * файла без дыр и дублей (иначе склейка дала бы битый APK), минимум размера
 * сегмента (мелкие файлы не дробятся), остаток от деления распределён по
 * байту и сумма ТОЧНО равна размеру файла.
 */
class SegmentPlanTest {

    @Test
    fun `segment count is clamped to 1 up to 24`() {
        assertEquals(1, SegmentPlan.clampSegmentCount(0))
        assertEquals(1, SegmentPlan.clampSegmentCount(-5))
        assertEquals(24, SegmentPlan.clampSegmentCount(100))
        assertEquals(8, SegmentPlan.clampSegmentCount(8))
        assertEquals(24, SegmentPlan.MAX_SEGMENTS)
    }

    @Test
    fun `string setting parses safely`() {
        assertEquals(SegmentPlan.DEFAULT_SEGMENT_COUNT, SegmentPlan.parseSegmentCount(null))
        assertEquals(SegmentPlan.DEFAULT_SEGMENT_COUNT, SegmentPlan.parseSegmentCount("мусор"))
        assertEquals(3, SegmentPlan.parseSegmentCount("3"))
        assertEquals(24, SegmentPlan.parseSegmentCount("999"))
        assertEquals(1, SegmentPlan.parseSegmentCount("0"))
    }

    @Test
    fun `small files are not fragmented below MIN_SEGMENT_BYTES`() {
        // 3 МБ при настройке 24 -> floor(3МБ / 1МБ) = 3 сегмента, не 24.
        assertEquals(3, SegmentPlan.effectiveSegmentCount(3L * 1024 * 1024, 24))
        // 500 КБ -> 1 сегмент (меньше минимума дробить нельзя).
        assertEquals(1, SegmentPlan.effectiveSegmentCount(500L * 1024, 24))
        // неизвестный размер -> 1.
        assertEquals(1, SegmentPlan.effectiveSegmentCount(-1L, 8))
        assertEquals(1, SegmentPlan.effectiveSegmentCount(0L, 8))
    }

    @Test
    fun `large file reaches the 24-segment cap`() {
        val total = 200L * 1024 * 1024 // 200 МБ как arm64-APK форка
        val plan = SegmentPlan.plan(total, 24)
        assertEquals(24, plan.size)
        assertTrue(SegmentPlan.isContiguous(plan, total))
        assertEquals(total, plan.sumOf { it.size })
        assertEquals(0L, plan.first().start)
        assertEquals(total - 1, plan.last().endInclusive)
    }

    @Test
    fun `remainder is distributed without gaps or duplicates`() {
        // 10 байт на 3 сегмента -> 4+3+3 (остаток первым), сплошь.
        val plan = SegmentPlan.plan(10L, 3)
        // effectiveSegmentCount(10, 3) = min(3, max(1, 10/1МБ)=1) = 1 — файл
        // меньше MIN_SEGMENT_BYTES, поэтому один сегмент. Проверим на
        // «крупном» размере, где дробление реально: 10 МБ на 3.
        assertEquals(1, plan.size)
        assertTrue(SegmentPlan.isContiguous(plan, 10L))

        val plan3 = SegmentPlan.plan(10L * 1024 * 1024, 3)
        assertEquals(3, plan3.size)
        assertTrue(SegmentPlan.isContiguous(plan3, 10L * 1024 * 1024))
        assertEquals(10L * 1024 * 1024, plan3.sumOf { it.size })
        // сегменты идут вплотную: end[i] + 1 == start[i+1]
        for (i in 0 until plan3.size - 1) {
            assertEquals(plan3[i].endInclusive + 1, plan3[i + 1].start)
        }
    }

    @Test
    fun `plan is empty for unknown size so caller downloads single-stream`() {
        assertTrue(SegmentPlan.plan(-1L, 8).isEmpty())
        assertTrue(SegmentPlan.plan(0L, 8).isEmpty())
    }

    @Test
    fun `contiguity check rejects broken plans`() {
        // Дыра между сегментами.
        val broken = listOf(
            SegmentPlan.Segment(0, 0, 4),
            SegmentPlan.Segment(1, 6, 9),
        )
        assertTrue(!SegmentPlan.isContiguous(broken, 10L))
        // Дубль байтов.
        val overlap = listOf(
            SegmentPlan.Segment(0, 0, 5),
            SegmentPlan.Segment(1, 5, 9),
        )
        assertTrue(!SegmentPlan.isContiguous(overlap, 10L))
        // Не покрыт хвост.
        val short = listOf(SegmentPlan.Segment(0, 0, 4))
        assertTrue(!SegmentPlan.isContiguous(short, 10L))
        // Пустой план.
        assertTrue(!SegmentPlan.isContiguous(emptyList(), 10L))
    }
}
