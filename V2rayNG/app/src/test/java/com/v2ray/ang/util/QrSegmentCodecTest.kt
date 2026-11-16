package com.v2ray.ang.util

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Сегментированный QR-экспорт: ЛЮБАЯ длина ссылки передаётся без сжатия и
 * сокращений — последовательностью QR, каждый несёт целый читаемый кусок.
 * Предел одного QR (ISO/IEC 18004, версия 40, byte mode) = 2953 байта,
 * поэтому длинные ссылки режутся на сегменты с номерами и CRC32.
 */
class QrSegmentCodecTest {

    // Реальная ссылка владельца: wireguard с шумом (hex 2504 символа + 8 rand),
    // 3463 байта без дубликата noises — больше предела одного QR.
    private val longLink = "wireguard://SECRET%3D@162.159.195.1:500" +
        "?address=172.16.0.2%2F32&fm=" +
        java.net.URLEncoder.encode(
            """{"udp":[{"type":"noise","settings":{"noise":[{"type":"hex","packet":"${"ab".repeat(1252)}","delay":"1-2"}""" +
                """,{"rand":"23-911","delay":"1-3"},{"rand":"23-911","delay":"1-3"},{"rand":"23-911","delay":"1-3"},{"rand":"23-911","delay":"1-3"},{"rand":"23-911","delay":"1-3"},{"rand":"23-911","delay":"1-3"},{"rand":"23-911","delay":"1-3"},{"rand":"23-911","delay":"1-3"}]}}]}""",
            "UTF-8"
        ) +
        "&publickey=PUB%3D&mtu=1280#WARP"

    @Test
    fun `short link stays a single plain QR`() {
        val parts = QrSegmentCodec.split("wireguard://S=@1.2.3.4:500?mtu=1280#w")
        assertEquals(1, parts.size)
        assertFalse(QrSegmentCodec.isSegment(parts[0]), "короткая ссылка — обычный QR без префикса")
        assertEquals("wireguard://S=@1.2.3.4:500?mtu=1280#w", parts[0])
    }

    @Test
    fun `long link splits into segments each within QR capacity`() {
        assertTrue(longLink.toByteArray(Charsets.UTF_8).size > 2953, "тестовая ссылка обязана быть длиннее предела QR")
        val parts = QrSegmentCodec.split(longLink)
        assertTrue(parts.size > 1, "длинная ссылка обязана резаться: ${parts.size}")
        for (p in parts) {
            assertTrue(QrSegmentCodec.isSegment(p), p.take(40))
            assertTrue(p.toByteArray(Charsets.UTF_8).size <= 2953,
                "сегмент обязан влезать в QR: ${p.toByteArray().size}")
        }
    }

    @Test
    fun `assembler restores full link in order`() {
        val parts = QrSegmentCodec.split(longLink)
        val asm = QrSegmentCodec.Assembler()
        var out: String? = null
        for (p in parts) {
            out = asm.offer(p)
        }
        assertEquals(longLink, out, "сборка по порядку обязана дать исходную ссылку байт в байт")
    }

    @Test
    fun `assembler restores full link out of order and with duplicates`() {
        val parts = QrSegmentCodec.split(longLink)
        val asm = QrSegmentCodec.Assembler()
        var out: String? = null
        // обратный порядок + дубликаты каждого сегмента
        for (p in parts.reversed()) {
            out = asm.offer(p) ?: asm.offer(p)
        }
        assertEquals(longLink, out, "любой порядок и дубликаты не должны ломать сборку")
    }

    @Test
    fun `foreign series resets the accumulator`() {
        val partsA = QrSegmentCodec.split(longLink)
        val other = QrSegmentCodec.split(longLink + "-other")
        val asm = QrSegmentCodec.Assembler()
        asm.offer(partsA[0])
        // чужая серия: накопленное сбрасывается
        var out: String? = null
        for (p in other) out = asm.offer(p)
        assertEquals(longLink + "-other", out)
    }

    @Test
    fun `corrupted segment fails CRC and yields nothing`() {
        val parts = QrSegmentCodec.split(longLink).toMutableList()
        // подмена одного символа полезной нагрузки в последнем сегменте
        val last = parts.removeAt(parts.size - 1)
        val broken = last.dropLast(1) + (if (last.endsWith("X")) "Y" else "X")
        parts.add(broken)
        val asm = QrSegmentCodec.Assembler()
        var out: String? = null
        for (p in parts) out = asm.offer(p)
        assertNull(out, "битый сегмент обязан быть отвергнут по CRC")
    }

    @Test
    fun `emoji payload survives segmentation without broken surrogates`() {
        // remarks с флагами (суррогатные пары): граница chunk не должна
        // разрезать пару, иначе round-trip даст символ замены.
        val payload = "wireguard://S=@1.2.3.4:500?fm=" + "x".repeat(3000) + "#" + "🇪🇺🇫🇷".repeat(150)
        val parts = QrSegmentCodec.split(payload)
        assertTrue(parts.size > 1)
        val asm = QrSegmentCodec.Assembler()
        var out: String? = null
        for (p in parts) out = asm.offer(p)
        assertEquals(payload, out, "эмодзи обязаны пережить сегментацию байт в байт")
        assertFalse(out!!.contains("\uFFFD"), "символ замены недопустим")
    }

    @Test
    fun `progress reports collected and total`() {
        val parts = QrSegmentCodec.split(longLink)
        val asm = QrSegmentCodec.Assembler()
        asm.offer(parts[0])
        val (got, total) = asm.progress()
        assertEquals(1, got)
        assertEquals(parts.size, total)
    }

    @Test
    fun `parse rejects malformed segments`() {
        assertNull(QrSegmentCodec.parse("wireguard://plain"))
        assertNull(QrSegmentCodec.parse("V2NGQR1|zzzzzzzz|1|2|00000000|x"))
        assertNull(QrSegmentCodec.parse("V2NGQR1|00000000|0|2|00000000|x"))
        assertNull(QrSegmentCodec.parse("V2NGQR1|00000000|3|2|00000000|x"))
        assertNull(QrSegmentCodec.parse("V2NGQR1|00000000|1|2|xyz|x"))
        assertNotNull(QrSegmentCodec.parse("V2NGQR1|00000000|1|2|00000000|x"))
    }
}