package com.v2ray.ang.util.updater

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Доказывает разбор SHA256SUMS.txt — того самого манифеста, который публикуется
 * в каждом релизе форка. От корректности разбора зависит, будет ли пользователю
 * предложен НЕПРОВЕРЕННЫЙ APK, поэтому покрыты: реальный формат релиза (с `./`),
 * бинарный режим (`*`), регистр hex, комментарии/мусор, поиск по имени ассета.
 */
class Sha256SumsTest {

    // Реальный манифест релиза v2.4.2-beta (формат GNU sha256sum, путь с ./).
    private val realManifest = """
        3fc877a69e70e458f28fd2b32c014ff2b1f9b8bfe60f941320de09784cc6a65b  ./v2rayNG_2.4.2_arm64-v8a.apk
        ee7024799a994926b5e1a4d2a6145b199e4292e3aa0c6aab3f53397b9c1557a1  ./v2rayNG_2.4.2_armeabi-v7a.apk
        f6c3bb3b585605a7056d12feed7693ce2eb04681051f86ac595ed384d0291be5  ./v2rayNG_2.4.2_x86_64.apk
    """.trimIndent()

    @Test
    fun `parses real release manifest`() {
        val map = Sha256Sums.parse(realManifest)
        assertEquals(3, map.size)
        assertEquals(
            "3fc877a69e70e458f28fd2b32c014ff2b1f9b8bfe60f941320de09784cc6a65b",
            map["v2rayNG_2.4.2_arm64-v8a.apk"],
        )
    }

    @Test
    fun `expectedHash finds by base name and is case-insensitive on hex`() {
        // В манифесте путь ./имя, ищем по чистому имени ассета.
        assertEquals(
            "ee7024799a994926b5e1a4d2a6145b199e4292e3aa0c6aab3f53397b9c1557a1",
            Sha256Sums.expectedHash(realManifest, "v2rayNG_2.4.2_armeabi-v7a.apk"),
        )
        // UPPERCASE hex в манифесте нормализуется к нижнему регистру.
        val upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789  app.apk"
        assertEquals(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            Sha256Sums.expectedHash(upper, "app.apk"),
        )
    }

    @Test
    fun `binary-mode separator and missing file are handled`() {
        // Бинарный режим: разделитель "пробел + звёздочка".
        val binary = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa *app.apk"
        assertEquals(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Sha256Sums.expectedHash(binary, "app.apk"),
        )
        // Несуществующий ассет -> null (не падение и не чужой хэш).
        assertNull(Sha256Sums.expectedHash(realManifest, "v2rayNG_2.4.2_universal.apk"))
        assertNull(Sha256Sums.expectedHash(realManifest, ""))
    }

    @Test
    fun `garbage and short hashes are skipped`() {
        val manifest = """
            # comment line
            notahash  ./file.apk
            abcdef  ./tooshort.apk

            3fc877a69e70e458f28fd2b32c014ff2b1f9b8bfe60f941320de09784cc6a65b  ./good.apk
        """.trimIndent()
        val map = Sha256Sums.parse(manifest)
        // Только одна валидная строка с 64-hex; комментарии/мусор/короткие отброшены.
        assertEquals(1, map.size)
        assertTrue(map.containsKey("good.apk"))
    }

    @Test
    fun `baseName strips directories`() {
        assertEquals("app.apk", Sha256Sums.baseName("./dir/sub/app.apk"))
        assertEquals("app.apk", Sha256Sums.baseName("dir\\sub\\app.apk"))
        assertEquals("app.apk", Sha256Sums.baseName("app.apk"))
    }
}
