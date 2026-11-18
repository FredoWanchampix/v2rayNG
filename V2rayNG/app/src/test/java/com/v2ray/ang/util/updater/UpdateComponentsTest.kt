package com.v2ray.ang.util.updater

import com.v2ray.ang.dto.GitHubRelease
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

/**
 * Тесты чистых компонентов загрузчика: стриминговый SHA-256, выбор ассета под
 * ABI, прогресс/фазы состояния, имена файлов рабочей папки. Все они не требуют
 * Android (кроме UpdatePaths.dir, который здесь не проверяется), поэтому
 * доказуемы на JVM.
 */
class UpdateHashVerifierTest {

    @TempDir
    lateinit var dir: File

    private fun sha256(bytes: ByteArray): String {
        val d = UpdateHashVerifier.newDigest()
        d.update(bytes)
        return UpdateHashVerifier.hex(d)
    }

    @Test
    fun `hash of known string matches reference`() {
        // sha256("abc") — общеизвестный эталон.
        val expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        assertEquals(expected, sha256("abc".toByteArray()))
        assertEquals(expected, UpdateHashVerifier.toHex(java.security.MessageDigest.getInstance("SHA-256").digest("abc".toByteArray())))
    }

    @Test
    fun `streaming digest equals one-shot digest for large input`() {
        val data = ByteArray(1_500_000) { i -> (i % 251).toByte() }
        val digest = UpdateHashVerifier.newDigest()
        // Кормим по кускам, как при склейке сегментов.
        var off = 0
        while (off < data.size) {
            val len = minOf(64 * 1024, data.size - off)
            digest.update(data, off, len)
            off += len
        }
        assertEquals(sha256(data), UpdateHashVerifier.hex(digest))
    }

    @Test
    fun `hashFile reads from disk and one corrupted byte changes it`() {
        val data = ByteArray(5000) { it.toByte() }
        val file = File(dir, "f.bin")
        file.writeBytes(data)
        val good = UpdateHashVerifier.hashFile(file)
        assertEquals(sha256(data), good)

        val corrupt = data.copyOf().also { it[2500] = (it[2500].toInt() xor 0xFF).toByte() }
        file.writeBytes(corrupt)
        assertTrue(good != UpdateHashVerifier.hashFile(file), "один битый байт обязан менять хэш")
    }

    @Test
    fun `hashFile of missing file is null`() {
        assertNull(UpdateHashVerifier.hashFile(File(dir, "nope.bin")))
    }

    @Test
    fun `equalsHex is case and space tolerant but strict otherwise`() {
        val h = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        assertTrue(UpdateHashVerifier.equalsHex(h, h.uppercase()))
        assertTrue(UpdateHashVerifier.equalsHex("  $h  ", h))
        assertFalse(UpdateHashVerifier.equalsHex(h, h.dropLast(1) + "0"))
        assertFalse(UpdateHashVerifier.equalsHex(null, h))
        assertFalse(UpdateHashVerifier.equalsHex(h, ""))
    }

    @Test
    fun `verifyFile true only on exact match`() {
        val data = "payload".toByteArray()
        val file = File(dir, "v.bin").apply { writeBytes(data) }
        assertTrue(UpdateHashVerifier.verifyFile(file, sha256(data)))
        assertFalse(UpdateHashVerifier.verifyFile(file, "0".repeat(64)))
        assertFalse(UpdateHashVerifier.verifyFile(file, null))
    }

    @Test
    fun `verifyStreaming finishes accumulated digest`() {
        val data = "streamed".toByteArray()
        val digest = UpdateHashVerifier.newDigest()
        digest.update(data)
        assertTrue(UpdateHashVerifier.verifyStreaming(digest, sha256(data)))
    }
}

class AssetSelectorTest {

    /** Ассеты ровно в том виде, в каком их публикует CI форка (5 APK на релиз). */
    private fun asset(name: String, size: Long = 100L) =
        GitHubRelease.Asset(name = name, browserDownloadUrl = "https://github.com/x/$name", size = size)

    private val assets = listOf(
        asset("v2rayNG_2.4.2_arm64-v8a.apk"),
        asset("v2rayNG_2.4.2_armeabi-v7a.apk"),
        asset("v2rayNG_2.4.2_x86_64.apk"),
        asset("v2rayNG_2.4.2_x86.apk"),
        asset("v2rayNG_2.4.2_universal.apk"),
        asset("v2rayNG_2.4.2-fdroid_arm64-v8a.apk"),
    )

    @Test
    fun `picks first matching abi in device order`() {
        val chosen = AssetSelector.select(assets, listOf("arm64-v8a", "armeabi-v7a"), isFdroid = false)
        assertEquals("v2rayNG_2.4.2_arm64-v8a.apk", chosen?.name)
    }

    @Test
    fun `device abi order wins over asset order`() {
        // Устройство 32-битное первым: берём v7a, даже если arm64 лежит раньше.
        val chosen = AssetSelector.select(assets, listOf("armeabi-v7a", "arm64-v8a"), isFdroid = false)
        assertEquals("v2rayNG_2.4.2_armeabi-v7a.apk", chosen?.name)
    }

    @Test
    fun `falls back to next abi when first absent`() {
        val chosen = AssetSelector.select(assets, listOf("mips", "armeabi-v7a"), isFdroid = false)
        assertEquals("v2rayNG_2.4.2_armeabi-v7a.apk", chosen?.name)
    }

    @Test
    fun `fdroid build prefers fdroid asset`() {
        val chosen = AssetSelector.select(assets, listOf("arm64-v8a"), isFdroid = true)
        assertEquals("v2rayNG_2.4.2-fdroid_arm64-v8a.apk", chosen?.name)
    }

    @Test
    fun `non-fdroid build never picks fdroid asset`() {
        // Если под ABI есть ТОЛЬКО fdroid-ассет, playstore-сборка обязана
        // вернуть null, а не подсунуть fdroid-вариант.
        val onlyFdroid = listOf(asset("v2rayNG_2.4.2-fdroid_arm64-v8a.apk"))
        assertNull(AssetSelector.select(onlyFdroid, listOf("arm64-v8a"), isFdroid = false))
        // А когда есть оба — берётся обычный.
        val chosen = AssetSelector.select(assets, listOf("arm64-v8a"), isFdroid = false)
        assertTrue(chosen?.name?.contains("fdroid") == false)
    }

    @Test
    fun `x86 does not match x86_64 asset and vice versa`() {
        // Имя ассета содержит подстроку ABI, поэтому x86_64-ассет содержит "x86"
        // как подстроку. Порядок ABI устройства это учитывает: x86_64 первым.
        assertEquals(
            "v2rayNG_2.4.2_x86_64.apk",
            AssetSelector.select(assets, listOf("x86_64", "x86"), isFdroid = false)?.name,
        )
        // 32-битное устройство получает свой x86, а не x86_64.
        assertEquals(
            "v2rayNG_2.4.2_x86.apk",
            AssetSelector.select(assets, listOf("x86"), isFdroid = false)?.name,
        )
    }

    @Test
    fun `no matching abi returns null (no silent universal fallback)`() {
        assertNull(AssetSelector.select(assets, listOf("riscv64"), isFdroid = false))
        // Пустой список ABI тоже не должен ничего выбрать молча.
        assertNull(AssetSelector.select(assets, emptyList(), isFdroid = false))
        // Universal сам по себе не выбирается (его имя не содержит ABI устройства).
        val universalOnly = listOf(asset("v2rayNG_2.4.2_universal.apk"))
        assertNull(AssetSelector.select(universalOnly, listOf("arm64-v8a"), isFdroid = false))
    }

    @Test
    fun `declared size is carried through for the size cross-check`() {
        val chosen = AssetSelector.select(listOf(asset("a_arm64-v8a.apk", 94928909L)), listOf("arm64-v8a"), false)
        assertEquals(94928909L, chosen?.size)
    }

    @Test
    fun `apkFileName strips directories`() {
        assertEquals("app.apk", AssetSelector.apkFileName("./dir/app.apk"))
    }
}

class DownloadStateTest {

    private fun state(done: Long, total: Long, phase: DownloadState.Phase = DownloadState.Phase.DOWNLOADING) =
        DownloadState(
            releaseTag = "v1",
            assetName = "a.apk",
            totalBytes = total,
            segmentDone = mapOf(0 to done),
            phase = phase,
        )

    @Test
    fun `progress percent and fraction are clamped`() {
        assertEquals(50, state(50L, 100L).progressPercent())
        assertEquals(0.5, state(50L, 100L).progressFraction(), 1e-9)
        // Переполнение (>100%) не должно давать процент >100.
        assertEquals(100, state(150L, 100L).progressPercent())
        assertEquals(1.0, state(150L, 100L).progressFraction(), 1e-9)
    }

    @Test
    fun `unknown total gives zero progress not 100`() {
        assertEquals(0, state(50L, -1L).progressPercent())
        assertEquals(0.0, state(50L, -1L).progressFraction(), 1e-9)
    }

    @Test
    fun `downloadedBytes sums all segments`() {
        val s = DownloadState(segmentDone = mapOf(0 to 10L, 1 to 20L, 2 to 5L))
        assertEquals(35L, s.downloadedBytes())
    }

    @Test
    fun `isActive covers in-flight phases only`() {
        val active = listOf(
            DownloadState.Phase.PROBING, DownloadState.Phase.DOWNLOADING,
            DownloadState.Phase.PAUSED, DownloadState.Phase.WAITING_NETWORK,
            DownloadState.Phase.MERGING, DownloadState.Phase.VERIFYING,
        )
        val inactive = listOf(
            DownloadState.Phase.IDLE, DownloadState.Phase.READY_TO_INSTALL,
            DownloadState.Phase.FAILED, DownloadState.Phase.CANCELLED,
            // Профиль отключился — загрузка остановлена, монитор снят.
            DownloadState.Phase.PROFILE_LOST,
        )
        active.forEach { assertTrue(state(1L, 2L, it).isActive(), "$it должна быть активной") }
        inactive.forEach { assertFalse(state(1L, 2L, it).isActive(), "$it НЕ должна быть активной") }
    }

    @Test
    fun `sameTarget compares tag and asset`() {
        val a = state(0L, 0L)
        assertTrue(a.sameTarget(DownloadState(releaseTag = "v1", assetName = "a.apk")))
        assertFalse(a.sameTarget(DownloadState(releaseTag = "v2", assetName = "a.apk")))
        assertFalse(a.sameTarget(DownloadState(releaseTag = "v1", assetName = "b.apk")))
    }

    @Test
    fun `touch updates timestamp without changing data`() {
        val a = state(10L, 100L).copy(updatedAt = 0L)
        val b = a.touch(1234L)
        assertEquals(1234L, b.updatedAt)
        assertEquals(a.downloadedBytes(), b.downloadedBytes())
    }
}

class UpdatePathsTest {

    @TempDir
    lateinit var dir0: File

    @Test
    fun `part file name encodes segment index with two digits`() {
        assertEquals("app.apk.seg00.part", UpdatePaths.partFileName("app.apk", 0))
        assertEquals("app.apk.seg07.part", UpdatePaths.partFileName("app.apk", 7))
        assertEquals("app.apk.seg23.part", UpdatePaths.partFileName("app.apk", 23))
    }

    @Test
    fun `merge temp name is distinct from final apk`() {
        assertEquals("app.apk.merging.tmp", UpdatePaths.mergeTempFileName("app.apk"))
        assertTrue(UpdatePaths.mergeTempFileName("app.apk") != "app.apk")
    }

    @Test
    fun `isUsable verifies real write access and cleans its probe`() {
        val dir = File(dir0, "usable")
        assertTrue(UpdatePaths.isUsable(dir), "свежий каталог должен создаваться и быть записываемым")
        assertTrue(dir.isDirectory)
        // Пробный файл обязан быть удалён — иначе мусор в рабочей папке.
        assertFalse(File(dir, ".write_probe").exists())
        // Существующий каталог тоже проходит.
        assertTrue(UpdatePaths.isUsable(dir))
    }

    @Test
    fun `isUsable false for a path that is a file not a dir`() {
        val f = File(dir0, "not_a_dir").apply { writeText("x") }
        assertFalse(UpdatePaths.isUsable(f), "обычный файл не является записываемым каталогом")
    }

    @Test
    fun `file helpers place everything under the work dir`() {
        val dir = File("/storage/emulated/0/Download/v2rayNG")
        assertEquals(File(dir, "app.apk.seg03.part"), UpdatePaths.partFile(dir, "app.apk", 3))
        assertEquals(File(dir, "app.apk"), UpdatePaths.apkFile(dir, "app.apk"))
        assertEquals(File(dir, "app.apk.merging.tmp"), UpdatePaths.mergeTempFile(dir, "app.apk"))
        assertEquals(File(dir, UpdatePaths.LOG_FILE_NAME), UpdatePaths.logFile(dir))
    }
}
