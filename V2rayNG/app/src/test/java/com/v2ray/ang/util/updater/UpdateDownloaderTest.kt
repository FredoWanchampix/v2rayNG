package com.v2ray.ang.util.updater

import kotlinx.coroutines.runBlocking
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import okhttp3.OkHttpClient
import okio.Buffer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Интеграционно-подобные тесты докачки на JVM через MockWebServer (okhttp 5.5.1).
 *
 * Сервер отдаёт фиктивный «APK» (детерминированные байты) с поддержкой Range,
 * как это делает реальный CDN релизов GitHub (замер 17.11.2026: 206 Partial
 * Content, Accept-Ranges: bytes, ETag, Last-Modified, Content-Range). Проверяются
 * ровно те сценарии, которые требует промт:
 *  - докачка с точного байта после прошлого обрыва: второй запрос идёт с
 *    `Range: bytes=<уже_скачано>-`, склейка = исходный файл ПОБАЙТОВО, SHA-256
 *    совпал (главный страх владельца: «докачка порвала пару байт»);
 *  - недокачанный сегмент (сервер прислал меньше байт, чем обещал Content-Range)
 *    распознаётся как Transient, а НЕ как Complete — иначе битый part ушёл бы в
 *    склейку;
 *  - смена ETag между запросами -> рестарт сегмента (не corrupt-докачка);
 *  - 416 Range Not Satisfiable -> Restart;
 *  - 503 -> Transient (ретраится сервисом);
 *  - редирект/URL вне allowlist -> Fatal (не качаем);
 *  - многопоточная склейка N сегментов со стриминговым SHA-256.
 *
 * allowlist в тестах отключается через injectable isAllowed (сервер на localhost
 * не github.com); в проде действует строгий [UpdateUrlPolicy]. Один из тестов,
 * наоборот, проверяет СТРОГИЙ allowlist.
 */
class UpdateDownloaderTest {

    private lateinit var server: MockWebServer
    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .followRedirects(false)
        .build()

    /** Любой хост разрешён ТОЛЬКО в тестах (MockWebServer на localhost). */
    private val allowAll: (String) -> Boolean = { true }

    // «APK»: 8 МБ детерминированных байт. Размер не кратен ни 64 КБ (буфер), ни
    // 1 МБ (MIN_SEGMENT_BYTES), чтобы ловить off-by-one на стыках сегментов.
    // 8 МБ > 6 * MIN_SEGMENT_BYTES, поэтому план на 6/4/3 сегмента реально
    // дробится (SegmentPlan не схлопнет его в 1).
    private val payload: ByteArray = ByteArray(8_000_003) { i -> (i * 31 + 7).toByte() }
    private val payloadSha256: String by lazy {
        val d = UpdateHashVerifier.newDigest()
        d.update(payload)
        UpdateHashVerifier.hex(d)
    }

    @TempDir
    lateinit var tempDirPath: File

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @AfterEach
    fun tearDown() {
        // В артефакте mockwebserver3 (линия okhttp 5.x) сервер закрывается через
        // Closeable.close(): метода shutdown() там НЕТ (он остался только в
        // legacy-пакете okhttp3.mockwebserver). Проверял по sources-jar 5.5.1.
        server.close()
    }

    private fun url(): String = server.url("/releases/download/x/app.apk").toString()

    /**
     * Диспетчер сервера с поддержкой Range (эмуляция CDN GitHub).
     *
     * @param etag значение ETag в ответах (для теста смены объекта).
     * @param failFirstN первые N запросов -> 503.
     * @param truncateAt если >=0 и запрошенный диапазон накрывает этот абсолютный
     *   байт, сервер присылает ТЕЛО КОРОЧЕ обещанного Content-Range (эмуляция
     *   недокачанного/оборванного сегмента без обмана по Content-Length).
     * @param rangesSupported false -> на любой запрос отдаёт 200 со всем телом.
     * @param lastRange сюда диспетчер пишет последний полученный заголовок Range.
     */
    private inner class RangeDispatcher(
        private val etag: String = "\"W/v1\"",
        private val failFirstN: Int = 0,
        private val truncateAt: Long = -1L,
        private val rangesSupported: Boolean = true,
        private val lastRange: AtomicReference<String?> = AtomicReference(null),
    ) : Dispatcher() {
        private var served = 0

        override fun dispatch(request: RecordedRequest): MockResponse {
            val rangeHeader = request.headers["Range"]
            lastRange.set(rangeHeader)
            if (served++ < failFirstN) {
                return MockResponse(code = 503)
            }
            if (!rangesSupported || rangeHeader == null) {
                return MockResponse.Builder()
                    .code(200)
                    .setHeader("ETag", etag)
                    .setHeader("Accept-Ranges", "none")
                    .body(Buffer().write(payload))
                    .build()
            }
            val spec = rangeHeader.removePrefix("bytes=").trim()
            val dash = spec.indexOf('-')
            val start = spec.substring(0, dash).toLong()
            val endSpec = spec.substring(dash + 1)
            val end = if (endSpec.isEmpty()) payload.size.toLong() - 1 else endSpec.toLong()

            if (start >= payload.size) {
                return MockResponse.Builder()
                    .code(416)
                    .setHeader("Content-Range", "bytes */${payload.size}")
                    .build()
            }
            val clampedEnd = minOf(end, payload.size.toLong() - 1)
            val declaredLen = (clampedEnd - start + 1).toInt()
            // Обрыв: присылаем меньше байт, чем обещает Content-Range. Реальный
            // Content-Length выставится по фактическому телу (MockResponse.body),
            // поэтому клиент дочитает «чисто», но сегмент останется неполным —
            // ровно тот случай, что обязан поймать пост-контроль длины в
            // UpdateDownloader.downloadSegment.
            val actualLen = if (truncateAt in start..clampedEnd) (truncateAt - start).toInt() else declaredLen
            return MockResponse.Builder()
                .code(206)
                .setHeader("Content-Range", "bytes $start-$clampedEnd/${payload.size}")
                .setHeader("ETag", etag)
                .setHeader("Accept-Ranges", "bytes")
                .body(Buffer().write(payload, start.toInt(), actualLen))
                .build()
        }
    }

    // ========================= PROBE =========================

    @Test
    fun `probe reads size and range support from 206`() = runBlocking {
        server.dispatcher = RangeDispatcher(etag = "\"etag-A\"")
        val probe = UpdateDownloader.probe(client, url(), allowAll)
        assertEquals(payload.size.toLong(), probe.totalBytes)
        assertTrue(probe.rangesSupported)
        assertTrue(probe.validator?.contains("etag-A") == true)
    }

    @Test
    fun `probe detects server without range support`() = runBlocking {
        server.dispatcher = RangeDispatcher(rangesSupported = false)
        val probe = UpdateDownloader.probe(client, url(), allowAll)
        assertEquals(payload.size.toLong(), probe.totalBytes)
        assertTrue(!probe.rangesSupported)
    }

    // ========================= ДОКАЧКА С ТОЧНОГО БАЙТА =========================

    @Test
    fun `resumes from exact byte and stitched file matches hash byte-for-byte`() = runBlocking {
        val lastRange = AtomicReference<String?>()
        server.dispatcher = RangeDispatcher(lastRange = lastRange)
        val part = File(tempDirPath, "app.apk.seg00.part")

        // Эмуляция итога прошлой оборванной сессии: в part уже лежит ровно
        // 1_000_003 первых байт (число «некруглое», чтобы поймать off-by-one).
        val alreadyHave = 1_000_003
        part.writeBytes(payload.copyOfRange(0, alreadyHave))

        val outcome = UpdateDownloader.downloadSegment(
            client = client,
            url = url(),
            partFile = part,
            segmentStart = 0L,
            segmentEndInclusive = payload.size.toLong() - 1,
            expectedValidator = "\"W/v1\"",
            onBytes = {},
            isAllowed = allowAll,
        )

        assertTrue(outcome is UpdateDownloader.SegmentOutcome.Complete, "ожидали Complete, получили $outcome")
        // Запрос докачки обязан начинаться РОВНО с уже скачанного байта.
        // Диапазон ЗАКРЫТЫЙ (segmentRangeHeader): bytes=<have>-<последний_байт>.
        assertEquals("bytes=$alreadyHave-${payload.size - 1}", lastRange.get())
        // Склеенный part побайтово равен исходному файлу, хэш совпал.
        assertEquals(payload.size.toLong(), part.length())
        assertTrue(part.readBytes().contentEquals(payload), "докачанный файл побайтово равен исходному")
        assertEquals(payloadSha256, UpdateHashVerifier.hashFile(part))
    }

    @Test
    fun `already-complete segment succeeds without a network request`() = runBlocking {
        server.dispatcher = RangeDispatcher()
        val part = File(tempDirPath, "done.part")
        // Сегмент [0..999] полностью на диске.
        part.writeBytes(payload.copyOfRange(0, 1000))
        val outcome = UpdateDownloader.downloadSegment(
            client, url(), part, 0L, 999L, "\"W/v1\"", {}, allowAll,
        )
        assertTrue(outcome is UpdateDownloader.SegmentOutcome.Complete)
        assertEquals(0L, (outcome as UpdateDownloader.SegmentOutcome.Complete).bytesWritten)
        assertEquals(0, server.requestCount, "полный сегмент не должен делать запрос")
    }

    @Test
    fun `truncated body is transient, never a false complete`() = runBlocking {
        // Сервер обещает Content-Range на весь файл, но присылает лишь 2 МБ.
        server.dispatcher = RangeDispatcher(truncateAt = 2_000_000L)
        val part = File(tempDirPath, "trunc.part")
        val outcome = UpdateDownloader.downloadSegment(
            client, url(), part, 0L, payload.size.toLong() - 1, "\"W/v1\"", {}, allowAll,
        )
        assertTrue(
            outcome is UpdateDownloader.SegmentOutcome.Transient,
            "недокачанный сегмент => Transient (ретрай), получили $outcome",
        )
        // Записанные 2 МБ СОХРАНЕНЫ: докачка продолжится с них, а не с нуля.
        assertEquals(2_000_000L, part.length())
    }

    // ========================= СМЕНА ETag -> РЕСТАРТ =========================

    @Test
    fun `changed etag triggers restart not corrupt resume`() = runBlocking {
        server.dispatcher = RangeDispatcher(etag = "\"etag-NEW\"")
        val part = File(tempDirPath, "etag.part")
        part.writeBytes(payload.copyOfRange(0, 100_000))

        // Сохранённый валидатор — СТАРЫЙ etag: объект на сервере сменился.
        val outcome = UpdateDownloader.downloadSegment(
            client, url(), part, 0L, payload.size.toLong() - 1, "\"etag-OLD\"", {}, allowAll,
        )
        assertTrue(outcome is UpdateDownloader.SegmentOutcome.Restart, "смена объекта => Restart, получили $outcome")
    }

    // ========================= 416 -> РЕСТАРТ =========================

    @Test
    fun `416 range not satisfiable triggers restart`() = runBlocking {
        server.dispatcher = RangeDispatcher()
        val part = File(tempDirPath, "416.part")
        part.writeBytes(payload.copyOfRange(0, 10))
        // Запрашиваем байты ЗА пределами объекта -> сервер отвечает 416.
        val outcome = UpdateDownloader.downloadSegment(
            client, url(), part,
            segmentStart = payload.size.toLong() + 1000,
            segmentEndInclusive = payload.size.toLong() + 2000,
            expectedValidator = null, onBytes = {}, isAllowed = allowAll,
        )
        assertTrue(outcome is UpdateDownloader.SegmentOutcome.Restart, "416 => Restart, получили $outcome")
    }

    // ========================= 503 -> TRANSIENT =========================

    @Test
    fun `503 is transient for retry`() = runBlocking {
        server.dispatcher = RangeDispatcher(failFirstN = 1)
        val part = File(tempDirPath, "503.part")
        val outcome = UpdateDownloader.downloadSegment(
            client, url(), part, 0L, payload.size.toLong() - 1, "\"W/v1\"", {}, allowAll,
        )
        assertTrue(outcome is UpdateDownloader.SegmentOutcome.Transient, "503 => Transient, получили $outcome")
    }

    // ========================= ALLOWLIST =========================

    @Test
    fun `url outside strict allowlist is refused as fatal`() = runBlocking {
        server.dispatcher = RangeDispatcher()
        val part = File(tempDirPath, "allowlist.part")
        // Строгий allowlist (как в проде): localhost не github.com => Fatal,
        // запрос даже не выполняется.
        val strict: (String) -> Boolean = { u -> UpdateUrlPolicy.isAllowed(u) }
        val outcome = UpdateDownloader.downloadSegment(
            client, url(), part, 0L, 10L, null, {}, strict,
        )
        assertTrue(outcome is UpdateDownloader.SegmentOutcome.Fatal, "вне allowlist => Fatal, получили $outcome")
    }

    @Test
    fun `redirect outside allowlist is refused`() = runBlocking {
        // Сервер отдаёт 302 на чужой хост; isAllowed пропускает localhost, но
        // редирект на malware.example строгий policy обязан завернуть.
        server.enqueue(
            MockResponse.Builder()
                .code(302)
                .setHeader("Location", "https://malware.example/evil.apk")
                .build()
        )
        // Разрешаем всё, КРОМЕ чужого хоста: стартовый localhost проходит, а
        // редирект на malware.example обязан быть отклонён как Fatal.
        val allowExceptMalware: (String) -> Boolean = { u -> !u.contains("malware.example") }
        val part = File(tempDirPath, "redir.part")
        val outcome = UpdateDownloader.downloadSegment(
            client, server.url("/x").toString(), part, 0L, 10L, null, {}, allowExceptMalware,
        )
        assertTrue(outcome is UpdateDownloader.SegmentOutcome.Fatal, "редирект вне allowlist => Fatal, получили $outcome")
    }

    // ========================= МНОГОПОТОЧНАЯ СКЛЕЙКА + SHA-256 =========================

    @Test
    fun `multi-segment merge reproduces file and streaming hash matches`() = runBlocking {
        server.dispatcher = RangeDispatcher()
        val plan = SegmentPlan.plan(payload.size.toLong(), 6)
        assertEquals(6, plan.size, "8 МБ при настройке 6 => 6 сегментов")
        assertTrue(SegmentPlan.isContiguous(plan, payload.size.toLong()))

        plan.forEach { seg ->
            val part = UpdatePaths.partFile(tempDirPath, "app.apk", seg.index)
            part.delete()
            val outcome = UpdateDownloader.downloadSegment(
                client, url(), part, seg.start, seg.endInclusive, "\"W/v1\"", {}, allowAll,
            )
            assertTrue(outcome is UpdateDownloader.SegmentOutcome.Complete, "сегмент ${seg.index}: $outcome")
        }

        val apk = File(tempDirPath, "app.apk")
        val result = UpdateDownloader.merge(
            segments = plan,
            partFileFor = { idx -> UpdatePaths.partFile(tempDirPath, "app.apk", idx) },
            mergedTarget = apk,
            expectedSha256 = payloadSha256,
            totalBytes = payload.size.toLong(),
        )
        assertTrue(result is UpdateDownloader.MergeResult.Verified, "ожидали Verified, получили $result")
        assertTrue(apk.readBytes().contentEquals(payload), "склейка 6 сегментов == исходный файл побайтово")
        // Временный файл склейки не должен остаться.
        assertTrue(!UpdatePaths.mergeTempFile(tempDirPath, "app.apk").exists())
    }

    @Test
    fun `merge detects single corrupted byte as hash mismatch`() = runBlocking {
        server.dispatcher = RangeDispatcher()
        val plan = SegmentPlan.plan(payload.size.toLong(), 4)
        plan.forEach { seg ->
            val part = UpdatePaths.partFile(tempDirPath, "c.apk", seg.index)
            part.delete()
            UpdateDownloader.downloadSegment(client, url(), part, seg.start, seg.endInclusive, "\"W/v1\"", {}, allowAll)
        }
        // Инвертируем ОДИН байт во втором сегменте — ровно страх владельца
        // «докачка порвала пару байт». Стриминговый SHA-256 обязан это поймать.
        val corrupt = UpdatePaths.partFile(tempDirPath, "c.apk", 1)
        val bytes = corrupt.readBytes()
        bytes[bytes.size / 2] = (bytes[bytes.size / 2].toInt() xor 0xFF).toByte()
        corrupt.writeBytes(bytes)

        val apk = File(tempDirPath, "c.apk")
        val result = UpdateDownloader.merge(
            segments = plan,
            partFileFor = { idx -> UpdatePaths.partFile(tempDirPath, "c.apk", idx) },
            mergedTarget = apk,
            expectedSha256 = payloadSha256,
            totalBytes = payload.size.toLong(),
        )
        assertTrue(result is UpdateDownloader.MergeResult.HashMismatch, "битый байт => HashMismatch, получили $result")
        assertTrue(!apk.exists(), "битый APK не должен публиковаться")
    }

    @Test
    fun `merge refuses incomplete segment instead of producing short file`() = runBlocking {
        val plan = SegmentPlan.plan(payload.size.toLong(), 3)
        // Все сегменты, кроме последнего, полные; последний — недокачан.
        plan.forEachIndexed { i, seg ->
            val part = UpdatePaths.partFile(tempDirPath, "inc.apk", seg.index)
            if (i < plan.size - 1) {
                part.writeBytes(payload.copyOfRange(seg.start.toInt(), (seg.endInclusive + 1).toInt()))
            } else {
                part.writeBytes(payload.copyOfRange(seg.start.toInt(), seg.start.toInt() + 10))
            }
        }
        val result = UpdateDownloader.merge(
            segments = plan,
            partFileFor = { idx -> UpdatePaths.partFile(tempDirPath, "inc.apk", idx) },
            mergedTarget = File(tempDirPath, "inc.apk"),
            expectedSha256 = payloadSha256,
            totalBytes = payload.size.toLong(),
        )
        assertTrue(result is UpdateDownloader.MergeResult.Error, "неполный сегмент => Error, получили $result")
    }

    // ========================= single-stream фолбэк =========================

    @Test
    fun `single-stream download writes whole file when no range`() = runBlocking {
        server.dispatcher = RangeDispatcher(rangesSupported = false)
        val target = File(tempDirPath, "single.apk")
        target.delete()
        val outcome = UpdateDownloader.downloadWhole(client, url(), target, {}, allowAll)
        assertTrue(outcome is UpdateDownloader.SegmentOutcome.Complete, "$outcome")
        assertEquals(payload.size.toLong(), target.length())
        assertTrue(target.readBytes().contentEquals(payload))
    }

    // ========================= SHA256SUMS: маленький текстовый запрос =========================

    @Test
    fun `fetchSmallText returns manifest body`() = runBlocking {
        server.enqueue(
            MockResponse.Builder()
                .code(200)
                .body("$payloadSha256  ./app.apk\n")
                .build()
        )
        val manifest = UpdateDownloader.fetchSmallText(client, server.url("/SHA256SUMS.txt").toString(), allowAll)
        assertTrue(manifest != null && manifest.contains(payloadSha256))
        assertEquals(payloadSha256, Sha256Sums.expectedHash(manifest!!, "app.apk"))
    }
}
