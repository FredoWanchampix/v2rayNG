package com.v2ray.ang.util.updater

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.net.URI
import java.net.URL

/**
 * Сетевой движок встроенного загрузчика обновлений: многопоточная сегментная
 * докачка + склейка + стриминговая проверка SHA-256.
 *
 * НАМЕРЕННО не зависит от android.* (только okhttp3 и java.io/java.security),
 * поэтому критичные сценарии — обрыв на N-м байте и докачка, смена ETag,
 * 416 Range Not Satisfiable, 503 с ретраем, редирект за пределы allowlist —
 * доказываются JVM-тестом на MockWebServer (см. UpdateDownloaderTest). Всё,
 * что требует Android (маршрут через профиль, внешнее хранилище, уведомления),
 * делает UpdateDownloadService, который передаёт сюда готовый [OkHttpClient].
 *
 * Требования владельца, закрытые здесь:
 *  - «скачивание в несколько потоков, максимум 24, настраивается» → [SegmentPlan];
 *  - «сегменты сами себя мержат» → [merge];
 *  - «проверяет хэш прямо до каждого байта» → стриминговый SHA-256 в [merge];
 *  - «докачка минимум час / не останавливается» → каждый сегментный запрос идёт
 *    по ПОСТОЯННОЙ ссылке GitHub (подписанный SAS-URL живёт ~1 час и не
 *    сохраняется), докачка с последнего байта part-файла, переходящие ошибки
 *    возвращаются как [SegmentOutcome.Transient] для бесконечного внешнего
 *    ретрая сервисом;
 *  - «стабильно даже на 2G/3G» → побайтовая дописывающая запись part-файла:
 *    обрыв в любой момент сохраняет прогресс;
 *  - безопасность (пункт 10) → [executeWithRedirects]: https-only, allowlist
 *    доменов GitHub, редирект за пределы allowlist запрещён.
 *
 * Trust-all TLS применяется к клиенту ВНЕ этого класса (сервис строит клиент
 * через [com.v2ray.ang.util.HttpUtil.applyTrustAll]) — политика форка.
 */
object UpdateDownloader {

    /** Размер буфера чтения тела ответа. 64 КБ — баланс для медленных сетей. */
    private const val BUFFER_SIZE = 64 * 1024

    /** Максимум редиректов в одной цепочке (GitHub делает ровно один). */
    private const val MAX_REDIRECTS = 5

    /** User-Agent запросов к GitHub (совпадает с общим паттерном приложения). */
    const val USER_AGENT = "v2rayNG-update-downloader"

    /**
     * Результат пробного запроса: что за объект и поддерживает ли он докачку.
     *
     * @param totalBytes полный размер объекта; -1 если сервер его не сообщил.
     * @param rangesSupported true, если сервер ответил 206 на Range-запрос.
     * @param validator метка объекта (ETag|Last-Modified) для контроля смены.
     */
    data class Probe(
        val totalBytes: Long,
        val rangesSupported: Boolean,
        val validator: String?,
        /**
         * Content-Type из ответа на пробный запрос (может быть null, если сервер
         * его не отдал). Используется для проверки, что сервер отдаёт APK, а не
         * HTML-заглушку captive-portal (пункт 10 требований).
         */
        val contentType: String? = null,
    )

    /** Исход закачки ОДНОГО сегмента. */
    sealed interface SegmentOutcome {
        /**
         * Сегмент докачан полностью.
         * @param bytesWritten сколько байт ДОПИСАНО в этом проходе (не всего сегмента).
         * @param validator метка объекта из ответа.
         */
        data class Complete(val bytesWritten: Long, val validator: String?) : SegmentOutcome

        /**
         * Part-файл сегмента больше не годится для продолжения.
         *
         * @param newValidator если НЕ null — сервер сменил объект (ETag/Last-Modified
         *   отличается от сохранённого). Это значит, что ВСЕ part-файлы релиза
         *   устарели: вызывающий код обязан сделать ПОЛНЫЙ рестарт загрузки
         *   (перечитать размер, валидатор и эталонный хэш), а не перезапускать
         *   один сегмент. Иначе сегменты вошли бы в бесконечный цикл рестартов.
         *   Если null — проблема локальная (416, сервер проигнорировал Range,
         *   part длиннее сегмента): достаточно перезапустить один сегмент.
         */
        data class Restart(val reason: String, val newValidator: String? = null) : SegmentOutcome

        /**
         * Переходящая ошибка (IOException, 5xx, 429, 408). Сервис обязан
         * подождать сеть и повторить — «скачивание не должно останавливаться».
         * Уже записанные байты part-файла СОХРАНЯЮТСЯ.
         */
        data class Transient(val reason: String) : SegmentOutcome

        /** Неустранимая ошибка (4xx кроме 408/429, редирект вне allowlist). */
        data class Fatal(val reason: String) : SegmentOutcome
    }

    /**
     * Исход выполнения запроса с самостоятельным ведением редиректов.
     * Редирект за пределы allowlist — это нарушение политики безопасности
     * (пункт 10), а НЕ сетевой сбой: он должен становиться Fatal, а не
     * ретраиться как IOException. Поэтому он выделен в отдельный случай.
     */
    sealed interface Redirected {
        /** Ответ получен (вызывающий ОБЯЗАН закрыть его use{}). */
        data class Ok(val response: Response) : Redirected

        /** Редирект/стартовый URL вне allowlist — фатально. */
        data class Disallowed(val reason: String) : Redirected
    }

    /**
     * Выполняет запрос, САМОСТОЯТЕЛЬНО ведя редиректы через allowlist.
     *
     * У клиента обязан быть followRedirects=false: иначе okhttp ушёл бы по
     * Location без проверки. Здесь каждый переход проверяется
     * [UpdateUrlPolicy.isRedirectAllowed] (https + домены GitHub). Начальный
     * URL тоже проверяется: подмена browser_download_url не должна приводить к
     * скачиванию APK с чужого хоста.
     *
     * GitHub отдаёт 302 на подписанный SAS-URL CDN (release-assets.
     * githubusercontent.com, живёт ~1 час) — поэтому каждый запрос сегмента
     * идёт по ПОСТОЯННОЙ ссылке и каждый раз получает свежий редирект:
     * докачка переживает час и больше.
     */
    fun executeWithRedirects(
        client: OkHttpClient,
        request: Request,
        isAllowed: (String) -> Boolean = { url -> UpdateUrlPolicy.isAllowed(url) },
        onCall: (okhttp3.Call) -> Unit = {},
    ): Redirected {
        if (!isAllowed(request.url.toString())) {
            return Redirected.Disallowed("URL outside the allowlist: ${request.url.host}")
        }
        var current: Request = request
        var redirects = 0
        while (true) {
            val call = client.newCall(current)
            // Сервис регистрирует активный Call, чтобы отменить его при
            // паузе/отмене: блокирующий InputStream.read не прерывается одной
            // отменой корутины, а call.cancel() рвёт сокет немедленно.
            onCall(call)
            val response = call.execute()
            if (!response.isRedirect) return Redirected.Ok(response)
            val location = response.header("Location")
            response.close()
            if (location.isNullOrBlank()) {
                throw IOException("redirect without Location header")
            }
            val resolved = resolveUrl(current.url.toString(), location)
            if (resolved == null || !isAllowed(resolved)) {
                return Redirected.Disallowed("redirect outside the allowlist: $location")
            }
            if (++redirects > MAX_REDIRECTS) {
                throw IOException("too many redirects (>$MAX_REDIRECTS)")
            }
            // Тот же метод и заголовки (включая Range!) на новый URL.
            current = current.newBuilder().url(resolved).build()
        }
    }

    /** Резолвит Location (абсолютный или относительный) против базового URL. */
    fun resolveUrl(baseUrl: String, location: String): String? = try {
        val resolved = URI(baseUrl).resolve(URI(location))
        resolved.toURL().toString()
    } catch (_: Exception) {
        try {
            URL(URL(baseUrl), location).toString()
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Скачивает маленький текстовый объект (SHA256SUMS.txt) целиком в строку.
     *
     * Отдельный метод, а не [downloadWhole], потому что манифест хэшей нужен как
     * ТЕКСТ для разбора [Sha256Sums], а не как файл на диске. Редиректы ведёт и
     * проверяет [executeWithRedirects] (тот же allowlist, что для APK).
     *
     * @return содержимое, либо null при сетевой ошибке/запрещённом редиректе/не-2xx.
     */
    suspend fun fetchSmallText(
        client: OkHttpClient,
        url: String,
        isAllowed: (String) -> Boolean = { u -> UpdateUrlPolicy.isAllowed(u) },
        onCall: (okhttp3.Call) -> Unit = {},
    ): String? = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(url)
            .header("User-Agent", USER_AGENT)
            .build()
        try {
            when (val redirected = executeWithRedirects(client, request, isAllowed, onCall)) {
                is Redirected.Disallowed -> null
                is Redirected.Ok -> redirected.response.use { response ->
                    if (response.isSuccessful) response.body.string() else null
                }
            }
        } catch (e: IOException) {
            null
        }
    }

    /**
     * Пробный запрос: выясняет размер объекта и поддержку Range одним GET
     * `Range: bytes=0-0`. GET предпочтительнее HEAD: некоторые CDN отдают
     * Content-Length только на GET, а 206 на Range однозначно доказывает
     * поддержку докачки. Тело (1 байт) читается и отбрасывается.
     */
    suspend fun probe(
        client: OkHttpClient,
        url: String,
        isAllowed: (String) -> Boolean = { u -> UpdateUrlPolicy.isAllowed(u) },
        onCall: (okhttp3.Call) -> Unit = {},
    ): Probe = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(url)
            .header("Range", "bytes=0-0")
            .header("User-Agent", USER_AGENT)
            .build()
        try {
            when (val redirected = executeWithRedirects(client, request, isAllowed, onCall)) {
                is Redirected.Disallowed ->
                    Probe(totalBytes = -1L, rangesSupported = false, validator = null)

                is Redirected.Ok -> redirected.response.use { response ->
                    val validator = ResumePolicy.validatorOf(
                        response.header("ETag"),
                        response.header("Last-Modified"),
                    )
                    val contentType = response.header("Content-Type")
                    when (response.code) {
                        206 -> {
                            val range = ResumePolicy.parseContentRange(response.header("Content-Range"))
                            val total = range?.second ?: response.body.contentLength()
                            Probe(totalBytes = total, rangesSupported = true, validator = validator, contentType = contentType)
                        }

                        200 -> Probe(
                            totalBytes = response.body.contentLength(),
                            rangesSupported = false,
                            validator = validator,
                            contentType = contentType,
                        )

                        else -> Probe(totalBytes = -1L, rangesSupported = false, validator = validator, contentType = contentType)
                    }
                }
            }
        } catch (e: IOException) {
            // Проба не удалась по сети: «неизвестно», сервис повторит.
            Probe(totalBytes = -1L, rangesSupported = false, validator = null)
        }
    }

    /**
     * Качает ОДИН сегмент `[segmentStart..segmentEndInclusive]` в [partFile]
     * с докачкой: продолжает с байта, следующего за уже записанным.
     *
     * Уже скачанная часть НЕ перечитывается и НЕ перезаписывается — запрос
     * начинается ровно с `segmentStart + partFile.length()`, байты дописываются
     * в конец по мере прихода, поэтому обрыв в любой момент сохраняет прогресс.
     *
     * @param expectedValidator валидатор объекта из [probe]; другой в ответе —
     *   [SegmentOutcome.Restart] (объект сменился, продолжать нельзя).
     * @param onBytes вызывается на каждую записанную порцию (скорость/прогресс).
     */
    suspend fun downloadSegment(
        client: OkHttpClient,
        url: String,
        partFile: File,
        segmentStart: Long,
        segmentEndInclusive: Long,
        expectedValidator: String?,
        onBytes: (Long) -> Unit,
        isAllowed: (String) -> Boolean = { u -> UpdateUrlPolicy.isAllowed(u) },
        onCall: (okhttp3.Call) -> Unit = {},
    ): SegmentOutcome = withContext(Dispatchers.IO) {
        val segmentSize = segmentEndInclusive - segmentStart + 1
        val existing = if (partFile.exists()) partFile.length() else 0L

        // Сегмент уже скачан целиком: успех без запроса (лишний запрос на
        // плохой сети дорог, а повторный вход в цикл докачки безопасен).
        if (existing >= segmentSize) {
            return@withContext SegmentOutcome.Complete(bytesWritten = 0L, validator = expectedValidator)
        }

        val resumeFrom = segmentStart + existing
        val range = ResumePolicy.segmentRangeHeader(resumeFrom, segmentEndInclusive)
            ?: return@withContext SegmentOutcome.Complete(0L, expectedValidator)

        val request = Request.Builder()
            .url(url)
            .header("Range", range)
            .header("User-Agent", USER_AGENT)
            .build()

        try {
            when (val redirected = executeWithRedirects(client, request, isAllowed, onCall)) {
                is Redirected.Disallowed -> SegmentOutcome.Fatal(redirected.reason)
                is Redirected.Ok -> redirected.response.use { response ->
                    val validator = ResumePolicy.validatorOf(
                        response.header("ETag"),
                        response.header("Last-Modified"),
                    )

                    // Объект сменился между запросами сегментов: продолжать
                    // нельзя НИ один сегмент этого релиза. Возвращаем новую
                    // метку, чтобы сервис сделал полный рестарт (иначе сегменты
                    // зациклились бы: state.validator остался бы старым).
                    if (!ResumePolicy.objectUnchanged(expectedValidator, validator)) {
                        return@use SegmentOutcome.Restart(
                            "object changed: expected=$expectedValidator got=$validator",
                            newValidator = validator,
                        )
                    }

                    when (val outcome = ResumePolicy.classify(
                        code = response.code,
                        contentRange = response.header("Content-Range"),
                        contentLength = response.body.contentLength(),
                    )) {
                        is ResumePolicy.Outcome.Partial -> {
                            // Сервер обязан начать РОВНО с запрошенного байта,
                            // иначе part-файл побьётся (стык сегментов).
                            if (outcome.start != resumeFrom) {
                                return@use SegmentOutcome.Restart(
                                    "range start mismatch: want=$resumeFrom got=${outcome.start}"
                                )
                            }
                            val written = appendBody(response, partFile, onBytes)
                            // Пост-запись: part обязан закрыть сегмент ЦЕЛИКОМ.
                            // Короткое тело при корректном Content-Length okhttp
                            // не ловит (EOF «чистый»), поэтому без этой проверки
                            // Complete вернулся бы при неполном сегменте, и
                            // ошибка всплыла бы только на склейке. Недокачано —
                            // значит переходящая ошибка: ретрай продолжит с
                            // фактического конца part-файла.
                            val have = if (partFile.exists()) partFile.length() else 0L
                            if (have < segmentSize) {
                                SegmentOutcome.Transient(
                                    "truncated body: wrote $written, part $have/$segmentSize"
                                )
                            } else {
                                SegmentOutcome.Complete(bytesWritten = written, validator = validator)
                            }
                        }

                        is ResumePolicy.Outcome.FullObject ->
                            // 200 на Range-запрос сегмента: для сегментной
                            // докачки тупик (part неполон, дозапросить нельзя).
                            SegmentOutcome.Restart("server ignored Range (got 200)")

                        ResumePolicy.Outcome.RangeNotSatisfiable ->
                            // 416: resumeFrom за пределами объекта (part длиннее
                            // сегмента или объект укоротился) — рестарт сегмента.
                            SegmentOutcome.Restart("416 Range Not Satisfiable (existing=$existing)")

                        is ResumePolicy.Outcome.HttpError ->
                            if (UpdateDecisions.isRetriableHttp(outcome.code)) {
                                SegmentOutcome.Transient("HTTP ${outcome.code}")
                            } else {
                                SegmentOutcome.Fatal("HTTP ${outcome.code}")
                            }
                    }
                }
            }
        } catch (e: IOException) {
            // Любой сетевой сбой = переходящая ошибка; записанные байты остались
            // в part-файле, докачка продолжится с них.
            SegmentOutcome.Transient("${e.javaClass.simpleName}: ${e.message}")
        }
    }

    /**
     * Дописывает тело ответа в конец [partFile], прогоняя байты через
     * [onBytes]. Возвращает число записанных байт. Append-режим: обрыв в любой
     * момент сохраняет уже принятое.
     */
    private fun appendBody(response: Response, partFile: File, onBytes: (Long) -> Unit): Long {
        var written = 0L
        partFile.parentFile?.let { if (!it.exists()) it.mkdirs() }
        response.body.byteStream().use { input ->
            FileOutputStream(partFile, true).use { output ->
                val buffer = ByteArray(BUFFER_SIZE)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    if (read > 0) {
                        output.write(buffer, 0, read)
                        written += read
                        onBytes(read.toLong())
                    }
                }
                output.flush()
            }
        }
        return written
    }

    /**
     * Скачивает объект ОДНИМ потоком (фолбэк, если сервер не поддержал Range).
     * Докачка здесь невозможна в принципе, поэтому файл пишется с нуля.
     */
    suspend fun downloadWhole(
        client: OkHttpClient,
        url: String,
        targetFile: File,
        onBytes: (Long) -> Unit,
        isAllowed: (String) -> Boolean = { u -> UpdateUrlPolicy.isAllowed(u) },
        onCall: (okhttp3.Call) -> Unit = {},
    ): SegmentOutcome = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(url)
            .header("User-Agent", USER_AGENT)
            .build()
        try {
            when (val redirected = executeWithRedirects(client, request, isAllowed, onCall)) {
                is Redirected.Disallowed -> SegmentOutcome.Fatal(redirected.reason)
                is Redirected.Ok -> redirected.response.use { response ->
                    val validator = ResumePolicy.validatorOf(
                        response.header("ETag"),
                        response.header("Last-Modified"),
                    )
                    if (response.code == 200) {
                        targetFile.parentFile?.let { if (!it.exists()) it.mkdirs() }
                        var written = 0L
                        response.body.byteStream().use { input ->
                            targetFile.outputStream().use { output ->
                                val buffer = ByteArray(BUFFER_SIZE)
                                while (true) {
                                    val read = input.read(buffer)
                                    if (read < 0) break
                                    if (read > 0) {
                                        output.write(buffer, 0, read)
                                        written += read
                                        onBytes(read.toLong())
                                    }
                                }
                                output.flush()
                            }
                        }
                        SegmentOutcome.Complete(written, validator)
                    } else if (UpdateDecisions.isRetriableHttp(response.code)) {
                        SegmentOutcome.Transient("HTTP ${response.code}")
                    } else {
                        SegmentOutcome.Fatal("HTTP ${response.code}")
                    }
                }
            }
        } catch (e: IOException) {
            SegmentOutcome.Transient("${e.javaClass.simpleName}: ${e.message}")
        }
    }

    /** Исход склейки сегментов. */
    sealed interface MergeResult {
        /** Склеено и хэш СОВПАЛ — файл готов к установке. */
        data class Verified(val mergedFile: File, val sha256: String) : MergeResult

        /** Склеено, но хэш НЕ совпал: битый APK (докачка «порвала байты»). */
        data class HashMismatch(val actual: String, val expected: String) : MergeResult

        /** Не удалось склеить (нет сегмента, IO-ошибка, неполный размер). */
        data class Error(val reason: String) : MergeResult
    }

    /**
     * Склейка сегментов в один APK ОДНОВРЕМЕННО со стриминговым SHA-256:
     * байты идут в итоговый файл и в MessageDigest за ОДИН проход, без второго
     * чтения 95-330 МБ файла — «проверяет хэш прямо до каждого байта».
     *
     * Сегменты обязаны покрывать файл сплошь ([SegmentPlan.isContiguous]),
     * каждый part-файл — быть ровно своего размера. Итог пишется во временный
     * файл и переименовывается атомарно: читатель никогда не увидит половину APK.
     *
     * @param expectedSha256 эталон из SHA256SUMS.txt того же релиза.
     * @param totalBytes ожидаемый полный размер объекта.
     */
    fun merge(
        segments: List<SegmentPlan.Segment>,
        partFileFor: (Int) -> File,
        mergedTarget: File,
        expectedSha256: String?,
        totalBytes: Long,
    ): MergeResult {
        if (segments.isEmpty()) return MergeResult.Error("no segments to merge")
        if (!SegmentPlan.isContiguous(segments, totalBytes)) {
            return MergeResult.Error("segment plan is not contiguous for total=$totalBytes")
        }

        // Пре-проверка: КАЖДЫЙ part обязан быть ровно своего размера. Проверяем
        // ДО создания временного файла, чтобы не оставлять мусор .merging.tmp,
        // если какой-то сегмент недокачан (тогда склейка вообще не начинается).
        for (segment in segments) {
            val part = partFileFor(segment.index)
            val actualSize = if (part.exists()) part.length() else 0L
            if (actualSize != segment.size) {
                return MergeResult.Error(
                    "segment ${segment.index} incomplete: have=$actualSize want=${segment.size}"
                )
            }
        }

        val temp = File(mergedTarget.parentFile, mergedTarget.name + ".merging.tmp")
        val digest = UpdateHashVerifier.newDigest()
        var total = 0L
        try {
            temp.parentFile?.let { if (!it.exists()) it.mkdirs() }
            FileOutputStream(temp).use { output ->
                val buffer = ByteArray(BUFFER_SIZE)
                for (segment in segments) {
                    val part = partFileFor(segment.index)
                    part.inputStream().use { input ->
                        while (true) {
                            val read = input.read(buffer)
                            if (read < 0) break
                            if (read > 0) {
                                output.write(buffer, 0, read)
                                digest.update(buffer, 0, read)
                                total += read
                            }
                        }
                    }
                }
                output.flush()
            }
        } catch (e: Exception) {
            temp.delete()
            return MergeResult.Error("merge failed: ${e.javaClass.simpleName}: ${e.message}")
        }

        if (total != totalBytes) {
            temp.delete()
            return MergeResult.Error("merged size mismatch: have=$total want=$totalBytes")
        }

        val actual = UpdateHashVerifier.hex(digest)
        if (!UpdateHashVerifier.equalsHex(actual, expectedSha256)) {
            temp.delete()
            return MergeResult.HashMismatch(actual = actual, expected = expectedSha256.orEmpty())
        }

        if (mergedTarget.exists() && !mergedTarget.delete()) {
            return MergeResult.Error("cannot replace existing ${mergedTarget.name}")
        }
        if (!temp.renameTo(mergedTarget)) {
            return MergeResult.Error("failed to rename temp to ${mergedTarget.name}")
        }
        return MergeResult.Verified(mergedFile = mergedTarget, sha256 = actual)
    }
}
