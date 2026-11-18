package com.v2ray.ang.service

import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.v2ray.ang.AppConfig
import com.v2ray.ang.R
import com.v2ray.ang.enums.NotificationChannelType
import com.v2ray.ang.extension.toSpeedString
import com.v2ray.ang.handler.AppLocaleManager
import com.v2ray.ang.helper.MessageHelper
import com.v2ray.ang.helper.NotificationHelper
import com.v2ray.ang.ui.checkupdate.CheckUpdateActivity
import com.v2ray.ang.ui.main.MainActivity
import com.v2ray.ang.util.ActiveProfileRoute
import com.v2ray.ang.util.JsonUtil
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.util.updater.DownloadState
import com.v2ray.ang.util.updater.SegmentPlan
import com.v2ray.ang.util.updater.Sha256Sums
import com.v2ray.ang.util.updater.SpeedTracker
import com.v2ray.ang.util.updater.UpdateDecisions
import com.v2ray.ang.util.updater.UpdateDownloadLogger
import com.v2ray.ang.util.updater.UpdateDownloadStore
import com.v2ray.ang.util.updater.UpdateDownloader
import com.v2ray.ang.util.updater.UpdateHashVerifier
import com.v2ray.ang.util.updater.UpdateHttpClient
import com.v2ray.ang.util.updater.UpdateInstallLauncher
import com.v2ray.ang.util.updater.UpdatePaths
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.coroutines.coroutineContext
import okhttp3.Call
import okhttp3.OkHttpClient
import java.io.File
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Foreground-сервис встроенного загрузчика обновлений клиента.
 *
 * АРХИТЕКТУРА (обоснование выбора, требование 7 промта):
 * выделенный foreground-сервис (process=:tasks, foregroundServiceType=
 * specialUse) — ТОТ ЖЕ паттерн, что доказанно работает в форке у
 * [SubscriptionUpdateService]/[CoreTestService]. WorkManager-foreground-воркер
 * ОТВЕРГНУТ: AngApplication задаёт WorkManager defaultProcessName=":bg"
 * (multiprocess), но androidx.work SystemForegroundService в манифесте НЕ
 * переопределён (нет ни android:process=":bg", ни foregroundServiceType для
 * API 34+) — foreground-воркер поднял бы уведомление в чужом процессе и без
 * типа, что на Android 14+ бросает SecurityException. FGS specialUse уже
 * разрешён манифестом (FOREGROUND_SERVICE_SPECIAL_USE) и переживает
 * сворачивание клиента.
 *
 * ВСЕ требования владельца по этому сервису:
 *  - многопоточная сегментная загрузка, потоков ≤24, настраивается в настройках
 *    → [SegmentPlan] + [requestedSegments];
 *  - докачка с того же байта при обрыве/смене сети/полёте/kill/перезагрузке →
 *    part-файлы + [DownloadState] в MMKV + ожидание сети через NetworkCallback +
 *    бесконечные ретраи переходящих ошибок («скачивание не должно
 *    останавливаться, даже на 2G/3G»);
 *  - докачка доступна минимум час → каждый сегментный запрос идёт по
 *    ПОСТОЯННОЙ ссылке GitHub (подписанный SAS-URL живёт ~1 час и НИКОГДА не
 *    сохраняется), part-файлы и состояние без TTL;
 *  - скорость загрузки обновляется КАЖДУЮ СЕКУНДУ (Б/КБ/МБ/ГБ в с) + ETA →
 *    [progressJob] тикает раз в секунду, [SpeedTracker] (скользящее окно),
 *    формат — существующий Long.toSpeedString();
 *  - стриминговая проверка SHA-256 против SHA256SUMS.txt того же релиза, хэш
 *    «до каждого байта» при склейке → [UpdateDownloader.merge];
 *  - пауза/продолжить/отмена из уведомления; отмена НЕ удаляет part-файлы
 *    («вдруг пользователь потом захочет скачать — подключится докачка»);
 *  - авто-установка ТОЛЬКО если пользователь внутри клиента: сервис живёт в
 *    :tasks и НЕ может сам видеть UI главного процесса, поэтому по готовности
 *    шлётся broadcast MSG_UPDATE_DOWNLOAD_READY, а решение принимает
 *    приёмник в main-процессе по [com.v2ray.ang.util.updater.AppForegroundTracker];
 *  - кнопка «Установить» живёт в уведомлении и вызывает intent прямо оттуда;
 *  - загрузка только через клиент: собственный okhttp, никакого WebView и
 *    системного/вендорского DownloadManager;
 *  - маршрут: свитч «через активный профиль» ВКЛ → loopback HTTP-прокси
 *    запущенного ядра ([ActiveProfileRoute], тот же резолвер, что у проверки
 *    обновлений), ВЫКЛ → прямой канал;
 *  - ошибки и ход загрузки пишутся в Download/v2rayNG/update_download.log
 *    («логи этой ошибки в конкретную папку конкретным файлом»).
 */
class UpdateDownloadService : Service() {

    companion object {
        private const val ACTIONS_PREFIX = "${AppConfig.ANG_PACKAGE}.action."

        /** Начать/возобновить загрузку релиза (extras: tag, asset, url, sums, size). */
        const val ACTION_START = ACTIONS_PREFIX + "update.download.start"
        const val ACTION_PAUSE = ACTIONS_PREFIX + "update.download.pause"
        const val ACTION_RESUME = ACTIONS_PREFIX + "update.download.resume"
        /** Отмена: НЕ удаляет part-файлы (докачка продолжится при следующем старте). */
        const val ACTION_CANCEL = ACTIONS_PREFIX + "update.download.cancel"
        /** Установка из уведомления (кнопка «Установить»). */
        const val ACTION_INSTALL = ACTIONS_PREFIX + "update.download.install"

        const val EXTRA_RELEASE_TAG = "extra_release_tag"
        const val EXTRA_ASSET_NAME = "extra_asset_name"
        const val EXTRA_DOWNLOAD_URL = "extra_download_url"
        const val EXTRA_CHECKSUMS_URL = "extra_checksums_url"
        const val EXTRA_EXPECTED_SHA256 = "extra_expected_sha256"
        const val EXTRA_DECLARED_SIZE = "extra_declared_size"

        /** Интервал обновления скорости/прогресса в уведомлении — 1 секунда (требование владельца). */
        private const val TICK_INTERVAL_MS = 1000L

        /** Потолок паузы backoff между ретраями переходящих ошибок. */
        private const val MAX_RETRY_BACKOFF_MS = 15_000L

        /** Пауза перед повтором после рестарта сегмента (смена объекта/416). */
        private const val RESTART_DELAY_MS = 3_000L

        /** Потолок полных рестартов загрузки (смена объекта на сервере): защита от циклов. */
        private const val MAX_FULL_RESTARTS = 5

        /**
         * Запускает загрузку из UI-процесса. Одна активная загрузка на релиз
         * гарантируется unique-именем сервиса и [UpdateDecisions.decideStart].
         */
        fun startDownload(
            context: Context,
            releaseTag: String,
            assetName: String,
            downloadUrl: String,
            checksumsUrl: String?,
            expectedSha256: String?,
            declaredSize: Long,
        ) {
            val intent = Intent(context, UpdateDownloadService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_RELEASE_TAG, releaseTag)
                putExtra(EXTRA_ASSET_NAME, assetName)
                putExtra(EXTRA_DOWNLOAD_URL, downloadUrl)
                putExtra(EXTRA_CHECKSUMS_URL, checksumsUrl)
                putExtra(EXTRA_EXPECTED_SHA256, expectedSha256)
                putExtra(EXTRA_DECLARED_SIZE, declaredSize)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        /** Команда сервису (пауза/возобновление/отмена/установка). */
        fun sendCommand(context: Context, action: String) {
            val intent = Intent(context, UpdateDownloadService::class.java).setAction(action)
            context.startService(intent)
        }

        /** True, если сервис сейчас должен быть жив (загрузка активна/готова к установке). */
        fun hasActiveDownload(): Boolean = UpdateDownloadStore.load()?.isActive() == true
    }

    override fun attachBaseContext(newBase: Context?) {
        super.attachBaseContext(newBase?.let(AppLocaleManager::localizedContext))
    }

    private val serviceJob = Job()
    private val serviceScope = CoroutineScope(Dispatchers.IO + serviceJob)

    /**
     * Активные сетевые вызовы: cancel() рвёт блокирующий read немедленно
     * (одной отменой корутины InputStream.read не прервать). Потокобезопасное
     * множество: вызывают из разных корутин сегментов и из onDestroy (main).
     */
    private val activeCalls: MutableSet<Call> =
        Collections.newSetFromMap(ConcurrentHashMap())

    /** Текущее состояние (зеркало MMKV). */
    @Volatile
    private var state: DownloadState = DownloadState()

    /** Сколько байт записано в part-файлы С НАЧАЛА СТАРТА процесса (для скорости). */
    private val bytesWrittenTotal = AtomicLong(0L)

    private val speedTracker = SpeedTracker(windowMillis = 5_000L)
    private val pausedFlag = AtomicBoolean(false)
    private val cancelledFlag = AtomicBoolean(false)

    /**
     * Доверять ли part-файлам, уже лежащим на диске, как продолжению ТЕКУЩЕЙ
     * загрузки. True только при докачке того же релиза/ассета; при смене цели
     * (другой релиз с тем же именем ассета) старые part-файлы ЧУЖИЕ и должны
     * быть удалены, иначе склейка собрала бы байты от другого APK (валидатор и
     * SHA-256 это поймали бы, но корректнее не начинать с мусора).
     */
    @Volatile
    private var trustExistingParts = false

    private var progressJob: Job? = null
    private var downloadJob: Job? = null
    private var networkCallback: ConnectivityCallback? = null
    private val networkAvailable = AtomicBoolean(true)

    /**
     * Рабочая папка загрузки. Выбирается ОДНАЖДЫ штатными средствами (без root):
     * публичный `Download/<app_name>`, а если он недоступен для записи —
     * приватный `filesDir/updates` (см. [UpdatePaths.ensureWritableDir]).
     * Логгер пишется в тот же каталог.
     */
    private val workDir: File by lazy {
        UpdatePaths.ensureWritableDir(this) { usedFallback ->
            if (usedFallback) {
                LogUtil.w(
                    AppConfig.TAG,
                    "UpdateDownloadService: public Download dir unavailable, using private app dir"
                )
            }
        }.also { dir ->
            UpdateDownloadLogger.setDir(dir)
            LogUtil.i(AppConfig.TAG, "UpdateDownloadService: work dir = ${dir.absolutePath}")
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        LogUtil.i(AppConfig.TAG, "UpdateDownloadService destroyed")
        serviceJob.cancel()
        // runBlocking в onDestroy (main thread) недопустим: cancel() у Call
        // неблокирующий, обходимся потокобезопасным множеством.
        cancelActiveCalls()
        unregisterNetworkCallback()
        NotificationHelper.stopForeground(this)
        super.onDestroy()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        // Foreground-контракт: startForegroundService (ACTION_START) обязан
        // получить startForeground быстро. Для INSTALL foreground не нужен:
        // сервис лишь запускает системный установщик и останавливается.
        if (action != ACTION_INSTALL) {
            ensureForeground()
        }
        when (action) {
            ACTION_START -> handleStart(intent!!)
            ACTION_PAUSE -> handlePause()
            ACTION_RESUME -> handleResume()
            ACTION_CANCEL -> handleCancel()
            ACTION_INSTALL -> handleInstall()
            else -> {
                // START_STICKY перезапустил сервис после kill процесса без intent:
                // продолжаем сохранённую загрузку (докачка после перезагрузки).
                resumePersistedDownload()
            }
        }
        // STICKY: после kill процесса/перезагрузки система поднимет сервис
        // заново, и докачка продолжится с сохранённых part-файлов.
        return START_STICKY
    }

    // -------------------------------------------------------------------------
    // Обработка команд
    // -------------------------------------------------------------------------

    private fun handleStart(intent: Intent) {
        val releaseTag = intent.getStringExtra(EXTRA_RELEASE_TAG).orEmpty()
        val assetName = intent.getStringExtra(EXTRA_ASSET_NAME).orEmpty()
        val downloadUrl = intent.getStringExtra(EXTRA_DOWNLOAD_URL).orEmpty()
        if (releaseTag.isEmpty() || assetName.isEmpty() || downloadUrl.isEmpty()) {
            LogUtil.w(AppConfig.TAG, "UpdateDownloadService: ACTION_START without extras, ignoring")
            stopSelfIfIdle()
            return
        }
        // workDir уже выбран через ensureWritableDir (публичный Download либо
        // приватный каталог). Проверяем фактически: если ни один не доступен
        // (крайне редко — нет места/сбой ФС), честно сообщаем и не качаем.
        if (!UpdatePaths.isUsable(workDir)) {
            failDownload(getString(R.string.update_download_error_storage), keepNotification = false)
            return
        }

        val existing = UpdateDownloadStore.load()
        when (UpdateDecisions.decideStart(existing, releaseTag, assetName)) {
            UpdateDecisions.StartDecision.AlreadyRunning -> {
                // Одна активная загрузка на релиз: не плодим задачи.
                if (downloadJob?.isActive == true) {
                    // Реально качается прямо сейчас: НЕ перезаписываем state из
                    // MMKV (иначе затрём параллельный прогресс сегментов),
                    // только показываем текущий прогресс.
                    ensureForeground()
                    return
                }
                // Служебный случай: состояние «качается», а джоба нет (сервис
                // только что перезапущен) — подхватываем сохранённое и докачиваем.
                state = existing ?: state
                trustExistingParts = true
                bytesWrittenTotal.set(state.downloadedBytes())
                speedTracker.reset()
                registerNetworkCallback()
                launchDownload()
                return
            }

            UpdateDecisions.StartDecision.AlreadyDownloaded -> {
                state = existing ?: return
                val apk = UpdatePaths.apkFile(workDir, state.assetName)
                if (apk.exists()) {
                    showReadyNotification(apk)
                    broadcastReady(apk.absolutePath)
                    return
                }
                // Файл исчез (чистка каталога) — качаем заново тем же путём.
            }

            UpdateDecisions.StartDecision.SwitchTarget -> {
                // Другой релиз: part-файлы старого НЕ удаляем (правило «отмена не
                // удаляет», а очистка — только явная), начинаем новое состояние.
                UpdateDownloadLogger.log(
                    this,
                    "switch target: ${existing?.releaseTag}/${existing?.assetName} -> $releaseTag/$assetName (old parts kept)"
                )
            }

            else -> Unit
        }

        pausedFlag.set(false)
        cancelledFlag.set(false)
        speedTracker.reset()

        val restoredExisting = existing?.takeIf { it.releaseTag == releaseTag && it.assetName == assetName }
        // Докачка того же релиза: доверяем part-файлам на диске. Новая цель
        // (в т.ч. SwitchTarget): старые part-файлы того же имени ассета чужие —
        // удаляем их, чтобы не подмешать байты другого релиза в склейку.
        trustExistingParts = restoredExisting != null
        if (!trustExistingParts) {
            clearPartFiles(assetName)
        }
        // Для докачки ТОГО ЖЕ релиза счётчик стартует с байтов, уже лежащих в
        // part-файлах (иначе скорость/прогресс на первом тике упали бы в ноль);
        // для новой цели — с нуля.
        bytesWrittenTotal.set(restoredExisting?.downloadedBytes() ?: 0L)
        state = DownloadState(
            releaseTag = releaseTag,
            assetName = assetName,
            browserDownloadUrl = downloadUrl,
            checksumsUrl = intent.getStringExtra(EXTRA_CHECKSUMS_URL).orEmpty(),
            expectedSha256 = intent.getStringExtra(EXTRA_EXPECTED_SHA256)
                ?.takeIf { it.isNotBlank() }
                ?: restoredExisting?.expectedSha256.orEmpty(),
            declaredSize = intent.getLongExtra(EXTRA_DECLARED_SIZE, -1L),
            totalBytes = restoredExisting?.totalBytes ?: -1L,
            validator = restoredExisting?.validator,
            rangesSupported = restoredExisting?.rangesSupported == true,
            requestedSegments = UpdateDownloadStore.requestedSegments(),
            phase = DownloadState.Phase.PROBING,
            segmentDone = restoredExisting?.segmentDone ?: emptyMap(),
            updatedAt = System.currentTimeMillis(),
        )
        UpdateDownloadStore.save(state)
        registerNetworkCallback()
        launchDownload()
    }

    /**
     * Продолжение сохранённой загрузки после START_STICKY-рестарта (kill
     * процесса, перезагрузка устройства): требование «докачка при kill процесса,
     * перезагрузке устройства».
     */
    private fun resumePersistedDownload() {
        val persisted = UpdateDownloadStore.load() ?: run {
            stopSelfIfIdle()
            return
        }
        if (persisted.phase == DownloadState.Phase.READY_TO_INSTALL) {
            state = persisted
            val apk = UpdatePaths.apkFile(workDir, persisted.assetName)
            if (apk.exists()) {
                showReadyNotification(apk)
                return
            }
            // APK удалён: состояние сбрасывается, пользователь запустит заново.
            UpdateDownloadStore.clear()
            stopSelfIfIdle()
            return
        }
        if (!persisted.isActive() || persisted.browserDownloadUrl.isBlank()) {
            stopSelfIfIdle()
            return
        }
        if (!UpdatePaths.isUsable(workDir)) {
            stopSelfIfIdle()
            return
        }
        state = persisted
        cancelledFlag.set(false)
        // Рестарт сервиса после kill/перезагрузки = докачка ТОЙ ЖЕ цели:
        // доверяем part-файлам на диске (runSegmented подхватит их байты).
        trustExistingParts = true
        bytesWrittenTotal.set(persisted.downloadedBytes())
        speedTracker.reset()
        if (persisted.phase == DownloadState.Phase.PAUSED) {
            // Пользователь сам ставил на паузу: после рестарта сервиса она
            // сохраняется, продолжение — только явной командой «Продолжить».
            pausedFlag.set(true)
            UpdateDownloadLogger.log(this, "service restarted, download stays PAUSED at ${persisted.progressPercent()}%")
            showPausedNotification()
            return
        }
        pausedFlag.set(false)
        UpdateDownloadLogger.log(this, "service restarted, resuming persisted download: ${persisted.releaseTag}/${persisted.assetName} at ${persisted.progressPercent()}%")
        registerNetworkCallback()
        launchDownload()
    }

    private fun handlePause() {
        if (!state.isActive()) {
            stopSelfIfIdle()
            return
        }
        pausedFlag.set(true)
        persistPhase(DownloadState.Phase.PAUSED)
        UpdateDownloadLogger.log(this, "paused by user at ${state.progressPercent()}% (${state.downloadedBytes()} of ${state.totalBytes} bytes)")
        cancelActiveCalls()
        showPausedNotification()
    }

    private fun handleResume() {
        val persisted = state.takeIf { it.releaseTag.isNotEmpty() } ?: UpdateDownloadStore.load()
        if (persisted == null) {
            stopSelfIfIdle()
            return
        }
        state = persisted
        pausedFlag.set(false)
        cancelledFlag.set(false)
        speedTracker.reset()
        if (downloadJob?.isActive != true) {
            registerNetworkCallback()
            launchDownload()
        } else {
            persistPhase(DownloadState.Phase.DOWNLOADING)
        }
        UpdateDownloadLogger.log(this, "resumed by user at ${state.progressPercent()}%")
    }

    private fun handleCancel() {
        cancelledFlag.set(true)
        persistPhase(DownloadState.Phase.CANCELLED)
        // Требование владельца: отмена НЕ удаляет скачанное — part-файлы
        // остаются, следующий «Скачать» продолжит докачку с того же байта.
        UpdateDownloadLogger.log(this, "cancelled by user at ${state.progressPercent()}%; part files KEPT in ${workDir.absolutePath}")
        cancelActiveCalls()
        downloadJob?.cancel()
        downloadJob = null
        showCancelledNotification()
        MessageHelper.sendMsg2UI(this, AppConfig.MSG_UPDATE_DOWNLOAD_FAILED, getString(R.string.update_download_cancelled))
        stopProgressTicker()
        unregisterNetworkCallback()
        // DETACH: уведомление «Отменено» с кнопкой «Продолжить» остаётся в
        // шторке после остановки сервиса.
        stopForeground(STOP_FOREGROUND_DETACH)
        stopSelf()
    }

    /** Кнопка «Установить» в уведомлении: запускает установщик прямо оттуда. */
    private fun handleInstall() {
        val persisted = UpdateDownloadStore.load() ?: state
        // Предпочитаем сохранённый фактический путь (может быть резервный
        // приватный каталог), иначе вычисляем от текущей рабочей папки.
        val apk = persisted.apkPath.takeIf { it.isNotBlank() }?.let(::File)
            ?: UpdatePaths.apkFile(workDir, persisted.assetName)
        if (persisted.assetName.isEmpty() || !apk.exists()) {
            LogUtil.w(AppConfig.TAG, "UpdateDownloadService: install requested but no verified APK")
            stopSelfIfIdle()
            return
        }
        UpdateInstallLauncher.install(this, apk)
        // Пользователь сам нажал «Установить»: уведомление больше не нужно.
        NotificationHelper.cancel(NotificationChannelType.UPDATE_DOWNLOAD, this)
        stopSelfIfIdle()
    }

    // -------------------------------------------------------------------------
    // Основной цикл загрузки
    // -------------------------------------------------------------------------

    private fun launchDownload() {
        downloadJob?.cancel()
        downloadJob = serviceScope.launch {
            try {
                runDownload()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                LogUtil.e(AppConfig.TAG, "UpdateDownloadService: unexpected failure", e)
                // IllegalStateException из resolveRoute несёт ТОЧНУЮ причину
                // («профиль не запущен», «нет loopback-прокси») — показываем её,
                // а не общий текст.
                val reason = if (e is IllegalStateException && !e.message.isNullOrBlank()) {
                    e.message!!
                } else {
                    getString(R.string.update_download_error_generic)
                }
                failDownload(reason, keepNotification = true)
            }
        }
    }

    private suspend fun runDownload() {
        startProgressTicker()

        val viaProfile = UpdateDownloadStore.viaActiveProfile()
        // Маршрут решается ОДНАЖДЫ на старте: тот же резолвер ActiveProfileRoute,
        // что у проверки обновлений (переиспользование, требование 9 промта).
        val route = resolveRoute(viaProfile)
        val client = UpdateHttpClient.build(route)
        UpdateDownloadLogger.log(
            this,
            "download run: ${state.releaseTag}/${state.assetName} segments=${state.requestedSegments} " +
                "route=${if (viaProfile) "via active profile" else "direct"} proxyPort=${route.proxyPort}"
        )

        var fullRestarts = 0
        // Внешний цикл: полный рестарт при смене объекта на сервере (ETag).
        while (coroutineContext.isActive) {
            if (cancelledFlag.get()) return

            // 1) Эталонный хэш: маленький запрос SHA256SUMS.txt того же релиза.
            if (state.expectedSha256.isBlank()) {
                fetchExpectedHash(client)
            }

            // 2) Проба: размер объекта и поддержка Range. Повторяется до успеха —
            //    «загрузка не должна останавливаться» даже на старте.
            var probe = UpdateDownloader.probe(client, state.browserDownloadUrl) { call -> registerCall(call) }
            while (probe.totalBytes <= 0L) {
                if (cancelledFlag.get()) return
                if (pausedFlag.get()) { waitWhilePaused(); continue }
                if (!networkAvailable.get()) {
                    persistPhase(DownloadState.Phase.WAITING_NETWORK)
                    delay(TICK_INTERVAL_MS)
                    continue
                }
                UpdateDownloadLogger.log(this, "probe failed, retrying in 5s")
                delay(5_000L)
                probe = UpdateDownloader.probe(client, state.browserDownloadUrl) { call -> registerCall(call) }
            }
            if (cancelledFlag.get()) return

            if (state.declaredSize > 0 && probe.totalBytes != state.declaredSize) {
                // Сверка размера против asset.size (требование 10). Расхождение =
                // объект релиза не тот, за кого себя выдаёт: не качаем.
                failDownload(getString(R.string.update_download_error_size_mismatch, state.declaredSize, probe.totalBytes))
                return
            }

            persistState(
                state.copy(
                    totalBytes = probe.totalBytes,
                    validator = probe.validator,
                    rangesSupported = probe.rangesSupported,
                    phase = DownloadState.Phase.DOWNLOADING,
                )
            )
            UpdateDownloadLogger.log(
                this,
                "probe ok: total=${probe.totalBytes} ranges=${probe.rangesSupported} validator=${probe.validator}"
            )

            val needFullRestart = if (probe.rangesSupported) {
                runSegmented(client, probe)
            } else {
                runSingleStream(client)
                false
            }
            if (!needFullRestart) return
            if (cancelledFlag.get()) return

            // Объект на сервере сменился: ВСЕ part-файлы устарели. Чистим их,
            // сбрасываем метаданные и идём на новый круг (свежая проба/хэш).
            if (++fullRestarts > MAX_FULL_RESTARTS) {
                failDownload(getString(R.string.update_download_error_object_changed))
                return
            }
            UpdateDownloadLogger.log(this, "FULL RESTART $fullRestarts/$MAX_FULL_RESTARTS: server object changed, clearing part files and re-probing")
            clearPartFiles(state.assetName)
            trustExistingParts = false
            bytesWrittenTotal.set(0L)
            speedTracker.reset()
            persistState(
                state.copy(
                    validator = null,
                    totalBytes = -1L,
                    rangesSupported = false,
                    segmentDone = emptyMap(),
                    expectedSha256 = "",
                    phase = DownloadState.Phase.PROBING,
                )
            )
            delay(RESTART_DELAY_MS)
        }
    }

    /** Получает эталонный SHA-256 из SHA256SUMS.txt релиза (маленький запрос). */
    private suspend fun fetchExpectedHash(client: OkHttpClient) {
        val sumsUrl = state.checksumsUrl
        if (sumsUrl.isBlank()) {
            UpdateDownloadLogger.log(this, "no checksums URL known; will refuse to install unverified APK")
            return
        }
        val manifest = UpdateDownloader.fetchSmallText(client, sumsUrl) { call -> registerCall(call) }
        if (manifest.isNullOrBlank()) {
            UpdateDownloadLogger.log(this, "WARNING: SHA256SUMS.txt fetch failed from $sumsUrl")
            return
        }
        val expected = Sha256Sums.expectedHash(manifest, state.assetName)
        if (expected != null) {
            persistState(state.copy(expectedSha256 = expected))
            UpdateDownloadLogger.log(this, "expected SHA-256 loaded: $expected")
        } else {
            UpdateDownloadLogger.log(this, "WARNING: ${state.assetName} not listed in SHA256SUMS.txt")
        }
    }

    /**
     * Многопоточная сегментная загрузка с бесконечными ретраями.
     * @return true, если объект на сервере сменился и нужен ПОЛНЫЙ рестарт
     *   загрузки (все сегменты); false — нормальное завершение/отмена/пауза/ошибка.
     */
    private suspend fun runSegmented(client: OkHttpClient, probe: UpdateDownloader.Probe): Boolean {
        val plan = SegmentPlan.plan(probe.totalBytes, state.requestedSegments)
        if (plan.isEmpty() || !SegmentPlan.isContiguous(plan, probe.totalBytes)) {
            failDownload("invalid segment plan for total=${probe.totalBytes}")
            return false
        }
        // Прогресс стартует с реально лежащих на диске part-файлов (докачка
        // после kill/перезагрузки: байты уже есть, считать их заново нельзя).
        // Только если доверяем существующим part (та же цель), иначе они уже
        // удалены в handleStart и initialDone пуст.
        val initialDone = if (trustExistingParts) {
            plan.associate { segment ->
                val part = UpdatePaths.partFile(workDir, state.assetName, segment.index)
                val have = if (part.exists()) part.length().coerceAtMost(segment.size) else 0L
                segment.index to have
            }.filterValues { it > 0L }
        } else {
            emptyMap()
        }
        if (initialDone.isNotEmpty()) {
            persistState(state.copy(segmentDone = initialDone))
            bytesWrittenTotal.set(initialDone.values.sum())
            UpdateDownloadLogger.log(this, "resuming ${initialDone.size} existing part files, ${bytesWrittenTotal.get()} bytes already on disk")
        }
        UpdateDownloadLogger.log(this, "plan: ${plan.size} segments for ${probe.totalBytes} bytes (requested=${state.requestedSegments})")

        // Каждый сегмент — своя корутина (число сегментов уже ограничено
        // настройкой 1..24 в SegmentPlan), ошибки изолированы. Результат
        // сегмента: true = объект сменился, нужен полный рестарт загрузки.
        val results = coroutineScope {
            plan.map { segment ->
                async(Dispatchers.IO) {
                    downloadSegmentLoop(client, segment)
                }
            }.awaitAll()
        }

        if (results.any { it }) {
            return true // объект сменился: полный рестарт на уровне runDownload
        }
        if (cancelledFlag.get()) return false
        if (pausedFlag.get()) {
            persistPhase(DownloadState.Phase.PAUSED)
            return false
        }
        if (state.phase == DownloadState.Phase.FAILED) return false

        mergeAndVerify(plan, probe.totalBytes)
        return false
    }

    /**
     * Цикл одного сегмента: докачка до полного успеха. Переходящие ошибки
     * ретраятся БЕЗ лимита с паузами («даже на 2G/3G загрузка должна хоть
     * как-то идти»), отсутствие сети — ожидание без отмены задачи.
     */
    private suspend fun downloadSegmentLoop(client: OkHttpClient, segment: SegmentPlan.Segment): Boolean {
        val partFile = UpdatePaths.partFile(workDir, state.assetName, segment.index)
        var attempt = 0
        while (coroutineContext.isActive) {
            if (cancelledFlag.get()) return false
            // Другой сегмент упал фатально (или пользователь отменил):
            // прекращаем, не плодим бесполезные запросы до остановки сервиса.
            if (state.phase == DownloadState.Phase.FAILED || state.phase == DownloadState.Phase.CANCELLED) {
                return false
            }
            if (pausedFlag.get()) {
                delay(500L)
                continue
            }
            if (!networkAvailable.get()) {
                persistPhase(DownloadState.Phase.WAITING_NETWORK)
                delay(TICK_INTERVAL_MS)
                continue
            }
            if (state.phase == DownloadState.Phase.PAUSED) {
                persistPhase(DownloadState.Phase.DOWNLOADING)
            }

            val onBytes: (Long) -> Unit = { bytes ->
                if (cancelledFlag.get()) throw CancellationException("user cancelled")
                if (pausedFlag.get()) throw CancellationException("user paused")
                bytesWrittenTotal.addAndGet(bytes)
            }
            val outcome = try {
                attempt++
                UpdateDownloader.downloadSegment(
                    client = client,
                    url = state.browserDownloadUrl,
                    partFile = partFile,
                    segmentStart = segment.start,
                    segmentEndInclusive = segment.endInclusive,
                    expectedValidator = state.validator,
                    onBytes = onBytes,
                    onCall = { call -> registerCall(call) },
                )
            } catch (e: CancellationException) {
                // Пауза/отмена прервали чтение потока — выходим, part сохранён.
                return false
            } catch (e: Exception) {
                UpdateDownloader.SegmentOutcome.Transient("${e.javaClass.simpleName}: ${e.message}")
            } finally {
                // Фактическая длина part — источник истины для прогресса.
                val have = if (partFile.exists()) partFile.length() else 0L
                persistSegmentProgress(segment.index, have.coerceAtMost(segment.size))
            }

            when (outcome) {
                is UpdateDownloader.SegmentOutcome.Complete -> {
                    persistSegmentProgress(segment.index, segment.size)
                    return false
                }

                is UpdateDownloader.SegmentOutcome.Transient -> {
                    val backoff = minOf(MAX_RETRY_BACKOFF_MS, 1500L * attempt)
                    UpdateDownloadLogger.log(
                        this,
                        "segment ${segment.index} transient error (attempt $attempt, retry in ${backoff}ms): ${outcome.reason}"
                    )
                    delay(backoff)
                }

                is UpdateDownloader.SegmentOutcome.Restart -> {
                    if (outcome.newValidator != null) {
                        // Сервер СМЕНИЛ объект (новый ETag/Last-Modified): все
                        // part-файлы релиза устарели разом. Локальный рестарт
                        // сегмента привёл бы к вечному циклу (валидатор в state
                        // старый). Сигналим runSegmented: полный рестарт.
                        UpdateDownloadLogger.log(this, "segment ${segment.index}: OBJECT CHANGED (${outcome.reason}), full restart required")
                        return true
                    }
                    // Локальная проблема (416 / сервер проигнорировал Range /
                    // part длиннее сегмента): удаляем ТОЛЬКО этот part и качаем
                    // сегмент заново, остальные не трогаем.
                    UpdateDownloadLogger.log(this, "segment ${segment.index} restart: ${outcome.reason}")
                    partFile.delete()
                    persistSegmentProgress(segment.index, 0L)
                    delay(RESTART_DELAY_MS)
                }

                is UpdateDownloader.SegmentOutcome.Fatal -> {
                    UpdateDownloadLogger.log(this, "segment ${segment.index} FATAL: ${outcome.reason}")
                    failDownload(getString(R.string.update_download_error_http, outcome.reason))
                    return false
                }
            }
        }
        return false
    }

    /**
     * Фолбэк для серверов без поддержки Range (не GitHub): один поток, без
     * докачки (сервер физически не может отдать часть объекта). Ретраи те же.
     */
    private suspend fun runSingleStream(client: OkHttpClient) {
        UpdateDownloadLogger.log(this, "server has no Range support: single-stream download (resume impossible)")
        val target = UpdatePaths.mergeTempFile(workDir, state.assetName)
        while (coroutineContext.isActive) {
            if (cancelledFlag.get()) return
            if (pausedFlag.get()) { delay(500L); continue }
            if (!networkAvailable.get()) {
                persistPhase(DownloadState.Phase.WAITING_NETWORK)
                delay(TICK_INTERVAL_MS)
                continue
            }
            val onBytes: (Long) -> Unit = { bytes ->
                if (cancelledFlag.get()) throw CancellationException("user cancelled")
                if (pausedFlag.get()) throw CancellationException("user paused")
                bytesWrittenTotal.addAndGet(bytes)
            }
            val outcome = try {
                UpdateDownloader.downloadWhole(
                    client = client,
                    url = state.browserDownloadUrl,
                    targetFile = target,
                    onBytes = onBytes,
                    onCall = { call -> registerCall(call) },
                )
            } catch (e: CancellationException) {
                return
            } catch (e: Exception) {
                UpdateDownloader.SegmentOutcome.Transient("${e.javaClass.simpleName}: ${e.message}")
            }
            when (outcome) {
                is UpdateDownloader.SegmentOutcome.Complete -> {
                    verifySingleFile(target)
                    return
                }
                is UpdateDownloader.SegmentOutcome.Transient -> {
                    UpdateDownloadLogger.log(this, "single-stream transient error, retrying in 5s: ${outcome.reason}")
                    delay(5_000L)
                }
                is UpdateDownloader.SegmentOutcome.Restart,
                is UpdateDownloader.SegmentOutcome.Fatal -> {
                    val reason = if (outcome is UpdateDownloader.SegmentOutcome.Fatal) outcome.reason else (outcome as UpdateDownloader.SegmentOutcome.Restart).reason
                    failDownload(reason)
                    return
                }
            }
        }
    }

    /**
     * Пост-проверка хэша для однопоточного пути: стриминговый дайджест здесь
     * невозможен (нет сегментов/склейки, файл писался напрямую), поэтому
     * единственный честный вариант — один проход по готовому файлу. Обоснование
     * отступления от «стримингового SHA-256»: файл и так писался одним потоком
     * без стыков, порваться негде, а второй проход по файлу приемлем, потому
     * что этот путь — фолбэк для серверов без Range (наши релизы на GitHub
     * Range поддерживают, см. доказательство в отчёте).
     */
    private fun verifySingleFile(tempFile: File) {
        val apk = UpdatePaths.apkFile(workDir, state.assetName)
        val expected = state.expectedSha256
        if (expected.isBlank()) {
            tempFile.delete()
            failDownload(getString(R.string.update_download_error_no_checksum))
            return
        }
        persistPhase(DownloadState.Phase.VERIFYING)
        val actual = UpdateHashVerifier.hashFile(tempFile)
        if (!UpdateHashVerifier.equalsHex(actual, expected)) {
            tempFile.delete()
            failDownload(getString(R.string.update_download_error_checksum))
            UpdateDownloadLogger.log(this, "single-stream SHA-256 MISMATCH: actual=$actual expected=$expected")
            return
        }
        if (apk.exists()) apk.delete()
        if (!tempFile.renameTo(apk)) {
            failDownload("cannot publish downloaded file")
            return
        }
        onVerified(apk, actual)
    }

    /** Склейка сегментов + стриминговый SHA-256 за один проход. */
    private suspend fun mergeAndVerify(plan: List<SegmentPlan.Segment>, totalBytes: Long) = withContext(Dispatchers.IO) {
        if (state.expectedSha256.isBlank()) {
            // Без эталона устанавливать нельзя НИКОГДА (требование 4: «никогда
            // не предлагать установку непроверенного файла»).
            failDownload(getString(R.string.update_download_error_no_checksum))
            return@withContext
        }
        persistPhase(DownloadState.Phase.MERGING)
        showMergingNotification()
        val apk = UpdatePaths.apkFile(workDir, state.assetName)
        val result = UpdateDownloader.merge(
            segments = plan,
            partFileFor = { idx -> UpdatePaths.partFile(workDir, state.assetName, idx) },
            mergedTarget = apk,
            expectedSha256 = state.expectedSha256,
            totalBytes = totalBytes,
        )
        when (result) {
            is UpdateDownloader.MergeResult.Verified -> onVerified(result.mergedFile, result.sha256)

            is UpdateDownloader.MergeResult.HashMismatch -> {
                // Требование: «несовпадение = удалить part, сообщить, предложить
                // повтор». Part-файлы битые (докачка порвала байты или диск
                // исказил их) — удаляем, чтобы «Повторить» скачал начисто,
                // а не смержил тот же мусор по кругу.
                UpdateDownloadLogger.log(
                    this,
                    "SHA-256 MISMATCH after merge: actual=${result.actual} expected=${result.expected}; part files DELETED, retry will re-download"
                )
                clearPartFiles(state.assetName)
                persistState(state.copy(segmentDone = emptyMap()))
                bytesWrittenTotal.set(0L)
                speedTracker.reset()
                failDownload(getString(R.string.update_download_error_checksum))
            }

            is UpdateDownloader.MergeResult.Error -> {
                UpdateDownloadLogger.log(this, "merge error: ${result.reason}")
                failDownload(getString(R.string.update_download_error_merge, result.reason))
            }
        }
    }

    /** Файл скачан и проверен: уведомление «Установить» + broadcast в UI. */
    private fun onVerified(apkFile: File, sha256: String) {
        // Сохраняем ФАКТИЧЕСКИЙ путь: рабочая папка может быть резервной
        // приватной (filesDir/updates), установщик обязан брать файл отсюда.
        persistState(
            state.copy(
                phase = DownloadState.Phase.READY_TO_INSTALL,
                apkPath = apkFile.absolutePath,
            )
        )
        UpdateDownloadLogger.log(this, "READY: ${apkFile.absolutePath} sha256=$sha256 size=${apkFile.length()}")
        showReadyNotification(apkFile)
        stopProgressTicker()
        unregisterNetworkCallback()
        // Авто-установку решает main-процесс по флагу resumed-activity
        // (сервис в :tasks не видит UI главного процесса).
        broadcastReady(apkFile.absolutePath)
        // Сервис больше не нужен, но уведомление с кнопкой «Установить»
        // обязано жить и после выхода из клиента: DETACH оставляет его в
        // шторке, а кнопка поднимет сервис заново по ACTION_INSTALL.
        stopForeground(STOP_FOREGROUND_DETACH)
        stopSelf()
    }

    // -------------------------------------------------------------------------
    // Прогресс, скорость, уведомления
    // -------------------------------------------------------------------------

    /**
     * Тик раз в секунду (требование владельца «скорость обновляется каждую
     * секунду»): пересчёт скорости по скользящему окну и перерисовка
     * уведомления с процентом, скоростью (Б/КБ/МБ/ГБ в с) и ETA.
     */
    private fun startProgressTicker() {
        progressJob?.cancel()
        progressJob = serviceScope.launch {
            while (coroutineContext.isActive) {
                delay(TICK_INTERVAL_MS)
                val now = System.currentTimeMillis()
                // Честная скорость: байты, записанные с последнего сброса
                // (пауза/возобновление/рестарт), делятся на реальное время окна.
                speedTracker.record(bytesWrittenTotal.get(), now)
                when (state.phase) {
                    DownloadState.Phase.DOWNLOADING -> showProgressNotification()
                    DownloadState.Phase.WAITING_NETWORK -> showWaitingNetworkNotification()
                    DownloadState.Phase.PAUSED -> Unit // уведомление паузы уже показано
                    else -> Unit
                }
                // Раз в секунду дублируем состояние в UI-процесс: экран
                // проверки обновлений показывает прогресс/скорость живьём.
                broadcastProgress()
            }
        }
    }

    private fun stopProgressTicker() {
        progressJob?.cancel()
        progressJob = null
    }

    private fun ensureForeground() {
        val channelId = NotificationHelper.ensureChannel(NotificationChannelType.UPDATE_DOWNLOAD, this)
        val percent = state.progressPercent()
        val notification = NotificationCompat.Builder(this, channelId)
            .setSmallIcon(R.drawable.ic_cloud_download_24dp)
            .setContentTitle(getString(R.string.update_download_notification_title))
            .setContentText(
                if (state.assetName.isEmpty()) getString(R.string.update_download_preparing)
                else getString(R.string.update_download_progress_line, percent, state.assetName)
            )
            .setProgress(100, percent, percent <= 0)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
        startForeground(NotificationChannelType.UPDATE_DOWNLOAD.notificationId, notification)
    }

    private fun baseBuilder(): NotificationCompat.Builder {
        val channelId = NotificationHelper.ensureChannel(NotificationChannelType.UPDATE_DOWNLOAD, this)
        return NotificationCompat.Builder(this, channelId)
            .setSmallIcon(R.drawable.ic_cloud_download_24dp)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOnlyAlertOnce(true)
            .setContentIntent(buildMainPendingIntent())
    }

    /** Показывает/обновляет уведомление загрузчика (переиспользует существующий канал). */
    private fun showNotification(builder: NotificationCompat.Builder) {
        NotificationHelper.getNotificationManager(this)
            .notify(NotificationChannelType.UPDATE_DOWNLOAD.notificationId, builder.build())
    }

    /**
     * Живой процент для уведомления: считается из [bytesWrittenTotal] (байты на
     * диске на старте + записанные в этой сессии), а НЕ из state.segmentDone.
     *
     * Почему не state.progressPercent(): segmentDone обновляется только в finally
     * каждой попытки сегмента (писать MMKV на каждый 64 КБ чанк дорого), поэтому
     * на крупном сегменте прогресс «зависал» бы до конца сегмента. Живой счётчик
     * даёт плавный процент каждую секунду — как требует владелец. state.segmentDone
     * остаётся персистентным источником истины для склейки/докачки.
     */
    private fun currentPercent(): Int {
        val total = state.totalBytes
        if (total <= 0L) return 0
        val done = bytesWrittenTotal.get().coerceIn(0L, total)
        return (done * 100L / total).toInt().coerceIn(0, 100)
    }

    private fun showProgressNotification() {
        val percent = currentPercent()
        val speed = speedTracker.bytesPerSecond(System.currentTimeMillis())
        val eta = speedTracker.etaMillis(System.currentTimeMillis(), state.totalBytes)
        val text = buildString {
            append(getString(R.string.update_download_progress_line, percent, state.assetName))
            append("\n")
            append(speed.toSpeedString())
            if (eta != null && eta > 0L) {
                append(" • ").append(getString(R.string.update_download_eta, formatEta(eta)))
            }
        }
        showNotification(
            baseBuilder()
                .setContentTitle(getString(R.string.update_download_notification_title))
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                .setProgress(100, percent, false)
                .setOngoing(true)
                .addAction(R.drawable.ic_pause_24dp, getString(R.string.update_download_action_pause), servicePendingIntent(ACTION_PAUSE))
                .addAction(R.drawable.ic_close_24dp, getString(R.string.action_cancel), servicePendingIntent(ACTION_CANCEL))
        )
    }

    private fun showPausedNotification() {
        val percent = currentPercent()
        showNotification(
            baseBuilder()
                .setContentTitle(getString(R.string.update_download_notification_title))
                .setContentText(getString(R.string.update_download_paused_line, percent))
                .setProgress(100, percent, false)
                .setOngoing(true)
                .addAction(R.drawable.ic_play_24dp, getString(R.string.update_download_action_resume), servicePendingIntent(ACTION_RESUME))
                .addAction(R.drawable.ic_close_24dp, getString(R.string.action_cancel), servicePendingIntent(ACTION_CANCEL))
        )
    }

    /** Склейка/проверка: прогресс неопределённый, без кнопок (идёт секунды). */
    private fun showMergingNotification() {
        showNotification(
            baseBuilder()
                .setContentTitle(getString(R.string.update_download_notification_title))
                .setContentText(getString(R.string.update_download_merging))
                .setProgress(0, 0, true)
                .setOngoing(true)
        )
    }

    private fun showWaitingNetworkNotification() {
        val percent = currentPercent()
        showNotification(
            baseBuilder()
                .setContentTitle(getString(R.string.update_download_notification_title))
                .setContentText(getString(R.string.update_download_waiting_network_line, percent))
                .setProgress(100, percent, false)
                .setOngoing(true)
                .addAction(R.drawable.ic_close_24dp, getString(R.string.action_cancel), servicePendingIntent(ACTION_CANCEL))
        )
    }

    /**
     * Готово к установке: уведомление НЕ ongoing, с действием «Установить»,
     * которое вызывает установщик прямо из шторки — даже если пользователь
     * давно вышел из клиента (требование владельца).
     */
    private fun showReadyNotification(apkFile: File) {
        showNotification(
            baseBuilder()
                .setSmallIcon(R.drawable.ic_check_update_24dp)
                .setContentTitle(getString(R.string.update_download_ready_title))
                .setContentText(getString(R.string.update_download_ready_text, apkFile.name))
                .setOngoing(false)
                .setAutoCancel(true)
                .addAction(R.drawable.ic_check_update_24dp, getString(R.string.update_download_action_install), servicePendingIntent(ACTION_INSTALL))
        )
    }

    private fun showFailedNotification(reason: String) {
        showNotification(
            baseBuilder()
                .setSmallIcon(R.drawable.ic_close_24dp)
                .setContentTitle(getString(R.string.update_download_failed_title))
                .setContentText(reason)
                .setStyle(NotificationCompat.BigTextStyle().bigText(reason))
                .setOngoing(false)
                .setAutoCancel(false)
                .addAction(R.drawable.ic_refresh_24dp, getString(R.string.update_download_action_retry), buildRetryPendingIntent())
        )
    }

    private fun showCancelledNotification() {
        showNotification(
            baseBuilder()
                .setContentTitle(getString(R.string.update_download_notification_title))
                .setContentText(getString(R.string.update_download_cancelled))
                .setOngoing(false)
                .setAutoCancel(true)
                .addAction(R.drawable.ic_refresh_24dp, getString(R.string.update_download_action_resume), buildRetryPendingIntent())
        )
    }

    private fun buildRetryPendingIntent(): PendingIntent {
        val persisted = UpdateDownloadStore.load()
        return if (persisted != null && persisted.browserDownloadUrl.isNotEmpty()) {
            val intent = Intent(this, UpdateDownloadService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_RELEASE_TAG, persisted.releaseTag)
                putExtra(EXTRA_ASSET_NAME, persisted.assetName)
                putExtra(EXTRA_DOWNLOAD_URL, persisted.browserDownloadUrl)
                putExtra(EXTRA_CHECKSUMS_URL, persisted.checksumsUrl)
                putExtra(EXTRA_EXPECTED_SHA256, persisted.expectedSha256)
                putExtra(EXTRA_DECLARED_SIZE, persisted.declaredSize)
            }
            PendingIntent.getService(this, 1, intent, piFlags)
        } else {
            // Нечего возобновлять: открываем экран проверки обновлений.
            checkUpdatePendingIntent()
        }
    }

    private val piFlags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE

    /** Тап по уведомлению — открыть клиент. */
    private fun buildMainPendingIntent(): PendingIntent =
        PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), piFlags)

    /** Кнопка-команда самому сервису (пауза/возобновить/отмена/установить). */
    private fun servicePendingIntent(action: String): PendingIntent =
        PendingIntent.getService(
            this,
            action.hashCode(),
            Intent(this, UpdateDownloadService::class.java).setAction(action),
            piFlags,
        )

    /** Открыть экран проверки обновлений (когда возобновлять нечего). */
    private fun checkUpdatePendingIntent(): PendingIntent =
        PendingIntent.getActivity(this, 2, Intent(this, CheckUpdateActivity::class.java), piFlags)

    private fun formatEta(millis: Long): String {
        val totalSeconds = millis / 1000L
        val h = totalSeconds / 3600L
        val m = (totalSeconds % 3600L) / 60L
        val s = totalSeconds % 60L
        return when {
            h > 0L -> getString(R.string.update_download_eta_hms, h, m, s)
            m > 0L -> getString(R.string.update_download_eta_ms, m, s)
            else -> getString(R.string.update_download_eta_s, s)
        }
    }

    // -------------------------------------------------------------------------
    // Сеть, состояние, вспомогательное
    // -------------------------------------------------------------------------

    /**
     * Маршрут загрузки. Требование владельца: свитч «через включённый профиль»
     * ВКЛ — загрузка идёт через активный профиль; ВЫКЛ — напрямую. Резолвер
     * переиспользуется (ActiveProfileRoute), как у проверки обновлений.
     *
     * Если профиль потребован, но не запущен/без loopback-порта — загрузка
     * честно отклоняется (тот же принцип, что у UpdateCheckerManager: прямой
     * сокет обошёл бы профиль, приложение исключено из собственного туннеля).
     */
    private suspend fun resolveRoute(viaProfile: Boolean): UpdateHttpClient.RouteConfig {
        val route = ActiveProfileRoute.resolve()
        ActiveProfileRoute.log("Update download", route)
        if (!viaProfile) {
            // Прямой канал. Но если профиль поднял loopback-прокси, всё равно
            // идём напрямую: свитч ВЫКЛ = «скачивание должно идти напрямую».
            return UpdateHttpClient.RouteConfig()
        }
        return when (route.mode) {
            ActiveProfileRoute.Mode.LOCAL_HTTP_PROXY -> UpdateHttpClient.RouteConfig(
                proxyHost = route.httpHost,
                proxyPort = route.httpPort,
                proxyUsername = route.proxyUsername,
                proxyPassword = route.proxyPassword,
            )

            ActiveProfileRoute.Mode.TUNNEL_DIRECT -> UpdateHttpClient.RouteConfig()

            else -> throw IllegalStateException(getString(R.string.toast_requires_active_proxy_no_local_proxy))
        }
    }

    private inner class ConnectivityCallback : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            if (networkAvailable.compareAndSet(false, true)) {
                UpdateDownloadLogger.log(this@UpdateDownloadService, "network available again, resuming")
                if (state.phase == DownloadState.Phase.WAITING_NETWORK && !pausedFlag.get()) {
                    persistPhase(DownloadState.Phase.DOWNLOADING)
                }
            }
        }

        override fun onLost(network: Network) {
            // Сеть пропала (обрыв/Wi-Fi->mobile/режим полёта): НЕ отменяем
            // загрузку, ждём появления (требование «не останавливаться»).
            if (networkAvailable.compareAndSet(true, false)) {
                UpdateDownloadLogger.log(this@UpdateDownloadService, "network lost, waiting (download not cancelled)")
                persistPhase(DownloadState.Phase.WAITING_NETWORK)
            }
        }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            val validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            if (validated && networkAvailable.compareAndSet(false, true)) {
                if (state.phase == DownloadState.Phase.WAITING_NETWORK && !pausedFlag.get()) {
                    persistPhase(DownloadState.Phase.DOWNLOADING)
                }
            }
        }
    }

    private fun registerNetworkCallback() {
        if (networkCallback != null) return
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        networkCallback = ConnectivityCallback().also {
            runCatching { cm.registerNetworkCallback(request, it) }
                .onFailure { e -> LogUtil.w(AppConfig.TAG, "network callback register failed", e) }
        }
        // Стартовое состояние: есть ли сеть прямо сейчас.
        val active = cm.activeNetwork?.let { n ->
            cm.getNetworkCapabilities(n)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
        } ?: false
        networkAvailable.set(active)
    }

    private fun unregisterNetworkCallback() {
        val cb = networkCallback ?: return
        networkCallback = null
        runCatching {
            (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).unregisterNetworkCallback(cb)
        }
    }

    private fun registerCall(call: Call) {
        activeCalls.add(call)
        // Одновременно активных вызовов не больше числа сегментов (<=24):
        // каждый сегмент держит один запрос за раз. Отменённые call'ы точно
        // мертвы — подчищаем их, чтобы множество не росло на длинных загрузках
        // с сотнями ретраев. НЕ трогаем isExecuted(): onCall вызывается ДО
        // execute(), поэтому свежий call ещё «не выполнен» и его удаление было
        // бы ошибкой (проверка isCanceled() от таких защищена).
        if (activeCalls.size > 64) {
            activeCalls.removeAll { it.isCanceled() }
        }
    }

    private fun cancelActiveCalls() {
        val snapshot = activeCalls.toList()
        activeCalls.clear()
        snapshot.forEach { runCatching { it.cancel() } }
    }

    /** Пауза изнутри сегментного цикла: ждём снятия флага, не выходим из джоба. */
    private suspend fun waitWhilePaused() {
        while (pausedFlag.get() && !cancelledFlag.get()) {
            delay(500L)
        }
    }

    private fun persistPhase(phase: DownloadState.Phase) {
        persistState(state.copy(phase = phase))
    }

    /**
     * Единственная точка записи состояния: synchronized, потому что сегменты
     * пишут прогресс параллельно из разных корутин, а тикер и команды читают и
     * обновляют фазу одновременно. Без лока возможны потерянные обновления
     * карты segmentDone (копия state перезаписала бы чужой прогресс).
     */
    @Synchronized
    private fun persistState(newState: DownloadState) {
        state = newState.touch(System.currentTimeMillis())
        UpdateDownloadStore.save(state)
    }

    /** Прогресс сегмента: фактическая длина part-файла — источник истины. */
    @Synchronized
    private fun persistSegmentProgress(index: Int, bytes: Long) {
        val updated = state.segmentDone.toMutableMap().apply { put(index, bytes) }
        state = state.copy(segmentDone = updated).touch(System.currentTimeMillis())
        UpdateDownloadStore.save(state)
    }

    private fun failDownload(reason: String, keepNotification: Boolean = true) {
        persistState(state.copy(phase = DownloadState.Phase.FAILED, lastError = reason))
        UpdateDownloadLogger.log(this, "FAILED: $reason")
        stopProgressTicker()
        if (keepNotification) {
            showFailedNotification(reason)
        }
        MessageHelper.sendMsg2UI(this, AppConfig.MSG_UPDATE_DOWNLOAD_FAILED, reason)
        unregisterNetworkCallback()
        // DETACH: уведомление об ошибке (с кнопкой «Повторить») остаётся в
        // шторке после остановки сервиса; stopSelf без detach снял бы его.
        stopForeground(STOP_FOREGROUND_DETACH)
        stopSelf()
    }

    private fun broadcastReady(apkPath: String) {
        MessageHelper.sendMsg2UI(this, AppConfig.MSG_UPDATE_DOWNLOAD_READY, apkPath)
    }

    /**
     * Прогресс для UI: JSON текущего состояния раз в секунду.
     *
     * Важно: [DownloadState.segmentDone] обновляется только на границах попыток
     * сегмента (писать MMKV на каждый чанк дорого), поэтому для ЖИВОГО
     * процента/скорости в UI подставляем синтетический segmentDone из
     * [bytesWrittenTotal] (байты на диске + записанные в этой сессии). Это
     * только отображение — персистентное состояние и склейка опираются на
     * реальные part-файлы. UI считает скорость своим SpeedTracker по этим
     * ежесекундным точкам.
     */
    private fun broadcastProgress() {
        val liveDone = bytesWrittenTotal.get().coerceAtLeast(0L)
        val uiState = state.copy(
            segmentDone = mapOf(-1 to liveDone),
            updatedAt = System.currentTimeMillis(),
        )
        MessageHelper.sendMsg2UI(this, AppConfig.MSG_UPDATE_DOWNLOAD_PROGRESS, JsonUtil.toJson(uiState))
    }

    /**
     * Удаляет part-файлы и временный файл склейки для [assetName]. Используется
     * при старте НОВОЙ цели (не докачки), чтобы чужие байты не попали в склейку.
     * Итоговый проверенный APK не трогается.
     */
    private fun clearPartFiles(assetName: String) {
        val removed = (0 until SegmentPlan.MAX_SEGMENTS).count { idx ->
            UpdatePaths.partFile(workDir, assetName, idx).delete()
        }
        UpdatePaths.mergeTempFile(workDir, assetName).delete()
        UpdateDownloadLogger.log(this, "cleared $removed stale part files for new target $assetName")
    }

    /** Останавливает сервис, если активной загрузки нет. */
    private fun stopSelfIfIdle() {
        if (downloadJob?.isActive != true) {
            stopProgressTicker()
            unregisterNetworkCallback()
            stopSelf()
        }
    }
}
