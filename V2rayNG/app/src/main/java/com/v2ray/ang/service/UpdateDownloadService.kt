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
import com.v2ray.ang.util.updater.UpdateUrlPolicy
import java.io.File
import java.io.IOException
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.coroutineContext
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
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.OkHttpClient

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

    /**
     * Сигналы паузы/отмены, пробрасываемые из колбэка записи байт.
     *
     * ОБА наследуют IOException НАМЕРЕННО, а не CancellationException.
     *
     * Почему это важно (найденный аудитом дефект): раньше при паузе колбэк
     * бросал CancellationException. В [downloadSegmentLoop] такой перехват
     * делал `return`, то есть сегмент завершался НАВСЕГДА. Но параллельно
     * [cancelActiveCalls] рвёт сокет, и часть сегментов получала вместо этого
     * обычный IOException -> Transient -> оставалась ждать в цикле. Возникала
     * смешанная картина: одни сегменты вышли, другие ждут. После «Продолжить»
     * дожили бы только ждущие, а вышедшие остались бы недокачанными, и склейка
     * упала бы с «segment N incomplete», хотя part-файлы целы.
     *
     * Теперь оба сигнала идут ЕДИНЫМ путём: IOException -> Transient ->
     * следующая итерация цикла, где флаг проверяется в самом верху
     * (пауза -> ожидание, отмена -> выход). Поведение всех сегментов
     * одинаковое, независимо от того, что успело произойти первым: проверка
     * флага в колбэке или разрыв сокета.
     *
     * Реальная отмена корутины (downloadJob.cancel()) по-прежнему даёт
     * CancellationException и обрабатывается отдельно.
     */
    private class PausedException : IOException("download paused by user")
    private class CancelledException : IOException("download cancelled by user")

    /**
     * Загрузка обязана идти через профиль, но профиль не пригоден прямо сейчас
     * (выключен, или запущен без loopback-прокси).
     *
     * Отдельный тип нужен, чтобы старт/возобновление при выключенном профиле
     * завершались как PROFILE_LOST (part-файлы сохраняются, показывается
     * «Профиль отключён — загрузка прервана»), а не как общая FAILED-ошибка:
     * это разные ситуации с разным продолжением. Возникает, например, при
     * возобновлении после перезагрузки, когда автозапуск VPN не поднял профиль.
     */
    private class ProfileRequiredException(message: String) : IllegalStateException(message)

    companion object {
        private const val ACTIONS_PREFIX = "${AppConfig.ANG_PACKAGE}.action."

        /** Начать/возобновить загрузку релиза (extras: tag, asset, url, sums, size). */
        const val ACTION_START = ACTIONS_PREFIX + "update.download.start"
        const val ACTION_PAUSE = ACTIONS_PREFIX + "update.download.pause"
        const val ACTION_RESUME = ACTIONS_PREFIX + "update.download.resume"
        /** Отмена: НЕ удаляет part-файлы (докачка продолжится при следующем старте). */
        const val ACTION_CANCEL = ACTIONS_PREFIX + "update.download.cancel"

        /**
         * Сброс устаревшей готовности: UI обнаружил, что проверенный APK удалён
         * из папки загрузки вручную, и просит сервис снять состояние
         * READY_TO_INSTALL и уведомление «Готово к установке». Без этого экран
         * продолжал бы показывать кнопку «Установить» для несуществующего файла
         * (баг, найденный владельцем).
         */
        const val ACTION_CLEAR_READY = ACTIONS_PREFIX + "update.download.clear_ready"

        /**
         * Полное снятие устаревшего состояния загрузки (любая фаза): состояние
         * переживало и установку обновления вручную, и проверку «обновлений
         * нет», из-за чего экран показывал блок с кнопками «Продолжить/Отмена»
         * для релиза, который уже не новее установленного, а «Продолжить»
         * скачивал старую цель (дефекты устройства 19.11). Команда останавливает
         * идущую загрузку, чистит MMKV-состояние и снимает уведомление.
         * Part-файлы НЕ удаляются (правило «отмена не удаляет скачанное»).
         */
        const val ACTION_CLEAR_STATE = ACTIONS_PREFIX + "update.download.clear_state"

        /**
         * requestCode PendingIntent'а кнопки «Установить» в уведомлении.
         *
         * Отдельного действия ACTION_INSTALL для сервиса НЕТ: кнопка ведёт
         * PendingIntent.getActivity прямо в системный установщик (см.
         * showReadyNotification). Команда сервису была бы недостижимым кодом, а
         * на Android 12+ startService из фона ещё и бросал бы исключение —
         * именно поэтому установка из шторки сделана через Activity-intent.
         */
        private const val REQUEST_CODE_INSTALL = 3

        /** Ключ маршрута для прямого канала (без прокси профиля). */
        private const val KEY_ROUTE_DIRECT = "direct"

        /**
         * Минимальный интервал между повторными TCP-пробами маршрута (мс).
         * Совпадает с интервалом наблюдателя профиля: чаще всё равно ничего не
         * меняется, а каждый resolve() — это реальная попытка соединения.
         */
        private const val ROUTE_RECHECK_TTL_MS = 2_000L

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
         * Интервал проверки живости профиля (мс).
         *
         * [ActiveProfileRoute.resolve] делает TCP-пробу loopback-порта, поэтому
         * слишком частый опрос был бы лишней нагрузкой; 2 секунды достаточно,
         * чтобы пользователь увидел остановку почти сразу после выключения
         * профиля, и при этом не дёргать сокет постоянно на медленной сети.
         */
        private const val PROFILE_WATCH_INTERVAL_MS = 2_000L

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
    private var profileWatchJob: Job? = null
    private var networkCallback: ConnectivityCallback? = null
    private val networkAvailable = AtomicBoolean(true)

    /**
     * Загрузка ОБЯЗАНА идти через активный профиль (свитч «через включённый
     * профиль» включён). Пока флаг true, [profileWatchJob] следит за профилем и
     * останавливает загрузку при его отключении — требование владельца:
     * «если профиль отключился во время скачивания, нужно останавливать
     * загрузку… тост, ошибка в логах и в уведомлении».
     */
    @Volatile
    private var requireProfile = false

    /**
     * Активный HTTP-клиент загрузки. @Volatile, потому что его пересоздаёт
     * наблюдатель профиля (отдельная корутина), а читают его сегментные корутины
     * на КАЖДОЙ итерации ретрая.
     *
     * Зачем пересоздавать: клиент держит конкретный loopback-прокси запущенного
     * ядра (адрес+порт+креды). Если пользователь переключил профиль, ядро
     * поднимает inbound на ДРУГОМ порту (порт может быть динамическим), и старый
     * клиент навсегда упирался бы в мёртвый порт: все сегменты бесконечно
     * получали бы Transient-ошибки. Это нарушало бы требование «скачивание не
     * должно останавливаться» — загрузка зависла бы без видимой причины.
     *
     * При ВЫКЛЮЧЕННОМ свитче «через профиль» клиент всегда прямой и не меняется.
     */
    @Volatile
    private var currentClient: OkHttpClient? = null

    /** Сигнатура маршрута, под который собран [currentClient] (для детекции смены). */
    @Volatile
    private var clientRouteKey: String = ""

    /**
     * Сериализует пересборку клиента и троттлит TCP-пробу маршрута.
     *
     * [currentClientFresh] вызывается КАЖДЫМ сегментом на КАЖДОЙ итерации ретрая,
     * то есть до 24 параллельных вызовов. При включённом свитче «через профиль»
     * каждый вызов делал бы ActiveProfileRoute.resolve() с TCP-пробой loopback-
     * порта — 24 одновременные пробы на каждом массовом ретрае (например, когда
     * сеть вернулась после обрыва и все сегменты проснулись разом). Мьютекс
     * сводит резолв к одному, а [ROUTE_RECHECK_TTL_MS] не даёт долбить порт чаще
     * необходимого.
     */
    private val routeMutex = Mutex()

    @Volatile
    private var lastRouteResolveMs = 0L

    /**
     * Атомарный флаг «остановка из-за профиля уже выполнена».
     *
     * [abortProfileLost] могут вызвать ДВА независимых источника почти
     * одновременно: наблюдатель профиля ([startProfileWatch]) и перехват
     * [ProfileRequiredException] в [launchDownload] (старт/возобновление при
     * выключенном профиле). Без флага пользователь получил бы ДВА одинаковых
     * тоста, а лог — дубль записи. compareAndSet гарантирует однократность.
     */
    private val profileAbortDone = AtomicBoolean(false)

    /**
     * Поколение текущей загрузки. Увеличивается в [launchDownload] при каждом
     * старте/возобновлении.
     *
     * Зачем (дефект найден по живому логу устройства 19.11): [launchDownload]
     * отменяет прежний job, но отменённая корутина может находиться ВНУТРИ
     * блокирующего IO без suspend-точек (склейка [mergeAndVerify], публикация
     * [onVerified], [failDownload]) и дожить до своего финала ПОЗЖЕ старта
     * нового поколения. Без защиты она перезаписала бы state, уведомление и
     * broadcastReady ЦУЖОЙ целью (старым релизом) поверх новой загрузки.
     * Проверка поколения в точках записи финального состояния делает такой
     * «призрак» безопасным: его результат игнорируется и пишется в лог.
     */
    @Volatile
    private var downloadGeneration = 0L

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
        requireProfile = false
        stopProfileWatch()
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
        // получить startForeground быстро. Команды паузы/отмены приходят в уже
        // поднятый сервис, и повторный startForeground просто обновляет
        // уведомление — это безопасно и соответствует контракту.
        //
        // ИСКЛЮЧЕНИЕ — ACTION_CLEAR_READY: сервис поднимается обычным
        // startService (FGS-контракта нет), а задача команды — СНЯТЬ уведомление
        // «Готово к установке». Показ FGS-уведомления здесь дал бы мерцание:
        // уведомление появилось бы на мгновение и тут же было отменено.
        if (action != ACTION_CLEAR_READY && action != ACTION_CLEAR_STATE) {
            ensureForeground()
        }
        when (action) {
            ACTION_START ->
                // `!!` не нужен: K2 выводит non-null из ветки when, потому что
                // action = intent?.action и совпадение с не-null константой
                // возможно только при ненулевом intent. Лишнее утверждение
                // давало warning «Unnecessary non-null assertion».
                handleStart(intent)
            ACTION_PAUSE -> handlePause()
            ACTION_RESUME -> handleResume()
            ACTION_CANCEL -> handleCancel()
            ACTION_CLEAR_READY -> handleClearReady()
            ACTION_CLEAR_STATE -> handleClearState()
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
                cancelledFlag.set(false)
                // Сбрасываем флаг однократности остановки по потере профиля:
                // иначе НОВАЯ остановка по той же причине была бы проигнорирована
                // как «дубль» (см. profileAbortDone), и пользователь не получил бы
                // ни тоста, ни уведомления.
                profileAbortDone.set(false)
                bytesWrittenTotal.set(state.downloadedBytes())
                speedTracker.reset()
                registerNetworkCallback()
                launchDownload()
                return
            }

            UpdateDecisions.StartDecision.AlreadyDownloaded -> {
                state = existing ?: return
                // Приоритет сохранённому apkPath: рабочая папка могла быть
                // резервной приватной (filesDir/updates), и пересчёт от workDir
                // дал бы ложное «файл исчез» с лишней полной перезакачкой.
                val apk = state.apkPath.takeIf { it.isNotBlank() }?.let(::File)
                    ?: UpdatePaths.apkFile(workDir, state.assetName)
                if (apk.exists()) {
                    showReadyNotification(apk)
                    broadcastReady(apk.absolutePath)
                    // Сервис свою работу сделал: файл проверен и готов. Без
                    // остановки FGS висел бы вечно с не-ongoing уведомлением
                    // «Готово» (утечка сервиса). DETACH сохраняет уведомление
                    // с кнопкой «Установить» в шторке после смерти сервиса.
                    stopForeground(STOP_FOREGROUND_DETACH)
                    stopSelf()
                    return
                }
                // Файл удалён вручную: готовность устарела — качаем заново тем
                // же путём (part-файлов после успеха уже нет, качается начисто).
                UpdateDownloadLogger.log(this, "READY state but APK missing (${apk.absolutePath}); re-downloading")
            }

            UpdateDecisions.StartDecision.SwitchTarget -> {
                // Другой релиз: начинаем новое состояние. Part-файлы старого
                // релиза с тем же именем ассета ЧУЖИЕ новой цели и удаляются
                // ниже общим путём (clearPartFiles при !trustExistingParts):
                // иначе их байты попали бы в склейку нового релиза. Правило
                // «отмена не удаляет» относится к ACTION_CANCEL, не к смене цели.
                UpdateDownloadLogger.log(
                    this,
                    "switch target: ${existing?.releaseTag}/${existing?.assetName} -> $releaseTag/$assetName (old parts kept)"
                )
            }

            else -> Unit
        }

        pausedFlag.set(false)
        cancelledFlag.set(false)
        profileAbortDone.set(false)
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
            // Подпись раскладки обязана восстанавливаться вместе с part-файлами:
            // без неё partsReusable("") вернула бы false, и докачка после
            // kill/перезагрузки стирала бы собственные part-файлы на каждой
            // итерации — прямое нарушение требования «докачка при kill процесса,
            // перезагрузке устройства».
            planSignature = restoredExisting?.planSignature.orEmpty(),
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
            // Приоритет сохранённому apkPath: рабочая папка могла быть
            // резервной приватной (filesDir/updates), и пересчёт от workDir
            // дал бы ложное «файл удалён» с сбросом валидной готовности.
            val apk = persisted.apkPath.takeIf { it.isNotBlank() }?.let(::File)
                ?: UpdatePaths.apkFile(workDir, persisted.assetName)
            if (apk.exists()) {
                showReadyNotification(apk)
                // См. handleStart: сервис не нужен, уведомление остаётся.
                stopForeground(STOP_FOREGROUND_DETACH)
                stopSelf()
                return
            }
            // APK действительно удалён: снимаем устаревшую готовность вместе с
            // уведомлением, чтобы в шторке не висела кнопка для пустоты.
            UpdateDownloadLogger.log(this, "persisted READY but APK missing (${apk.absolutePath}); clearing")
            UpdateDownloadStore.clear()
            state = DownloadState()
            NotificationHelper.cancel(NotificationChannelType.UPDATE_DOWNLOAD, this)
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
        profileAbortDone.set(false)
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

    /**
     * Сброс устаревшей готовности (файл удалён из папки загрузки вручную).
     *
     * Проверяет ФАКТ: если проверенный APK всё ещё на месте — ничего не делаем
     * (команда пришла от гонки UI/сервиса, трогать готовность нельзя). Если
     * файла нет — очищаем персистентное состояние и снимаем уведомление
     * «Готово к установке», иначе пользователь видел бы кнопку для
     * несуществующего файла и в шторке, и на экране.
     */
    private fun handleClearReady() {
        val persisted = UpdateDownloadStore.load()
        if (persisted == null || persisted.phase != DownloadState.Phase.READY_TO_INSTALL) {
            stopSelfIfIdle()
            return
        }
        val apk = persisted.apkPath.takeIf { it.isNotBlank() }?.let(::File)
            ?: UpdatePaths.apkFile(workDir, persisted.assetName)
        if (apk.exists()) {
            // Файл на месте: готовность актуальна, сбрасывать нечего.
            stopSelfIfIdle()
            return
        }
        UpdateDownloadLogger.log(this, "READY state is stale: verified APK missing (${apk.absolutePath}); clearing state and notification")
        UpdateDownloadStore.clear()
        state = DownloadState()
        NotificationHelper.cancel(NotificationChannelType.UPDATE_DOWNLOAD, this)
        stopSelfIfIdle()
    }

    /**
     * Снятие устаревшего состояния ЛЮБОЙ фазы (см. [ACTION_CLEAR_STATE]).
     * Вызывается UI, когда проверка обновлений установила, что сохранённая
     * цель загрузчика не новее установленного клиента: продолжать её
     * бессмысленно, а блок с кнопками вводил пользователя в заблуждение.
     */
    private fun handleClearState() {
        val persisted = UpdateDownloadStore.load()
        if (persisted == null || persisted.releaseTag.isEmpty()) {
            stopSelfIfIdle()
            return
        }
        UpdateDownloadLogger.log(this, "stale download state cleared by UI: ${persisted.releaseTag}/${persisted.assetName} at phase ${persisted.phase}")
        cancelledFlag.set(true) // останавливает сегментные циклы идущей загрузки
        // Смена поколения ОБЯЗАТЕЛЬНА: умирающая блокирующая склейка иначе
        // дожила бы onVerified/persistSegmentProgress ПОСЛЕ очистки и
        // воскресила состояние READY (уведомление, store) поверх снятого.
        downloadGeneration++
        requireProfile = false
        stopProfileWatch()
        cancelActiveCalls()
        downloadJob?.cancel()
        downloadJob = null
        stopProgressTicker()
        unregisterNetworkCallback()
        UpdateDownloadStore.clear()
        state = DownloadState()
        NotificationHelper.cancel(NotificationChannelType.UPDATE_DOWNLOAD, this)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun handlePause() {
        if (!state.isActive()) {
            stopSelfIfIdle()
            return
        }
        pausedFlag.set(true)
        persistPhase(DownloadState.Phase.PAUSED)
        UpdateDownloadLogger.log(this, "paused by user at ${state.progressPercent()}% (${state.downloadedBytes()} of ${state.totalBytes} bytes)")
        // На паузе загрузка не идёт, поэтому терять профиль нечего: наблюдение
        // приостанавливаем, чтобы оно не превратило ручную паузу в PROFILE_LOST.
        stopProfileWatch()
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
        profileAbortDone.set(false)
        cancelledFlag.set(false)

        // Если за это время файл уже готов и лежит на диске (например, готовность
        // пришла, пока пользователь смотрел на кнопку «Продолжить»), перезакачка
        // не нужна: показываем готовность и выходим.
        if (persisted.phase == DownloadState.Phase.READY_TO_INSTALL) {
            val apk = persisted.apkPath.takeIf { it.isNotBlank() }?.let(::File)
                ?: UpdatePaths.apkFile(workDir, persisted.assetName)
            if (apk.exists()) {
                showReadyNotification(apk)
                stopForeground(STOP_FOREGROUND_DETACH)
                stopSelf()
                return
            }
        }

        // Возобновление после остановки (пауза, отмена, PROFILE_LOST) всегда
        // продолжает докачку ТОЙ ЖЕ цели: part-файлы на диске доверенные, их
        // байты надо учесть в прогрессе (иначе шкала упала бы в ноль, хотя
        // половина файла уже скачана).
        trustExistingParts = true
        bytesWrittenTotal.set(persisted.downloadedBytes())
        speedTracker.reset()
        if (downloadJob?.isActive != true) {
            registerNetworkCallback()
            // Уведомление переключаем на прогресс НЕМЕДЛЕННО, до probe: пока
            // фаза PROBING (до нескольких секунд на плохой сети), в шторке
            // иначе оставалось бы ПРЕЖНЕЕ уведомление с кнопкой «Продолжить» —
            // пользователь тапал её повторно и плодил дубли команд (видно в
            // логе устройства: 5 «resumed by user» за 1.5 секунды).
            persistPhaseIfChanged(DownloadState.Phase.DOWNLOADING)
            showProgressNotification()
            launchDownload()
        } else {
            persistPhaseIfChanged(DownloadState.Phase.DOWNLOADING)
            showProgressNotification()
            // Загрузка продолжается тем же клиентом и маршрутом: восстанавливаем
            // наблюдение за профилем (на паузе оно было приостановлено).
            // Актуальность требования монитор проверит сам на первом тике.
            requireProfile = UpdateDownloadStore.viaActiveProfile()
            if (requireProfile) startProfileWatch(downloadGeneration)
        }
        UpdateDownloadLogger.log(this, "resumed by user at ${state.progressPercent()}%")
    }

    private fun handleCancel() {
        cancelledFlag.set(true)
        persistPhase(DownloadState.Phase.CANCELLED)
        // Требование владельца: отмена НЕ удаляет скачанное — part-файлы
        // остаются, следующий «Скачать» продолжит докачку с того же байта.
        UpdateDownloadLogger.log(this, "cancelled by user at ${state.progressPercent()}%; part files KEPT in ${workDir.absolutePath}")
        requireProfile = false
        stopProfileWatch()
        cancelActiveCalls()
        downloadJob?.cancel()
        downloadJob = null
        // Отмена — окончательный финал: умирающий job может доживать
        // блокирующую склейку. Сменой поколения его onVerified/failDownload/
        // HashMismatch становятся немыми, иначе отменённая загрузка успела бы
        // показать «Готово к установке» и позвать установщик.
        downloadGeneration++
        showCancelledNotification()
        MessageHelper.sendMsg2UI(this, AppConfig.MSG_UPDATE_DOWNLOAD_FAILED, getString(R.string.update_download_cancelled))
        stopProgressTicker()
        unregisterNetworkCallback()
        // DETACH: уведомление «Отменено» с кнопкой «Продолжить» остаётся в
        // шторке после остановки сервиса.
        stopForeground(STOP_FOREGROUND_DETACH)
        stopSelf()
    }

    // -------------------------------------------------------------------------
    // Основной цикл загрузки
    // -------------------------------------------------------------------------

    private fun launchDownload() {
        downloadJob?.cancel()
        val gen = ++downloadGeneration
        // Новая сессия загрузки: счётчик проблем логгера обнуляется. Лог-файл
        // удалится после успешного READY только если ЭТА сессия прошла без
        // единой ошибки/заминки (требование владельца 19.11 07:36).
        UpdateDownloadLogger.beginSession()
        // Временные файлы склейки прошлых поколений больше не нужны никому:
        // новая склейка создаст свой temp с суффиксом текущего поколения, а
        // брошенные отменёнными склейками temp — мусор размером с APK.
        // Part-файлы НЕ трогаем: они источник докачки (требование владельца).
        clearMergeTemps()
        downloadJob = serviceScope.launch {
            try {
                runDownload(gen)
            } catch (e: CancellationException) {
                throw e
            } catch (e: ProfileRequiredException) {
                // Профиль обязателен, но не пригоден (выключен / без loopback).
                // Требование владельца: останавливать загрузку, сообщать причину.
                // Идём через PROFILE_LOST, а не FAILED: part-файлы сохраняются,
                // и после включения профиля докачка продолжится с того же байта.
                // this@UpdateDownloadService: catch находится внутри
                // serviceScope.launch, где голый `this` — это CoroutineScope,
                // а логгер требует Context.
                UpdateDownloadLogger.log(this@UpdateDownloadService, "PROFILE REQUIRED but unavailable: ${e.message}")
                abortProfileLost(detail = e.message, gen = gen)
            } catch (e: Exception) {
                LogUtil.e(AppConfig.TAG, "UpdateDownloadService: unexpected failure", e)
                val reason = if (e is IllegalStateException && !e.message.isNullOrBlank()) {
                    e.message!!
                } else {
                    getString(R.string.update_download_error_generic)
                }
                failDownload(reason, keepNotification = true, gen = gen)
            }
        }
    }

    private suspend fun runDownload(gen: Long) {
        startProgressTicker()

        val viaProfile = UpdateDownloadStore.viaActiveProfile()
        // Требование владельца: если загрузка обязана идти через профиль, а
        // профиль ОТКЛЮЧИЛСЯ во время скачивания — загрузку остановить (с тостом,
        // записью в лог и уведомлением), а не продолжать через мёртвый прокси.
        requireProfile = viaProfile
        if (viaProfile) {
            startProfileWatch(gen)
        }
        // Клиент собирается через currentClientFresh(): он же решает маршрут тем
        // же резолвером ActiveProfileRoute, что и проверка обновлений (требование
        // 9 промта — переиспользование), и дальше пересоздаёт клиент при смене
        // профиля. Отдельный resolveRoute() здесь дал бы вторую TCP-пробу порта.
        // Первый вызов собирает клиент и фиксирует ключ маршрута в логе ниже.
        currentClientFresh()
        UpdateDownloadLogger.log(
            this,
            "download run: ${state.releaseTag}/${state.assetName} segments=${state.requestedSegments} " +
                "route=${if (viaProfile) "via active profile ($clientRouteKey)" else "direct"}"
        )

        var fullRestarts = 0
        // Внешний цикл: полный рестарт при смене объекта на сервере (ETag).
        while (coroutineContext.isActive) {
            if (cancelledFlag.get()) return

            // 1) Эталонный хэш: маленький запрос SHA256SUMS.txt того же релиза.
            if (state.expectedSha256.isBlank()) {
                fetchExpectedHash(currentClientFresh())
            }

            // 2) Проба: размер объекта и поддержка Range. Повторяется до успеха —
            //    «загрузка не должна останавливаться» даже на старте.
            var probe = UpdateDownloader.probe(
                client = currentClientFresh(),
                url = state.browserDownloadUrl,
                onCall = { call -> registerCall(call) },
                onCallDone = { call -> unregisterCall(call) },
            )
            while (probe.totalBytes <= 0L) {
                if (cancelledFlag.get()) return
                if (pausedFlag.get()) { waitWhilePaused(); continue }
                if (!networkAvailable.get()) {
                    persistPhaseIfChanged(DownloadState.Phase.WAITING_NETWORK)
                    delay(TICK_INTERVAL_MS)
                    continue
                }
                UpdateDownloadLogger.log(this, "probe failed, retrying in 5s")
                delay(5_000L)
                probe = UpdateDownloader.probe(
                client = currentClientFresh(),
                url = state.browserDownloadUrl,
                onCall = { call -> registerCall(call) },
                onCallDone = { call -> unregisterCall(call) },
            )
            }
            if (cancelledFlag.get()) return

            if (state.declaredSize > 0 && probe.totalBytes != state.declaredSize) {
                // Сверка размера против asset.size (требование 10). Расхождение =
                // объект релиза не тот, за кого себя выдаёт: не качаем.
                failDownload(getString(R.string.update_download_error_size_mismatch, state.declaredSize, probe.totalBytes), gen = gen)
                return
            }

            // Сверка Content-Type (требование 10). Ловит подмену содержимого:
            // например captive-portal в публичной сети отдаёт 200 + text/html со
            // своей страницей. Без проверки мы бы честно скачали HTML и узнали о
            // проблеме только на SHA-256 — поздно и непонятно для пользователя.
            val contentTypeProblem = UpdateUrlPolicy.checkApkContentType(probe.contentType)
            if (contentTypeProblem != null) {
                UpdateDownloadLogger.log(this, "Content-Type rejected: $contentTypeProblem")
                failDownload(getString(R.string.update_download_error_content_type, contentTypeProblem), gen = gen)
                return
            }

            // Part-файлы привязаны к раскладке сегментов. Если между запусками
            // изменилось число потоков (настройка) или размер объекта (сервер
            // пересобрал ассет), прежние part чужие: докачка по ним дала бы
            // битый файл. Подпись «размер:число_сегментов» выявляет это ДО
            // закачки и чистит устаревшие part.
            val signature = SegmentPlan.signature(probe.totalBytes, state.requestedSegments)
            if (trustExistingParts &&
                !SegmentPlan.partsReusable(state.planSignature, probe.totalBytes, state.requestedSegments)
            ) {
                UpdateDownloadLogger.log(
                    this,
                    "segment plan changed (stored=${state.planSignature} now=$signature): clearing stale part files before resume"
                )
                clearPartFiles(state.assetName)
                trustExistingParts = false
                bytesWrittenTotal.set(0L)
                speedTracker.reset()
            }

            persistState(
                state.copy(
                    totalBytes = probe.totalBytes,
                    validator = probe.validator,
                    rangesSupported = probe.rangesSupported,
                    planSignature = signature,
                    phase = DownloadState.Phase.DOWNLOADING,
                )
            )
            UpdateDownloadLogger.log(
                this,
                "probe ok: total=${probe.totalBytes} ranges=${probe.rangesSupported} validator=${probe.validator} plan=$signature"
            )

            val needFullRestart = if (probe.rangesSupported) {
                runSegmented(probe, gen)
            } else {
                runSingleStream(gen)
                false
            }
            if (!needFullRestart) return
            if (cancelledFlag.get()) return

            // Объект на сервере сменился: ВСЕ part-файлы устарели. Чистим их,
            // сбрасываем метаданные и идём на новый круг (свежая проба/хэш).
            if (++fullRestarts > MAX_FULL_RESTARTS) {
                failDownload(getString(R.string.update_download_error_object_changed), gen = gen)
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
        val manifest = UpdateDownloader.fetchSmallText(
            client = client,
            url = sumsUrl,
            onCall = { call -> registerCall(call) },
            onCallDone = { call -> unregisterCall(call) },
        )
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
    private suspend fun runSegmented(probe: UpdateDownloader.Probe, gen: Long): Boolean {
        val plan = SegmentPlan.plan(probe.totalBytes, state.requestedSegments)
        if (plan.isEmpty() || !SegmentPlan.isContiguous(plan, probe.totalBytes)) {
            failDownload("invalid segment plan for total=${probe.totalBytes}", gen = gen)
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
                    downloadSegmentLoop(segment, gen)
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

        mergeAndVerify(plan, probe.totalBytes, gen)
        return false
    }

    /**
     * Цикл одного сегмента: докачка до полного успеха. Переходящие ошибки
     * ретраятся БЕЗ лимита с паузами («даже на 2G/3G загрузка должна хоть
     * как-то идти»), отсутствие сети — ожидание без отмены задачи.
     */
    private suspend fun downloadSegmentLoop(segment: SegmentPlan.Segment, gen: Long): Boolean {
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
                persistPhaseIfChanged(DownloadState.Phase.WAITING_NETWORK)
                delay(TICK_INTERVAL_MS)
                continue
            }
            // Сеть есть, а фаза осталась PAUSED/WAITING_NETWORK — восстанавливаем
            // DOWNLOADING. Полагаться только на ConnectivityCallback нельзя: если
            // registerNetworkCallback упал (нет ACCESS_NETWORK_STATE / OEM-ограничение),
            // фаза залипла бы в «ожидание сети» навсегда при реально идущей закачке.
            if (state.phase == DownloadState.Phase.PAUSED ||
                state.phase == DownloadState.Phase.WAITING_NETWORK
            ) {
                persistPhaseIfChanged(DownloadState.Phase.DOWNLOADING)
            }

            val onBytes: (Long) -> Unit = { bytes ->
                if (cancelledFlag.get()) throw CancelledException()
                if (pausedFlag.get()) throw PausedException()
                bytesWrittenTotal.addAndGet(bytes)
            }
            val outcome = try {
                attempt++
                UpdateDownloader.downloadSegment(
                    // Клиент берётся заново на КАЖДОЙ итерации ретрая: если
                    // пользователь переключил профиль, loopback-порт ядра сменился
                    // и старый клиент упирался бы в мёртвый порт вечно.
                    client = currentClientFresh(),
                    url = state.browserDownloadUrl,
                    partFile = partFile,
                    segmentStart = segment.start,
                    segmentEndInclusive = segment.endInclusive,
                    expectedValidator = state.validator,
                    onBytes = onBytes,
                    onCall = { call -> registerCall(call) },
                    onCallDone = { call -> unregisterCall(call) },
                )
            } catch (e: CancellationException) {
                // Пауза/отмена прервали чтение потока — выходим, part сохранён.
                return false
            } catch (e: ProfileRequiredException) {
                // Профиль обязателен, но пропал (переключили/выключили) — это НЕ
                // переходящая сетевая ошибка: ретраить бессмысленно, иначе сегмент
                // крутился бы вечно. Пробрасываем наверх, там launchDownload
                // остановит загрузку через abortProfileLost() (фаза PROFILE_LOST).
                throw e
            } catch (e: Exception) {
                UpdateDownloader.SegmentOutcome.Transient("${e.javaClass.simpleName}: ${e.message}")
            } finally {
                // Фактическая длина part — источник истины для прогресса.
                // Только для ТЕКУЩЕГО поколения: finally отменённого сегмента
                // иначе дописал бы в segmentDone НОВОЙ цели байты чужих part.
                if (gen == downloadGeneration) {
                    val have = if (partFile.exists()) partFile.length() else 0L
                    persistSegmentProgress(segment.index, have.coerceAtMost(segment.size))
                }
            }

            when (outcome) {
                is UpdateDownloader.SegmentOutcome.Complete -> {
                    persistSegmentProgress(segment.index, segment.size)
                    return false
                }

                is UpdateDownloader.SegmentOutcome.Transient -> {
                    // Пауза/отмена пришли через Transient (см. PausedException):
                    // спать backoff НЕЛЬЗЯ — иначе «Продолжить» сработает с
                    // задержкой до MAX_RETRY_BACKOFF_MS. Идём сразу в начало
                    // цикла, где флаги обработаны корректно.
                    if (pausedFlag.get() || cancelledFlag.get()) continue
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
                    //
                    // Обязательно вычитаем удалённые байты из живого счётчика:
                    // иначе при повторной закачке того же сегмента они попали бы
                    // в bytesWrittenTotal второй раз, и прогресс/скорость
                    // завысились бы (вплоть до залипания на 100% при серии
                    // рестартов). Полный рестарт загрузки сбрасывает счётчик
                    // целиком, здесь нужен точечный вычет.
                    val discarded = if (partFile.exists()) partFile.length() else 0L
                    UpdateDownloadLogger.log(this, "segment ${segment.index} restart: ${outcome.reason} (discarding $discarded bytes)")
                    partFile.delete()
                    if (discarded > 0L) bytesWrittenTotal.addAndGet(-discarded)
                    persistSegmentProgress(segment.index, 0L)
                    delay(RESTART_DELAY_MS)
                }

                is UpdateDownloader.SegmentOutcome.Fatal -> {
                    UpdateDownloadLogger.log(this, "segment ${segment.index} FATAL: ${outcome.reason}")
                    failDownload(getString(R.string.update_download_error_http, outcome.reason), gen = gen)
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
    private suspend fun runSingleStream(gen: Long) {
        UpdateDownloadLogger.log(this, "server has no Range support: single-stream download (resume impossible)")
        // Суффикс поколения: отменённый однопоточный поток может доживать свой
        // блокирующий read и писать в свой файловый дескриптор; без суффикса он
        // делил бы один temp-файл с новым поколением и испортил бы его байты.
        val target = UpdatePaths.mergeTempFile(workDir, state.assetName, "-g$gen")
        while (coroutineContext.isActive) {
            if (cancelledFlag.get()) return
            if (pausedFlag.get()) { delay(500L); continue }
            if (!networkAvailable.get()) {
                persistPhaseIfChanged(DownloadState.Phase.WAITING_NETWORK)
                delay(TICK_INTERVAL_MS)
                continue
            }
            val onBytes: (Long) -> Unit = { bytes ->
                if (cancelledFlag.get()) throw CancelledException()
                if (pausedFlag.get()) throw PausedException()
                bytesWrittenTotal.addAndGet(bytes)
            }
            val outcome = try {
                // Single-stream перезапускается С НУЛЯ на каждой попытке (сервер
                // без Range не может отдать часть объекта), поэтому счётчик
                // сброшен: иначе каждая неудача добавляла бы свои байты повторно
                // и скорость/прогресс завышались бы в разы.
                bytesWrittenTotal.set(0L)
                speedTracker.reset()
                UpdateDownloader.downloadWhole(
                    client = currentClientFresh(),
                    url = state.browserDownloadUrl,
                    targetFile = target,
                    onBytes = onBytes,
                    onCall = { call -> registerCall(call) },
                    onCallDone = { call -> unregisterCall(call) },
                )
            } catch (e: CancellationException) {
                return
            } catch (e: ProfileRequiredException) {
                // См. downloadSegmentLoop: потеря обязательного профиля — не
                // сетевой сбой, пробрасываем для остановки загрузки.
                throw e
            } catch (e: Exception) {
                UpdateDownloader.SegmentOutcome.Transient("${e.javaClass.simpleName}: ${e.message}")
            }
            when (outcome) {
                is UpdateDownloader.SegmentOutcome.Complete -> {
                    verifySingleFile(target, gen)
                    return
                }
                is UpdateDownloader.SegmentOutcome.Transient -> {
                    // Пауза/отмена -> без пятисекундного сна, флаги проверит
                    // начало цикла.
                    if (pausedFlag.get() || cancelledFlag.get()) continue
                    UpdateDownloadLogger.log(this, "single-stream transient error, retrying in 5s: ${outcome.reason}")
                    delay(5_000L)
                }
                is UpdateDownloader.SegmentOutcome.Restart,
                is UpdateDownloader.SegmentOutcome.Fatal -> {
                    val reason = if (outcome is UpdateDownloader.SegmentOutcome.Fatal) outcome.reason else (outcome as UpdateDownloader.SegmentOutcome.Restart).reason
                    failDownload(reason, gen = gen)
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
    private fun verifySingleFile(tempFile: File, gen: Long) {
        if (gen != downloadGeneration) {
            UpdateDownloadLogger.log(this, "stale download generation $gen (current $downloadGeneration): single-stream verify result ignored")
            tempFile.delete()
            return
        }
        val apk = UpdatePaths.apkFile(workDir, state.assetName)
        val expected = state.expectedSha256
        if (expected.isBlank()) {
            tempFile.delete()
            failDownload(getString(R.string.update_download_error_no_checksum), gen = gen)
            return
        }
        persistPhase(DownloadState.Phase.VERIFYING)
        // hashFile возвращает null, если файл пропал (чистка каталога/сбой ФС):
        // это НЕ «хэш не совпал», а невозможность проверить — ставим общий сбой.
        val actual = UpdateHashVerifier.hashFile(tempFile)
        if (actual == null) {
            UpdateDownloadLogger.log(this, "single-stream: cannot hash downloaded file (missing?)")
            tempFile.delete()
            failDownload(getString(R.string.update_download_error_generic), gen = gen)
            return
        }
        if (!UpdateHashVerifier.equalsHex(actual, expected)) {
            tempFile.delete()
            UpdateDownloadLogger.log(this, "single-stream SHA-256 MISMATCH: actual=$actual expected=$expected")
            failDownload(getString(R.string.update_download_error_checksum), gen = gen)
            return
        }
        // Повторная проверка поколения ПЕРЕД публикацией файла: между хэшем и
        // rename могла стартовать новая загрузка — тогда байты устаревшей цели
        // не должны лечь в итоговый APK.
        if (gen != downloadGeneration) {
            UpdateDownloadLogger.log(this, "stale download generation $gen (current $downloadGeneration): single-stream publish aborted")
            tempFile.delete()
            return
        }
        if (apk.exists()) apk.delete()
        if (!tempFile.renameTo(apk)) {
            failDownload("cannot publish downloaded file", gen = gen)
            return
        }
        onVerified(apk, actual, gen)
    }

    /** Склейка сегментов + стриминговый SHA-256 за один проход. */
    private suspend fun mergeAndVerify(plan: List<SegmentPlan.Segment>, totalBytes: Long, gen: Long) = withContext(Dispatchers.IO) {
        // Поколение могло смениться, пока сегменты докачивались: склейка
        // блокирующая и без suspend-точек, поэтому проверяем НА ВХОДЕ.
        if (gen != downloadGeneration) {
            UpdateDownloadLogger.log(this@UpdateDownloadService, "stale download generation $gen (current $downloadGeneration): merge aborted, state untouched")
            return@withContext
        }
        if (state.expectedSha256.isBlank()) {
            // Без эталона устанавливать нельзя НИКОГДА (требование 4: «никогда
            // не предлагать установку непроверенного файла»).
            failDownload(getString(R.string.update_download_error_no_checksum), gen = gen)
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
            tempNameSuffix = "-g$gen",
        )
        when (result) {
            is UpdateDownloader.MergeResult.Verified -> onVerified(result.mergedFile, result.sha256, gen)

            is UpdateDownloader.MergeResult.HashMismatch -> {
                if (gen != downloadGeneration) {
                    // Устаревшее поколение: его part-файлы носят ТЕ ЖЕ имена,
                    // что part нового поколения (имя ассета одно), поэтому
                    // чистка здесь уничтожила бы прогресс живой загрузки.
                    UpdateDownloadLogger.log(this@UpdateDownloadService, "stale generation $gen: merge mismatch ignored, parts untouched")
                    return@withContext
                }
                // Требование: «несовпадение = удалить part, сообщить, предложить
                // повтор». Part-файлы битые (докачка порвала байты или диск
                // исказил их) — удаляем, чтобы «Повторить» скачал начисто,
                // а не смержил тот же мусор по кругу.
                UpdateDownloadLogger.log(
                    this@UpdateDownloadService,
                    "SHA-256 MISMATCH after merge: actual=${result.actual} expected=${result.expected}; part files DELETED, retry will re-download"
                )
                clearPartFiles(state.assetName)
                persistState(state.copy(segmentDone = emptyMap()))
                bytesWrittenTotal.set(0L)
                speedTracker.reset()
                failDownload(getString(R.string.update_download_error_checksum), gen = gen)
            }

            is UpdateDownloader.MergeResult.Error -> {
                UpdateDownloadLogger.log(this@UpdateDownloadService, "merge error: ${result.reason}")
                // failDownload сам проверит поколение; здесь дополнительных
                // изменений состояния нет.
                failDownload(getString(R.string.update_download_error_merge, result.reason), gen = gen)
            }
        }
    }

    /** Файл скачан и проверен: уведомление «Установить» + broadcast в UI. */
    private fun onVerified(apkFile: File, sha256: String, gen: Long) {
        if (gen != downloadGeneration) {
            // Финал УСТАРЕВШЕГО поколения (job отменён новой командой, но склейка
            // уже дошла до конца): файл на диске валиден, однако состояние,
            // уведомление и broadcast принадлежат НОВОЙ цели — не перезаписываем.
            UpdateDownloadLogger.log(this, "stale download generation $gen (current $downloadGeneration): READY notification/broadcast suppressed for ${apkFile.name}")
            return
        }
        // Отмена/пауза/потеря профиля могли прийти, пока склейка (блокирующий
        // IO) доживала. Байты к этому моменту УЖЕ скачаны и проверены, поэтому
        // состояние READY честно и файл не теряется (правило «отмена не
        // удаляет скачанное»). Но АВТО-установку запрещаем: broadcastReady
        // триггерит установщик в foreground, а пользователь только что явно
        // попросил остановиться — решение об установке остаётся за ним
        // (кнопка «Установить» в уведомлении).
        val userStopped = cancelledFlag.get() || pausedFlag.get() || profileAbortDone.get()
        // Part-файлы сегментов больше не нужны: APK склеен, хэш совпал, файл
        // опубликован. Оставлять их — мусор в папке загрузки размером с сам
        // APK (жалоба владельца: «мержи не удаляются»). Удаляем ТОЛЬКО part и
        // временный файл склейки; готовый APK и лог не трогаем.
        clearPartFiles(state.assetName)
        // Сохраняем ФАКТИЧЕСКИЙ путь: рабочая папка может быть резервной
        // приватной (filesDir/updates), установщик обязан брать файл отсюда.
        persistState(
            state.copy(
                phase = DownloadState.Phase.READY_TO_INSTALL,
                apkPath = apkFile.absolutePath,
                // Прогресс сегментов обнуляем: part-файлов больше нет, и эти
                // байты не должны учитываться ни в прогрессе, ни при докачке.
                segmentDone = emptyMap(),
            )
        )
        UpdateDownloadLogger.log(this, "READY: ${apkFile.absolutePath} sha256=$sha256 size=${apkFile.length()}")
        showReadyNotification(apkFile)
        requireProfile = false
        stopProfileWatch()
        stopProgressTicker()
        unregisterNetworkCallback()
        // Авто-установку решает main-процесс по флагу resumed-activity
        // (сервис в :tasks не видит UI главного процесса).
        if (userStopped) {
            UpdateDownloadLogger.log(this, "user stop signal during merge: READY kept for ${apkFile.name}, auto-install suppressed")
        } else {
            broadcastReady(apkFile.absolutePath)
        }
        // Требование владельца 19.11 07:36: лог-файл удаляется автоматически
        // после успешного скачивания+склейки+проверки хэша, но ТОЛЬКО если за
        // эту сессию не было ни одной ошибки/заминки (иначе улики остаются).
        // ПОСЛЕ всех финальных записей — чтобы каждая учитывалась счётчиком.
        UpdateDownloadLogger.deleteIfClean()
        // Сервис больше не нужен, но уведомление с кнопкой «Установить»
        // обязано жить и после выхода из клиента: DETACH оставляет его в
        // шторке, а сама кнопка — это PendingIntent.getActivity прямо в
        // системный установщик (см. showReadyNotification), сервис ей не нужен.
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
                    // PROBING включён намеренно: между стартом/возобновлением и
                    // успешной пробой уведомление обязано быть прогресс-
                    // уведомлением (с Пауза/Отмена), а не устаревшим «Продолжить».
                    DownloadState.Phase.DOWNLOADING,
                    DownloadState.Phase.PROBING -> showProgressNotification()
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
            // PROBING: процента ещё нет (размер не подтверждён сервером) —
            // «подготовка» и бегущий индикатор вместо «0%» (жалоба 19.11
            // «застрял на 0%» касалась и повторного нажатия «Скачать»).
            .setContentText(
                if (state.assetName.isEmpty() ||
                    state.phase == DownloadState.Phase.PROBING ||
                    state.totalBytes <= 0L
                ) {
                    getString(R.string.update_download_preparing) +
                        if (state.assetName.isNotEmpty()) " ${state.assetName}" else ""
                } else {
                    getString(R.string.update_download_progress_line, percent, state.assetName)
                }
            )
            .setProgress(100, percent, percent <= 0 || state.phase == DownloadState.Phase.PROBING || state.totalBytes <= 0L)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
        // На Android 12+ (API 31) startForeground из запрещённого фона бросает
        // ForegroundServiceStartNotAllowedException. Мы стартуем корректно
        // (startForegroundService из UI / тап по уведомлению / BOOT_COMPLETED),
        // но при sticky-рестарте решение принимает система, и гарантий нет.
        // Падение сервиса убило бы загрузку, поэтому исключение гасим: part-файлы
        // и состояние в MMKV целы, докачка продолжится (BootReceiver/«Скачать»).
        // Двухаргументный startForeground — тот же вызов, что у доказанно
        // работающих на этом устройстве (Android 16/API 36) sibling-сервисов
        // SubscriptionUpdateService/CoreTestService через NotificationHelper:
        // тип specialUse берётся из манифеста, дополнительно его не передаём.
        try {
            startForeground(NotificationChannelType.UPDATE_DOWNLOAD.notificationId, notification)
        } catch (e: Exception) {
            // На Android 12+ startForeground из запрещённого фона бросает
            // ForegroundServiceStartNotAllowedException. Мы стартуем корректно
            // (startForegroundService из UI / тап по уведомлению / BOOT_COMPLETED),
            // но при sticky-рестарте решение принимает система. Падение сервиса
            // убило бы загрузку, поэтому гасим исключение: part-файлы и состояние
            // в MMKV целы, докачка продолжится (BootReceiver / «Скачать»).
            LogUtil.e(AppConfig.TAG, "startForeground failed; download continues without FGS notification", e)
            UpdateDownloadLogger.log(this, "startForeground FAILED: ${e.javaClass.simpleName}: ${e.message}", e)
        }
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
            // PROBING: процента ещё физически нет (размер не подтверждён
            // сервером). Показ «0%» на этом этапе читался пользователем как
            // «загрузка зависла на 0%» (жалоба 19.11) — честно пишем
            // «подготовка» и имя цели, процент появится с первой записью байт.
            // Процента ещё нет не только на PROBING: после возобновления
            // загрузки, убитой ДО пробы, totalBytes неизвестен (-1) при фазе
            // DOWNLOADING — «0%» здесь читался бы как «завис» (жалоба 19.11).
            if (state.phase == DownloadState.Phase.PROBING || state.totalBytes <= 0L) {
                append(getString(R.string.update_download_preparing))
                if (state.assetName.isNotEmpty()) append(" ").append(state.assetName)
            } else {
                append(getString(R.string.update_download_progress_line, percent, state.assetName))
            }
            if (state.phase != DownloadState.Phase.PROBING && state.totalBytes > 0L) {
                append("\n")
                append(speed.toSpeedString())
                if (eta != null && eta > 0L) {
                    append(" • ").append(getString(R.string.update_download_eta, formatEta(eta)))
                }
            }
        }
        // Свёрнутая строка уведомления = contentText: там обязан быть прогресс,
        // а не тег. Тег релиза (видимость цели: имя файла одинаково у разных
        // бет одной версии, дефект 19.11) живёт в развёрнутом BigText.
        val big = if (state.releaseTag.isNotEmpty()) "${state.releaseTag}\n$text" else text
        showNotification(
            baseBuilder()
                .setContentTitle(getString(R.string.update_download_notification_title))
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(big))
                // Размер ещё не подтверждён сервером: честный неопределённый
                // (бегущий) индикатор вместо пустой шкалы «0%».
                .setProgress(100, percent, state.phase == DownloadState.Phase.PROBING || state.totalBytes <= 0L)
                .setOngoing(true)
                .addAction(R.drawable.ic_pause_24dp, getString(R.string.update_download_action_pause), servicePendingIntent(ACTION_PAUSE))
                .addAction(R.drawable.ic_close_24dp, getString(R.string.action_cancel), servicePendingIntent(ACTION_CANCEL))
        )
    }

    private fun showPausedNotification() {
        val percent = currentPercent()
        // Пауза ДО пробы (totalBytes неизвестен): «Пауза 0%» было бы ложью —
        // байты ещё не считались. Честно: «подготовка» + имя цели (та же
        // причина жалобы «зависло на 0%», что и у активной загрузки).
        val body = if (state.totalBytes <= 0L) {
            getString(R.string.update_download_preparing) +
                if (state.assetName.isNotEmpty()) " ${state.assetName}" else ""
        } else {
            getString(R.string.update_download_paused_line, percent)
        }
        showNotification(
            baseBuilder()
                .setContentTitle(getString(R.string.update_download_notification_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(
                    if (state.releaseTag.isNotEmpty()) "${state.releaseTag}\n$body" else body
                ))
                // До пробы процента нет: бегущий индикатор вместо пустой шкалы.
                .setProgress(100, percent, state.totalBytes <= 0L)
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
        val body = if (state.totalBytes <= 0L) {
            getString(R.string.update_download_preparing) +
                if (state.assetName.isNotEmpty()) " ${state.assetName}" else ""
        } else {
            getString(R.string.update_download_waiting_network_line, percent)
        }
        showNotification(
            baseBuilder()
                .setContentTitle(getString(R.string.update_download_notification_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(
                    if (state.releaseTag.isNotEmpty()) "${state.releaseTag}\n$body" else body
                ))
                // До пробы процента нет: бегущий индикатор вместо пустой шкалы.
                .setProgress(100, percent, state.totalBytes <= 0L)
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
        // Кнопка «Установить» ведёт ПРЯМО в системный установщик через
        // PendingIntent.getActivity. Через сервис (getService) здесь нельзя:
        // после готовности загрузчик останавливается, а Android 12+ запрещает
        // startService из фона — нажатие из шторки не сработало бы, если
        // пользователь вышел из клиента (требование владельца: установка из
        // уведомления должна работать в любой момент).
        val installPi = UpdateInstallLauncher.installIntent(this, apkFile)?.let { intent ->
            PendingIntent.getActivity(this, REQUEST_CODE_INSTALL, intent, piFlags)
        }
        // Дефект с устройства 19.11: имя файла ОДИНАКОВО у разных бет одной
        // версии (v2rayNG_2.4.2_arm64-v8a.apk), поэтому по одному имени нельзя
        // понять, КАКОЙ релиз готов. Тег релиза (не локализуется — это идентификатор)
        // показываем в развёрнутом тексте уведомления.
        val readyBigText = buildString {
            append(getString(R.string.update_download_ready_text, apkFile.name))
            if (state.releaseTag.isNotEmpty()) {
                append("\n").append(state.releaseTag)
            }
        }
        val builder = baseBuilder()
            .setSmallIcon(R.drawable.ic_check_update_24dp)
            .setContentTitle(getString(R.string.update_download_ready_title))
            .setContentText(getString(R.string.update_download_ready_text, apkFile.name))
            .setStyle(NotificationCompat.BigTextStyle().bigText(readyBigText))
            .setOngoing(false)
            .setAutoCancel(true)
        if (installPi != null) {
            builder.addAction(
                R.drawable.ic_check_update_24dp,
                getString(R.string.update_download_action_install),
                installPi,
            )
        }
        showNotification(builder)
    }

    private fun showFailedNotification(reason: String) {
        // Тег цели в развёрнутом тексте: «Повторить» из шторки возобновляет
        // ИМЕННО эту цель, пользователь обязан видеть какую (дефект 19.11 —
        // невидимость цели).
        val big = if (state.releaseTag.isNotEmpty()) "${state.releaseTag}\n$reason" else reason
        showNotification(
            baseBuilder()
                .setSmallIcon(R.drawable.ic_close_24dp)
                .setContentTitle(getString(R.string.update_download_failed_title))
                .setContentText(reason)
                .setStyle(NotificationCompat.BigTextStyle().bigText(big))
                .setOngoing(false)
                .setAutoCancel(false)
                .addAction(R.drawable.ic_refresh_24dp, getString(R.string.update_download_action_retry), buildRetryPendingIntent())
        )
    }

    private fun showCancelledNotification() {
        // Свёрнутая строка = смысл («Отменено»), тег цели — только в BigText
        // (контракт уведомления, см. showProgressNotification).
        val body = getString(R.string.update_download_cancelled)
        showNotification(
            baseBuilder()
                .setContentTitle(getString(R.string.update_download_notification_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(
                    if (state.releaseTag.isNotEmpty()) "${state.releaseTag}\n$body" else body
                ))
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
            pendingIntentForService(1, intent)
        } else {
            // Нечего возобновлять: открываем экран проверки обновлений.
            checkUpdatePendingIntent()
        }
    }

    private val piFlags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE

    /** Тап по уведомлению — открыть клиент. */
    private fun buildMainPendingIntent(): PendingIntent =
        PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), piFlags)

    /**
     * Кнопка-команда самому сервису (пауза/возобновить/отмена).
     *
     * Используется [PendingIntent.getForegroundService], а не getService:
     * onStartCommand безусловно вызывает ensureForeground() -> startForeground(),
     * а на Android 12+ (API 31) startForeground в сервисе, запущенном как
     * обычный фоновый, бросает ForegroundServiceStartNotAllowedException —
     * кнопка «Пауза» в шторке просто не сработала бы. getForegroundService
     * запускает сервис как foreground-сервис, что соответствует контракту.
     * (API доступен с 26; minSdk 24 — ниже остаётся getService.)
     */
    private fun servicePendingIntent(action: String): PendingIntent =
        pendingIntentForService(
            action.hashCode(),
            Intent(this, UpdateDownloadService::class.java).setAction(action),
        )

    private fun pendingIntentForService(requestCode: Int, intent: Intent): PendingIntent =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            PendingIntent.getForegroundService(this, requestCode, intent, piFlags)
        } else {
            PendingIntent.getService(this, requestCode, intent, piFlags)
        }

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
     * Наблюдатель профиля: работает только когда [requireProfile] и загрузка
     * активна. При потере профиля немедленно останавливает загрузку.
     *
     * Остановка — НЕ отмена скачанного: part-файлы остаются на диске, поэтому
     * после включения профиля повторное «Скачать» продолжит докачку с того же
     * байта (см. [UpdateDecisions.StartDecision.ResumeExisting] для PROFILE_LOST).
     */
    private fun startProfileWatch(gen: Long) {
        profileWatchJob?.cancel()
        profileWatchJob = serviceScope.launch {
            while (coroutineContext.isActive) {
                delay(PROFILE_WATCH_INTERVAL_MS)
                if (cancelledFlag.get()) break
                if (!state.isActive()) break

                // Требование «идти строго через профиль» перечитывается из
                // настройки на КАЖДОМ тике, а не берётся из кэша запуска.
                // Иначе пользователь, выключивший свитч посреди загрузки,
                // получил бы остановку по причине, которую сам только что снял.
                // viaActiveProfile() читает один bool из MMKV — дёшево, в
                // отличие от resolve() с его TCP-пробой.
                val stillRequired = UpdateDownloadStore.viaActiveProfile()
                requireProfile = stillRequired
                if (!stillRequired) continue

                val route = runCatching { ActiveProfileRoute.resolve() }.getOrNull()
                if (route == null) continue // не удалось опросить — не дёргаем загрузку
                val usable = route.mode == ActiveProfileRoute.Mode.LOCAL_HTTP_PROXY ||
                    route.mode == ActiveProfileRoute.Mode.TUNNEL_DIRECT
                if (!usable) {
                    ActiveProfileRoute.log("Update download: profile lost", route)
                    abortProfileLost(gen = gen)
                    break
                }
            }
        }
    }

    private fun stopProfileWatch() {
        profileWatchJob?.cancel()
        profileWatchJob = null
    }

    /**
     * Останавливает загрузку из-за отключения профиля (требование владельца).
     *
     * Делает ВСЕ четыре вещи, которые он просил:
     *  1. фаза [DownloadState.Phase.PROFILE_LOST] в персистентном состоянии;
     *  2. причина пишется в лог-файл загрузки;
     *  3. уведомление в шторке с этой причиной;
     *  4. broadcast в UI -> тост «Профиль отключён — загрузка прервана».
     *
     * Part-файлы НЕ удаляются: докачка продолжится после включения профиля.
     */
    private fun abortProfileLost(detail: String? = null, gen: Long = downloadGeneration) {
        // Устаревшее поколение (наблюдатель профиля прежней загрузки дожил до
        // новой команды) не вправе останавливать НОВУЮ загрузку.
        if (gen != downloadGeneration) {
            UpdateDownloadLogger.log(this, "stale download generation $gen (current $downloadGeneration): profile-lost abort ignored")
            return
        }
        // Однократность: повторный вызов (см. [profileAbortDone]) игнорируется.
        if (!profileAbortDone.compareAndSet(false, true)) {
            UpdateDownloadLogger.log(this, "PROFILE LOST abort already in progress, skipping duplicate")
            return
        }
        requireProfile = false
        cancelledFlag.set(true) // останавливает сегментные циклы без удаления part
        val reason = detail?.let { "${getString(R.string.update_download_profile_lost_reason)} ($it)" }
            ?: getString(R.string.update_download_profile_lost_reason)
        persistState(state.copy(phase = DownloadState.Phase.PROFILE_LOST, lastError = reason))
        UpdateDownloadLogger.log(this, "PROFILE LOST: download stopped. $reason Part files kept at ${workDir.absolutePath}")
        stopProgressTicker()
        showProfileLostNotification()
        MessageHelper.sendMsg2UI(
            this,
            AppConfig.MSG_UPDATE_DOWNLOAD_FAILED,
            getString(R.string.update_download_profile_lost_toast),
        )
        serviceScope.launch {
            cancelActiveCalls()
            downloadJob?.cancel()
            downloadJob = null
            // Наблюдатель профиля останавливаем явно. Если abort вызван из него
            // самого, он и так выходит через break; но если причина пришла из
            // launchDownload (профиль уже был выключен на старте), наблюдатель
            // продолжил бы каждые 2 с дёргать ActiveProfileRoute.resolve() с его
            // TCP-пробой — лишняя работа после остановки загрузки.
            stopProfileWatch()
            unregisterNetworkCallback()
            stopForeground(STOP_FOREGROUND_DETACH)
            stopSelf()
        }
    }

    /** Уведомление об остановке из-за профиля: с кнопкой «Продолжить». */
    private fun showProfileLostNotification() {
        // Кнопка «Продолжить» этого уведомления возобновляет ИМЕННО эту цель:
        // тег релиза обязан быть виден (имя файла одинаково у бет одной
        // версии, дефект невидимости цели 19.11).
        val headline = getString(R.string.update_download_profile_lost_notification)
        // Требование владельца: ПРИЧИНА («почему так произошло») обязана быть не
        // только в логе, но и в уведомлении. Точная причина лежит в
        // state.lastError — туда abortProfileLost кладёт профиль-строку плюс
        // уточнение (профиль выключен / профиль без loopback-прокси). Раскрываем
        // её в BigText, а в одной строке остаёмся в пределах стандартной ширины.
        val reason = state.lastError
        // Свёрнутая строка = причина остановки; тег цели и подробная причина —
        // в развёрнутом тексте.
        val bigText = buildString {
            if (state.releaseTag.isNotEmpty()) append(state.releaseTag).append("\n")
            append(headline)
            if (reason.isNotBlank()) append("\n").append(reason)
        }
        showNotification(
            baseBuilder()
                .setSmallIcon(R.drawable.ic_close_24dp)
                .setContentTitle(getString(R.string.update_download_notification_title))
                .setContentText(headline)
                .setStyle(NotificationCompat.BigTextStyle().bigText(bigText))
                .setOngoing(false)
                .setAutoCancel(false)
                .addAction(
                    R.drawable.ic_play_24dp,
                    getString(R.string.update_download_action_resume),
                    buildRetryPendingIntent(),
                )
        )
    }

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
        if (!viaProfile) {
            // Прямой канал: свитч ВЫКЛ = «скачивание должно идти напрямую», даже
            // если профиль поднял loopback-прокси. Возвращаем СРАЗУ, до
            // ActiveProfileRoute.resolve(): та делает TCP-пробу порта, а
            // resolveRoute теперь вызывается на КАЖДОМ ретрае каждого сегмента —
            // долбить пробой loopback-порта 24 параллельными сегментами ради
            // значения, которое мы всё равно не используем, недопустимо.
            return UpdateHttpClient.RouteConfig()
        }
        val route = ActiveProfileRoute.resolve()
        ActiveProfileRoute.log("Update download", route)
        return when (route.mode) {
            ActiveProfileRoute.Mode.LOCAL_HTTP_PROXY -> UpdateHttpClient.RouteConfig(
                proxyHost = route.httpHost,
                proxyPort = route.httpPort,
                proxyUsername = route.proxyUsername,
                proxyPassword = route.proxyPassword,
            )

            ActiveProfileRoute.Mode.TUNNEL_DIRECT -> UpdateHttpClient.RouteConfig()

            ActiveProfileRoute.Mode.NONE -> throw ProfileRequiredException(
                getString(R.string.toast_requires_active_proxy)
            )

            ActiveProfileRoute.Mode.PROFILE_WITHOUT_LOCAL_PROXY -> throw ProfileRequiredException(
                getString(R.string.toast_requires_active_proxy_no_local_proxy)
            )
        }
    }

    private inner class ConnectivityCallback : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            if (networkAvailable.compareAndSet(false, true)) {
                UpdateDownloadLogger.log(this@UpdateDownloadService, "network available again, resuming")
                if (state.phase == DownloadState.Phase.WAITING_NETWORK && !pausedFlag.get()) {
                    persistPhaseIfChanged(DownloadState.Phase.DOWNLOADING)
                }
            }
        }

        override fun onLost(network: Network) {
            // Сеть пропала (обрыв/Wi-Fi->mobile/режим полёта): НЕ отменяем
            // загрузку, ждём появления (требование «не останавливаться»).
            if (networkAvailable.compareAndSet(true, false)) {
                UpdateDownloadLogger.log(this@UpdateDownloadService, "network lost, waiting (download not cancelled)")
                persistPhaseIfChanged(DownloadState.Phase.WAITING_NETWORK)
            }
        }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            val validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            if (validated && networkAvailable.compareAndSet(false, true)) {
                if (state.phase == DownloadState.Phase.WAITING_NETWORK && !pausedFlag.get()) {
                    persistPhaseIfChanged(DownloadState.Phase.DOWNLOADING)
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

    /**
     * Ключ маршрута для детекции смены loopback-прокси. Включает адрес, порт и
     * наличие кредов (сами креды не логируем): при смене профиля ядро поднимает
     * inbound на другом порту, и ключ меняется.
     */
    private fun routeKey(route: UpdateHttpClient.RouteConfig): String =
        if (route.proxyPort == 0) {
            KEY_ROUTE_DIRECT
        } else {
            "${route.proxyHost}:${route.proxyPort}:${!route.proxyUsername.isNullOrBlank()}"
        }

    /**
     * Возвращает клиент, пересозданный под АКТУАЛЬНЫЙ маршрут.
     *
     * Вызывается сегментными корутинами на каждой итерации: если профиль
     * переключили и loopback-порт сменился, следующий ретрай пойдёт уже через
     * новый прокси, а не в мёртвый порт. При выключенном свитче маршрут всегда
     * прямой, ключ стабилен и клиент пересоздаётся ровно один раз.
     *
     * @throws ProfileRequiredException если профиль обязателен, но сейчас не
     *   пригоден (выключен / без loopback-прокси) — загрузку останавливает
     *   [launchDownload].
     */
    private suspend fun currentClientFresh(): OkHttpClient {
        val viaProfile = UpdateDownloadStore.viaActiveProfile()

        // Свитч «через профиль» выключен (или только что выключен): маршрут всегда
        // прямой, ключ стабилен — возвращаем готовый клиент БЕЗ TCP-пробы и БЕЗ
        // мьютекса. Это самый частый путь (вызывается на каждом ретрае каждого
        // сегмента), поэтому он обязан быть максимально дешёвым.
        if (!viaProfile) {
            val existing = currentClient
            if (existing != null && clientRouteKey == KEY_ROUTE_DIRECT) return existing
            clientRouteKey = KEY_ROUTE_DIRECT
            return UpdateHttpClient.build(UpdateHttpClient.RouteConfig())
                .also {
                    currentClient = it
                    lastRouteResolveMs = System.currentTimeMillis()
                }
        }

        // Через профиль: сериализуем резолв, чтобы 24 сегмента не долбили
        // loopback-порт одновременно, и троттлим частоту проб через TTL.
        routeMutex.withLock {
            val existing = currentClient
            val now = System.currentTimeMillis()
            if (existing != null && clientRouteKey != KEY_ROUTE_DIRECT &&
                now - lastRouteResolveMs < ROUTE_RECHECK_TTL_MS
            ) {
                return existing
            }

            val route = resolveRoute(viaProfile = true)
            lastRouteResolveMs = System.currentTimeMillis()
            val key = routeKey(route)
            if (existing != null && key == clientRouteKey) return existing
            // this@UpdateDownloadService: внутри withLock голый `this` — это
            // Mutex (receiver расширения), а логгер требует Context. Та же
            // ловушка, что с withContext, — квалифицируем явно.
            UpdateDownloadLogger.log(
                this@UpdateDownloadService,
                "route changed ($clientRouteKey -> $key), rebuilding HTTP client"
            )
            clientRouteKey = key
            return UpdateHttpClient.build(route).also { currentClient = it }
        }
    }

    private fun registerCall(call: Call) {
        activeCalls.add(call)
    }

    /**
     * Снимает завершённый call из набора активных.
     *
     * Обязателен: без него набор рос бы на каждый редирект и ретрай — GitHub
     * отдаёт 302 на КАЖДЫЙ сегментный запрос, а на плохой сети ретраев сотни,
     * поэтому cancelActiveCalls() перебирал бы тысячи мёртвых объектов.
     * Снимать можно только ПОСЛЕ закрытия тела ответа: пока тело читается, call
     * обязан оставаться в наборе, иначе пауза/отмена не смогут прервать
     * блокирующий InputStream.read.
     */
    private fun unregisterCall(call: Call) {
        activeCalls.remove(call)
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
     * То же, что [persistPhase], но без записи, если фаза не изменилась.
     *
     * Циклы ожидания (нет сети, пауза) вызывают это раз в секунду на каждый
     * сегмент (до 24 параллельно): без защиты каждая итерация писала бы JSON
     * состояния в MMKV — десятки лишних mmap-записей в секунду на флеш в тот
     * самый момент, когда сеть и так плохая. Сравнение фазы делает запись
     * однократной на переход.
     */
    private fun persistPhaseIfChanged(phase: DownloadState.Phase) {
        if (state.phase == phase) return
        persistPhase(phase)
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

    private fun failDownload(reason: String, keepNotification: Boolean = true, gen: Long = downloadGeneration) {
        if (gen != downloadGeneration) {
            UpdateDownloadLogger.log(this, "stale download generation $gen (current $downloadGeneration): failure of an aborted download ignored ($reason)")
            return
        }
        persistState(state.copy(phase = DownloadState.Phase.FAILED, lastError = reason))
        UpdateDownloadLogger.log(this, "FAILED: $reason")
        requireProfile = false
        stopProfileWatch()
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
    /**
     * Удаляет ВСЕ временные файлы склейки (`*.merging.tmp`) рабочей папки.
     *
     * Это не только гигиена: отменённое поколение может доживать блокирующую
     * склейку. Удалив её temp сейчас, мы делаем невозможным её финальный
     * rename в итоговый APK (renameTo вернёт false -> MergeResult.Error), то
     * есть байты УСТАРЕВШЕЙ цели физически не могут затереть APK нового
     * поколения. Part-файлы здесь НЕ удаляются.
     */
    private fun clearMergeTemps() {
        workDir.listFiles()?.forEach { f ->
            if (f.name.endsWith(".merging.tmp")) f.delete()
        }
    }

    private fun clearPartFiles(assetName: String) {
        val removed = (0 until SegmentPlan.MAX_SEGMENTS).count { idx ->
            UpdatePaths.partFile(workDir, assetName, idx).delete()
        }
        // Временные файлы склейки ВСЕХ поколений (имена несут суффикс -gN):
        // брошенный отменённой склейкой temp не должен оставаться мусором
        // размером с APK в папке загрузки.
        clearMergeTemps()
        UpdateDownloadLogger.log(this, "cleared $removed part files and merge temp files for $assetName")
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
