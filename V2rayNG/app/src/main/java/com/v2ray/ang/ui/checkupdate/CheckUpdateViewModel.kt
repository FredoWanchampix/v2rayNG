package com.v2ray.ang.ui.checkupdate

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewModelScope
import com.v2ray.ang.AppConfig
import com.v2ray.ang.BuildConfig
import com.v2ray.ang.R
import com.v2ray.ang.dto.CheckUpdateResult
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.UpdateCheckerManager
import com.v2ray.ang.service.UpdateDownloadService
import com.v2ray.ang.ui.base.BaseViewModel
import com.v2ray.ang.util.ActiveProfileRoute
import com.v2ray.ang.util.JsonUtil
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.util.Utils
import com.v2ray.ang.util.updater.DownloadState
import com.v2ray.ang.util.updater.UpdateDecisions
import com.v2ray.ang.util.updater.UpdateDownloadStore
import com.v2ray.ang.util.updater.UpdateInstallLauncher
import com.v2ray.ang.util.updater.UpdatePaths
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class CheckUpdateViewModel(application: Application) : BaseViewModel(application) {

    private val _checkPreRelease = MutableStateFlow(
        MmkvManager.decodeSettingsBool(AppConfig.PREF_CHECK_UPDATE_PRE_RELEASE, false)
    )
    val checkPreRelease: StateFlow<Boolean> = _checkPreRelease.asStateFlow()

    private val _updateViaActiveProxy = MutableStateFlow(
        MmkvManager.decodeSettingsBool(AppConfig.PREF_CHECK_UPDATE_VIA_ACTIVE_PROXY, false)
    )
    val updateViaActiveProxy: StateFlow<Boolean> = _updateViaActiveProxy.asStateFlow()

    /** «Скачивать через встроенный загрузчик»: ВЫКЛ = браузер (прежнее поведение). */
    private val _useBuiltinDownloader = MutableStateFlow(UpdateDownloadStore.useBuiltinDownloader())
    val useBuiltinDownloader: StateFlow<Boolean> = _useBuiltinDownloader.asStateFlow()

    /**
     * Число параллельных потоков загрузчика. Хранится СЫРОЙ строкой (паттерн
     * rememberMmkvString из SettingsActivity), чтобы поле ввода показывало ровно
     * то, что набрал пользователь; клампинг к 1..24 выполняется при чтении в
     * [UpdateDownloadStore.requestedSegments].
     */
    private val _downloadSegments = MutableStateFlow(UpdateDownloadStore.rawSegments())
    val downloadSegments: StateFlow<String> = _downloadSegments.asStateFlow()

    private val _updateResult = MutableStateFlow<CheckUpdateResult?>(null)
    val updateResult: StateFlow<CheckUpdateResult?> = _updateResult.asStateFlow()

    private val _showUpdateDialog = MutableStateFlow(false)
    val showUpdateDialog: StateFlow<Boolean> = _showUpdateDialog.asStateFlow()

    /**
     * Живое состояние встроенной загрузки для UI (прогресс/фаза/скорость).
     *
     * Инициализация НЕ показывает устаревшую готовность: если сохранённая фаза
     * READY_TO_INSTALL, а проверенный APK по сохранённому пути отсутствует
     * (удалён вручную), подставляется пустое состояние сразу, без ожидания
     * фоновой сверки — иначе кнопка «Установить» мелькала бы на мгновение для
     * несуществующего файла. Проверка здесь — только stat одного файла по
     * готовому пути (без mkdirs), то есть дешёвая и безопасная в main-потоке;
     * полная сверка с резервным каталогом идёт фоном в refreshReadyState().
     */
    private val _downloadState = MutableStateFlow(initialDownloadState())
    val downloadState: StateFlow<DownloadState> = _downloadState.asStateFlow()

    /**
     * Момент последнего broadcast-прогресса от сервиса. Тикер сервиса шлёт
     * прогресс КАЖДУЮ секунду, пока загрузка реально идёт (downloadJob жив в
     * :tasks); значит свежая отметка — достоверный признак «загрузка жива»,
     * в отличие от фазы в MMKV, которая переживает kill процесса и может
     * врать (DOWNLOADING при мёртвом job). Используется, чтобы снятие
     * устаревшей цели не убивало идущую загрузку, которую пользователь
     * запустил осознанно.
     */
    @Volatile
    private var lastDownloadProgressMs = 0L

    private fun initialDownloadState(): DownloadState {
        val persisted = UpdateDownloadStore.load() ?: return DownloadState()
        if (persisted.phase == DownloadState.Phase.READY_TO_INSTALL) {
            val apkPath = persisted.apkPath
            if (apkPath.isNotBlank() && !File(apkPath).exists()) {
                return DownloadState()
            }
        }
        return persisted
    }

    /**
     * Приёмник сообщений загрузчика (сервис живёт в :tasks, шлёт broadcast).
     * Зарегистрирован в main-процессе: только здесь виден
     * [AppForegroundTracker], решающий «ставить сейчас или оставить кнопку в
     * уведомлении» (пункт 6 требования владельца).
     */
    private val downloadReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent == null || intent.action != AppConfig.BROADCAST_ACTION_ACTIVITY) return
            when (intent.getIntExtra("key", 0)) {
                AppConfig.MSG_UPDATE_DOWNLOAD_PROGRESS -> {
                    val json = intent.getStringExtra("content") ?: return
                    val parsed = JsonUtil.fromJsonSafe(json, DownloadState::class.java) ?: return
                    // Прогресс УЖЕ отменённой загрузки (broadcast был в полёте,
                    // когда пришла отмена) не должен возвращать блок с
                    // «Продолжить»: отмена — конец операции.
                    if (parsed.phase == DownloadState.Phase.CANCELLED) {
                        _downloadState.value = DownloadState()
                        return
                    }
                    // Broadcast мог быть в полёте, когда сервис уже снял
                    // состояние (CLEAR_STATE): пустой store означает «загрузки
                    // больше нет», прогресс игнорируем, иначе блок мигнул бы
                    // на кадр после очистки. Проверка нужна ТОЛЬКО когда
                    // локальный flow пуст: в живой загрузке (flow заполнен)
                    // не тратим MMKV-чтение на каждый тик.
                    if (_downloadState.value.releaseTag.isEmpty() &&
                        UpdateDownloadStore.load() == null
                    ) return
                    lastDownloadProgressMs = System.currentTimeMillis()
                    _downloadState.value = parsed
                }

                AppConfig.MSG_UPDATE_DOWNLOAD_READY -> {
                    // Авто-установку решает ГЛОБАЛЬНЫЙ UpdateInstallReceiver
                    // (живёт всё время работы main-процесса, даже если этот
                    // экран закрыт). Здесь только обновляем UI-состояние — и
                    // тоже сверяем с фактом на диске (файл могли успеть удалить).
                    // onReceive выполняется в main-потоке, поэтому сверка — в IO.
                    viewModelScope.launch(Dispatchers.IO) { refreshReadyState() }
                }

                AppConfig.MSG_UPDATE_DOWNLOAD_FAILED -> {
                    val reason = intent.getStringExtra("content").orEmpty()
                    val persisted = UpdateDownloadStore.load()
                    // Отмена — это КОНЕЦ операции: блок с кнопками
                    // «Продолжить/Отмена» на экране не должен оставаться
                    // (жалоба владельца 19.11). Ошибка (FAILED) блок сохраняет:
                    // там «Продолжить» осмысленен.
                    _downloadState.value =
                        if (persisted == null || persisted.phase == DownloadState.Phase.CANCELLED) {
                            DownloadState()
                        } else {
                            persisted
                        }
                    LogUtil.w(AppConfig.TAG, "Update download failed: $reason")
                    toastError(reason.ifEmpty { getString(R.string.update_download_failed_title) })
                }
            }
        }
    }

    init {
        // RECEIVER_NOT_EXPORTED: сообщения загрузчика внутриприложенческие
        // (сервис :tasks -> main того же UID). С EXPORTED стороннее приложение
        // могло бы слать фейковый прогресс/ошибки в этот экран. См. комментарий
        // в AngApplication.
        ContextCompat.registerReceiver(
            app,
            downloadReceiver,
            IntentFilter(AppConfig.BROADCAST_ACTION_ACTIVITY),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
        // Пользователь мог удалить проверенный APK из папки загрузки вручную
        // (Files и т.п.), пока клиента не было в памяти. Персистентное состояние
        // при этом всё ещё READY_TO_INSTALL, и экран показал бы кнопку
        // «Установить» для НЕСУЩЕСТВУЮЩЕГО файла (баг владельца). Поэтому при
        // открытии экрана готовность сверяется с ФАКТОМ на диске — в фоне,
        // чтобы stat/mkdirs не шли в главном потоке.
        viewModelScope.launch(Dispatchers.IO) { refreshReadyState() }
    }

    /**
     * Сверяет сохранённую готовность с наличием файла. Если файла нет —
     * просит сервис сбросить состояние и уведомление, и чистит локальный flow.
     */
    private fun refreshReadyState() {
        // Безусловно устаревшая цель (строго старее установленной версии)
        // снимается сразу при открытии экрана: блок с «Продолжить» для
        // релиза, который заведомо не новее клиента, показывать нельзя.
        clearStaleDownloadState(onlyStrictlyOlder = true)
        val persisted = UpdateDownloadStore.load() ?: return
        if (persisted.phase != DownloadState.Phase.READY_TO_INSTALL) {
            _downloadState.value = persisted
            return
        }
        val apk = persisted.apkPath.takeIf { it.isNotBlank() }?.let(::File)
            ?: UpdatePaths.apkFile(
                UpdatePaths.dir(app), persisted.assetName
            )
        if (apk.exists()) {
            _downloadState.value = persisted
            return
        }
        // Файла нет: готовность устарела. Сбрасываем через сервис (он снимет и
        // уведомление из шторки), локально показываем пустое состояние.
        _downloadState.value = DownloadState()
        UpdateDownloadService.sendCommand(app, UpdateDownloadService.ACTION_CLEAR_READY)
    }

    override fun onCleared() {
        runCatching { app.unregisterReceiver(downloadReceiver) }
        super.onCleared()
    }

    fun toggleCheckPreRelease(enabled: Boolean) {
        _checkPreRelease.value = enabled
        MmkvManager.encodeSettings(AppConfig.PREF_CHECK_UPDATE_PRE_RELEASE, enabled)
    }

    fun toggleUpdateViaActiveProxy(enabled: Boolean) {
        _updateViaActiveProxy.value = enabled
        MmkvManager.encodeSettings(AppConfig.PREF_CHECK_UPDATE_VIA_ACTIVE_PROXY, enabled)
    }

    fun toggleUseBuiltinDownloader(enabled: Boolean) {
        _useBuiltinDownloader.value = enabled
        MmkvManager.encodeSettings(AppConfig.PREF_UPDATE_USE_BUILTIN_DOWNLOADER, enabled)
    }

    /**
     * Сохраняет введённое число потоков СЫРОЙ строкой (только цифры, как
     * отфильтровал UI). Пустая строка допустима — это «пользователь стирает
     * поле», загрузчик прочитает дефолт. Клампинг — на стороне чтения.
     */
    fun setDownloadSegments(raw: String) {
        val digitsOnly = raw.filter { it.isDigit() }
        _downloadSegments.value = digitsOnly
        MmkvManager.encodeSettings(AppConfig.PREF_UPDATE_DOWNLOAD_SEGMENTS, digitsOnly)
    }

    fun checkForUpdates() {
        launchLoading {
            val viaActiveProfile = _updateViaActiveProxy.value

            // Resolve the route the same way the manager will, so the user gets a
            // precise message instead of a silent "already up to date". Probing the
            // HTTP port alone was wrong: in VPN-tun and root modes that inbound may
            // not exist while the profile is active and already carrying the app's
            // traffic.
            //
            // ВАЖНО: resolve() выполняет TCP-пробу loopback-порта. launchLoading
            // стартует блок на Dispatchers.Main, а Socket().connect() на главном
            // потоке бросает NetworkOnMainThreadException, которую проба честно
            // трактует как «порт не слушает». Из-за этого проверка обновления и
            // загрузка geo-файлов сообщали «профиль не включён» при полностью
            // рабочем профиле, тогда как обновление подписки (вызывается внутри
            // withContext(IO)) работало. Проба обязана выполняться вне главного
            // потока.
            val route = withContext(Dispatchers.IO) { ActiveProfileRoute.resolve() }
            ActiveProfileRoute.log("Update check requested", route)

            if (viaActiveProfile) {
                when (route.mode) {
                    ActiveProfileRoute.Mode.NONE -> {
                        toast(R.string.toast_requires_active_proxy)
                        return@launchLoading
                    }
                    ActiveProfileRoute.Mode.PROFILE_WITHOUT_LOCAL_PROXY -> {
                        // Профиль запущен, но loopback HTTP inbound не поднят.
                        // Сообщаем именно это, а не общую ошибку.
                        toast(R.string.toast_requires_active_proxy_no_local_proxy)
                        return@launchLoading
                    }
                    ActiveProfileRoute.Mode.TUNNEL_DIRECT -> Unit
                    // Профиль FPTN: запрос пойдёт напрямую и пройдёт через туннель
                    // профиля, так что требование «через активный профиль» соблюдено.
                    ActiveProfileRoute.Mode.LOCAL_HTTP_PROXY -> Unit
                }
            }
            if (!viaActiveProfile && route.mode == ActiveProfileRoute.Mode.NONE) {
                // Nothing is running: a direct request is the only option, which is
                // exactly what the switch-off case means.
                LogUtil.i(AppConfig.TAG, "Update check: no active profile, fetching directly")
            }

            toast(R.string.update_checking_for_update)
            try {
                val result = UpdateCheckerManager.checkForUpdate(
                    includePreRelease = _checkPreRelease.value,
                    viaActiveProfile = viaActiveProfile,
                )
                if (result.hasUpdate) {
                    _updateResult.value = result
                    _showUpdateDialog.value = true
                } else {
                    // Обновлений нет: сохранённая цель загрузчика той же или
                    // более старой версии, чем установленная, — УСТАРЕВШАЯ.
                    // Без этой сверки экран показывал тост «обновлений нет»
                    // РЯДОМ с блоком загрузчика и кнопкой «Продолжить», а
                    // «Продолжить» скачивал старый релиз (дефект устройства
                    // 19.11: докачка ушла на бету, уже перекрытую установленной).
                    clearStaleDownloadState()
                    toastSuccess(R.string.update_already_latest_version)
                }
            } catch (e: UpdateCheckerManager.ProfileTurnedOffException) {
                // Профиль отключился УЖЕ во время проверки (требование
                // владельца): проверка прервана, показываем отдельный тост.
                LogUtil.w(AppConfig.TAG, "Update check aborted, profile turned off: ${e.message}")
                toast(R.string.update_check_profile_lost_toast)
            } catch (e: UpdateCheckerManager.NoActiveProfileException) {
                // Raised when the route could not honour "via active profile".
                LogUtil.w(AppConfig.TAG, "Update check refused: ${e.message}")
                toast(e.message ?: getString(R.string.toast_requires_active_proxy))
            } catch (e: Exception) {
                LogUtil.e(AppConfig.TAG, "Failed to check for updates", e)
                toast("Error: ${e.message}")
            }
        }
    }

    /**
     * Кнопка «Скачать» в диалоге новой версии.
     *
     * Свитч «Скачивать через встроенный загрузчик» ВЫКЛ (default) — прежнее
     * поведение: браузер внешним intent. ВКЛ — загрузка внутри клиента
     * ([UpdateDownloadService]): без браузеров, WebView и системного
     * DownloadManager (требование владельца).
     */
    fun downloadUpdate(result: CheckUpdateResult) {
        val downloadUrl = result.downloadUrl
        val assetName = result.assetName
        if (downloadUrl.isNullOrBlank() || assetName.isNullOrBlank()) {
            toastError(R.string.update_download_error_no_asset)
            return
        }
        if (!_useBuiltinDownloader.value) {
            // Прежний путь: внешний браузер. Не ломать дефолтное поведение.
            Utils.openUri(app, downloadUrl)
            return
        }

        // Через активный профиль, если свитч включён: отказываем заранее с
        // точной причиной (тот же принцип, что у проверки обновлений). Проба
        // маршрута — вне главного потока (см. комментарий в checkForUpdates).
        if (_updateViaActiveProxy.value) {
            launchLoading {
                val resolved = withContext(Dispatchers.IO) { ActiveProfileRoute.resolve() }
                when (resolved.mode) {
                    ActiveProfileRoute.Mode.NONE ->
                        toast(R.string.toast_requires_active_proxy)

                    ActiveProfileRoute.Mode.PROFILE_WITHOUT_LOCAL_PROXY ->
                        toast(R.string.toast_requires_active_proxy_no_local_proxy)

                    else -> startServiceDownload(result, downloadUrl, assetName)
                }
            }
            return
        }
        startServiceDownload(result, downloadUrl, assetName)
    }

    private fun startServiceDownload(
        result: CheckUpdateResult,
        downloadUrl: String,
        assetName: String,
    ) {
        // Идентификатор релиза для дедупликации «одна активная загрузка на
        // релиз»: полный тег (v2.4.2-beta.20261117-095329). Если тег пуст —
        // фолбэк на URL (он тоже уникален для релиза).
        val releaseTag = result.releaseTag?.takeIf { it.isNotBlank() } ?: downloadUrl
        UpdateDownloadService.startDownload(
            context = app,
            releaseTag = releaseTag,
            assetName = assetName,
            downloadUrl = downloadUrl,
            checksumsUrl = result.checksumsUrl,
            expectedSha256 = null,
            declaredSize = result.declaredSize,
        )
        toast(R.string.update_download_started)
        _downloadState.value = UpdateDownloadStore.load() ?: _downloadState.value
    }

    /** Команды паузы/возобновления/отмены — сервису (кнопки UI и уведомления). */
    fun pauseDownload() = UpdateDownloadService.sendCommand(app, UpdateDownloadService.ACTION_PAUSE)
    fun resumeDownload() = UpdateDownloadService.sendCommand(app, UpdateDownloadService.ACTION_RESUME)
    fun cancelDownload() = UpdateDownloadService.sendCommand(app, UpdateDownloadService.ACTION_CANCEL)

    /** Кнопка «Установить» на экране: файл уже проверен сервисом. */
    fun installDownloaded() {
        val state = UpdateDownloadStore.load() ?: _downloadState.value
        if (state.phase != DownloadState.Phase.READY_TO_INSTALL) return
        // Гонка: файл могли удалить между отрисовкой кнопки и нажатием.
        val apkNow = state.apkPath.takeIf { it.isNotBlank() }?.let(::File)
        if (apkNow != null && !apkNow.exists()) {
            toastError(R.string.update_download_error_file_missing)
            _downloadState.value = DownloadState()
            // Сброс устаревшей готовности (stat/mkdirs) — в фоне, не в main.
            viewModelScope.launch(Dispatchers.IO) { refreshReadyState() }
            return
        }
        // Берём ФАКТИЧЕСКИЙ путь из состояния: рабочая папка может быть
        // резервной приватной (filesDir/updates), если публичный Download
        // недоступен — пересчёт от публичного каталога дал бы несуществующий файл.
        val apk = state.apkPath.takeIf { it.isNotBlank() }?.let(::File)
            ?: UpdatePaths.apkFile(
                UpdatePaths.dir(app), state.assetName
            )
        UpdateInstallLauncher.install(app, apk)
    }

    fun dismissUpdateDialog() {
        _showUpdateDialog.value = false
    }

    /**
     * Снимает сохранённую загрузку, если её цель не новее установленного
     * клиента (точечная версия тега <= [BuildConfig.VERSION_NAME]): такая цель
     * либо уже установлена, либо старше — продолжать её нечего. Команда идёт
     * сервису (он остановит идущую загрузку, почистит MMKV и снимет
     * уведомление), локальный flow сбрасывается сразу, без мерцания блока.
     * Цель СТРОГО новее установленной (другой канал проверок) сохраняется.
     */
    private fun clearStaleDownloadState(onlyStrictlyOlder: Boolean = false) {
        val persisted = UpdateDownloadStore.load() ?: return
        if (persisted.releaseTag.isEmpty()) return
        val cmp = UpdateDecisions.savedTargetStaleness(persisted.releaseTag, BuildConfig.VERSION_NAME)
        if (cmp > 0) return
        // «Та же версия» до проверки не трогаем: беты одной версии различимы
        // только по коммиту (правило проверки обновлений), а при открытии
        // экрана результата проверки ещё нет. Строго старшая цель не нужна
        // никогда — её снимаем сразу, без мерцания блока.
        if (onlyStrictlyOlder && cmp == 0) return
        // Живую загрузку (прогресс приходил в последние секунды) НЕ снимаем:
        // пользователь мог осознанно качать бету своей версии, а «обновлений
        // нет» пришло из другого канала проверок. Убьём только мёртвое
        // состояние — ровно то, что показывало ложный блок с «Продолжить».
        if (!onlyStrictlyOlder &&
            System.currentTimeMillis() - lastDownloadProgressMs < 5_000L
        ) return
        LogUtil.i(
            AppConfig.TAG,
            "Update download state is stale (saved ${persisted.releaseTag} vs installed ${BuildConfig.VERSION_NAME}); clearing",
        )
        _downloadState.value = DownloadState()
        UpdateDownloadService.sendCommand(app, UpdateDownloadService.ACTION_CLEAR_STATE)
    }
}
