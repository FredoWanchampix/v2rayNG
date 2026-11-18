package com.v2ray.ang.ui.checkupdate

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import com.v2ray.ang.AppConfig
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
import com.v2ray.ang.util.updater.UpdateDownloadStore
import com.v2ray.ang.util.updater.UpdateInstallLauncher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.File

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

    /** Живое состояние встроенной загрузки для UI (прогресс/фаза/скорость-строка). */
    private val _downloadState = MutableStateFlow(UpdateDownloadStore.load() ?: DownloadState())
    val downloadState: StateFlow<DownloadState> = _downloadState.asStateFlow()

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
                    JsonUtil.fromJsonSafe(json, DownloadState::class.java)?.let {
                        _downloadState.value = it
                    }
                }

                AppConfig.MSG_UPDATE_DOWNLOAD_READY -> {
                    // Авто-установку решает ГЛОБАЛЬНЫЙ UpdateInstallReceiver
                    // (живёт всё время работы main-процесса, даже если этот
                    // экран закрыт). Здесь только обновляем UI-состояние.
                    _downloadState.value = UpdateDownloadStore.load() ?: _downloadState.value
                }

                AppConfig.MSG_UPDATE_DOWNLOAD_FAILED -> {
                    val reason = intent.getStringExtra("content").orEmpty()
                    _downloadState.value = UpdateDownloadStore.load() ?: _downloadState.value
                    LogUtil.w(AppConfig.TAG, "Update download failed: $reason")
                    toastError(reason.ifEmpty { getString(R.string.update_download_failed_title) })
                }
            }
        }
    }

    init {
        ContextCompat.registerReceiver(
            app,
            downloadReceiver,
            IntentFilter(AppConfig.BROADCAST_ACTION_ACTIVITY),
            Utils.receiverFlags()
        )
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
        // Берём ФАКТИЧЕСКИЙ путь из состояния: рабочая папка может быть
        // резервной приватной (filesDir/updates), если публичный Download
        // недоступен — пересчёт от публичного каталога дал бы несуществующий файл.
        val apk = state.apkPath.takeIf { it.isNotBlank() }?.let(::File)
            ?: com.v2ray.ang.util.updater.UpdatePaths.apkFile(
                com.v2ray.ang.util.updater.UpdatePaths.dir(app), state.assetName
            )
        UpdateInstallLauncher.install(app, apk)
    }

    fun dismissUpdateDialog() {
        _showUpdateDialog.value = false
    }
}
