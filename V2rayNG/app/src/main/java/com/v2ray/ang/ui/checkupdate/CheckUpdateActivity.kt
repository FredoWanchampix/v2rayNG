package com.v2ray.ang.ui.checkupdate

import android.os.Build
import android.os.Bundle
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.v2ray.ang.BuildConfig
import com.v2ray.ang.R
import com.v2ray.ang.core.CoreNativeManager
import com.v2ray.ang.enums.PermissionType
import com.v2ray.ang.extension.toSpeedString
import com.v2ray.ang.ui.base.HelperBaseComponentActivity
import com.v2ray.ang.ui.compose.AppTopBar
import com.v2ray.ang.ui.compose.FormTextField
import com.v2ray.ang.ui.compose.NavigationBarsSpacer
import com.v2ray.ang.ui.compose.SettingsMenuItem
import com.v2ray.ang.ui.compose.SettingsSwitchItem
import com.v2ray.ang.ui.compose.VersionInfoBlock
import com.v2ray.ang.ui.compose.verticalScrollbar
import com.v2ray.ang.util.updater.DownloadState
import com.v2ray.ang.util.updater.SegmentPlan
import com.v2ray.ang.util.updater.SpeedTracker

class CheckUpdateActivity : HelperBaseComponentActivity() {

    private val viewModel: CheckUpdateViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Прогресс загрузки живёт в уведомлении: на Android 13+ без
        // POST_NOTIFICATIONS пользователь просто не увидит ни прогресс, ни
        // кнопку «Установить». Запрашиваем так же, как MainActivity (экран
        // обновлений может быть открыт и напрямую, минуя главный).
        checkAndRequestPermission(PermissionType.POST_NOTIFICATIONS) {}
        // На Android 8.1 и ниже запись в публичный Download требует runtime-
        // разрешения WRITE_EXTERNAL_STORAGE: без него загрузчик молча ушёл бы
        // в резервный приватный каталог. На API 29+ разрешение не нужно
        // (scoped storage), а на 30+ его запрос всегда denied — не дёргаем.
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.P && viewModel.useBuiltinDownloader.value) {
            checkAndRequestPermission(PermissionType.STORAGE_WRITE) {}
        }
        if (savedInstanceState == null) {
            viewModel.checkForUpdates()
        }
    }

    /**
     * Публичная обёртка над защищённым checkAndRequestPermission: нужна
     * top-level composable CheckUpdateScreen, которая НЕ является подклассом
     * HelperBaseComponentActivity и потому не видит protected-метод.
     */
    fun requestStorageWrite(onGranted: () -> Unit = {}) {
        checkAndRequestPermission(PermissionType.STORAGE_WRITE, onGranted)
    }

    @Composable
    override fun ScreenContent() {
        CheckUpdateScreen(viewModel = viewModel, onBackClick = { finish() })
    }
}

@Composable
fun CheckUpdateScreen(
    viewModel: CheckUpdateViewModel,
    onBackClick: () -> Unit
) {
    // LocalContext доступен ТОЛЬКО в composable-контексте: захватываем
    // активность здесь, а не в лямбде onCheckedChange (лямбда — не composable,
    // компилятор ответил бы «@Composable invocations can only happen from the
    // context of a @Composable function»).
    val activity = LocalContext.current as? CheckUpdateActivity

    val isLoading by viewModel.isLoading.collectAsStateWithLifecycle()
    val checkPreRelease by viewModel.checkPreRelease.collectAsStateWithLifecycle()
    val updateViaActiveProxy by viewModel.updateViaActiveProxy.collectAsStateWithLifecycle()
    val useBuiltinDownloader by viewModel.useBuiltinDownloader.collectAsStateWithLifecycle()
    val downloadSegments by viewModel.downloadSegments.collectAsStateWithLifecycle()
    val showUpdateDialog by viewModel.showUpdateDialog.collectAsStateWithLifecycle()
    val updateResult by viewModel.updateResult.collectAsStateWithLifecycle()
    val downloadState by viewModel.downloadState.collectAsStateWithLifecycle()

    val libVersion = CoreNativeManager.getLibVersion()
    val versionText = "v${BuildConfig.VERSION_NAME} ($libVersion)"

    Scaffold(
        contentWindowInsets = WindowInsets(0),
        topBar = {
            AppTopBar(
                title = stringResource(R.string.update_check_for_update),
                onBackClick = onBackClick,
                isLoading = isLoading
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
        ) {
            SettingsSwitchItem(
                icon = painterResource(R.drawable.ic_source_code_24dp),
                title = stringResource(R.string.update_check_pre_release),
                checked = checkPreRelease,
                onCheckedChange = { viewModel.toggleCheckPreRelease(it) }
            )
            SettingsSwitchItem(
                icon = painterResource(R.drawable.ic_check_update_24dp),
                title = stringResource(R.string.update_via_active_proxy_title),
                summary = stringResource(R.string.update_via_active_proxy_summary),
                checked = updateViaActiveProxy,
                onCheckedChange = { viewModel.toggleUpdateViaActiveProxy(it) }
            )
            SettingsSwitchItem(
                icon = painterResource(R.drawable.ic_cloud_download_24dp),
                title = stringResource(R.string.update_use_builtin_downloader_title),
                summary = stringResource(R.string.update_use_builtin_downloader_summary),
                checked = useBuiltinDownloader,
                onCheckedChange = { enabled ->
                    viewModel.toggleUseBuiltinDownloader(enabled)
                    if (enabled && Build.VERSION.SDK_INT <= Build.VERSION_CODES.P) {
                        // Разрешение на запись в публичный Download запрашиваем
                        // параллельно со свитчом: свитч включается сразу, а при
                        // отказе загрузчик честно уйдёт в резервный приватный
                        // каталог и запишет это в update_download.log — лучше,
                        // чем «залипший» выключенный свитч без объяснений.
                        // checkAndRequestPermission — protected в базовом
                        // классе, а composable не подкласс, поэтому идём через
                        // публичный wrapper активности (LocalContext в setContent
                        // и есть сама активность).
                        activity?.requestStorageWrite()
                    }
                }
            )
            if (useBuiltinDownloader) {
                SegmentsField(
                    draftValue = downloadSegments,
                    onDraftChange = { viewModel.setDownloadSegments(it) },
                )
                DownloadProgressBlock(
                    state = downloadState,
                    onPause = { viewModel.pauseDownload() },
                    onResume = { viewModel.resumeDownload() },
                    onCancel = { viewModel.cancelDownload() },
                    onInstall = { viewModel.installDownloaded() },
                )
            }
            SettingsMenuItem(
                icon = painterResource(R.drawable.ic_check_update_24dp),
                title = stringResource(R.string.update_check_for_update),
                onClick = { viewModel.checkForUpdates() }
            )
            VersionInfoBlock(versionText = versionText)
            NavigationBarsSpacer()
        }
    }

    if (showUpdateDialog && updateResult != null) {
        val result = updateResult!!
        AlertDialog(
            onDismissRequest = { viewModel.dismissUpdateDialog() },
            title = {
                // Если история пропущенных релизов собрана (skippedCount > 1 —
                // пропущено НЕСКОЛЬКО), показываем это в заголовке: пользователь
                // понимает, что ниже — сводка нескольких версий, а не одной.
                val base = stringResource(R.string.update_new_version_found, result.latestVersion ?: "")
                Text(
                    if (result.skippedCount > 1) {
                        stringResource(R.string.update_skipped_releases_header, result.skippedCount) + "\n" + base
                    } else {
                        base
                    }
                )
            },
            text = {
                val scrollState = rememberScrollState()
                Text(
                    text = result.releaseNotes.orEmpty(),
                    modifier = Modifier
                        .fillMaxWidth()
                        .verticalScroll(scrollState)
                        .verticalScrollbar(scrollState)
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.dismissUpdateDialog()
                    viewModel.downloadUpdate(result)
                }) {
                    // Подпись НЕ зависит от свитча «встроенный загрузчик»:
                    // действие одно и то же — скачать обновление; свитч меняет
                    // лишь СПОСОБ (браузер или загрузчик клиента). Раньше
                    // подпись переключалась «Обновить»/«Скачать», что сбивало
                    // с толку (жалоба владельца).
                    Text(stringResource(R.string.update_download_action_start))
                }
            },
            dismissButton = {
                TextButton(onClick = { viewModel.dismissUpdateDialog() }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
            containerColor = MaterialTheme.colorScheme.surface
        )
    }
}

/**
 * Блок состояния встроенной загрузки: процент, скорость (обновляется раз в
 * секунду broadcast'ами сервиса), ETA и кнопки Пауза/Продолжить/Отмена/
 * Установить. Дизайн — существующая система (Material3, те же отступы, что у
 * SettingsItemRow): никаких самодеятельных layout.
 */
@Composable
private fun DownloadProgressBlock(
    state: DownloadState,
    onPause: () -> Unit,
    onResume: () -> Unit,
    onCancel: () -> Unit,
    onInstall: () -> Unit,
) {
    if (state.phase == DownloadState.Phase.IDLE && state.totalBytes <= 0L) return

    val speed = rememberSpeedBytesPerSecond(
        downloadedBytes = state.downloadedBytes(),
        // Ключ цели: при смене релиза/ассета трекер пересоздаётся, иначе окно
        // осталось бы с байтами прежней загрузки. Сброс счётчика ВНУТРИ той же
        // цели (рестарт сегмента, переход на single-stream) ключ не меняет —
        // это нормально: SpeedTracker на отрицательной дельте возвращает 0,
        // то есть скорость честно уходит в ноль и снова растёт.
        targetKey = "${state.releaseTag}/${state.assetName}",
    )
    val phaseText = when (state.phase) {
        DownloadState.Phase.IDLE -> ""
        DownloadState.Phase.PROBING -> stringResource(R.string.update_download_phase_probing)
        // DOWNLOADING до пробы (totalBytes неизвестен): процента и скорости
        // ещё нет физически — честный текст «проба», а не «0% 0 Б/с»
        // (жалоба 19.11 «застрял на 0%»).
        DownloadState.Phase.DOWNLOADING ->
            if (state.totalBytes > 0L) {
                stringResource(
                    R.string.update_download_phase_downloading,
                    state.progressPercent(),
                    speed.toSpeedString(),
                )
            } else {
                stringResource(R.string.update_download_phase_probing)
            }
        // Пауза/ожидание ДО пробы (totalBytes неизвестен): «Пауза 0%» — ложь,
        // байты ещё не считались (то же лицо жалобы «зависло на 0%»).
        DownloadState.Phase.PAUSED ->
            if (state.totalBytes > 0L) {
                stringResource(R.string.update_download_phase_paused, state.progressPercent())
            } else {
                stringResource(R.string.update_download_phase_probing)
            }
        DownloadState.Phase.WAITING_NETWORK ->
            if (state.totalBytes > 0L) {
                stringResource(R.string.update_download_phase_waiting_network)
            } else {
                stringResource(R.string.update_download_phase_probing)
            }
        DownloadState.Phase.MERGING -> stringResource(R.string.update_download_phase_merging)
        DownloadState.Phase.VERIFYING -> stringResource(R.string.update_download_phase_verifying)
        DownloadState.Phase.READY_TO_INSTALL -> stringResource(R.string.update_download_ready_toast)
        DownloadState.Phase.FAILED -> stringResource(R.string.update_download_phase_failed, state.lastError)
        DownloadState.Phase.CANCELLED -> stringResource(R.string.update_download_cancelled)
        // Профиль отключился во время загрузки — операция остановлена
        // (требование владельца). Показываем отдельный текст, а не «ошибка»:
        // part-файлы целы и докачка продолжится после включения профиля.
        DownloadState.Phase.PROFILE_LOST -> stringResource(R.string.update_download_profile_lost_toast)
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
    ) {
        Text(
            text = state.assetName.ifEmpty { stringResource(R.string.update_download_notification_title) },
            style = MaterialTheme.typography.bodyLarge,
        )
        // Тег релиза: имя файла одинаково у разных бет одной версии, поэтому
        // без тега пользователь не видит, КАКОЙ именно релиз качается/готов
        // (дефект с устройства 19.11: докачка ушла на устаревшую бету).
        if (state.releaseTag.isNotEmpty()) {
            Text(
                text = state.releaseTag,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = phaseText,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (state.phase == DownloadState.Phase.DOWNLOADING ||
            state.phase == DownloadState.Phase.PAUSED ||
            state.phase == DownloadState.Phase.WAITING_NETWORK
        ) {
            Spacer(modifier = Modifier.height(8.dp))
            // До пробы totalBytes неизвестен (-1): детерминированный бар на 0
            // читался бы как «завис на 0%» (жалоба 19.11). Без progress —
            // неопределённый (бегущий) индикатор.
            if (state.totalBytes > 0L) {
                LinearProgressIndicator(
                    progress = { state.progressFraction().toFloat() },
                    modifier = Modifier.fillMaxWidth(),
                )
            } else {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
        }
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            when (state.phase) {
                DownloadState.Phase.DOWNLOADING,
                DownloadState.Phase.WAITING_NETWORK,
                -> {
                    OutlinedButton(onClick = onPause) {
                        Text(stringResource(R.string.update_download_action_pause))
                    }
                    OutlinedButton(
                        onClick = onCancel,
                        modifier = Modifier.padding(start = 8.dp),
                    ) {
                        Text(stringResource(R.string.action_cancel))
                    }
                }

                DownloadState.Phase.PAUSED,
                DownloadState.Phase.CANCELLED,
                DownloadState.Phase.FAILED,
                DownloadState.Phase.PROFILE_LOST,
                -> {
                    OutlinedButton(onClick = onResume) {
                        Text(stringResource(R.string.update_download_action_resume))
                    }
                    OutlinedButton(
                        onClick = onCancel,
                        modifier = Modifier.padding(start = 8.dp),
                        enabled = state.phase == DownloadState.Phase.PAUSED,
                    ) {
                        Text(stringResource(R.string.action_cancel))
                    }
                }

                DownloadState.Phase.READY_TO_INSTALL -> {
                    OutlinedButton(onClick = onInstall) {
                        Text(stringResource(R.string.update_download_action_install))
                    }
                }

                else -> Unit
            }
        }
    }
}

/**
 * Поле «Потоков загрузки» (1..24).
 *
 * Текст редактируется ЛОКАЛЬНО (черновик), а в MMKV уходит только валидное
 * число. Так сделано по двум причинам:
 *  1. UX: привязка поля напрямую к сохранённому Int не даёт стереть цифру —
 *     пустая строка не парсится в число, ввод игнорируется, и поле «заедает»;
 *  2. кламп не должен ломать набор: при вводе «83» сохранится 24, но пользователь
 *     увидит именно то, что набрал, а подсказка объясняет диапазон.
 *
 * Паттерн совпадает с эталоном форка (SettingsActivity хранит числа как сырую
 * строку через rememberMmkvString и парсит при использовании).
 *
 * Черновик синхронизируется с сохранённым значением, когда оно меняется
 * извне (например, после клампа в другом месте), но НЕ затирается в процессе
 * ввода: ключ [storedValue] пересоздаёт состояние только при смене сохранённого
 * значения, а не каждого нажатия клавиши.
 */
@Composable
private fun SegmentsField(
    draftValue: String,
    onDraftChange: (String) -> Unit,
) {
    // Значение приходит СЫРОЙ строкой из MMKV (через ViewModel) — это и есть
    // черновик, поэтому локальный mutableStateOf не нужен: поле редактирует
    // сам сохранённый текст (паттерн rememberMmkvString из SettingsActivity).
    val parsed = draftValue.trim().toIntOrNull()
    val clamped = parsed?.let(SegmentPlan::clampSegmentCount)
    // Ошибка, когда введено число вне 1..24: показываем красную рамку, но
    // текст НЕ перезаписываем — пользователь видит, что набрал, и сам правит.
    val outOfRange = parsed != null && clamped != parsed

    FormTextField(
        label = stringResource(R.string.update_download_segments_title),
        value = draftValue,
        onValueChange = { raw ->
            // Принимаем только цифры: KeyboardType.Number не гарантирует
            // фильтрацию на всех клавиатурах (вставляемый текст проходит мимо).
            onDraftChange(raw.filter { it.isDigit() })
        },
        keyboardType = KeyboardType.Number,
        isError = outOfRange,
        supportingText = stringResource(
            R.string.update_download_segments_summary,
            SegmentPlan.MAX_SEGMENTS
        ),
    )
}

/**
 * Скорость на экране считается тем же [SpeedTracker], что и в уведомлении:
 * broadcast сервиса приходит раз в секунду с новым downloadedBytes, remember
 * пересоздаёт трекер при смене фазы/цели.
 */
@Composable
private fun rememberSpeedBytesPerSecond(downloadedBytes: Long, targetKey: String): Long {
    // remember(targetKey): трекер живёт ровно в пределах одной загрузки.
    val tracker = remember(targetKey) {
        SpeedTracker(windowMillis = 5_000L)
    }
    // Broadcast из сервиса приходит раз в секунду, поэтому recomposition и
    // пересчёт скорости происходят с той же периодичностью — это и есть
    // требование «скорость обновляется каждую секунду».
    LaunchedEffect(downloadedBytes) {
        tracker.record(downloadedBytes, System.currentTimeMillis())
    }
    return tracker.bytesPerSecond(System.currentTimeMillis())
}
