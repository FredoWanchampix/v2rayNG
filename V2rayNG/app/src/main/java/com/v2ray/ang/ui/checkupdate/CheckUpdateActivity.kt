package com.v2ray.ang.ui.checkupdate

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
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
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
        if (savedInstanceState == null) {
            viewModel.checkForUpdates()
        }
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
                onCheckedChange = { viewModel.toggleUseBuiltinDownloader(it) }
            )
            if (useBuiltinDownloader) {
                FormTextField(
                    label = stringResource(R.string.update_download_segments_title),
                    value = downloadSegments.toString(),
                    onValueChange = { raw ->
                        raw.trim().toIntOrNull()?.let { viewModel.setDownloadSegments(it) }
                    },
                    keyboardType = KeyboardType.Number,
                    supportingText = stringResource(
                        R.string.update_download_segments_summary,
                        SegmentPlan.MAX_SEGMENTS
                    ),
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
            title = { Text(stringResource(R.string.update_new_version_found, result.latestVersion ?: "")) },
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
                    Text(
                        stringResource(
                            if (useBuiltinDownloader) R.string.update_download_action_start
                            else R.string.update_now
                        )
                    )
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

    val speed = rememberSpeedBytesPerSecond(state.downloadedBytes())
    val phaseText = when (state.phase) {
        DownloadState.Phase.IDLE -> ""
        DownloadState.Phase.PROBING -> stringResource(R.string.update_download_phase_probing)
        DownloadState.Phase.DOWNLOADING -> stringResource(
            R.string.update_download_phase_downloading,
            state.progressPercent(),
            speed.toSpeedString(),
        )
        DownloadState.Phase.PAUSED -> stringResource(
            R.string.update_download_phase_paused,
            state.progressPercent(),
        )
        DownloadState.Phase.WAITING_NETWORK -> stringResource(R.string.update_download_phase_waiting_network)
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
            LinearProgressIndicator(
                progress = { state.progressFraction().toFloat() },
                modifier = Modifier.fillMaxWidth(),
            )
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
 * Скорость на экране считается тем же [SpeedTracker], что и в уведомлении:
 * broadcast сервиса приходит раз в секунду с новым downloadedBytes, remember
 * пересоздаёт трекер при смене фазы/цели.
 */
@Composable
private fun rememberSpeedBytesPerSecond(downloadedBytes: Long): Long {
    val tracker = androidx.compose.runtime.remember { SpeedTracker(windowMillis = 5_000L) }
    androidx.compose.runtime.LaunchedEffect(downloadedBytes) {
        tracker.record(downloadedBytes, System.currentTimeMillis())
    }
    return tracker.bytesPerSecond(System.currentTimeMillis())
}
