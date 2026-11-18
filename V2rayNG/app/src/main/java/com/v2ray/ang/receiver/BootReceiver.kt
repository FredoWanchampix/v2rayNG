package com.v2ray.ang.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.UserManager
import com.v2ray.ang.AppConfig
import com.v2ray.ang.core.LauncherManager
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.SubscriptionUpdater
import com.v2ray.ang.BuildConfig
import com.v2ray.ang.service.UpdateDownloadService
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.util.updater.ChangelogCollector
import com.v2ray.ang.util.updater.DownloadState
import com.v2ray.ang.util.updater.UpdateDownloadStore

class BootReceiver : BroadcastReceiver() {
    /**
     * This method is called when the BroadcastReceiver is receiving an Intent broadcast.
     * It handles BOOT_COMPLETED, LOCKED_BOOT_COMPLETED, and MY_PACKAGE_REPLACED.
     * If the conditions are met, it starts the V2Ray service.
     *
     * @param context The Context in which the receiver is running.
     * @param intent The Intent being received.
     */
    override fun onReceive(context: Context?, intent: Intent?) {
        val action = intent?.action ?: return
        if (context == null) return

        LogUtil.i(AppConfig.TAG, "BootReceiver received: $action")

        when (action) {
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED -> {
                // Continue
            }

            Intent.ACTION_LOCKED_BOOT_COMPLETED -> {
                val userManager = context.getSystemService(Context.USER_SERVICE) as? UserManager
                if (userManager != null && !userManager.isUserUnlocked) {
                    LogUtil.w(AppConfig.TAG, "BootReceiver: User is locked, skipping auto start")
                    return
                }
            }

            else -> {
                LogUtil.w(AppConfig.TAG, "BootReceiver: Unhandled action: $action")
                return
            }
        }

        // После УСПЕШНОЙ установки обновления приложение перезапускается с
        // MY_PACKAGE_REPLACED. Персистентное состояние загрузчика осталось
        // READY_TO_INSTALL и указывало бы на уже установленную версию: экран
        // предложил бы «Установить» повторно. Если сохранённый тег совпадает по
        // версии с установленной — состояние больше не нужно, очищаем его.
        // Сам APK в папке загрузки оставляем: это артефакт пользователя
        // (поделиться/повторная установка), а не мусор загрузчика.
        if (action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            clearInstalledUpdateState(context)
        }

        // Сначала поднимаем профиль (если включён автозапуск), и ТОЛЬКО ПОТОМ
        // возобновляем докачку обновления. Порядок важен: при включённом свитче
        // «загружать через активный профиль» загрузка обязана идти через профиль,
        // а сразу после BOOT_COMPLETED он ещё не поднят — возобновление до старта
        // VPN немедленно остановило бы докачку с «профиль отключён».
        //
        // Автозапуск VPN и докачка обновления при этом независимы: докачка
        // возобновляется в любом случае (см. ниже), просто после попытки старта.
        val autoStart = MmkvManager.decodeStartOnBoot() &&
            !MmkvManager.getSelectServer().isNullOrEmpty()
        if (autoStart) {
            LogUtil.i(AppConfig.TAG, "BootReceiver: Starting V2Ray service")
            LauncherManager.startService(context)
        } else {
            LogUtil.i(AppConfig.TAG, "BootReceiver: Auto-start on boot is disabled or no server selected")
        }

        // Докачка обновления не зависит от автозапуска VPN: возобновляем её
        // всегда после разблокированной загрузки (не из MY_PACKAGE_REPLACED —
        // там файлы приложения и так на месте, а сервис поднимет START_STICKY).
        if (action != Intent.ACTION_MY_PACKAGE_REPLACED) {
            resumeUpdateDownloadIfActive(context)
        }

        if (autoStart) {
            SubscriptionUpdater.sync(context)
        }
    }

    companion object {
        /**
         * Возобновляет докачку обновления после BOOT_COMPLETED (требование
         * владельца: докачка должна переживать перезагрузку устройства).
         *
         * Вызывается ПОСЛЕ попытки автозапуска VPN: если загрузка обязана идти
         * через профиль, к этому моменту у профиля уже был шанс подняться.
         * Возобновляются только АКТИВНЫЕ загрузки (качалась/ждала сеть).
         * НЕ возобновляются автоматически:
         *  - PAUSED — ручную паузу продолжает сам пользователь;
         *  - CANCELLED — отмена была явной;
         *  - PROFILE_LOST — профиль выключен, автозапуск нарушил бы требование
         *    «строго через профиль»; продолжит пользователь кнопкой «Продолжить».
         */
        /**
         * Очищает состояние загрузчика, если сохранённая готовость относится к
         * УЖЕ УСТАНОВЛЕННОЙ версии (сравнивается точечная версия тега релиза с
         * BuildConfig.VERSION_NAME). Вызывается на MY_PACKAGE_REPLACED.
         */
        private fun clearInstalledUpdateState(context: Context) {
            val state = UpdateDownloadStore.load() ?: return
            if (state.phase != DownloadState.Phase.READY_TO_INSTALL) return
            val tagVersion = ChangelogCollector.parseVersion(state.releaseTag)
            if (tagVersion != BuildConfig.VERSION_NAME) return
            LogUtil.i(
                AppConfig.TAG,
                "BootReceiver: update ${state.releaseTag} is installed; clearing stale download state"
            )
            UpdateDownloadStore.clear()
        }

        fun resumeUpdateDownloadIfActive(context: Context) {
            val state = UpdateDownloadStore.load() ?: return
            val resumable = state.phase == DownloadState.Phase.DOWNLOADING ||
                state.phase == DownloadState.Phase.WAITING_NETWORK ||
                state.phase == DownloadState.Phase.PROBING ||
                // MERGING/VERIFYING: процесс убили посреди склейки или проверки.
                // Part-файлы целы (склейка пишет во временный файл), поэтому
                // возобновление безопасно: сегментный путь пересклеит и
                // перепроверит, однопоточный — перезапишет временный файл.
                state.phase == DownloadState.Phase.MERGING ||
                state.phase == DownloadState.Phase.VERIFYING
            if (!resumable || state.browserDownloadUrl.isBlank()) return

            LogUtil.i(
                AppConfig.TAG,
                "BootReceiver: resuming update download ${state.releaseTag}/${state.assetName} at ${state.progressPercent()}%"
            )
            UpdateDownloadService.startDownload(
                context = context,
                releaseTag = state.releaseTag,
                assetName = state.assetName,
                downloadUrl = state.browserDownloadUrl,
                checksumsUrl = state.checksumsUrl.ifBlank { null },
                expectedSha256 = state.expectedSha256.ifBlank { null },
                declaredSize = state.declaredSize,
            )
        }
    }
}
