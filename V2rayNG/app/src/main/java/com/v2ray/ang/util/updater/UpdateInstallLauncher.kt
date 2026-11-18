package com.v2ray.ang.util.updater

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import com.v2ray.ang.AppConfig
import com.v2ray.ang.util.LogUtil
import java.io.File

/**
 * Запуск системного установщика пакетов для скачанного и ПРОВЕРЕННОГО APK.
 *
 * Требования владельца:
 *  - установка — стандартным intent'ом через FileProvider-URI нашего файла
 *    (FileProvider в манифесте уже есть: authority `${applicationId}.cache`);
 *  - авто-запуск установки ТОЛЬКО если пользователь внутри клиента
 *    ([AppForegroundTracker.isAppInForeground]); если вышел — установку не
 *    вызываем, в уведомлении остаётся действие «Установить», которое запускает
 *    ЭТОТ ЖЕ метод по нажатию (PendingIntent на троттл-ресивер/сервис);
 *  - НИКОГДА не предлагать непроверенный файл: метод вызывается только после
 *    MergeResult.Verified, но перестраховывается проверкой существования и
 *    непустого размера.
 *
 * Никакого WebView/встроенных браузеров/системного DownloadManager: только
 * системный установщик пакетов (ACTION_VIEW c MIME application/vnd.android.
 * package-archive) — это разрешено требованием «загрузка только через клиент»,
 * потому что сама ЗАГРУЗКА идёт внутри клиента, а установка пакета — системная
 * обязанность PackageInstaller (аналогично установке любого APK из Files).
 */
object UpdateInstallLauncher {

    private const val APK_MIME = "application/vnd.android.package-archive"

    /**
     * Открывает системный установщик для [apkFile].
     *
     * @return true, если intent успешно отправлен.
     */
    fun install(context: Context, apkFile: File): Boolean {
        if (!apkFile.exists() || apkFile.length() <= 0L) {
            LogUtil.w(AppConfig.TAG, "UpdateInstall: APK missing or empty: ${apkFile.absolutePath}")
            return false
        }
        return try {
            val uri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.cache",
                apkFile,
            )
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, APK_MIME)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
            UpdateDownloadLogger.log(context, "install intent sent for ${apkFile.name}")
            true
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "UpdateInstall: failed to start installer", e)
            UpdateDownloadLogger.log(context, "install intent FAILED", e)
            false
        }
    }

    /**
     * Авто-установка после успешной проверки: только когда пользователь ещё
     * внутри клиента (пункт 6). Решение принимает [UpdateDecisions.decideInstall],
     * чтобы правило было доказано JVM-тестом.
     *
     * @return true, если установка была запущена.
     */
    fun installIfForeground(context: Context, apkFile: File): Boolean {
        val decision = UpdateDecisions.decideInstall(
            appInForeground = AppForegroundTracker.isAppInForeground,
        )
        return when (decision) {
            UpdateDecisions.InstallDecision.InstallNow -> install(context, apkFile)
            UpdateDecisions.InstallDecision.DeferToNotification -> {
                UpdateDownloadLogger.log(
                    context,
                    "app not in foreground: install deferred to the notification action"
                )
                false
            }
        }
    }
}
