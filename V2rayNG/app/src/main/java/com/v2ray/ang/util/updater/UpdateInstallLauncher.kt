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
     * Строит intent системного установщика для [apkFile] (FileProvider URI +
     * FLAG_GRANT_READ_URI_PERMISSION), НЕ запуская его.
     *
     * Выделен отдельно от [install], потому что этот же intent вкладывается в
     * PendingIntent кнопки «Установить» в уведомлении. Через PendingIntent
     * обязателен именно ACTIVITY-путь: после готовности загрузчик останавливает
     * сервис, а Android 12+ (API 31) ЗАПРЕЩАЕТ startService из фона — кнопка
     * «Установить» через сервис просто не сработала бы, когда пользователь вышел
     * из клиента (ровно тот сценарий, который требует владелец). Тап по
     * уведомлению даёт временное право на запуск Activity, поэтому
     * PendingIntent.getActivity здесь надёжен и без trampolines.
     *
     * @return null, если файла нет/он пуст или URI построить не удалось.
     */
    fun installIntent(context: Context, apkFile: File): Intent? {
        if (!apkFile.exists() || apkFile.length() <= 0L) {
            LogUtil.w(AppConfig.TAG, "UpdateInstall: APK missing or empty: ${apkFile.absolutePath}")
            return null
        }
        return try {
            val uri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.cache",
                apkFile,
            )
            Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, APK_MIME)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
        } catch (e: Exception) {
            // FileProvider бросает IllegalArgumentException, если путь не описан
            // в cache_paths.xml (публичный Download ИЛИ резервный filesDir).
            LogUtil.e(AppConfig.TAG, "UpdateInstall: cannot build FileProvider URI", e)
            UpdateDownloadLogger.log(context, "install intent build FAILED", e)
            null
        }
    }

    /**
     * Открывает системный установщик для [apkFile].
     *
     * @return true, если intent успешно отправлен.
     */
    fun install(context: Context, apkFile: File): Boolean {
        val intent = installIntent(context, apkFile) ?: return false
        return try {
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
