package com.v2ray.ang.util.updater

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.v2ray.ang.AppConfig
import com.v2ray.ang.util.LogUtil
import java.io.File

/**
 * Глобальный приёмник событий встроенного загрузчика обновлений.
 *
 * ЗАЧЕМ он отдельный, а не внутри экрана проверки обновлений: сервис живёт в
 * процессе `:tasks` и по завершении шлёт broadcast; пользователь к тому моменту
 * может быть на ЛЮБОМ экране клиента (или вовсе вне его). Требование владельца:
 * «если пользователь начал скачивание, но вышел из клиента, интент не вызывать,
 * а просто оставить файл в уведомлении». Поэтому приёмник регистрируется в
 * ГЛАВНОМ процессе приложения на всё время его жизни (AngApplication), а
 * решение «ставить сейчас» принимает [AppForegroundTracker] — единственный
 * достоверный признак «пользователь внутри клиента» в главном процессе.
 *
 * Регистрируется ТОЛЬКО в главном процессе: broadcast уходит всем процессам
 * приложения, и дубль в :tasks/:daemon вызвал бы вторую попытку установки.
 */
class UpdateInstallReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        if (intent == null || intent.action != AppConfig.BROADCAST_ACTION_ACTIVITY) return
        when (intent.getIntExtra("key", 0)) {
            AppConfig.MSG_UPDATE_DOWNLOAD_READY -> {
                // content = ФАКТИЧЕСКИЙ путь к проверенному APK (сервис шлёт
                // apkFile.absolutePath): рабочий каталог может быть резервным
                // приватным, поэтому путь берём из сообщения, а не пересчитываем.
                val apkPath = intent.getStringExtra("content").orEmpty()
                if (apkPath.isBlank()) return
                val apkFile = File(apkPath)
                if (!apkFile.exists()) {
                    LogUtil.w(AppConfig.TAG, "UpdateInstallReceiver: ready but file missing: $apkPath")
                    return
                }
                // Пункт 6 требования: авто-установка ТОЛЬКО пока пользователь
                // внутри клиента. Иначе — ничего: в уведомлении уже есть кнопка
                // «Установить», которая вызовет установщик по нажатию.
                val decision = UpdateDecisions.decideInstall(AppForegroundTracker.isAppInForeground)
                when (decision) {
                    UpdateDecisions.InstallDecision.InstallNow -> {
                        UpdateDownloadLogger.log(context, "app in foreground: launching installer for $apkPath")
                        UpdateInstallLauncher.install(context, apkFile)
                    }
                    UpdateDecisions.InstallDecision.DeferToNotification ->
                        UpdateDownloadLogger.log(
                            context,
                            "app not in foreground: install left to the notification action ($apkPath)"
                        )
                }
            }
            // Прогресс и ошибки отображает экран проверки обновлений (свой
            // приёмник в ViewModel); глобально они не нужны.
        }
    }
}
