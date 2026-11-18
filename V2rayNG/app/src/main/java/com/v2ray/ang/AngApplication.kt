package com.v2ray.ang

import android.app.Application
import android.content.Context
import android.content.IntentFilter
import android.os.Build
import androidx.core.content.ContextCompat
import androidx.work.Configuration
import androidx.work.WorkManager
import com.v2ray.ang.AppConfig
import com.v2ray.ang.AppConfig.ANG_PACKAGE
import com.v2ray.ang.handler.AppLocaleManager
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.SettingsManager
import com.v2ray.ang.ui.compose.ThemeManager
import com.v2ray.ang.util.Utils
import com.v2ray.ang.util.updater.AppForegroundTracker
import com.v2ray.ang.util.updater.UpdateInstallReceiver

class AngApplication : Application() {
    companion object {
        lateinit var application: AngApplication
    }

    /**
     * Attaches the base context to the application.
     * @param base The base context.
     */
    override fun attachBaseContext(base: Context?) {
        super.attachBaseContext(base?.let(ContextCompat::getContextForLanguage))
        application = this
    }

    private val workManagerConfiguration: Configuration = Configuration.Builder()
        .setDefaultProcessName("${ANG_PACKAGE}:bg")
        .build()

    /**
     * Initializes the application.
     */
    override fun onCreate() {
        super.onCreate()

        MmkvManager.initialize(this)

        AppLocaleManager.initialize(this)

        // Initialize WorkManager with the custom configuration
        WorkManager.initialize(this, workManagerConfiguration)

        // Ensure critical preference defaults are present in MMKV early
        SettingsManager.initApp(this)

        // Initialize theme state from MMKV
        ThemeManager.refresh()

        // Счётчик видимых Activity: нужен встроенному загрузчику обновлений,
        // чтобы запускать установку ТОЛЬКО пока пользователь внутри клиента
        // (требование владельца). Регистрируется в главном процессе, где живут
        // Activity; в :tasks/:daemon/:bg колбэки просто не сработают (счётчик 0),
        // а решение об авто-установке всё равно принимает приёмник в main-процессе.
        registerActivityLifecycleCallbacks(AppForegroundTracker)

        // Глобальный приёмник завершения загрузки обновлений — ТОЛЬКО в главном
        // процессе: broadcast приложения рассылаются ВСЕМ процессам (:main,
        // :tasks, :daemon, :bg), и регистрация в каждом вызвала бы несколько
        // попыток установки. Решение «ставить сейчас» принимает
        // UpdateInstallReceiver по AppForegroundTracker (живёт здесь же, в main).
        if (isMainProcess()) {
            ContextCompat.registerReceiver(
                this,
                UpdateInstallReceiver(),
                IntentFilter(AppConfig.BROADCAST_ACTION_ACTIVITY),
                Utils.receiverFlags()
            )
        }
    }

    /**
     * True, если текущий процесс — главный (`com.v2ray.ang` без суффикса
     * `:tasks`/`:daemon`/`:bg`). Application.onCreate() вызывается в КАЖДОМ
     * процессе приложения, поэтому UI-логику (трекер foreground, приёмник
     * установки) нужно ставить только в главном.
     *
     * [Application.getProcessName] есть с API 28; для minSdk 24 читаем
     * /proc/self/cmdline — тот же приём, что в ActiveProfileRoute.isOurProcess.
     */
    private fun isMainProcess(): Boolean {
        val name = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            getProcessName()
        } else {
            runCatching { java.io.File("/proc/self/cmdline").readText().trim() }.getOrNull()
        }
        return name == ANG_PACKAGE
    }
}
