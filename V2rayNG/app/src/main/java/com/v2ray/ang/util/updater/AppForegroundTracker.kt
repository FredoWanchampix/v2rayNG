package com.v2ray.ang.util.updater

import android.app.Activity
import android.app.Application
import android.os.Bundle
import java.util.concurrent.atomic.AtomicInteger

/**
 * Счётчик видимых Activity приложения: «пользователь сейчас внутри клиента».
 *
 * Требование владельца (пункт 6): авто-запуск установки обновления ТОЛЬКО если
 * пользователь всё ещё внутри клиента; если вышел/свернул — установку не
 * вызывать, оставить кнопку «Установить» в уведомлении.
 *
 * Почему выбран флаг resumed-activity, а НЕ ProcessLifecycleOwner: загрузчик
 * живёт в процессе `:tasks` (паттерн SubscriptionUpdateService), а Activity —
 * в главном процессе. ProcessLifecycleOwner в `:tasks` не видит UI главного
 * процесса вообще. Поэтому флаг ведётся [Application.ActivityLifecycleCallbacks]
 * в ГЛАВНОМ процессе, а решение «устанавливать сейчас» принимает приёмник
 * broadcast-сообщения, тоже зарегистрированный в главном процессе (см.
 * UpdateDownloadService -> MessageHelper.sendMsg2UI). Кросс-процессная передача —
 * обычный broadcast приложения, никакого нового IPC не нужно.
 *
 * Счётчик (а не boolean) потому, что при конфигурационных изменениях новая
 * Activity стартует ДО onStop старой: на мгновение обе «видимы», и boolean дал
 * бы ложный false. AtomicInteger потокобезопасен (колбэки приходят в main thread,
 * но читают флаг из фоновых потоков сервиса).
 */
object AppForegroundTracker : Application.ActivityLifecycleCallbacks {

    private val resumedCount = AtomicInteger(0)

    /** True, если хотя бы одна Activity приложения сейчас в RESUMED. */
    val isAppInForeground: Boolean
        get() = resumedCount.get() > 0

    override fun onActivityResumed(activity: Activity) {
        resumedCount.incrementAndGet()
    }

    override fun onActivityPaused(activity: Activity) {
        // Не опускаем ниже нуля на случай парных вызовов от системы.
        resumedCount.updateAndGet { if (it > 0) it - 1 else 0 }
    }

    // Остальные колбэки не нужны: resumed/paused достаточно и точнее, чем
    // started/stopped (окно с диалогом поверх остаётся started, но не resumed).
    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit
    override fun onActivityStarted(activity: Activity) = Unit
    override fun onActivityStopped(activity: Activity) = Unit
    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
    override fun onActivityDestroyed(activity: Activity) = Unit
}
