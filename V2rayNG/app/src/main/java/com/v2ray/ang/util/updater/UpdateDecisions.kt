package com.v2ray.ang.util.updater

/**
 * Чистые решения, которые принимает загрузчик в ключевых точках. Вынесены в
 * отдельный объект без зависимостей Android/MMKV, чтобы их можно было доказать
 * JVM-тестом: ошибка здесь = либо авто-установка выскочит, когда пользователь
 * уже ушёл из клиента, либо загрузчик наплодит дублей задач.
 */
object UpdateDecisions {

    /**
     * Что делать после успешной проверки SHA-256, когда файл READY_TO_INSTALL.
     */
    sealed interface InstallDecision {
        /** Пользователь внутри клиента (foreground) — запускаем установщик сразу. */
        object InstallNow : InstallDecision {
            override fun toString() = "InstallNow"
        }

        /**
         * Пользователь вышел/свернул — установку НЕ вызываем. В уведомлении
         * остаётся действие «Установить» (PendingIntent), он жмёт его сам позже.
         */
        object DeferToNotification : InstallDecision {
            override fun toString() = "DeferToNotification"
        }
    }

    /**
     * Требование владельца (пункт 6): авто-запуск установки ТОЛЬКО если пользователь
     * всё ещё внутри клиента. Решение принимается по флагу «есть resumed-activity»
     * приложения.
     *
     * @param appInForeground true, если сейчас хотя бы одна Activity приложения в
     *   состоянии RESUMED (флаг ведёт [com.v2ray.ang.util.updater.AppForegroundTracker]).
     * @param userAllowedAutoInstall true, если пользователь не запретил авто-установку
     *   (по умолчанию разрешена при скачивании внутри клиента).
     */
    fun decideInstall(appInForeground: Boolean, userAllowedAutoInstall: Boolean = true): InstallDecision =
        if (appInForeground && userAllowedAutoInstall) InstallDecision.InstallNow
        else InstallDecision.DeferToNotification

    /**
     * Что делать при нажатии «Скачать», если загрузка для релиза уже существует.
     * Требование владельца (пункт 8): одна активная загрузка на релиз; повторное
     * нажатие = возобновить/показать прогресс, не плодить задачи.
     */
    sealed interface StartDecision {
        /** Загрузки нет или она окончательно провалилась — стартуем новую (с докачкой part, если есть). */
        object StartNew : StartDecision {
            override fun toString() = "StartNew"
        }

        /** Загрузка уже идёт — ничего не плодим, просто показать прогресс. */
        object AlreadyRunning : StartDecision {
            override fun toString() = "AlreadyRunning"
        }

        /** Загрузка на паузе/ждёт сеть/отменена — возобновить существующую (докачка). */
        object ResumeExisting : StartDecision {
            override fun toString() = "ResumeExisting"
        }

        /**
         * Файл уже скачан, проверен и готов — не качать заново, предложить установку.
         */
        object AlreadyDownloaded : StartDecision {
            override fun toString() = "AlreadyDownloaded"
        }

        /**
         * Существующее состояние относится к ДРУГОМУ релизу/ассету — начать новую
         * загрузку, но НЕ удалять part-файлы чужого релиза (пусть чистит отдельная
         * логика по месту, а не по нажатию).
         */
        object SwitchTarget : StartDecision {
            override fun toString() = "SwitchTarget"
        }
    }

    /**
     * Решает, что делать при повторном «Скачать».
     *
     * @param existing сохранённое состояние (null если нет).
     * @param requestedTag тег релиза, который пользователь хочет скачать сейчас.
     * @param requestedAsset имя ассета сейчас.
     */
    fun decideStart(
        existing: DownloadState?,
        requestedTag: String,
        requestedAsset: String,
    ): StartDecision {
        if (existing == null) return StartDecision.StartNew
        val sameTarget = existing.releaseTag == requestedTag && existing.assetName == requestedAsset
        if (!sameTarget) return StartDecision.SwitchTarget
        return when (existing.phase) {
            DownloadState.Phase.PROBING,
            DownloadState.Phase.DOWNLOADING,
            DownloadState.Phase.MERGING,
            DownloadState.Phase.VERIFYING,
            -> StartDecision.AlreadyRunning

            DownloadState.Phase.PAUSED,
            DownloadState.Phase.WAITING_NETWORK,
            DownloadState.Phase.CANCELLED,
            DownloadState.Phase.FAILED,
            DownloadState.Phase.IDLE,
            -> StartDecision.ResumeExisting

            DownloadState.Phase.READY_TO_INSTALL -> StartDecision.AlreadyDownloaded
        }
    }

    /**
     * Ретраить ли ошибку HTTP на уровне сегмента.
     *
     * 5xx и 429 — переходящие (CDN GitHub их отдаёт под нагрузкой), ретраим с
     * backoff. 4xx (кроме 408/429) — постоянные, не ретраим: например 404 значит
     * ассет удалён, повторять бесполезно.
     */
    fun isRetriableHttp(code: Int): Boolean = code in 500..599 || code == 429 || code == 408

    /**
     * Ретраить ли сетевое исключение. IOException/проблемы TLS — переходящие
     * (ограничительные сети рвут рукопожатия), поэтому ретраим. Остальное — нет.
     *
     * Принимаем имя класса строкой, чтобы решение оставалось чистым и тестируемым
     * без создания реальных исключений и без android.*.
     */
    fun isRetriableIo(exceptionClassNames: List<String>): Boolean {
        return exceptionClassNames.any { name ->
            name == "java.io.IOException" ||
                name.endsWith(".SSLException") ||
                name.endsWith(".SocketTimeoutException") ||
                name.endsWith(".InterruptedIOException") ||
                name.endsWith(".SocketException")
        }
    }
}
