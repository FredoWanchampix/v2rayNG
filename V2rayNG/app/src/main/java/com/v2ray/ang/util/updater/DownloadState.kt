package com.v2ray.ang.util.updater

/**
 * Персистентное состояние одной загрузки обновления.
 *
 * Требование владельца: докачка должна переживать обрыв сети, смену сети, режим
 * полёта, kill процесса и перезагрузку, и быть доступной «как минимум час».
 * Поэтому состояние сериализуется в MMKV (multi-process) через Gson и НЕ имеет
 * короткого TTL: part-файлы сегментов лежат в приватном каталоге до явной отмены
 * пользователем или успешной установки.
 *
 * Ключевая деталь про «час»: подписанный SAS-URL GitHub (release-assets.
 * githubusercontent.com) живёт ~1 час (поле `se=`). Мы его НЕ сохраняем — вместо
 * него храним ПОСТОЯННЫЙ [browserDownloadUrl] (github.com/.../releases/download/
 * TAG/FILE) и при каждой (пере)попытке сегмента идём по нему заново, каждый раз
 * получая свежий редирект. Так докачка работает сколь угодно долго, пока
 * пользователь сам не отменит.
 *
 * Класс — простая data-структура (все поля имеют значения по умолчанию), чтобы
 * Gson мог и сериализовать, и читать её из старых записей после добавления полей.
 */
data class DownloadState(
    /** Тег релиза, к которому относится загрузка (для сверки «тот же релиз»). */
    val releaseTag: String = "",
    /** Имя ассета = базовое имя APK = ключ в SHA256SUMS.txt. */
    val assetName: String = "",
    /** Постоянная ссылка GitHub на ассет (НЕ подписанный SAS-URL). */
    val browserDownloadUrl: String = "",
    /** URL SHA256SUMS.txt того же релиза. */
    val checksumsUrl: String = "",
    /** Эталонный SHA-256 этого ассета (из SHA256SUMS.txt); пусто, если ещё не получен. */
    val expectedSha256: String = "",
    /** Заявленный размер ассета из манифеста релиза (байт); -1 если неизвестен. */
    val declaredSize: Long = -1L,
    /** Фактический размер объекта, подтверждённый сервером (Content-Range total); -1 если ещё не подтверждён. */
    val totalBytes: Long = -1L,
    /** Валидатор объекта (ETag|Last-Modified) из пробного ответа; null если сервер его не отдаёт. */
    val validator: String? = null,
    /** Поддерживает ли сервер Range (206). false -> однопоточная докачка невозможна. */
    val rangesSupported: Boolean = false,
    /** Запрошенное пользователем число потоков (1..24) на момент старта. */
    val requestedSegments: Int = SegmentPlan.DEFAULT_SEGMENT_COUNT,
    /** Фаза загрузки. */
    val phase: Phase = Phase.IDLE,
    /** Прогресс каждого сегмента: индекс -> сколько байт сегмента уже лежит в его part-файле. */
    val segmentDone: Map<Int, Long> = emptyMap(),
    /** Человекочитаемая причина последней ошибки (для уведомления и лога). */
    val lastError: String = "",
    /** Момент последней активности (мс), для логов/диагностики; не ограничивает жизнь загрузки. */
    val updatedAt: Long = 0L,
    /**
     * ФАКТИЧЕСКИЙ путь к проверенному APK (заполняется при READY_TO_INSTALL).
     * Хранится потому, что рабочая папка может быть либо публичным
     * Download/<app>, либо резервным приватным filesDir/updates (если публичная
     * недоступна) — установщик обязан брать файл по РЕАЛЬНОМУ пути, а не
     * пересчитывать его от публичного каталога.
     */
    val apkPath: String = "",
) {

    /**
     * Фазы жизненного цикла загрузки. Хранятся как имя (Gson пишет enum строкой),
     * поэтому добавление нового значения безопасно для старых записей.
     */
    enum class Phase {
        /** Загрузки нет / ещё не начиналась. */
        IDLE,

        /** Идёт пробный запрос (HEAD/первый Range) для выяснения размера и поддержки Range. */
        PROBING,

        /** Активная закачка сегментов. */
        DOWNLOADING,

        /** Пользователь поставил на паузу (part-файлы сохранены, докачка возможна). */
        PAUSED,

        /** Ждём появления сети после обрыва/режима полёта (part-файлы сохранены). */
        WAITING_NETWORK,

        /** Все сегменты скачаны, идёт склейка в один APK. */
        MERGING,

        /** Склеено, идёт проверка SHA-256. */
        VERIFYING,

        /** Хэш совпал, файл готов к установке. */
        READY_TO_INSTALL,

        /** Неустранимая ошибка (хэш не сошёлся, 4xx, битый объект); part может остаться для ретрая. */
        FAILED,

        /** Пользователь отменил. Part-файлы НЕ удаляются (требование владельца), чтобы докачка продолжила. */
        CANCELLED,
    }

    /** Сколько байт суммарно уже лежит в part-файлах всех сегментов. */
    fun downloadedBytes(): Long = segmentDone.values.sum()

    /**
     * Доля выполнения 0..1. Возвращает 0 при неизвестном размере, чтобы UI не
     * показывал «100%» до подтверждения сервера.
     */
    fun progressFraction(): Double {
        if (totalBytes <= 0L) return 0.0
        return (downloadedBytes().toDouble() / totalBytes.toDouble()).coerceIn(0.0, 1.0)
    }

    /** Процент 0..100 для уведомления и прогресс-бара. */
    fun progressPercent(): Int = (progressFraction() * 100.0).toInt().coerceIn(0, 100)

    /** True, если это активная (не завершённая/не отменённая) загрузка. */
    fun isActive(): Boolean = phase == Phase.DOWNLOADING ||
        phase == Phase.PAUSED ||
        phase == Phase.WAITING_NETWORK ||
        phase == Phase.PROBING ||
        phase == Phase.MERGING ||
        phase == Phase.VERIFYING

    /** True, если загрузка относится к тому же релизу и ассету [other]. */
    fun sameTarget(other: DownloadState): Boolean =
        releaseTag == other.releaseTag && assetName == other.assetName

    /** Копия с обновлённой меткой времени. */
    fun touch(now: Long): DownloadState = copy(updatedAt = now)
}
